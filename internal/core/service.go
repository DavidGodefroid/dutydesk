// Package core is DutyDesk's dispatcher: one Service that wires the
// deterministic packages (config, check, intake, incident, seat, forge,
// notify) behind the ports of internal/model and runs the daemon's loops.
//
// The agent thinks, the core acts: everything that leaves an agent container
// (verdict, edited clones) is applied here, after the checks of each package.
package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/forge"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/intake"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/notify"
	"github.com/DavidGodefroid/dutydesk/internal/seat"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// DBName is the database file inside the data directory.
const DBName = "dutydesk.db"

// Periods are how often the periodic duties run, measured on the service
// clock. Zero values take the defaults; a negative value means every turn
// of the main loop (tests).
type Periods struct {
	Health        time.Duration // lock gate poll (15s)
	Tickets       time.Duration // green-light tickets (30s)
	Cleared       time.Duration // replay checks of escalated / blocked / mr_open incidents (5m)
	KnownProblems time.Duration // merge request states on the forge (5m)
	ConfigSync    time.Duration // git fetch of the config repository (1m)
	Reminders     time.Duration // reminders, seat expiry, capacity (1m)
	RecheckRetry  time.Duration // wait before replaying a check that failed (1m)
	Retention     time.Duration // pruning of old resolved incidents (1h)
}

func (p Periods) withDefaults() Periods {
	def := func(v *time.Duration, d time.Duration) {
		if *v == 0 {
			*v = d
		}
	}
	def(&p.Health, 15*time.Second)
	def(&p.Tickets, 30*time.Second)
	def(&p.Cleared, 5*time.Minute)
	def(&p.KnownProblems, 5*time.Minute)
	def(&p.ConfigSync, time.Minute)
	def(&p.Reminders, time.Minute)
	def(&p.RecheckRetry, time.Minute)
	def(&p.Retention, time.Hour)
	return p
}

// Options configure a Service. Daemon, Reader, Status, Launcher and Notifier
// are required.
type Options struct {
	Daemon   *config.Daemon
	Reader   model.LockReader
	Status   model.LockStatus
	Launcher model.AgentLauncher
	Notifier model.Notifier

	// Forge overrides the forge built from ForgeConfig (tests with a fake).
	Forge model.Forge
	// ForgeConfig is the base of the real forge; the service sets its path
	// policy (configuration repository) and its secret list itself.
	ForgeConfig forge.Config

	// Syncer overrides how the config checkout follows config_remote
	// (default: git fetch + fast-forward). Unused without config_remote.
	Syncer ConfigSyncer
	// LoadRepo overrides config.LoadRepo (tests adapt the loaded projects).
	LoadRepo func(dir string) (*config.Repo, error)
	// Containers lists and removes the agent containers left by a crash,
	// through the container runtime client. nil: nothing is cleaned up.
	Containers agent.Runner

	Now    func() time.Time // default time.Now
	Logger *slog.Logger     // default slog.Default()
	// Tick is the real-time pace of the main loop (default 1s).
	Tick    time.Duration
	Periods Periods

	// Scheduler knobs, for tests.
	NewCron     func() check.Cron
	CheckJitter time.Duration
	// EffectTimeout bounds one attempt at the merge requests of a pass
	// (push, forge API); default 5 minutes. Alerts have their own timeout.
	EffectTimeout time.Duration
	// AlertTimeout bounds the delivery of one alert; default 1 minute.
	AlertTimeout time.Duration
	// OutboxBackoff is the wait before each retry of an owed effect that
	// failed (the last value repeats); default 15s, 1m, 5m, 15m.
	OutboxBackoff []time.Duration
	// ReplayWorkers bounds the check replays that run at once (default 4).
	ReplayWorkers int
	// LeftoverRetry is the pause between two attempts to remove an agent
	// container that survived its pass (default 30s).
	LeftoverRetry time.Duration
}

// pass is one running agent pass.
type pass struct {
	cancel    context.CancelFunc
	container string      // name of the agent container
	ended     atomic.Bool // the launcher returned
	reaped    bool        // cancelled because the incident left investigating
}

// Service is the daemon. Build it with New, then call Run.
type Service struct {
	o       Options
	d       *config.Daemon
	log     *slog.Logger
	now     func() time.Time
	periods Periods

	st      *store.Store
	dossier *incident.Dossier
	mgr     *incident.Manager
	pool    *seat.Pool
	forge   model.Forge
	sched   *check.Scheduler
	hooks   *intake.Handler
	syncer  ConfigSyncer

	cfg atomic.Pointer[config.Repo]

	mu         sync.Mutex
	runCtx     context.Context
	passes     map[string]*pass  // running passes, by incident id
	passTokens map[string]string // agent tokens of the incidents being worked on
	perProject map[string]int
	gate       map[string]*gateState // by lock workspace
	lastDuty   map[string]time.Time
	retryAt    map[string]time.Time // incident id -> next replay of its check
	onceAlerts map[string]time.Time // de-duplication of system alerts
	badConfig  string               // remote revision already rejected
	inflight   map[string]bool      // background duties running, by key
	seatsOut   bool                 // the "every seat is exhausted" alert was sent for this episode

	replaySem chan struct{} // bounded pool of check replays
	ioSem     chan struct{} // bounded pool of the other slow duties (lock status, forge, git)
	outKick   map[string]chan struct{}

	wg         sync.WaitGroup
	kick       chan struct{}
	lastLoopOK atomic.Int64 // unix nano (real time) of the last healthy loop turn
	schedDown  atomic.Bool
	closeOnce  sync.Once
}

// New opens the data directory, loads the configuration and wires the
// service. It starts nothing: call Run.
func New(o Options) (*Service, error) {
	switch {
	case o.Daemon == nil:
		return nil, errors.New("core: no daemon configuration")
	case o.Reader == nil || o.Status == nil:
		return nil, errors.New("core: a lock reader and a lock status are required")
	case o.Launcher == nil:
		return nil, errors.New("core: an agent launcher is required")
	case o.Notifier == nil:
		return nil, errors.New("core: a notifier is required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Tick <= 0 {
		o.Tick = time.Second
	}
	if o.LoadRepo == nil {
		o.LoadRepo = config.LoadRepo
	}
	if o.EffectTimeout <= 0 {
		o.EffectTimeout = 5 * time.Minute
	}
	if o.AlertTimeout <= 0 {
		o.AlertTimeout = time.Minute
	}
	if len(o.OutboxBackoff) == 0 {
		o.OutboxBackoff = []time.Duration{15 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute}
	}
	if o.ReplayWorkers <= 0 {
		o.ReplayWorkers = 4
	}
	if o.LeftoverRetry <= 0 {
		o.LeftoverRetry = 30 * time.Second
	}
	s := &Service{
		o: o, d: o.Daemon, log: o.Logger, now: o.Now, periods: o.Periods.withDefaults(),
		passes: map[string]*pass{}, passTokens: map[string]string{}, perProject: map[string]int{}, gate: map[string]*gateState{},
		lastDuty: map[string]time.Time{}, retryAt: map[string]time.Time{}, onceAlerts: map[string]time.Time{},
		kick: make(chan struct{}, 1), inflight: map[string]bool{},
		replaySem: make(chan struct{}, o.ReplayWorkers), ioSem: make(chan struct{}, 4),
		outKick: map[string]chan struct{}{store.EffectAlert: make(chan struct{}, 1), store.EffectTransition: make(chan struct{}, 1)},
	}
	if err := os.MkdirAll(s.d.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("core: data dir: %w", err)
	}
	repo, err := s.loadRepo(s.d.ConfigRepo)
	if err != nil {
		return nil, fmt.Errorf("core: configuration: %w", err)
	}
	s.cfg.Store(repo)

	st, err := store.Open(filepath.Join(s.d.DataDir, DBName), s.now)
	if err != nil {
		return nil, err
	}
	s.st = st
	fail := func(err error) (*Service, error) {
		st.Close()
		return nil, err
	}
	if s.pool, err = seat.New(s.d.Seats, SeatState{st}, seat.WithClock(s.now), seat.WithMaxExhaustion(s.d.QuotaCap)); err != nil {
		return fail(err)
	}
	s.dossier = incident.NewDossier(s.d.DataDir)
	s.mgr = incident.NewManager(st, s.now, s.limitsOf, incident.WithDossier(s.dossier))

	s.forge = o.Forge
	if s.forge == nil {
		fc := o.ForgeConfig
		fc.PolicyFor = proposalPolicy
		fc.Secrets = s.Secrets
		if fc.Logf == nil {
			fc.Logf = func(format string, args ...any) { s.log.Warn(s.scrub(fmt.Sprintf(format, args...))) }
		}
		s.forge = forge.New(fc)
	}
	if s.d.ConfigRemote != nil {
		if s.syncer = o.Syncer; s.syncer == nil {
			s.syncer = &GitSyncer{Dir: s.d.ConfigRepo, Remote: *s.d.ConfigRemote, AllowLocal: o.ForgeConfig.AllowLocal}
		}
	}

	s.sched, err = check.NewScheduler(check.Options{
		Reader: gatedReader{s}, Sink: s.checkSink, Now: s.now, NewCron: o.NewCron, Jitter: o.CheckJitter,
		OnTruncated: func(c model.Check) {
			s.log.Warn("check returned more rows than the cap; signals were left out", "project", c.Project, "check", c.ID, "cap", check.MaxRows)
		},
	})
	if err != nil {
		return fail(err)
	}
	if err := s.sched.Reload(repo.Projects); err != nil {
		return fail(fmt.Errorf("core: checks: %w", err))
	}
	s.hooks, err = intake.New(intake.Options{
		Project:  s.Project,
		Sink:     func(sig model.Signal) { s.ingest(sig) },
		Resolved: s.sourceResolved,
		Now:      s.now,
		Logger:   s.log,
	})
	if err != nil {
		return fail(err)
	}
	return s, nil
}

// Handler is the inbound webhook endpoint (POST /hooks/{project}/{source}).
func (s *Service) Handler() http.Handler { return s.hooks }

// Store gives read access to the database (CLI, tests).
func (s *Service) Store() *store.Store { return s.st }

// Manager is the incident lifecycle of this service.
func (s *Service) Manager() *incident.Manager { return s.mgr }

// Project returns the current configuration of a project, or nil.
func (s *Service) Project(slug string) *model.Project { return s.cfg.Load().Project(slug) }

func (s *Service) limitsOf(project string) model.Limits {
	if p := s.Project(project); p != nil {
		return p.Limits
	}
	return config.DefaultLimits()
}

// Run runs the daemon until ctx is cancelled, then stops taking work,
// cancels the running passes (they go back to the queue), and closes the
// store.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.runCtx != nil {
		s.mu.Unlock()
		return errors.New("core: the service already runs")
	}
	s.runCtx = ctx
	s.mu.Unlock()
	defer s.Close()

	if recovered, err := s.st.RecoverInterrupted(); err != nil {
		return fmt.Errorf("core: recover: %w", err)
	} else if len(recovered) > 0 {
		for _, inc := range recovered {
			s.journal(inc.ID, "recovered", "DutyDesk restarted while a pass was running: the incident is back in the queue.")
		}
		s.log.Info("recovered interrupted incidents", "count", len(recovered))
	}
	s.removeLeftoverContainers(ctx)
	s.sweepWorkDirs()

	var bg sync.WaitGroup
	// The outbox is drained from the first moment: what a previous run owed
	// (alerts, merge requests) goes out before anything new.
	for kind, handle := range map[string]func(context.Context, store.Effect){
		store.EffectAlert: s.deliverAlert, store.EffectTransition: s.runEffect,
	} {
		bg.Add(1)
		go func() {
			defer bg.Done()
			s.drain(ctx, kind, handle)
		}()
	}
	bg.Add(1)
	go func() {
		defer bg.Done()
		if err := s.sched.Run(ctx); err != nil {
			s.log.Error("check scheduler stopped", "error", err)
		}
		if ctx.Err() == nil {
			s.schedDown.Store(true)
		}
	}()
	beats := s.startHeartbeats(ctx)

	s.log.Info("dutydesk core started", "projects", len(s.cfg.Load().Projects), "seats", len(s.d.Seats),
		"max_parallel_runs", s.d.MaxParallelRuns)
	ticker := time.NewTicker(s.o.Tick)
	defer ticker.Stop()
	for ctx.Err() == nil {
		s.turn(ctx)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		case <-s.kick:
		}
	}

	s.log.Info("dutydesk core stopping: waiting for running passes")
	s.wg.Wait()
	bg.Wait()
	for _, done := range beats {
		<-done
	}
	return nil
}

// Close closes the store. Run calls it; it is safe to call again.
func (s *Service) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.st.Close() })
	return err
}

// Kick asks for a loop turn now instead of at the next tick.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// turn is one pass of the main loop. Each duty is isolated: an error is
// logged and the next duty runs.
func (s *Service) turn(ctx context.Context) {
	if _, err := s.st.SchemaVersion(); err != nil {
		s.log.Error("store unreachable", "error", err)
		return
	}
	s.lastLoopOK.Store(time.Now().UnixNano())

	// Nothing below waits on a lock, the forge, git or a webhook: every
	// slow call runs in a bounded background pool (background) or in the
	// outbox drain, so the loop keeps turning and the heartbeat stays
	// truthful whatever a slow lock does.
	s.reapPasses(ctx)
	if s.due("health", s.periods.Health) {
		s.pollLocks(ctx)
	}
	if s.syncer != nil && s.due("config", s.periods.ConfigSync) {
		s.background(ctx, s.ioSem, "config", s.syncConfig)
	}
	s.rechecks(ctx)
	if s.due("tickets", s.periods.Tickets) {
		s.greenLights(ctx)
	}
	if s.due("cleared", s.periods.Cleared) {
		s.clearedConditions(ctx)
	}
	if s.due("known", s.periods.KnownProblems) {
		s.background(ctx, s.ioSem, "known", s.knownProblems)
	}
	if s.due("reminders", s.periods.Reminders) {
		s.ageLimits()
		s.reminders()
		s.seatExpiry()
		s.seatsExhausted()
	}
	if s.due("retention", s.periods.Retention) {
		s.background(ctx, s.ioSem, "retention", func(context.Context) { s.retention() })
	}
	s.dispatch(ctx)
}

// background runs a slow duty outside the main loop, in the bounded pool
// sem. A duty that is still running under the same key, or a full pool,
// makes it a no-op: the next turn tries again. It reports whether the duty
// was started.
func (s *Service) background(ctx context.Context, sem chan struct{}, key string, fn func(context.Context)) bool {
	if ctx.Err() != nil {
		return false
	}
	s.mu.Lock()
	if s.inflight[key] {
		s.mu.Unlock()
		return false
	}
	select {
	case sem <- struct{}{}:
	default:
		s.mu.Unlock()
		return false
	}
	s.inflight[key] = true
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer func() {
			<-sem
			s.mu.Lock()
			delete(s.inflight, key)
			s.mu.Unlock()
			s.wg.Done()
		}()
		fn(ctx)
	}()
	return true
}

// due reports whether a duty's period has elapsed on the service clock, and
// restarts it.
func (s *Service) due(name string, every time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.lastDuty[name]
	if ok && every > 0 && now.Sub(last) < every && !now.Before(last) {
		return false
	}
	s.lastDuty[name] = now
	return true
}

// Healthy is what the heartbeat reports: the main loop turns, the store
// answers and the check scheduler is alive.
func (s *Service) Healthy() bool {
	last := s.lastLoopOK.Load()
	if last == 0 || s.schedDown.Load() {
		return false
	}
	limit := 10 * s.o.Tick
	if limit < 30*time.Second {
		limit = 30 * time.Second
	}
	return time.Since(time.Unix(0, last)) < limit
}

func (s *Service) startHeartbeats(ctx context.Context) []<-chan struct{} {
	urls := map[string]time.Duration{}
	if u := s.d.Heartbeat.URL; u != "" {
		urls[u] = s.d.Heartbeat.Every
	}
	for _, p := range s.cfg.Load().Projects {
		if u := p.Alerts.HeartbeatURL; u != "" {
			if _, ok := urls[u]; !ok {
				urls[u] = s.d.Heartbeat.Every
			}
		}
	}
	var done []<-chan struct{}
	for u, every := range urls {
		hb := &notify.Heartbeat{URL: u, Interval: every, Healthy: s.Healthy,
			Logf: func(format string, args ...any) { s.log.Warn(fmt.Sprintf(format, args...)) }}
		done = append(done, hb.Start(ctx))
	}
	return done
}

// SeatState adapts the store to seat.StateStore.
type SeatState struct{ St *store.Store }

func (a SeatState) ExhaustedUntil(name string) (time.Time, error) {
	return a.St.SeatExhaustedUntil(name)
}
func (a SeatState) SetExhaustedUntil(name string, t time.Time) error {
	return a.St.SetSeatExhausted(name, t)
}

// SeatTokens reads seat tokens from the files the daemon configuration
// names; it is the agent launcher's TokenSource.
type SeatTokens []model.Seat

func (t SeatTokens) Token(name string) (string, error) {
	for _, s := range t {
		if s.Name == name {
			return seat.ReadTokenFile(s.TokenFile)
		}
	}
	return "", fmt.Errorf("core: unknown seat %q", name)
}

// journal appends to the dossier journal; a failure is logged, never fatal.
// body is text the core wrote: untrusted text inside it goes through
// incident.Quote first.
func (s *Service) journal(id, title, body string) {
	if err := s.dossier.Append(id, s.now(), title, s.scrub(body)); err != nil {
		s.log.Error("journal not written", "incident", id, "error", err)
	}
}
