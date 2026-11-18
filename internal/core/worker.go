package core

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// dispatch starts passes while there is room: global and per-project
// parallel limits, locks serving, a free seat among the project's seats.
func (s *Service) dispatch(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	skip := map[string]bool{}
	for {
		s.mu.Lock()
		running := len(s.passes)
		var exclude []string
		for slug := range skip {
			exclude = append(exclude, slug)
		}
		for slug, n := range s.perProject {
			if p := s.Project(slug); p != nil && p.Limits.MaxParallelRuns > 0 && n >= p.Limits.MaxParallelRuns && !skip[slug] {
				exclude = append(exclude, slug)
			}
		}
		s.mu.Unlock()
		if running >= s.d.MaxParallelRuns {
			return
		}
		next, err := s.st.NextQueued(exclude...)
		if err != nil {
			s.log.Error("queue not read", "error", err)
			return
		}
		if next == nil {
			return
		}
		p := s.Project(next.Project)
		if p == nil {
			s.orphan(*next)
			continue
		}
		if !s.locksServing(p) {
			skip[p.Slug] = true
			continue
		}
		st, release, ok := s.pool.Acquire(p.Seats)
		if !ok {
			// No seat for this project now: its incidents wait in the queue.
			skip[p.Slug] = true
			s.capacity(p)
			continue
		}
		inc, err := s.st.ClaimIncident(next.ID)
		if err != nil {
			release()
			if !errors.Is(err, store.ErrStateConflict) {
				s.log.Error("incident not claimed", "incident", next.ID, "error", err)
				return
			}
			continue
		}
		passCtx, cancel := context.WithCancel(ctx)
		live := &pass{cancel: cancel}
		s.mu.Lock()
		s.passes[inc.ID] = live
		s.passTokens[inc.ID] = inc.AgentToken
		s.perProject[p.Slug]++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			leftover := ""
			defer func() {
				cancel()
				// A container that survived its pass still holds the seat
				// token: the seat is not given to another pass before the
				// container is gone.
				s.releaseSeat(ctx, st, leftover, release)
				s.mu.Lock()
				delete(s.passes, inc.ID)
				delete(s.passTokens, inc.ID)
				if s.perProject[p.Slug]--; s.perProject[p.Slug] <= 0 {
					delete(s.perProject, p.Slug)
				}
				s.mu.Unlock()
				s.Kick()
			}()
			leftover = s.runPass(passCtx, p, inc, st, live)
		}()
	}
}

// releaseSeat gives the seat back once the agent container of the pass is
// gone. leftover names a container the launcher could not remove: a human
// is alerted and the removal is retried until it succeeds (or the daemon
// stops); the seat stays held meanwhile.
func (s *Service) releaseSeat(ctx context.Context, st model.Seat, leftover string, release func()) {
	if leftover == "" {
		release()
		return
	}
	s.log.Error("agent container not removed: the seat stays held", "container", leftover, "seat", st.Name)
	s.alertOnce("leftover:"+leftover, 24*time.Hour, model.Alert{Kind: model.AlertSystem,
		Title: "Agent container " + leftover + " could not be removed",
		Body: "The container of a finished pass is still there and still holds the token of seat " + st.Name +
			". The seat is not used again until the container is gone. DutyDesk keeps trying; on the host: `" +
			s.d.Runtime + " rm -f " + leftover + "`."})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer release()
		if s.o.Containers == nil {
			<-ctx.Done() // nothing to retry with: held until the daemon restarts
			return
		}
		t := time.NewTicker(s.o.LeftoverRetry)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := agent.RemoveContainer(rctx, s.o.Containers, s.d.Runtime, leftover)
			cancel()
			if err == nil {
				s.log.Info("leftover agent container removed: the seat is free again", "container", leftover, "seat", st.Name)
				s.Kick()
				return
			}
		}
	}()
}

func (s *Service) cancelPass(id string) {
	s.mu.Lock()
	running := s.passes[id]
	s.mu.Unlock()
	if running != nil {
		running.cancel()
	}
}

// reapPasses stops the pass of every incident that left investigating
// while its agent runs (closed by a human with the CLI, by its source, by
// anything that writes the database): the pass is cancelled and its
// container killed. It runs at every turn of the loop.
func (s *Service) reapPasses(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.passes))
	for id, running := range s.passes {
		if !running.reaped && !running.ended.Load() {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	for _, id := range ids {
		inc, err := s.st.GetIncident(id)
		if err != nil || inc.State == model.StateInvestigating {
			continue
		}
		s.mu.Lock()
		running := s.passes[id]
		if running == nil || running.reaped || running.ended.Load() {
			s.mu.Unlock()
			continue
		}
		running.reaped = true
		container := running.container
		s.mu.Unlock()
		s.log.Warn("incident left investigating while its pass ran: the pass is stopped", "incident", id, "state", string(inc.State))
		running.cancel()
		if container != "" && s.o.Containers != nil {
			s.background(ctx, s.ioSem, "kill:"+container, func(ctx context.Context) {
				kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				defer cancel()
				if err := agent.RemoveContainer(kctx, s.o.Containers, s.d.Runtime, container); err != nil {
					s.log.Warn("container of a stopped pass not removed yet", "container", container, "error", err)
				}
			})
		}
	}
}

// orphan escalates a queued incident whose project left the configuration:
// nothing can run for it.
func (s *Service) orphan(inc model.Incident) {
	_, err := s.st.UpdateIncident(inc.ID, []model.IncidentState{model.StateQueued}, func(i *model.Incident) error {
		i.State = model.StateEscalated
		return nil
	})
	if err != nil {
		s.log.Error("orphan incident not escalated", "incident", inc.ID, "error", err)
		return
	}
	s.journal(inc.ID, "escalated", "Project "+inc.Project+" is no longer in the configuration: no pass can run. State: queued → escalated.")
	s.log.Warn("incident of an unknown project escalated", "incident", inc.ID, "project", inc.Project)
}

// capacity alerts when a high or critical incident of the project has been
// waiting for a seat longer than QueueAlertAfter.
func (s *Service) capacity(p *model.Project) {
	after := p.Limits.QueueAlertAfter
	if after <= 0 {
		return
	}
	queued, err := s.st.ListIncidents(store.IncidentFilter{Project: p.Slug, States: []model.IncidentState{model.StateQueued}})
	if err != nil {
		return
	}
	now := s.now()
	for _, inc := range queued {
		if inc.Severity < model.SevHigh {
			continue
		}
		since, err := s.st.StateSince(inc.ID)
		if err != nil || now.Sub(since) < after {
			continue
		}
		every := after
		if every < time.Hour {
			every = time.Hour
		}
		var lines []string
		for _, st := range s.pool.Stats() {
			switch {
			case st.Exhausted:
				lines = append(lines, fmt.Sprintf("%s: quota exhausted until %s", st.Name, st.ExhaustedUntil.UTC().Format("15:04 UTC")))
			default:
				lines = append(lines, fmt.Sprintf("%s: %d/%d passes running", st.Name, st.InUse, st.MaxParallel))
			}
		}
		s.alertOnce("capacity:"+p.Slug, every, model.Alert{Kind: model.AlertCapacity, Project: p.Slug,
			Title: fmt.Sprintf("No seat free: %s (%s) has been waiting since %s", inc.ID, severityName(inc.Severity), since.UTC().Format("15:04 UTC")),
			Body: "Every seat allowed for this project is busy or out of quota, so no agent investigates.\n" +
				strings.Join(lines, "\n") + "\nAdd a seat, or handle the incident by hand."})
		return
	}
}

func severityName(sev model.Severity) string {
	switch sev {
	case model.SevLow:
		return "low"
	case model.SevMedium:
		return "medium"
	case model.SevHigh:
		return "high"
	case model.SevCritical:
		return "critical"
	}
	return "unknown"
}

func runbookOf(p *model.Project, inc model.Incident) model.Runbook {
	for _, rb := range p.Runbooks {
		if rb.ID == inc.Runbook {
			return rb
		}
	}
	return config.RunbookFor(p, inc.Source)
}

func maxRunsOf(p *model.Project, rb model.Runbook) int {
	if rb.MaxRuns > 0 {
		return rb.MaxRuns
	}
	return p.Limits.MaxRunsPerIncident
}

// passContext is what the effects of a pass need after the pass, even
// after a daemon restart: it is stored in the outbox with the transition.
type passContext struct {
	Run       int               `json:"run"`
	WorkDir   string            `json:"work_dir,omitempty"`
	RepoDirs  map[string]string `json:"repo_dirs,omitempty"`
	ConfigDir string            `json:"config_dir,omitempty"`
	// Bases are the commits the clones were made from, by clone directory,
	// as recorded by the core when it cloned: never read back from a clone.
	Bases       map[string]string `json:"bases,omitempty"`
	TaintMR     bool              `json:"taint_mr,omitempty"`
	TaintConfig bool              `json:"taint_config,omitempty"`
}

// baseKeeper is the part of the forge that remembers which commit a clone
// was made from (internal/forge.Forge).
type baseKeeper interface {
	BaseOf(dir string) (string, bool)
	RestoreBase(dir, rev string) error
}

// runPass is one agent pass on a claimed incident (state investigating). It
// returns the name of the agent container when the launcher could not
// remove it.
func (s *Service) runPass(ctx context.Context, p *model.Project, inc model.Incident, st model.Seat, running *pass) (leftover string) {
	rb := runbookOf(p, inc)
	log := s.log.With("incident", inc.ID, "project", p.Slug, "seat", st.Name)

	run, err := s.st.StartRun(inc.ID, st.Name)
	if err != nil {
		log.Error("run not recorded", "error", err)
		s.failed(p, rb, inc, model.RunResult{Status: model.RunCancelled, Error: "the pass could not be recorded"})
		return ""
	}
	// The pass number is unique per incident, quota retries included: it
	// names the container and the run directory of the dossier.
	n := 1
	if runs, err := s.st.ListRuns(inc.ID); err == nil && len(runs) > 0 {
		n = len(runs)
	}
	finish := func(res model.RunResult) {
		if err := s.st.FinishRun(run.ID, res); err != nil {
			log.Error("run result not recorded", "error", err)
		}
	}
	s.mu.Lock()
	running.container = agent.ContainerNameFor(inc.ID, n)
	s.mu.Unlock()

	workDir := filepath.Join(s.d.DataDir, "work", fmt.Sprintf("%s-%d", strings.ToLower(inc.ID), n))
	s.removeWork(workDir)
	keepWork := false
	defer func() {
		// A merge request that is still owed needs the clones: the work
		// directory is then removed by the effect, not here.
		if !keepWork {
			s.removeWork(workDir)
		}
	}()

	req, err := s.prepare(ctx, p, rb, inc, st, n, workDir)
	if err != nil {
		res := model.RunResult{Status: model.RunFailed, Error: s.scrub("pass not prepared: " + err.Error())}
		if ctx.Err() != nil {
			res.Status = model.RunCancelled
		}
		log.Warn("pass not prepared", "error", res.Error)
		finish(res)
		s.failed(p, rb, inc, res)
		return ""
	}

	log.Info("pass started", "run", n, "runbook", rb.ID)
	started := time.Now()
	res := s.o.Launcher.Run(ctx, req)
	running.ended.Store(true)
	leftover = res.Leftover
	res.Error = model.CleanLine(s.scrub(res.Error))
	var tainted taint
	if res.Verdict != nil {
		res.Verdict, tainted = s.scrubVerdict(res.Verdict)
	}
	if res.Status == model.RunOK && res.Verdict == nil {
		res.Status, res.Error = model.RunFailed, "the launcher returned no verdict"
	}
	finish(res)
	log.Info("pass ended", "run", n, "status", string(res.Status), "turns", res.Turns, "cost_usd", res.CostUSD,
		"duration", time.Since(started).Round(time.Millisecond).String())

	if res.Status != model.RunOK {
		if res.Status == model.RunQuota {
			// The reset time comes from the output of the agent container:
			// the pool caps it (quota_cap).
			if err := s.pool.MarkExhausted(st.Name, res.QuotaReset); err != nil {
				log.Warn("seat exhaustion not saved", "error", err)
			}
			log.Warn("seat exhausted; the incident goes to another seat")
			s.seatsExhausted()
		}
		s.failed(p, rb, inc, res)
		return leftover
	}

	v := *res.Verdict
	for _, a := range v.ActionsRun {
		if err := s.st.RecordAction(inc.ID, run.ID, a); err != nil {
			log.Warn("action not recorded", "error", err)
		}
	}
	// "resolved" is the word of an untrusted agent: when the incident has a
	// deterministic check, the check decides.
	state := incident.CheckNone
	if v.Outcome == model.OutcomeResolved {
		state = s.checkAfterResolved(ctx, p, inc, log)
	}
	pc := passContext{Run: n, RepoDirs: req.RepoDirs, ConfigDir: req.ConfigDir, TaintMR: tainted.mr, TaintConfig: tainted.config}
	owesClones := v.MR != nil || v.MissingAction != nil || v.Improvement != nil
	if owesClones {
		pc.WorkDir = workDir
		if bk, ok := s.forge.(baseKeeper); ok {
			pc.Bases = map[string]string{}
			for _, dir := range append(mapValues(req.RepoDirs), req.ConfigDir) {
				if rev, ok := bk.BaseOf(dir); ok && dir != "" {
					pc.Bases[dir] = rev
				}
			}
		}
	}
	tr, err := s.mgr.ApplyVerdict(inc, v, rb, p.Limits, incident.WithCheck(state), incident.WithContext(pc))
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		// Typically closed by a human or by its source while the pass ran.
		log.Warn("verdict not applied", "outcome", string(v.Outcome), "error", err)
		return leftover
	}
	keepWork = owesClones
	log.Info("verdict applied", "outcome", string(v.Outcome), "from", string(tr.From), "to", string(tr.To), "reason", tr.Reason)
	s.kickOutbox(store.EffectTransition)
	return leftover
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m)+1)
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// checkAfterResolved replays the deterministic check of an incident whose
// agent just answered "resolved".
func (s *Service) checkAfterResolved(ctx context.Context, p *model.Project, inc model.Incident, log *slog.Logger) incident.CheckState {
	c, fp, ok := replayCheck(p, inc)
	if !ok {
		return incident.CheckNone
	}
	if !s.locksServing(p) {
		return incident.CheckUnknown
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	firing, err := check.StillFiring(cctx, c, p, s.o.Reader, fp)
	switch {
	case err != nil:
		log.Warn("check not replayed after a resolved verdict", "check", c.ID, "error", s.scrub(err.Error()))
		return incident.CheckUnknown
	case firing:
		log.Warn("the agent answered resolved but the check still fires", "check", c.ID)
		return incident.CheckFiring
	}
	return incident.CheckCleared
}

// failed applies a pass that ended without a valid verdict; the alert of an
// escalation is owed through the outbox.
func (s *Service) failed(p *model.Project, rb model.Runbook, inc model.Incident, res model.RunResult) {
	tr, err := s.mgr.RunFailed(inc, res.Status, rb, p.Limits, res.Error)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		s.log.Warn("failed pass not applied", "incident", inc.ID, "status", string(res.Status), "error", err)
		return
	}
	if res.Error != "" && res.Status != model.RunCancelled {
		s.journal(inc.ID, "pass error", "The pass ended with this error (untrusted text):\n\n"+incident.Quote(res.Error))
	}
	if tr.Alert != "" {
		s.kickOutbox(store.EffectTransition)
	}
}

// removeWork removes the work directory of a pass. The agent wrote there as
// it pleased: modes are opened first (a tree of 0000 directories is not a
// way to fill the disk for ever), and a human is told when it still fails.
func (s *Service) removeWork(dir string) {
	if dir == "" {
		return
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err := removeTree(dir); err != nil {
		s.log.Error("work directory not removed", "dir", dir, "error", err)
		s.alertOnce("work-dir:"+dir, 24*time.Hour, model.Alert{Kind: model.AlertSystem,
			Title: "A work directory could not be removed",
			Body: "The clones of a finished pass are still on disk: " + dir + " (" + short(err.Error(), 200) +
				"). Remove it by hand; left alone, such directories can fill the disk."})
	}
}

// removeTree is `chmod -R u+rwx` followed by `rm -rf`, without following
// any symbolic link: every directory is opened before it is read.
func removeTree(dir string) error {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// sweepWorkDirs removes, at start-up, the work directories no owed effect
// refers to (left by a crash).
func (s *Service) sweepWorkDirs() {
	root := filepath.Join(s.d.DataDir, "work")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	keep := map[string]bool{}
	if owed, err := s.st.PendingEffects(store.EffectTransition); err == nil {
		for _, e := range owed {
			if _, pc, err := decodeOwed(e); err == nil && pc.WorkDir != "" {
				keep[filepath.Clean(pc.WorkDir)] = true
			}
		}
	} else {
		return // not knowing what is owed, nothing is removed
	}
	for _, e := range entries {
		if dir := filepath.Join(root, e.Name()); !keep[dir] {
			s.removeWork(dir)
		}
	}
}

// prepare builds everything one pass needs: fresh clones, the dossier
// directories and the prompt.
func (s *Service) prepare(ctx context.Context, p *model.Project, rb model.Runbook, inc model.Incident, st model.Seat, n int, workDir string) (model.RunRequest, error) {
	var req model.RunRequest
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return req, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	repoDirs := map[string]string{}
	var repoNames []string
	for _, r := range p.Repos {
		dir := filepath.Join(workDir, "repos", r.Name)
		if err := s.forge.Clone(cctx, r, dir); err != nil {
			return req, fmt.Errorf("clone of %s: %w", r.Name, err)
		}
		repoDirs[r.Name] = dir
		repoNames = append(repoNames, r.Name)
	}
	configDir := ""
	if cr, ok := s.configRepo(p.Slug); ok {
		// A throwaway clone of the protected branch: the agent may write a
		// proposal there, the running configuration never comes from it.
		configDir = filepath.Join(workDir, "config")
		if err := s.forge.Clone(cctx, cr, configDir); err != nil {
			return req, fmt.Errorf("clone of the config repository: %w", err)
		}
	}
	dossierDir, err := s.dossier.Dir(inc.ID)
	if err != nil {
		return req, err
	}
	outDir, err := s.dossier.RunDir(inc.ID, n)
	if err != nil {
		return req, err
	}

	in := agent.PromptInput{
		Method: s.cfg.Load().Method, Project: p, Runbook: rb, Incident: inc,
		Run: inc.Runs + 1, MaxRuns: maxRunsOf(p, rb),
		ActionInstallDir: s.d.ActionInstallDir, Repos: repoNames, ConfigMounted: configDir != "",
	}
	// Only the origin signal is read: an incident can have attached
	// thousands of signals since.
	if origin, err := s.st.OriginSignal(inc.ID); err == nil && origin != nil {
		in.Signal = origin.Signal
	}
	if text, err := s.dossier.Journal(inc.ID); err == nil {
		in.Journal = parseJournal(text)
	}
	if known, err := s.st.ListOpenKnownProblems(p.Slug); err == nil {
		for _, k := range known {
			if k.Family == inc.Family {
				in.KnownProblems = append(in.KnownProblems, k)
			}
		}
	}
	for _, name := range rb.Actions {
		if a, ok := p.Actions[name]; ok {
			in.Actions = append(in.Actions, agent.PromptAction{Action: a,
				CommandLine: agent.ActionCommandLine(a, s.d.ActionInstallDir)})
		}
	}
	if inc.Ticket != "" {
		tctx, tcancel := context.WithTimeout(ctx, 15*time.Second)
		state, err := s.o.Status.Ticket(tctx, p.Locks.Workspace, inc.Ticket)
		tcancel()
		if err == nil && state == model.TicketApproved {
			in.ApprovedTicket = inc.Ticket
		}
	}
	return model.RunRequest{
		Incident: inc, Run: n, Project: p, Runbook: rb, Seat: st, Prompt: agent.BuildPrompt(in),
		DossierDir: dossierDir, RepoDirs: repoDirs, ConfigDir: configDir, OutDir: outDir,
	}, nil
}

var journalHead = regexp.MustCompile(`^## (\S+) — (.*)$`)

// parseJournal turns journal.md into the entries shown in the prompt: one
// per "## <time> — <title>" heading, with its body. The lines of the body
// are kept as lines (the quoted agent text keeps its "> " prefix); the
// prompt builder presents the whole journal as quoted data.
func parseJournal(text string) []agent.JournalEntry {
	var out []agent.JournalEntry
	var cur *agent.JournalEntry
	for _, line := range strings.Split(text, "\n") {
		if m := journalHead.FindStringSubmatch(line); m != nil {
			if at, err := time.Parse(time.RFC3339, m[1]); err == nil {
				out = append(out, agent.JournalEntry{At: at, Text: m[2] + ":"})
				cur = &out[len(out)-1]
				continue
			}
		}
		if line = strings.TrimRight(line, " \t"); cur != nil && strings.TrimSpace(line) != "" {
			cur.Text += "\n" + line
		}
	}
	return out
}

// taint says which proposals of a verdict held a secret in their text: such
// a proposal is refused as a whole, like a secret in its diff.
type taint struct{ mr, config bool }

// scrubVerdict removes known secrets from every text of a verdict before it
// is stored, journaled or shown to a human: the agent holds its seat token
// and its lock identity token, and its output is not trusted.
func (s *Service) scrubVerdict(v *model.Verdict) (*model.Verdict, taint) {
	secrets := s.Secrets()
	var t taint
	dirty := false
	c := func(text string) string {
		// Control characters (ESC included) never reach the database, the
		// journal, an alert or a terminal.
		text = model.CleanText(text)
		for _, sec := range secrets {
			if strings.Contains(text, sec) {
				text, dirty = strings.ReplaceAll(text, sec, "[redacted]"), true
			}
		}
		return text
	}
	out := *v
	out.Summary, out.RootCause, out.Ticket = c(v.Summary), c(v.RootCause), c(v.Ticket)
	out.Confidence, out.Outcome = c(v.Confidence), model.Outcome(c(string(v.Outcome)))
	out.Evidence = nil
	for _, e := range v.Evidence {
		out.Evidence = append(out.Evidence, c(e))
	}
	out.ActionsRun = nil
	for _, a := range v.ActionsRun {
		out.ActionsRun = append(out.ActionsRun, c(a))
	}
	dirty = false
	if v.MR != nil {
		out.MR = &model.MRProposal{Repo: c(v.MR.Repo), Title: c(v.MR.Title), Description: c(v.MR.Description)}
		t.mr = dirty
	}
	dirty = false
	if m := v.MissingAction; m != nil {
		out.MissingAction = &model.MissingAction{Name: c(m.Name), Why: c(m.Why), Title: c(m.Title), Detail: c(m.Detail)}
	}
	if m := v.Improvement; m != nil {
		out.Improvement = &model.Improvement{Title: c(m.Title), Observation: c(m.Observation), Change: c(m.Change),
			Effect: c(m.Effect), Risk: c(m.Risk)}
	}
	t.config = dirty
	return &out, t
}
