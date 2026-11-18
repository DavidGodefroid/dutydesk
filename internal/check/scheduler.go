package check

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Sink receives every evaluation: the signals, or the error. It is called
// from the scheduler's goroutines, possibly for several checks at once.
//
// A check that fails ErrorThreshold times in a row hands a *FailingError
// (wrapping the last error) instead of the plain error: the caller alerts.
type Sink func(c model.Check, signals []model.Signal, err error)

// FailingError says a check failed Consecutive times in a row. It is handed
// to the sink when the streak reaches the threshold, then again at every
// further multiple of it.
type FailingError struct {
	Consecutive int
	Err         error
}

func (e *FailingError) Error() string {
	return fmt.Sprintf("failed %d times in a row: %v", e.Consecutive, e.Err)
}
func (e *FailingError) Unwrap() error { return e.Err }

// Cron is the part of a cron engine the scheduler needs. Jobs may run
// concurrently. Stop returns once no new job starts.
type Cron interface {
	// Add schedules job on a standard 5-field cron spec.
	Add(spec string, job func()) error
	Start()
	Stop()
}

// Options configure a Scheduler. Reader and Sink are required.
type Options struct {
	Reader model.LockReader
	Sink   Sink
	// ErrorThreshold is N of "N errors in a row" (default 3).
	ErrorThreshold int
	// Jitter is the largest random delay before an evaluation, so that the
	// checks of one minute do not hit the locks together (default 10s;
	// negative: none).
	Jitter time.Duration
	// EvalTimeout bounds one evaluation (default 2 minutes).
	EvalTimeout time.Duration
	// OnTruncated is told when a sql check returned more than MaxRows rows.
	OnTruncated func(c model.Check)

	// For tests.
	Now     func() time.Time
	NewCron func() Cron
	Sleep   func(ctx context.Context, d time.Duration) error
	Rand    func(max time.Duration) time.Duration
}

// Scheduler runs the checks of every project on their schedule, one
// evaluation at a time per check.
type Scheduler struct {
	o Options

	mu      sync.Mutex
	cron    Cron // current set
	ctx     context.Context
	started bool
	states  map[string]*checkState // by project/check id, kept across reloads
	wg      sync.WaitGroup
}

type checkState struct {
	mu      sync.Mutex
	running bool
	errs    int
}

// NewScheduler returns a scheduler with no check: call Reload, then Run.
func NewScheduler(o Options) (*Scheduler, error) {
	if o.Reader == nil || o.Sink == nil {
		return nil, errors.New("check: the scheduler needs a reader and a sink")
	}
	if o.ErrorThreshold <= 0 {
		o.ErrorThreshold = 3
	}
	if o.Jitter == 0 {
		o.Jitter = 10 * time.Second
	}
	if o.EvalTimeout <= 0 {
		o.EvalTimeout = 2 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NewCron == nil {
		o.NewCron = newRobfig
	}
	if o.Sleep == nil {
		o.Sleep = sleep
	}
	if o.Rand == nil {
		o.Rand = func(max time.Duration) time.Duration { return rand.N(max) }
	}
	return &Scheduler{o: o, states: map[string]*checkState{}}, nil
}

// Reload swaps the set of checks for those of projects, at once: an
// evaluation already running finishes, later ticks use the new set.
//
// A check whose schedule does not parse is left out and named in the
// returned error; the other checks are loaded all the same.
func (s *Scheduler) Reload(projects []*model.Project) error {
	next := s.o.NewCron()
	states := map[string]*checkState{}
	var errs []error

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range projects {
		if p == nil {
			continue
		}
		for _, c := range p.Checks {
			key := p.Slug + "/" + c.ID
			if _, dup := states[key]; dup {
				errs = append(errs, fmt.Errorf("check %s: declared twice", key))
				continue
			}
			st := s.states[key]
			if st == nil {
				st = &checkState{}
			}
			c, p := c, p
			if err := next.Add(c.Schedule, func() { s.tick(c, p, st) }); err != nil {
				errs = append(errs, fmt.Errorf("check %s: schedule %q: %w", key, c.Schedule, err))
				continue
			}
			states[key] = st
		}
	}
	old := s.cron
	s.cron, s.states = next, states
	if s.started {
		next.Start()
		if old != nil {
			old.Stop()
		}
	}
	return errors.Join(errs...)
}

// Run starts the schedule and blocks until ctx is cancelled; it returns
// once the evaluations in flight have ended (their context is ctx).
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("check: the scheduler already runs")
	}
	s.started, s.ctx = true, ctx
	if s.cron != nil {
		s.cron.Start()
	}
	s.mu.Unlock()

	<-ctx.Done()

	s.mu.Lock()
	if s.cron != nil {
		s.cron.Stop()
	}
	s.cron = nil
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// tick is one cron firing of a check.
func (s *Scheduler) tick(c model.Check, p *model.Project, st *checkState) {
	s.mu.Lock()
	ctx := s.ctx
	if !s.started || ctx == nil || ctx.Err() != nil {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	st.mu.Lock()
	if st.running {
		// The previous evaluation still runs: skip this tick.
		st.mu.Unlock()
		return
	}
	st.running = true
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		st.running = false
		st.mu.Unlock()
	}()

	if s.o.Jitter > 0 {
		if err := s.o.Sleep(ctx, s.o.Rand(s.o.Jitter)); err != nil {
			return
		}
	}
	ectx, cancel := context.WithTimeout(ctx, s.o.EvalTimeout)
	res, err := Run(ectx, c, p, s.o.Reader, s.o.Now())
	cancel()
	if ctx.Err() != nil {
		return // stopping: neither a result nor a failure of the check
	}

	st.mu.Lock()
	if err != nil {
		st.errs++
		if st.errs%s.o.ErrorThreshold == 0 {
			err = &FailingError{Consecutive: st.errs, Err: err}
		}
	} else {
		st.errs = 0
	}
	st.mu.Unlock()

	if err != nil {
		s.o.Sink(c, nil, err)
		return
	}
	if res.Truncated && s.o.OnTruncated != nil {
		s.o.OnTruncated(c)
	}
	s.o.Sink(c, res.Signals, nil)
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ValidSchedule reports whether spec is a standard 5-field cron schedule.
func ValidSchedule(spec string) error {
	_, err := cron.ParseStandard(spec)
	return err
}

// robfig adapts robfig/cron with the standard 5-field parser.
type robfig struct{ c *cron.Cron }

func newRobfig() Cron { return &robfig{c: cron.New()} }

func (r *robfig) Add(spec string, job func()) error {
	_, err := r.c.AddFunc(spec, job)
	return err
}
func (r *robfig) Start() { r.c.Start() }
func (r *robfig) Stop()  { r.c.Stop() }
