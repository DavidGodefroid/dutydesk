package check

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// fakeCron keeps the jobs; the test fires them by spec.
type fakeCron struct {
	mu      sync.Mutex
	jobs    map[string][]func()
	started bool
	stopped bool
}

func (f *fakeCron) Add(spec string, job func()) error {
	if err := ValidSchedule(spec); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jobs == nil {
		f.jobs = map[string][]func(){}
	}
	f.jobs[spec] = append(f.jobs[spec], job)
	return nil
}
func (f *fakeCron) Start() { f.mu.Lock(); f.started = true; f.mu.Unlock() }
func (f *fakeCron) Stop()  { f.mu.Lock(); f.stopped = true; f.mu.Unlock() }

// fire runs the jobs of spec as the cron engine would, if it runs.
func (f *fakeCron) fire(spec string) {
	f.mu.Lock()
	jobs, on := f.jobs[spec], f.started && !f.stopped
	f.mu.Unlock()
	if !on {
		return
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() { defer wg.Done(); j() }()
	}
	wg.Wait()
}

type sunk struct {
	check   string
	signals []model.Signal
	err     error
}

type harness struct {
	t     *testing.T
	s     *Scheduler
	mu    sync.Mutex
	crons []*fakeCron
	got   []sunk
	slept []time.Duration
	stop  context.CancelFunc
	done  chan struct{}
}

func newHarness(t *testing.T, r model.LockReader, mod func(*Options)) *harness {
	h := &harness{t: t, done: make(chan struct{})}
	o := Options{
		Reader: r,
		Sink: func(c model.Check, sig []model.Signal, err error) {
			h.mu.Lock()
			h.got = append(h.got, sunk{c.ID, sig, err})
			h.mu.Unlock()
		},
		Now: func() time.Time { return now },
		NewCron: func() Cron {
			c := &fakeCron{}
			h.mu.Lock()
			h.crons = append(h.crons, c)
			h.mu.Unlock()
			return c
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.mu.Lock()
			h.slept = append(h.slept, d)
			h.mu.Unlock()
			return ctx.Err()
		},
		Rand: func(max time.Duration) time.Duration { return max / 2 },
	}
	if mod != nil {
		mod(&o)
	}
	s, err := NewScheduler(o)
	if err != nil {
		t.Fatal(err)
	}
	h.s = s
	return h
}

func (h *harness) run() {
	ctx, cancel := context.WithCancel(context.Background())
	h.stop = cancel
	go func() { h.s.Run(ctx); close(h.done) }()
	// Wait until Run has started the cron.
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.s.mu.Lock()
		started := h.s.started
		h.s.mu.Unlock()
		if started {
			return
		}
		if time.Now().After(deadline) {
			h.t.Fatal("the scheduler did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *harness) cron(i int) *fakeCron {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.crons[i]
}

func (h *harness) results() []sunk {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]sunk(nil), h.got...)
}

func projects(checks ...model.Check) []*model.Project {
	return []*model.Project{{Slug: "shop", Checks: checks}}
}

func TestSchedulerRunsChecksOnTheirSchedule(t *testing.T) {
	r := &fakeReader{rows: []model.Row{{"id": "7"}}, count: 5}
	h := newHarness(t, r, nil)
	err := h.s.Reload(projects(
		model.Check{ID: "sql", Kind: model.CheckSQL, Schedule: "*/5 * * * *", Fingerprint: "x:{id}"},
		model.Check{ID: "log", Kind: model.CheckLog, Schedule: "0 6 * * *", Threshold: 3},
	))
	if err != nil {
		t.Fatal(err)
	}
	h.run()
	h.cron(0).fire("*/5 * * * *")
	got := h.results()
	if len(got) != 1 || got[0].check != "sql" || got[0].err != nil || len(got[0].signals) != 1 || got[0].signals[0].Fingerprint != "x:7" || !got[0].signals[0].At.Equal(now) {
		t.Fatalf("results: %+v", got)
	}
	h.cron(0).fire("0 6 * * *")
	if got := h.results(); len(got) != 2 || got[1].check != "log" || len(got[1].signals) != 1 {
		t.Fatalf("results: %+v", got)
	}
	// Jittered start: half of the default 10s with the test's Rand.
	if len(h.slept) != 2 || h.slept[0] != 5*time.Second {
		t.Fatalf("jitter: %v", h.slept)
	}
	h.stop()
	<-h.done
	if !h.cron(0).stopped {
		t.Fatal("the cron still runs after cancellation")
	}
}

func TestSchedulerSkipsWhileThePreviousRuns(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	r := &blockingReader{entered: entered, release: release}
	h := newHarness(t, r, nil)
	h.s.Reload(projects(model.Check{ID: "slow", Kind: model.CheckSQL, Schedule: "* * * * *"}))
	h.run()
	first := make(chan struct{})
	go func() { h.cron(0).fire("* * * * *"); close(first) }()
	<-entered
	h.cron(0).fire("* * * * *") // returns at once: skipped
	if n := r.calls(); n != 1 {
		t.Fatalf("evaluations while one runs: %d", n)
	}
	close(release)
	<-first
	if got := h.results(); len(got) != 1 {
		t.Fatalf("results: %+v", got)
	}
	h.cron(0).fire("* * * * *")
	if n := r.calls(); n != 2 {
		t.Fatalf("evaluations after the first ended: %d", n)
	}
	h.stop()
	<-h.done
}

type blockingReader struct {
	mu      sync.Mutex
	n       int
	entered chan struct{}
	release chan struct{}
}

func (b *blockingReader) calls() int { b.mu.Lock(); defer b.mu.Unlock(); return b.n }

func (b *blockingReader) SQL(ctx context.Context, _ *model.Project, _ string) ([]model.Row, error) {
	b.mu.Lock()
	b.n++
	first := b.n == 1
	b.mu.Unlock()
	if first {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, nil
}

func (b *blockingReader) LogCount(context.Context, *model.Project, string, time.Duration) (int, error) {
	return 0, nil
}

func TestSchedulerReportsRepeatedErrors(t *testing.T) {
	boom := errors.New("lock down")
	r := &fakeReader{err: boom}
	h := newHarness(t, r, func(o *Options) { o.ErrorThreshold = 3 })
	h.s.Reload(projects(model.Check{ID: "c", Kind: model.CheckSQL, Schedule: "* * * * *"}))
	h.run()
	failing := func(err error) int {
		var fe *FailingError
		if errors.As(err, &fe) {
			return fe.Consecutive
		}
		return 0
	}
	for i := 0; i < 7; i++ {
		h.cron(0).fire("* * * * *")
	}
	got := h.results()
	if len(got) != 7 {
		t.Fatalf("results: %d", len(got))
	}
	for i, want := range []int{0, 0, 3, 0, 0, 6, 0} {
		if !errors.Is(got[i].err, boom) || failing(got[i].err) != want {
			t.Errorf("run %d: %v (want failing=%d)", i+1, got[i].err, want)
		}
	}
	// A success ends the streak.
	r.mu.Lock()
	r.err = nil
	r.mu.Unlock()
	h.cron(0).fire("* * * * *")
	r.mu.Lock()
	r.err = boom
	r.mu.Unlock()
	h.cron(0).fire("* * * * *")
	h.cron(0).fire("* * * * *")
	got = h.results()
	if got[7].err != nil || failing(got[8].err) != 0 || failing(got[9].err) != 0 {
		t.Fatalf("after a success: %v / %v / %v", got[7].err, got[8].err, got[9].err)
	}
	h.stop()
	<-h.done
}

func TestSchedulerReloadSwapsTheSet(t *testing.T) {
	r := &fakeReader{err: errors.New("down")}
	h := newHarness(t, r, func(o *Options) { o.ErrorThreshold = 2 })
	h.s.Reload(projects(
		model.Check{ID: "kept", Kind: model.CheckSQL, Schedule: "* * * * *"},
		model.Check{ID: "gone", Kind: model.CheckSQL, Schedule: "1 * * * *"},
	))
	h.run()
	h.cron(0).fire("* * * * *") // kept: 1 error

	err := h.s.Reload(projects(
		model.Check{ID: "kept", Kind: model.CheckSQL, Schedule: "*/2 * * * *"},
		model.Check{ID: "new", Kind: model.CheckSQL, Schedule: "2 * * * *"},
		model.Check{ID: "bad", Kind: model.CheckSQL, Schedule: "every day"},
		model.Check{ID: "six", Kind: model.CheckSQL, Schedule: "0 * * * * *"},
	))
	if err == nil || !strings.Contains(err.Error(), "shop/bad") || !strings.Contains(err.Error(), "shop/six") {
		t.Fatalf("reload error: %v", err)
	}
	if !h.cron(0).stopped || !h.cron(1).started {
		t.Fatal("the old set still runs or the new one does not")
	}
	h.cron(0).fire("1 * * * *") // old set: nothing
	h.cron(1).fire("2 * * * *")
	h.cron(1).fire("*/2 * * * *") // kept: its streak survives the reload
	got := h.results()
	if len(got) != 3 || got[1].check != "new" || got[2].check != "kept" {
		t.Fatalf("results: %+v", got)
	}
	var fe *FailingError
	if !errors.As(got[2].err, &fe) || fe.Consecutive != 2 {
		t.Fatalf("streak across reload: %v", got[2].err)
	}
	h.stop()
	<-h.done
}

func TestSchedulerStopsOnCancel(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	r := &blockingReader{entered: entered, release: release}
	h := newHarness(t, r, nil)
	h.s.Reload(projects(model.Check{ID: "slow", Kind: model.CheckSQL, Schedule: "* * * * *"}))
	h.run()
	c := h.cron(0)
	fired := make(chan struct{})
	go func() { c.fire("* * * * *"); close(fired) }()
	<-entered
	h.stop() // cancels the evaluation in flight
	<-h.done
	<-fired
	if got := h.results(); len(got) != 0 {
		t.Fatalf("a cancelled evaluation reached the sink: %+v", got)
	}
	// A late tick of a job the engine had already started does nothing.
	c.mu.Lock()
	job := c.jobs["* * * * *"][0]
	c.mu.Unlock()
	job()
	if n := r.calls(); n != 1 {
		t.Fatalf("evaluations after stop: %d", n)
	}
}

func TestSchedulerTruncatedCallback(t *testing.T) {
	r := &fakeReader{}
	for i := 0; i <= MaxRows; i++ {
		r.rows = append(r.rows, model.Row{})
	}
	var truncated []string
	h := newHarness(t, r, func(o *Options) {
		o.OnTruncated = func(c model.Check) { truncated = append(truncated, c.ID) }
		o.Jitter = -1
	})
	h.s.Reload(projects(model.Check{ID: "big", Kind: model.CheckSQL, Schedule: "* * * * *"}))
	h.run()
	h.cron(0).fire("* * * * *")
	if got := h.results(); len(got) != 1 || len(got[0].signals) != MaxRows || len(truncated) != 1 || len(h.slept) != 0 {
		t.Fatalf("results=%d truncated=%v slept=%v", len(got), truncated, h.slept)
	}
	h.stop()
	<-h.done
}

func TestSchedulerRealCron(t *testing.T) {
	// The default engine parses 5 fields and stops cleanly.
	s, err := NewScheduler(Options{Reader: &fakeReader{}, Sink: func(model.Check, []model.Signal, error) {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(projects(model.Check{ID: "a", Kind: model.CheckSQL, Schedule: "*/5 * * * *"})); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(projects(model.Check{ID: "a", Kind: model.CheckSQL, Schedule: "* * * * * *"})); err == nil {
		t.Fatal("6 fields: want an error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if _, err := NewScheduler(Options{}); err == nil {
		t.Fatal("want an error without reader and sink")
	}
}
