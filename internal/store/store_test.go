package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func newStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: t0}
	s, err := Open(filepath.Join(t.TempDir(), "dutydesk.db"), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, clk
}

func mk(t *testing.T, s *Store, inc model.Incident) model.Incident {
	t.Helper()
	if inc.Project == "" {
		inc.Project = "shop"
	}
	if inc.Source == "" {
		inc.Source = "stuck-job"
	}
	if inc.Severity == 0 {
		inc.Severity = model.SevMedium
	}
	out, err := s.CreateIncident(inc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenMigratesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub dir?#", "d.db")
	if _, err := Open(path, nil); err == nil {
		t.Fatal("want an error when the directory is missing")
	}
	path = filepath.Join(t.TempDir(), "odd name?#%.db")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SchemaVersion()
	if err != nil || v < 1 {
		t.Fatalf("schema version = %d, %v", v, err)
	}
	var mode, fk string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v", mode, err)
	}
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != "1" {
		t.Fatalf("foreign_keys = %q, %v", fk, err)
	}
	if _, err := s.CreateIncident(model.Incident{Project: "p", Source: "c", Fingerprint: "f", Severity: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v2, _ := s.SchemaVersion(); v2 != v {
		t.Fatalf("version changed on reopen: %d -> %d", v, v2)
	}
	if _, err := s.GetIncident("INC-000001"); err != nil {
		t.Fatal(err)
	}
}

func TestIncidentCreateGetList(t *testing.T) {
	s, clk := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "stuck-job:1", Family: "stuck-job", Summary: "job 1", AgentToken: "tok", Runbook: "rb"})
	clk.Add(time.Minute)
	b := mk(t, s, model.Incident{Project: "other", Fingerprint: "stuck-job:2", State: model.StateEscalated, Mass: true, Recurrent: true})
	if a.ID != "INC-000001" || b.ID != "INC-000002" {
		t.Fatalf("ids = %s, %s", a.ID, b.ID)
	}
	got, err := s.GetIncident(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != a {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, a)
	}
	if got.State != model.StateQueued || !got.OpenedAt.Equal(t0) || !got.UpdatedAt.Equal(t0) {
		t.Fatalf("defaults: %+v", got)
	}
	if gb, _ := s.GetIncident(b.ID); !gb.Mass || !gb.Recurrent || gb.State != model.StateEscalated {
		t.Fatalf("flags: %+v", gb)
	}
	if _, err := s.GetIncident("INC-999999"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.CreateIncident(model.Incident{Project: "shop", Source: "x", Fingerprint: "stuck-job:1", Severity: 1}); !errors.Is(err, ErrDuplicateOpen) {
		t.Fatalf("duplicate: err = %v", err)
	}
	if _, err := s.UpdateIncident(a.ID, nil, func(i *model.Incident) error { i.State = model.StateResolved; return nil }); err != nil {
		t.Fatal(err)
	}
	c := mk(t, s, model.Incident{Fingerprint: "stuck-job:1"}) // same fingerprint once the first is resolved
	cases := []struct {
		name string
		f    IncidentFilter
		want []string
	}{
		{"all", IncidentFilter{}, []string{a.ID, b.ID, c.ID}},
		{"project", IncidentFilter{Project: "shop"}, []string{a.ID, c.ID}},
		{"open", IncidentFilter{OpenOnly: true}, []string{b.ID, c.ID}},
		{"open project", IncidentFilter{Project: "shop", OpenOnly: true}, []string{c.ID}},
		{"state", IncidentFilter{States: []model.IncidentState{model.StateResolved, model.StateEscalated}}, []string{a.ID, b.ID}},
		{"limit", IncidentFilter{Limit: 1}, []string{a.ID}},
	}
	for _, tc := range cases {
		list, err := s.ListIncidents(tc.f)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, i := range list {
			ids = append(ids, i.ID)
		}
		if len(ids) != len(tc.want) {
			t.Fatalf("%s: got %v want %v", tc.name, ids, tc.want)
		}
		for k := range ids {
			if ids[k] != tc.want[k] {
				t.Fatalf("%s: got %v want %v", tc.name, ids, tc.want)
			}
		}
	}
}

func TestUpdateIncident(t *testing.T) {
	s, clk := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "f1"})
	clk.Add(5 * time.Minute)

	if _, err := s.UpdateIncident(a.ID, []model.IncidentState{model.StateWaiting}, func(i *model.Incident) error {
		t.Fatal("mutate must not run on a state conflict")
		return nil
	}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("err = %v", err)
	}
	boom := errors.New("boom")
	if _, err := s.UpdateIncident(a.ID, nil, func(i *model.Incident) error { i.State = model.StateBlocked; return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if g, _ := s.GetIncident(a.ID); g.State != model.StateQueued {
		t.Fatalf("a failed mutate saved state %s", g.State)
	}
	if _, err := s.UpdateIncident("INC-000404", nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}

	u, err := s.UpdateIncident(a.ID, []model.IncidentState{model.StateQueued}, func(i *model.Incident) error {
		i.State = model.StateWaiting
		i.RecheckAt = clk.Now().Add(10 * time.Minute)
		i.Runs = 2
		i.ID, i.Project, i.SignalCount = "hack", "hack", 99 // ignored
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != a.ID || u.Project != "shop" || u.SignalCount != 0 || u.Runs != 2 || !u.UpdatedAt.Equal(clk.Now()) {
		t.Fatalf("update: %+v", u)
	}
	if since, _ := s.StateSince(a.ID); !since.Equal(clk.Now()) {
		t.Fatalf("state_since = %v", since)
	}
	if due, _ := s.DueRechecks(); len(due) != 0 {
		t.Fatalf("due too early: %v", due)
	}
	clk.Add(10 * time.Minute)
	due, err := s.DueRechecks()
	if err != nil || len(due) != 1 || due[0].ID != a.ID {
		t.Fatalf("due = %v, %v", due, err)
	}
	// Same state: the state timestamp does not move.
	if _, err := s.UpdateIncident(a.ID, nil, func(i *model.Incident) error { i.Summary = "x"; return nil }); err != nil {
		t.Fatal(err)
	}
	if since, _ := s.StateSince(a.ID); !since.Equal(t0.Add(5 * time.Minute)) {
		t.Fatalf("state_since moved: %v", since)
	}
	r, err := s.UpdateIncident(a.ID, nil, func(i *model.Incident) error {
		i.State, i.CloseReason = model.StateResolved, "done"
		return nil
	})
	if err != nil || !r.ClosedAt.Equal(clk.Now()) || r.CloseReason != "done" {
		t.Fatalf("resolve: %+v, %v", r, err)
	}
	// Reopening clears ClosedAt.
	r, err = s.UpdateIncident(a.ID, nil, func(i *model.Incident) error { i.State = model.StateQueued; return nil })
	if err != nil || !r.ClosedAt.IsZero() {
		t.Fatalf("reopen: %+v, %v", r, err)
	}
}

func TestFindCountAndRecurrence(t *testing.T) {
	s, clk := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "stuck-job:1", Family: "stuck-job"})
	mk(t, s, model.Incident{Fingerprint: "stuck-job:2", Family: "stuck-job", State: model.StateEscalated})
	mk(t, s, model.Incident{Fingerprint: "stuck-job:mass", Mass: true, State: model.StateEscalated})
	mk(t, s, model.Incident{Fingerprint: "x:1", Source: "other"})
	mk(t, s, model.Incident{Fingerprint: "stuck-job:1", Project: "p2"})

	f, err := s.FindOpenIncident("shop", "stuck-job:1")
	if err != nil || f == nil || f.ID != a.ID {
		t.Fatalf("find = %+v, %v", f, err)
	}
	if f, err := s.FindOpenIncident("shop", "nope"); err != nil || f != nil {
		t.Fatalf("find missing = %+v, %v", f, err)
	}
	if n, _ := s.CountOpenIncidents("shop", "stuck-job"); n != 2 {
		t.Fatalf("open count = %d, want 2 (mass excluded)", n)
	}
	if n, _ := s.CountIncidentsInState("", model.StateQueued); n != 3 {
		t.Fatalf("queued = %d", n)
	}
	if n, _ := s.CountIncidentsInState("shop", model.StateEscalated); n != 2 {
		t.Fatalf("escalated = %d", n)
	}

	resolve := func(id string) {
		if _, err := s.UpdateIncident(id, nil, func(i *model.Incident) error { i.State = model.StateResolved; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	resolve(a.ID) // closed at t0
	clk.Add(48 * time.Hour)
	b := mk(t, s, model.Incident{Fingerprint: "stuck-job:9", Family: "stuck-job"})
	resolve(b.ID) // closed at t0+48h
	if f, _ := s.FindOpenIncident("shop", "stuck-job:1"); f != nil {
		t.Fatalf("resolved incident found as open: %+v", f)
	}
	for _, tc := range []struct {
		window time.Duration
		want   int
	}{{time.Hour, 1}, {48 * time.Hour, 2}, {72 * time.Hour, 2}} {
		n, err := s.CountResolvedByFamily("shop", "stuck-job", clk.Now().Add(-tc.window))
		if err != nil || n != tc.want {
			t.Fatalf("window %v: n = %d, %v; want %d", tc.window, n, err, tc.want)
		}
	}
	if n, _ := s.CountResolvedByFamily("p2", "stuck-job", t0); n != 0 {
		t.Fatalf("other project counted: %d", n)
	}
}

func TestQueuePriorityAndClaim(t *testing.T) {
	s, clk := newStore(t)
	low := mk(t, s, model.Incident{Fingerprint: "a", Severity: model.SevLow})
	clk.Add(time.Minute)
	high2 := mk(t, s, model.Incident{Fingerprint: "b", Severity: model.SevHigh, Project: "p2"})
	clk.Add(-30 * time.Second)
	high1 := mk(t, s, model.Incident{Fingerprint: "c", Severity: model.SevHigh}) // older than high2, created later
	mk(t, s, model.Incident{Fingerprint: "d", Severity: model.SevCritical, State: model.StateWaiting})
	same := mk(t, s, model.Incident{Fingerprint: "e", Severity: model.SevHigh}) // same second as high1: insertion order

	if n, err := s.NextQueued(); err != nil || n == nil || n.ID != high1.ID {
		t.Fatalf("peek = %+v, %v", n, err)
	}
	if n, err := s.NextQueued("shop"); err != nil || n == nil || n.ID != high2.ID {
		t.Fatalf("peek excluding shop = %+v, %v", n, err)
	}
	if c, err := s.ClaimNextQueued("shop", "p2"); err != nil || c != nil {
		t.Fatalf("claim with everything excluded = %+v, %v", c, err)
	}
	var got []string
	for {
		c, err := s.ClaimNextQueued()
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			break
		}
		if c.State != model.StateInvestigating {
			t.Fatalf("claimed state = %s", c.State)
		}
		got = append(got, c.ID)
	}
	want := []string{high1.ID, same.ID, high2.ID, low.ID}
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	if _, err := s.ClaimIncident(low.ID); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("claim a taken incident: %v", err)
	}
}

func TestClaimIsAtomicAcrossGoroutines(t *testing.T) {
	s, _ := newStore(t)
	const incidents, workers = 40, 8
	for i := 0; i < incidents; i++ {
		mk(t, s, model.Incident{Fingerprint: "f" + string(rune('A'+i))})
	}
	var (
		mu     sync.Mutex
		claims = map[string]int{}
		wg     sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := s.ClaimNextQueued()
				if err != nil {
					t.Error(err)
					return
				}
				if c == nil {
					return
				}
				mu.Lock()
				claims[c.ID]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claims) != incidents {
		t.Fatalf("claimed %d incidents, want %d", len(claims), incidents)
	}
	for id, n := range claims {
		if n != 1 {
			t.Fatalf("%s claimed %d times", id, n)
		}
	}
}

func TestClaimIncidentSingleWinner(t *testing.T) {
	s, _ := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "f"})
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ClaimIncident(a.ID)
			switch {
			case err == nil:
				mu.Lock()
				wins++
				mu.Unlock()
			case !errors.Is(err, ErrStateConflict):
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins = %d", wins)
	}
}

func TestSignals(t *testing.T) {
	s, clk := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "f", Severity: model.SevLow})
	sig := model.Signal{Project: "shop", Source: "stuck-job", Fingerprint: "f", Severity: model.SevLow,
		Summary: "job 1 stuck", Fields: map[string]string{"job_id": "1"}, At: t0.Add(-time.Minute)}
	id, err := s.InsertSignal(sig)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListSignals(a.ID); len(l) != 0 {
		t.Fatalf("unattached signal listed: %v", l)
	}
	if err := s.AttachSignal(id, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AttachSignal(id, a.ID); err == nil {
		t.Fatal("attaching twice must fail")
	}
	if err := s.AttachSignal(9999, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	clk.Add(time.Hour)
	sig2 := sig
	sig2.At, sig2.Severity, sig2.Fields = time.Time{}, model.SevHigh, nil
	if _, err := s.RecordSignal(sig2, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSignal(sig2, "INC-000404"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	g, _ := s.GetIncident(a.ID)
	if g.SignalCount != 2 || g.Severity != model.SevHigh || !g.UpdatedAt.Equal(clk.Now()) {
		t.Fatalf("incident after signals: %+v", g)
	}
	if last, _ := s.LastSignalAt(a.ID); !last.Equal(clk.Now()) {
		t.Fatalf("last seen = %v", last)
	}
	l, err := s.ListSignals(a.ID)
	if err != nil || len(l) != 2 {
		t.Fatalf("list = %v, %v", l, err)
	}
	if l[0].ID != id || l[0].IncidentID != a.ID || l[0].Fields["job_id"] != "1" || !l[0].At.Equal(sig.At) || l[0].Summary != sig.Summary {
		t.Fatalf("signal 0 = %+v", l[0])
	}
	if !l[1].At.Equal(clk.Now()) || len(l[1].Fields) != 0 {
		t.Fatalf("signal 1 = %+v", l[1])
	}
}

func TestRuns(t *testing.T) {
	s, clk := newStore(t)
	a := mk(t, s, model.Incident{Fingerprint: "f"})
	if _, err := s.StartRun("INC-000404", "seat-a"); err == nil {
		t.Fatal("a run needs an existing incident (foreign key)")
	}
	r1, err := s.StartRun(a.ID, "seat-a")
	if err != nil {
		t.Fatal(err)
	}
	clk.Add(3 * time.Minute)
	v := &model.Verdict{Outcome: model.OutcomeRecheck, Summary: "wait", Evidence: []string{"q1"}, RecheckMinutes: 10,
		MR: &model.MRProposal{Repo: "app", Title: "fix"}, Confidence: "high"}
	if err := s.FinishRun(r1.ID, model.RunResult{Status: model.RunOK, Verdict: v, CostUSD: 1.25, Turns: 7, InputTok: 100, OutputTok: 20}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(r1.ID, model.RunResult{Status: model.RunFailed}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finishing twice: %v", err)
	}
	if err := s.FinishRun(r1.ID+50, model.RunResult{}); err == nil {
		t.Fatal("empty status accepted")
	}
	clk.Add(time.Minute)
	r2, _ := s.StartRun(a.ID, "seat-b")
	active, _ := s.ActiveRunsBySeat()
	if len(active) != 1 || active["seat-b"] != 1 {
		t.Fatalf("active = %v", active)
	}
	used, _ := s.SeatLastUsed()
	if !used["seat-a"].Equal(t0) || !used["seat-b"].Equal(t0.Add(4*time.Minute)) {
		t.Fatalf("last used = %v", used)
	}
	if err := s.FinishRun(r2.ID, model.RunResult{Status: model.RunTimeout, Error: "too long"}); err != nil {
		t.Fatal(err)
	}
	runs, err := s.ListRuns(a.ID)
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs = %v, %v", runs, err)
	}
	g := runs[0]
	if g.Status != model.RunOK || g.Seat != "seat-a" || !g.StartedAt.Equal(t0) || !g.EndedAt.Equal(t0.Add(3*time.Minute)) ||
		g.CostUSD != 1.25 || g.Turns != 7 || g.InputTok != 100 || g.OutputTok != 20 {
		t.Fatalf("run 0 = %+v", g)
	}
	if g.Verdict == nil || g.Verdict.Outcome != model.OutcomeRecheck || g.Verdict.MR == nil || g.Verdict.MR.Title != "fix" || g.Verdict.Evidence[0] != "q1" {
		t.Fatalf("verdict = %+v", g.Verdict)
	}
	if runs[1].Status != model.RunTimeout || runs[1].Verdict != nil || runs[1].Error != "too long" {
		t.Fatalf("run 1 = %+v", runs[1])
	}
	if err := s.RecordAction(a.ID, r1.ID, "restart-job"); err != nil {
		t.Fatal(err)
	}
	if acts, _ := s.ListActions(a.ID); len(acts) != 1 || acts[0].Name != "restart-job" || acts[0].RunID != r1.ID {
		t.Fatalf("actions = %+v", acts)
	}
}

func TestRecoverInterrupted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.db")
	clk := &fakeClock{t: t0}
	s, err := Open(path, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	a := mk(t, s, model.Incident{Fingerprint: "a"})
	b := mk(t, s, model.Incident{Fingerprint: "b", State: model.StateWaiting})
	c := mk(t, s, model.Incident{Fingerprint: "c"})
	if _, err := s.ClaimIncident(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimIncident(c.ID); err != nil {
		t.Fatal(err)
	}
	ra, _ := s.StartRun(a.ID, "seat-a")
	rc, _ := s.StartRun(c.ID, "seat-a")
	if err := s.FinishRun(rc.ID, model.RunResult{Status: model.RunOK}); err != nil {
		t.Fatal(err)
	}
	s.Close() // crash

	clk.Add(time.Hour)
	s, err = Open(path, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rec, err := s.RecoverInterrupted()
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 2 || rec[0].ID != a.ID || rec[1].ID != c.ID || rec[0].State != model.StateQueued {
		t.Fatalf("recovered = %+v", rec)
	}
	if g, _ := s.GetIncident(b.ID); g.State != model.StateWaiting {
		t.Fatalf("waiting incident touched: %s", g.State)
	}
	runs, _ := s.ListRuns(a.ID)
	if len(runs) != 1 || runs[0].ID != ra.ID || runs[0].Status != model.RunCancelled || !runs[0].EndedAt.Equal(clk.Now()) || runs[0].Error == "" {
		t.Fatalf("unfinished run = %+v", runs)
	}
	if runs, _ := s.ListRuns(c.ID); runs[0].Status != model.RunOK {
		t.Fatalf("finished run rewritten: %+v", runs[0])
	}
	if again, err := s.RecoverInterrupted(); err != nil || len(again) != 0 {
		t.Fatalf("second recovery = %v, %v", again, err)
	}
	if n, _ := s.ClaimNextQueued(); n == nil || n.ID != a.ID {
		t.Fatalf("recovered incident not claimable: %+v", n)
	}
}

func TestKnownProblems(t *testing.T) {
	s, clk := newStore(t)
	k, err := s.OpenKnownProblem(model.KnownProblem{Project: "shop", Family: "stuck-job", Repo: "app", MRURL: "https://forge/mr/1", MRID: "1", Incident: "INC-000001"})
	if err != nil || k.ID == 0 || !k.OpenedAt.Equal(t0) {
		t.Fatalf("open = %+v, %v", k, err)
	}
	s.OpenKnownProblem(model.KnownProblem{Project: "p2", Family: "stuck-job"})
	f, err := s.FindOpenKnownProblem("shop", "stuck-job")
	if err != nil || f == nil || *f != k {
		t.Fatalf("find = %+v, %v", f, err)
	}
	if f, _ := s.FindOpenKnownProblem("shop", "other"); f != nil {
		t.Fatalf("found %+v", f)
	}
	if l, _ := s.ListOpenKnownProblems(""); len(l) != 2 {
		t.Fatalf("list all = %v", l)
	}
	if l, _ := s.ListOpenKnownProblems("shop"); len(l) != 1 {
		t.Fatalf("list shop = %v", l)
	}
	clk.Add(time.Hour)
	if err := s.CloseKnownProblem(k.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseKnownProblem(k.ID); err != nil {
		t.Fatalf("closing twice: %v", err)
	}
	if err := s.CloseKnownProblem(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if f, _ := s.FindOpenKnownProblem("shop", "stuck-job"); f != nil {
		t.Fatalf("closed problem still open: %+v", f)
	}
}

func TestAlertsAndReminders(t *testing.T) {
	s, clk := newStore(t)
	esc := mk(t, s, model.Incident{Fingerprint: "a", State: model.StateEscalated})
	mk(t, s, model.Incident{Fingerprint: "b", State: model.StateQueued})
	gl := mk(t, s, model.Incident{Fingerprint: "c", State: model.StateGreenLight, Project: "p2"})

	ids := func(l []model.Incident) string {
		out := ""
		for _, i := range l {
			out += i.ID + " "
		}
		return out
	}
	day := 24 * time.Hour
	// No alert recorded yet: the delay runs from the entry into the state.
	if l, _ := s.IncidentsNeedingReminder("", clk.Now().Add(-day)); len(l) != 0 {
		t.Fatalf("too early: %s", ids(l))
	}
	clk.Add(time.Hour)
	if _, err := s.RecordAlert(model.Alert{Kind: model.AlertEscalated, Project: "shop", Incident: esc.ID, Title: "t", Body: "b", URL: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordAlert(model.Alert{Kind: model.NoticeMROpened, Project: "p2", Incident: gl.ID, At: t0.Add(30 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GetIncident(esc.ID); !g.LastAlertAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("last alert at = %v", g.LastAlertAt)
	}
	if g, _ := s.GetIncident(gl.ID); !g.LastAlertAt.IsZero() {
		t.Fatalf("a notice moved LastAlertAt: %v", g.LastAlertAt)
	}
	clk.Add(23*time.Hour + 30*time.Minute) // t0 + 24h30
	l, _ := s.IncidentsNeedingReminder("", clk.Now().Add(-day))
	if ids(l) != gl.ID+" " {
		t.Fatalf("due = %q, want only the green light (state since t0)", ids(l))
	}
	clk.Add(time.Hour) // t0 + 25h30
	if l, _ := s.IncidentsNeedingReminder("", clk.Now().Add(-day)); ids(l) != esc.ID+" "+gl.ID+" " {
		t.Fatalf("due = %q", ids(l))
	}
	if l, _ := s.IncidentsNeedingReminder("shop", clk.Now().Add(-day)); ids(l) != esc.ID+" " {
		t.Fatalf("due shop = %q", ids(l))
	}
	if _, err := s.RecordAlert(model.Alert{Kind: model.AlertReminder, Project: "shop", Incident: esc.ID}); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.IncidentsNeedingReminder("shop", clk.Now().Add(-day)); len(l) != 0 {
		t.Fatalf("reminded incident still due: %s", ids(l))
	}

	a, err := s.LastAlert(esc.ID, model.AlertEscalated)
	if err != nil || a == nil || a.Title != "t" || a.Body != "b" || a.URL != "u" || !a.At.Equal(t0.Add(time.Hour)) || a.Kind != model.AlertEscalated {
		t.Fatalf("last alert = %+v, %v", a, err)
	}
	if a, _ := s.LastAlert(esc.ID, model.AlertBlocked); a != nil {
		t.Fatalf("unexpected %+v", a)
	}
	s.RecordAlert(model.Alert{Kind: model.AlertCapacity, Title: "first"})
	s.RecordAlert(model.Alert{Kind: model.AlertCapacity, Title: "second"})
	if a, _ := s.LastSystemAlert("", model.AlertCapacity); a == nil || a.Title != "second" {
		t.Fatalf("system alert = %+v", a)
	}
	if a, _ := s.LastSystemAlert("", model.AlertEscalated); a != nil {
		t.Fatalf("incident alert returned as system alert: %+v", a)
	}

	in, _ := s.IncidentsInStateSince(model.StateGreenLight, clk.Now().Add(-time.Hour))
	if ids(in) != gl.ID+" " {
		t.Fatalf("in state since = %q", ids(in))
	}
	if in, _ := s.IncidentsInStateSince(model.StateGreenLight, t0.Add(-time.Second)); len(in) != 0 {
		t.Fatalf("in state since (before) = %q", ids(in))
	}
}

func TestProposalsSeatsKVFailures(t *testing.T) {
	s, _ := newStore(t)
	p, err := s.RecordProposal(Proposal{Project: "shop", Incident: "INC-000001", Kind: ProposalMissingAction, Title: "add purge", MRURL: "u", MRID: "7"})
	if err != nil || p.ID == 0 || p.State != "open" || !p.CreatedAt.Equal(t0) {
		t.Fatalf("proposal = %+v, %v", p, err)
	}
	s.RecordProposal(Proposal{Project: "p2", Kind: ProposalImprovement})
	if l, _ := s.ListProposals("shop", false); len(l) != 1 || l[0] != p {
		t.Fatalf("list = %+v", l)
	}
	if err := s.SetProposalState(p.ID, "merged"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetProposalState(99, "merged"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if l, _ := s.ListProposals("", true); len(l) != 1 || l[0].Project != "p2" {
		t.Fatalf("open list = %+v", l)
	}

	if u, err := s.SeatExhaustedUntil("seat-a"); err != nil || !u.IsZero() {
		t.Fatalf("fresh seat = %v, %v", u, err)
	}
	until := t0.Add(time.Hour)
	if err := s.SetSeatExhausted("seat-a", until.In(time.FixedZone("x", 3600))); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.SeatExhaustedUntil("seat-a"); !u.Equal(until) || u.Location() != time.UTC {
		t.Fatalf("until = %v", u)
	}
	s.SetSeatExhausted("seat-a", time.Time{})
	if u, _ := s.SeatExhaustedUntil("seat-a"); !u.IsZero() {
		t.Fatalf("cleared = %v", u)
	}

	if _, ok, err := s.GetKV("k"); ok || err != nil {
		t.Fatalf("missing key: %v, %v", ok, err)
	}
	s.SetKV("k", "1")
	s.SetKV("k", "2")
	if v, ok, _ := s.GetKV("k"); !ok || v != "2" {
		t.Fatalf("kv = %q, %v", v, ok)
	}
	s.DeleteKV("k")
	if _, ok, _ := s.GetKV("k"); ok {
		t.Fatal("key not deleted")
	}

	a := mk(t, s, model.Incident{Fingerprint: "f"})
	if n, _ := s.IncrementFailures(a.ID); n != 1 {
		t.Fatalf("failures = %d", n)
	}
	if n, _ := s.IncrementFailures(a.ID); n != 2 {
		t.Fatalf("failures = %d", n)
	}
	s.ResetFailures(a.ID)
	if n, _ := s.Failures(a.ID); n != 0 {
		t.Fatalf("failures after reset = %d", n)
	}
	if _, err := s.IncrementFailures("INC-000404"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
