package incident

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
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

type env struct {
	t       *testing.T
	st      *store.Store
	clk     *fakeClock
	m       *Manager
	dossier *Dossier
	dbPath  string
	limits  map[string]model.Limits
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, clk: &fakeClock{t: t0}, dbPath: filepath.Join(dir, "d.db"), limits: map[string]model.Limits{}}
	st, err := store.Open(e.dbPath, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.st = st
	e.dossier = NewDossier(dir)
	e.m = NewManager(st, e.clk.Now, func(p string) model.Limits { return e.limits[p] }, WithDossier(e.dossier))
	return e
}

func sig(fp string) model.Signal {
	return model.Signal{Project: "shop", Source: "stuck-job", Fingerprint: fp, Severity: model.SevMedium,
		Summary: "job stuck: " + fp, Fields: map[string]string{"job_id": strings.TrimPrefix(fp, "stuck-job:")}}
}

func (e *env) ingest(s model.Signal, l model.Limits) IngestResult {
	e.t.Helper()
	res, err := e.m.Ingest(s, l, "stuck-job", "rb-stuck")
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// investigating returns a fresh incident claimed by a worker.
func (e *env) investigating(fp string) model.Incident {
	e.t.Helper()
	res := e.ingest(sig(fp), model.Limits{})
	inc, err := e.st.ClaimIncident(res.Incident.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return inc
}

// inState drives a fresh incident to the given state through the manager.
func (e *env) inState(fp string, state model.IncidentState) model.Incident {
	e.t.Helper()
	if state == model.StateQueued {
		return e.ingest(sig(fp), model.Limits{}).Incident
	}
	inc := e.investigating(fp)
	var v model.Verdict
	switch state {
	case model.StateInvestigating:
		return inc
	case model.StateWaiting:
		v = model.Verdict{Outcome: model.OutcomeRecheck, RecheckMinutes: 10}
	case model.StateGreenLight:
		v = model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: "ssh-prod/42"}
	case model.StateMROpen:
		v = model.Verdict{Outcome: model.OutcomeEscalate, MR: &model.MRProposal{Repo: "app", Title: "fix"}}
	case model.StateEscalated:
		v = model.Verdict{Outcome: model.OutcomeEscalate}
	case model.StateBlocked:
		v = model.Verdict{Outcome: model.OutcomeBlocked}
	case model.StateResolved:
		v = model.Verdict{Outcome: model.OutcomeResolved}
	}
	tr, err := e.m.ApplyVerdict(inc, v, model.Runbook{}, model.Limits{})
	if err != nil {
		e.t.Fatal(err)
	}
	if tr.To != state {
		e.t.Fatalf("setup: got %s, want %s", tr.To, state)
	}
	return tr.Incident
}

func (e *env) get(id string) model.Incident {
	e.t.Helper()
	inc, err := e.st.GetIncident(id)
	if err != nil {
		e.t.Fatal(err)
	}
	return inc
}

var allStates = []model.IncidentState{model.StateQueued, model.StateInvestigating, model.StateWaiting, model.StateGreenLight,
	model.StateMROpen, model.StateEscalated, model.StateBlocked, model.StateResolved}

func TestIngestCreateAndDedup(t *testing.T) {
	e := newEnv(t)
	res := e.ingest(sig("stuck-job:1"), model.Limits{})
	inc := res.Incident
	if res.Kind != IngestCreated || res.Alert != "" {
		t.Fatalf("result = %+v", res)
	}
	if inc.ID != "INC-000001" || inc.State != model.StateQueued || inc.SignalCount != 1 || inc.Family != "stuck-job" ||
		inc.Runbook != "rb-stuck" || inc.Recurrent || inc.Mass || !inc.OpenedAt.Equal(t0) || inc.Summary != "job stuck: stuck-job:1" {
		t.Fatalf("incident = %+v", inc)
	}
	if len(inc.AgentToken) != 64 || strings.Trim(inc.AgentToken, "0123456789abcdef") != "" {
		t.Fatalf("agent token = %q", inc.AgentToken)
	}

	// The same fingerprint attaches whatever the open state: no new
	// incident, no requeue.
	for _, state := range allStates[:7] {
		t.Run(string(state), func(t *testing.T) {
			e := newEnv(t)
			e.t = t
			inc := e.inState("stuck-job:1", state)
			e.clk.Add(time.Minute)
			s := sig("stuck-job:1")
			s.Severity = model.SevCritical
			res := e.ingest(s, model.Limits{MaxOpenPerCheck: 1})
			if res.Kind != IngestAttached || res.Incident.ID != inc.ID {
				t.Fatalf("result = %+v", res)
			}
			got := res.Incident
			if got.State != state || got.SignalCount != 2 || got.Severity != model.SevCritical || got.AgentToken != inc.AgentToken {
				t.Fatalf("after attach: %+v", got)
			}
			if last, _ := e.st.LastSignalAt(inc.ID); !last.Equal(e.clk.Now()) {
				t.Fatalf("last seen = %v", last)
			}
			if all, _ := e.st.ListIncidents(store.IncidentFilter{}); len(all) != 1 {
				t.Fatalf("%d incidents", len(all))
			}
			if sigs, _ := e.st.ListSignals(inc.ID); len(sigs) != 2 {
				t.Fatalf("%d signals", len(sigs))
			}
		})
	}

	t.Run("resolved gives a new incident", func(t *testing.T) {
		e := newEnv(t)
		e.t = t
		old := e.inState("stuck-job:1", model.StateResolved)
		res := e.ingest(sig("stuck-job:1"), model.Limits{})
		if res.Kind != IngestCreated || res.Incident.ID == old.ID || res.Incident.AgentToken == old.AgentToken {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("other project is another incident", func(t *testing.T) {
		s := sig("stuck-job:1")
		s.Project = "other"
		if res := e.ingest(s, model.Limits{}); res.Kind != IngestCreated {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("invalid signal", func(t *testing.T) {
		for _, s := range []model.Signal{{Source: "c", Fingerprint: "f"}, {Project: "p", Fingerprint: "f"}, {Project: "p", Source: "c"}} {
			if _, err := e.m.Ingest(s, model.Limits{}, "", ""); err == nil {
				t.Fatalf("accepted %+v", s)
			}
		}
	})
}

func TestIngestConcurrentDedup(t *testing.T) {
	e := newEnv(t)
	const n = 16
	var wg sync.WaitGroup
	kinds := make([]IngestKind, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := e.m.Ingest(sig("stuck-job:1"), model.Limits{}, "stuck-job", "")
			if err != nil {
				t.Error(err)
				return
			}
			kinds[i] = res.Kind
		}(i)
	}
	wg.Wait()
	created := 0
	for _, k := range kinds {
		if k == IngestCreated {
			created++
		}
	}
	all, _ := e.st.ListIncidents(store.IncidentFilter{})
	if created != 1 || len(all) != 1 || all[0].SignalCount != n {
		t.Fatalf("created = %d, incidents = %+v", created, all)
	}
}

func TestStormGuard(t *testing.T) {
	e := newEnv(t)
	l := model.Limits{MaxOpenPerCheck: 3}
	for i := 1; i <= 3; i++ {
		if res := e.ingest(sig(fmt.Sprintf("stuck-job:%d", i)), l); res.Kind != IngestCreated {
			t.Fatalf("signal %d: %+v", i, res)
		}
	}
	// Another source of the same project is not concerned.
	other := sig("queue:1")
	other.Source = "queue-depth"
	if res := e.ingest(other, l); res.Kind != IngestCreated {
		t.Fatalf("other source: %+v", res)
	}
	// Same fingerprint as an open incident: plain dedup, even at the limit.
	if res := e.ingest(sig("stuck-job:2"), l); res.Kind != IngestAttached {
		t.Fatalf("dedup at the limit: %+v", res)
	}

	res := e.ingest(sig("stuck-job:4"), l)
	mass := res.Incident
	if res.Kind != IngestMassCreated || res.Alert != model.AlertStorm {
		t.Fatalf("storm: %+v", res)
	}
	if !mass.Mass || mass.State != model.StateEscalated || mass.Fingerprint != "stuck-job:mass" || mass.Source != "stuck-job" ||
		mass.SignalCount != 1 || len(mass.AgentToken) != 64 {
		t.Fatalf("mass incident = %+v", mass)
	}
	for i := 5; i <= 7; i++ {
		res := e.ingest(sig(fmt.Sprintf("stuck-job:%d", i)), l)
		if res.Kind != IngestMassAttached || res.Incident.ID != mass.ID || res.Alert != "" {
			t.Fatalf("signal %d: %+v", i, res)
		}
	}
	if got := e.get(mass.ID); got.SignalCount != 4 || got.State != model.StateEscalated {
		t.Fatalf("mass after attaches = %+v", got)
	}
	all, _ := e.st.ListIncidents(store.IncidentFilter{Project: "shop"})
	masses := 0
	for _, i := range all {
		if i.Mass {
			masses++
		}
	}
	if len(all) != 5 || masses != 1 {
		t.Fatalf("%d incidents, %d mass; want 5 and 1", len(all), masses)
	}
	if next, _ := e.st.ClaimNextQueued("other"); next == nil || next.Mass {
		t.Fatalf("queue head = %+v", next)
	}

	// Once the mass incident is closed and the count is back under the
	// limit, new fingerprints are ordinary incidents again.
	if _, err := e.m.Close(mass.ID, "storm over"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Close("INC-000001", ""); err != nil {
		t.Fatal(err)
	}
	if res := e.ingest(sig("stuck-job:8"), l); res.Kind != IngestCreated {
		t.Fatalf("after the storm: %+v", res)
	}
	// Guard off.
	if res := e.ingest(sig("stuck-job:9"), model.Limits{}); res.Kind != IngestCreated {
		t.Fatalf("guard off: %+v", res)
	}
}

func TestRecurrence(t *testing.T) {
	l := model.Limits{RecurrenceCount: 2, RecurrenceWindow: 24 * time.Hour}
	cases := []struct {
		name     string
		resolved []time.Duration // ages of the resolved incidents of the family
		limits   model.Limits
		want     bool
	}{
		{"none resolved", nil, l, false},
		{"below the count", []time.Duration{time.Hour}, l, false},
		{"count reached", []time.Duration{time.Hour, 2 * time.Hour}, l, true},
		{"above the count", []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}, l, true},
		{"one outside the window", []time.Duration{time.Hour, 30 * time.Hour}, l, false},
		{"disabled", []time.Duration{time.Hour, 2 * time.Hour}, model.Limits{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.clk.Add(-48 * time.Hour)
			start := e.clk.Now()
			for i, age := range tc.resolved {
				res := e.ingest(sig(fmt.Sprintf("stuck-job:%d", i)), model.Limits{})
				e.clk.Add(t0.Add(-age).Sub(e.clk.Now()))
				if _, err := e.m.Close(res.Incident.ID, ""); err != nil {
					t.Fatal(err)
				}
				e.clk.Add(start.Sub(e.clk.Now()))
			}
			// An open incident of the family and a resolved one of another family do not count.
			e.ingest(sig("stuck-job:open"), model.Limits{})
			o, _ := e.m.Ingest(sig("other:1"), model.Limits{}, "other", "")
			e.m.Close(o.Incident.ID, "")
			e.clk.Add(t0.Sub(e.clk.Now()))
			res := e.ingest(sig("stuck-job:new"), tc.limits)
			if res.Kind != IngestCreated || res.Incident.Recurrent != tc.want {
				t.Fatalf("recurrent = %v, want %v (%+v)", res.Incident.Recurrent, tc.want, res)
			}
		})
	}
}

func TestApplyVerdict(t *testing.T) {
	mr := &model.MRProposal{Repo: "app", Title: "fix the worker"}
	missing := &model.MissingAction{Name: "purge-queue", Why: "nothing can purge"}
	improvement := &model.Improvement{Title: "tune the check"}
	lim := model.Limits{MaxRunsPerIncident: 3, MaxIncidentAge: 6 * time.Hour}
	cases := []struct {
		name      string
		v         model.Verdict
		rb        model.Runbook
		limits    model.Limits
		priorRuns int
		age       time.Duration
		want      model.IncidentState
		alert     model.AlertKind
		recheckIn time.Duration
		ticket    string
		openMR    bool
		known     bool
		closeWith string
	}{
		{name: "resolved", v: model.Verdict{Outcome: model.OutcomeResolved}, want: model.StateResolved, closeWith: ReasonResolvedByAgent},
		{name: "resolved with MR stays resolved", v: model.Verdict{Outcome: model.OutcomeResolved, MR: mr},
			want: model.StateResolved, alert: model.NoticeMROpened, openMR: true, known: true, closeWith: ReasonResolvedByAgent},
		{name: "recheck with minutes", v: model.Verdict{Outcome: model.OutcomeRecheck, RecheckMinutes: 20},
			rb: model.Runbook{RecheckDefault: time.Hour}, limits: lim, want: model.StateWaiting, recheckIn: 20 * time.Minute},
		{name: "recheck runbook default", v: model.Verdict{Outcome: model.OutcomeRecheck},
			rb: model.Runbook{RecheckDefault: time.Hour}, want: model.StateWaiting, recheckIn: time.Hour},
		{name: "recheck built-in default", v: model.Verdict{Outcome: model.OutcomeRecheck}, want: model.StateWaiting, recheckIn: DefaultRecheck},
		{name: "recheck below max runs", v: model.Verdict{Outcome: model.OutcomeRecheck, RecheckMinutes: 5},
			limits: lim, priorRuns: 1, want: model.StateWaiting, recheckIn: 5 * time.Minute},
		{name: "recheck at max runs", v: model.Verdict{Outcome: model.OutcomeRecheck, RecheckMinutes: 5},
			limits: lim, priorRuns: 2, want: model.StateEscalated, alert: model.AlertEscalated},
		{name: "recheck at runbook max runs", v: model.Verdict{Outcome: model.OutcomeRecheck},
			rb: model.Runbook{MaxRuns: 1}, limits: lim, want: model.StateEscalated, alert: model.AlertEscalated},
		{name: "runbook max runs overrides a lower limit", v: model.Verdict{Outcome: model.OutcomeRecheck},
			rb: model.Runbook{MaxRuns: 5}, limits: lim, priorRuns: 3, want: model.StateWaiting, recheckIn: DefaultRecheck},
		{name: "recheck at max age", v: model.Verdict{Outcome: model.OutcomeRecheck}, limits: lim, age: 6 * time.Hour,
			want: model.StateEscalated, alert: model.AlertEscalated},
		{name: "recheck just under max age", v: model.Verdict{Outcome: model.OutcomeRecheck}, limits: lim, age: 6*time.Hour - time.Second,
			want: model.StateWaiting, recheckIn: DefaultRecheck},
		{name: "recheck with MR", v: model.Verdict{Outcome: model.OutcomeRecheck, RecheckMinutes: 5, MR: mr},
			want: model.StateMROpen, alert: model.NoticeMROpened, openMR: true},
		{name: "green light", v: model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: " ssh-prod/42 "},
			want: model.StateGreenLight, alert: model.AlertGreenLight, ticket: "ssh-prod/42"},
		{name: "green light without ticket", v: model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: "  "},
			want: model.StateEscalated, alert: model.AlertEscalated},
		{name: "green light with MR keeps the ticket", v: model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: "ssh-prod/42", MR: mr},
			want: model.StateGreenLight, alert: model.AlertGreenLight, ticket: "ssh-prod/42", openMR: true},
		{name: "green light without ticket, with MR", v: model.Verdict{Outcome: model.OutcomeGreenLight, MR: mr},
			want: model.StateMROpen, alert: model.NoticeMROpened, openMR: true},
		{name: "escalate", v: model.Verdict{Outcome: model.OutcomeEscalate}, want: model.StateEscalated, alert: model.AlertEscalated},
		{name: "escalate with MR", v: model.Verdict{Outcome: model.OutcomeEscalate, MR: mr},
			want: model.StateMROpen, alert: model.NoticeMROpened, openMR: true},
		{name: "blocked", v: model.Verdict{Outcome: model.OutcomeBlocked, MissingAction: missing},
			want: model.StateBlocked, alert: model.AlertBlocked},
		{name: "blocked with MR stays blocked", v: model.Verdict{Outcome: model.OutcomeBlocked, MissingAction: missing, MR: mr},
			want: model.StateBlocked, alert: model.AlertBlocked, openMR: true},
		{name: "improvement rides along", v: model.Verdict{Outcome: model.OutcomeResolved, Improvement: improvement},
			want: model.StateResolved, closeWith: ReasonResolvedByAgent},
		{name: "unknown outcome", v: model.Verdict{Outcome: "shrug"}, want: model.StateEscalated, alert: model.AlertEscalated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			inc := e.investigating("stuck-job:1")
			if tc.priorRuns > 0 {
				if _, err := e.st.UpdateIncident(inc.ID, nil, func(i *model.Incident) error { i.Runs = tc.priorRuns; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			e.st.IncrementFailures(inc.ID)
			e.clk.Add(tc.age)
			tr, err := e.m.ApplyVerdict(inc, tc.v, tc.rb, tc.limits)
			if err != nil {
				t.Fatal(err)
			}
			got := e.get(inc.ID)
			if tr.Incident != got {
				t.Fatalf("transition incident differs from the stored one:\n%+v\n%+v", tr.Incident, got)
			}
			if tr.From != model.StateInvestigating || tr.To != tc.want || got.State != tc.want {
				t.Fatalf("state = %s (stored %s), want %s; reason %q", tr.To, got.State, tc.want, tr.Reason)
			}
			if tr.Alert != tc.alert {
				t.Fatalf("alert = %q, want %q", tr.Alert, tc.alert)
			}
			if got.Runs != tc.priorRuns+1 {
				t.Fatalf("runs = %d", got.Runs)
			}
			wantRecheck := time.Time{}
			if tc.recheckIn > 0 {
				wantRecheck = e.clk.Now().Add(tc.recheckIn)
			}
			if !tr.RecheckAt.Equal(wantRecheck) || !got.RecheckAt.Equal(wantRecheck) {
				t.Fatalf("recheck at = %v (stored %v), want %v", tr.RecheckAt, got.RecheckAt, wantRecheck)
			}
			if got.Ticket != tc.ticket {
				t.Fatalf("ticket = %q", got.Ticket)
			}
			if (tr.OpenMR != nil) != tc.openMR || tr.KnownProblem != tc.known {
				t.Fatalf("OpenMR = %v, KnownProblem = %v", tr.OpenMR, tr.KnownProblem)
			}
			if tr.MissingAction != tc.v.MissingAction || tr.Improvement != tc.v.Improvement {
				t.Fatalf("config MRs not passed through: %+v", tr)
			}
			if got.CloseReason != tc.closeWith || got.ClosedAt.IsZero() != (tc.want != model.StateResolved) {
				t.Fatalf("close: reason %q at %v", got.CloseReason, got.ClosedAt)
			}
			if n, _ := e.st.Failures(inc.ID); n != 0 {
				t.Fatalf("failures not cleared: %d", n)
			}
			if tr.Reason == "" && tc.want != model.StateResolved {
				t.Fatal("no reason given")
			}
		})
	}

	t.Run("needs an incident in investigating", func(t *testing.T) {
		for _, state := range allStates {
			if state == model.StateInvestigating {
				continue
			}
			e := newEnv(t)
			inc := e.inState("stuck-job:1", state)
			if _, err := e.m.ApplyVerdict(inc, model.Verdict{Outcome: model.OutcomeResolved}, model.Runbook{}, model.Limits{}); !errors.Is(err, store.ErrStateConflict) {
				t.Fatalf("%s: err = %v", state, err)
			}
			if got := e.get(inc.ID); got.State != state || got.Runs != inc.Runs {
				t.Fatalf("%s: incident changed: %+v", state, got)
			}
		}
	})
}

func TestRunFailed(t *testing.T) {
	lim := model.Limits{MaxRunsPerIncident: 5, MaxIncidentAge: 6 * time.Hour}
	cases := []struct {
		name          string
		status        model.RunStatus
		priorFailures int
		priorRuns     int
		age           time.Duration
		want          model.IncidentState
		counted       bool
		alert         model.AlertKind
	}{
		{name: "quota is requeued and not counted", status: model.RunQuota, priorRuns: 2, want: model.StateQueued},
		{name: "quota after a failure is not a second failure", status: model.RunQuota, priorFailures: 1, want: model.StateQueued},
		{name: "quota at max runs still requeues", status: model.RunQuota, priorRuns: 5, want: model.StateQueued},
		{name: "cancelled is requeued and not counted", status: model.RunCancelled, want: model.StateQueued},
		{name: "first failure retries", status: model.RunFailed, want: model.StateQueued, counted: true},
		{name: "first timeout retries", status: model.RunTimeout, want: model.StateQueued, counted: true},
		{name: "second failure escalates", status: model.RunFailed, priorFailures: 1, want: model.StateEscalated, counted: true, alert: model.AlertEscalated},
		{name: "timeout after a failure escalates", status: model.RunTimeout, priorFailures: 1, want: model.StateEscalated, counted: true, alert: model.AlertEscalated},
		{name: "failure at max runs escalates", status: model.RunFailed, priorRuns: 4, want: model.StateEscalated, counted: true, alert: model.AlertEscalated},
		{name: "failure at max age escalates", status: model.RunFailed, age: 6 * time.Hour, want: model.StateEscalated, counted: true, alert: model.AlertEscalated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			inc := e.investigating("stuck-job:1")
			for i := 0; i < tc.priorFailures; i++ {
				e.st.IncrementFailures(inc.ID)
			}
			e.st.UpdateIncident(inc.ID, nil, func(i *model.Incident) error { i.Runs = tc.priorRuns; return nil })
			e.clk.Add(tc.age)
			tr, err := e.m.RunFailed(inc, tc.status, lim)
			if err != nil {
				t.Fatal(err)
			}
			got := e.get(inc.ID)
			wantRuns := tc.priorRuns
			if tc.counted {
				wantRuns++
			}
			if tr.To != tc.want || got.State != tc.want || tr.Alert != tc.alert || got.Runs != wantRuns || tr.Incident != got {
				t.Fatalf("to %s (stored %s), alert %q, runs %d; want %s, %q, %d", tr.To, got.State, tr.Alert, got.Runs, tc.want, tc.alert, wantRuns)
			}
		})
	}

	t.Run("a valid verdict between two failures restarts the retry", func(t *testing.T) {
		e := newEnv(t)
		inc := e.investigating("stuck-job:1")
		if tr, _ := e.m.RunFailed(inc, model.RunFailed, model.Limits{}); tr.To != model.StateQueued {
			t.Fatalf("first failure: %s", tr.To)
		}
		e.st.ClaimIncident(inc.ID)
		if tr, _ := e.m.ApplyVerdict(inc, model.Verdict{Outcome: model.OutcomeRecheck}, model.Runbook{}, model.Limits{}); tr.To != model.StateWaiting {
			t.Fatalf("verdict: %s", tr.To)
		}
		e.m.Recheck(inc, true)
		e.st.ClaimIncident(inc.ID)
		if tr, _ := e.m.RunFailed(inc, model.RunTimeout, model.Limits{}); tr.To != model.StateQueued {
			t.Fatalf("failure after a verdict: %s", tr.To)
		}
		e.st.ClaimIncident(inc.ID)
		if tr, _ := e.m.RunFailed(inc, model.RunFailed, model.Limits{}); tr.To != model.StateEscalated {
			t.Fatalf("second consecutive failure: %s", tr.To)
		}
	})
	t.Run("wrong status or state", func(t *testing.T) {
		e := newEnv(t)
		inc := e.investigating("stuck-job:1")
		if _, err := e.m.RunFailed(inc, model.RunOK, model.Limits{}); err == nil {
			t.Fatal("RunOK accepted")
		}
		q := e.inState("stuck-job:2", model.StateQueued)
		for _, st := range []model.RunStatus{model.RunFailed, model.RunQuota} {
			if _, err := e.m.RunFailed(q, st, model.Limits{}); !errors.Is(err, store.ErrStateConflict) {
				t.Fatalf("%s on a queued incident: %v", st, err)
			}
		}
		if n, _ := e.st.Failures(q.ID); n != 0 {
			t.Fatalf("failure counted on a conflict: %d", n)
		}
	})
}

func TestRecheck(t *testing.T) {
	cases := []struct {
		state       model.IncidentState
		stillFiring bool
		want        model.IncidentState
		conflict    bool
	}{
		{model.StateWaiting, false, model.StateResolved, false},
		{model.StateWaiting, true, model.StateQueued, false},
		{model.StateEscalated, false, model.StateResolved, false},
		{model.StateEscalated, true, model.StateEscalated, false},
		{model.StateBlocked, false, model.StateResolved, false},
		{model.StateBlocked, true, model.StateBlocked, false},
		{model.StateMROpen, false, model.StateResolved, false},
		{model.StateMROpen, true, model.StateMROpen, false},
		{model.StateQueued, false, "", true},
		{model.StateInvestigating, false, "", true},
		{model.StateGreenLight, false, "", true},
		{model.StateResolved, false, "", true},
		{model.StateResolved, true, "", true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s firing=%v", tc.state, tc.stillFiring), func(t *testing.T) {
			e := newEnv(t)
			inc := e.inState("stuck-job:1", tc.state)
			e.clk.Add(10 * time.Minute)
			tr, err := e.m.Recheck(inc, tc.stillFiring)
			got := e.get(inc.ID)
			if tc.conflict {
				if !errors.Is(err, store.ErrStateConflict) || got.State != tc.state {
					t.Fatalf("err = %v, state = %s", err, got.State)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tr.From != tc.state || tr.To != tc.want || got.State != tc.want || tr.Changed() != (tc.state != tc.want) || tr.Alert != "" {
				t.Fatalf("transition = %+v, stored %s", tr, got.State)
			}
			if !got.RecheckAt.IsZero() && tc.want != tc.state {
				t.Fatalf("recheck time kept: %v", got.RecheckAt)
			}
			switch tc.want {
			case model.StateResolved:
				if got.CloseReason != ReasonConditionCleared || !got.ClosedAt.Equal(e.clk.Now()) {
					t.Fatalf("close: %q at %v", got.CloseReason, got.ClosedAt)
				}
			case tc.state:
				if !got.UpdatedAt.Equal(inc.UpdatedAt) {
					t.Fatal("an unchanged incident was rewritten")
				}
			}
		})
	}
}

func TestGreenLight(t *testing.T) {
	cases := []struct {
		ticket model.TicketState
		want   model.IncidentState
		alert  model.AlertKind
		keep   bool // ticket stays on the incident
	}{
		{model.TicketApproved, model.StateQueued, "", true},
		{model.TicketConsumed, model.StateQueued, "", true},
		{model.TicketDenied, model.StateEscalated, model.AlertEscalated, false},
		{model.TicketExpired, model.StateEscalated, model.AlertEscalated, false},
		{model.TicketWithdrawn, model.StateEscalated, model.AlertEscalated, false},
		{model.TicketPending, model.StateGreenLight, "", true},
		{model.TicketUnknown, model.StateGreenLight, "", true},
	}
	for _, tc := range cases {
		t.Run(string(tc.ticket), func(t *testing.T) {
			e := newEnv(t)
			inc := e.inState("stuck-job:1", model.StateGreenLight)
			tr, err := e.m.GreenLightDecided(inc, tc.ticket)
			if err != nil {
				t.Fatal(err)
			}
			got := e.get(inc.ID)
			if tr.To != tc.want || got.State != tc.want || tr.Alert != tc.alert || (got.Ticket == "ssh-prod/42") != tc.keep || tr.WithdrawTicket != "" {
				t.Fatalf("transition = %+v, stored = %+v", tr, got)
			}
		})
	}
	t.Run("timed out", func(t *testing.T) {
		e := newEnv(t)
		inc := e.inState("stuck-job:1", model.StateGreenLight)
		tr, err := e.m.GreenLightTimedOut(inc)
		if err != nil {
			t.Fatal(err)
		}
		if got := e.get(inc.ID); tr.To != model.StateEscalated || got.State != model.StateEscalated || tr.Alert != model.AlertEscalated ||
			tr.WithdrawTicket != "ssh-prod/42" || got.Ticket != "" {
			t.Fatalf("transition = %+v, stored = %+v", tr, got)
		}
	})
	t.Run("approved ticket is replayed by the next pass", func(t *testing.T) {
		e := newEnv(t)
		inc := e.inState("stuck-job:1", model.StateGreenLight)
		e.m.GreenLightDecided(inc, model.TicketApproved)
		next, err := e.st.ClaimNextQueued()
		if err != nil || next == nil || next.ID != inc.ID || next.Ticket != "ssh-prod/42" || next.AgentToken != inc.AgentToken {
			t.Fatalf("next = %+v, %v", next, err)
		}
		tr, _ := e.m.ApplyVerdict(*next, model.Verdict{Outcome: model.OutcomeResolved}, model.Runbook{}, model.Limits{})
		if tr.To != model.StateResolved || tr.Incident.Ticket != "" {
			t.Fatalf("after the replay: %+v", tr.Incident)
		}
	})
	t.Run("not waiting for a green light", func(t *testing.T) {
		for _, state := range allStates {
			if state == model.StateGreenLight {
				continue
			}
			e := newEnv(t)
			inc := e.inState("stuck-job:1", state)
			for _, ts := range []model.TicketState{model.TicketApproved, model.TicketDenied, model.TicketPending} {
				if _, err := e.m.GreenLightDecided(inc, ts); !errors.Is(err, store.ErrStateConflict) {
					t.Fatalf("%s/%s: err = %v", state, ts, err)
				}
			}
			if _, err := e.m.GreenLightTimedOut(inc); !errors.Is(err, store.ErrStateConflict) {
				t.Fatalf("%s: timeout err = %v", state, err)
			}
		}
		e := newEnv(t)
		if _, err := e.m.GreenLightDecided(e.inState("stuck-job:1", model.StateGreenLight), "bogus"); err == nil {
			t.Fatal("bogus ticket state accepted")
		}
	})
}

func TestCloseAndResume(t *testing.T) {
	for _, state := range allStates {
		t.Run("close "+string(state), func(t *testing.T) {
			e := newEnv(t)
			inc := e.inState("stuck-job:1", state)
			tr, err := e.m.Close(inc.ID, "  fixed\nby hand ")
			if state == model.StateResolved {
				if !errors.Is(err, store.ErrStateConflict) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := e.get(inc.ID)
			if got.State != model.StateResolved || got.CloseReason != "fixed by hand" || got.ClosedAt.IsZero() || got.Ticket != "" || !got.RecheckAt.IsZero() {
				t.Fatalf("closed = %+v", got)
			}
			if (tr.WithdrawTicket == "ssh-prod/42") != (state == model.StateGreenLight) {
				t.Fatalf("withdraw = %q", tr.WithdrawTicket)
			}
		})
		t.Run("resume "+string(state), func(t *testing.T) {
			e := newEnv(t)
			inc := e.inState("stuck-job:1", state)
			e.st.IncrementFailures(inc.ID)
			tr, err := e.m.Resume(inc.ID)
			switch state {
			case model.StateQueued, model.StateInvestigating, model.StateResolved:
				if !errors.Is(err, store.ErrStateConflict) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := e.get(inc.ID)
			if got.State != model.StateQueued || got.Ticket != "" || !got.RecheckAt.IsZero() || tr.From != state {
				t.Fatalf("resumed = %+v", got)
			}
			if (tr.WithdrawTicket == "ssh-prod/42") != (state == model.StateGreenLight) {
				t.Fatalf("withdraw = %q", tr.WithdrawTicket)
			}
			if n, _ := e.st.Failures(inc.ID); n != 0 {
				t.Fatalf("failures = %d", n)
			}
		})
	}
	e := newEnv(t)
	if _, err := e.m.Close("INC-000404", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	inc := e.inState("stuck-job:1", model.StateEscalated)
	e.m.Close(inc.ID, "")
	if got := e.get(inc.ID); got.CloseReason != ReasonClosedByHuman {
		t.Fatalf("default reason = %q", got.CloseReason)
	}
}

func TestDueReminders(t *testing.T) {
	e := newEnv(t)
	e.limits["fast"] = model.Limits{ReminderEvery: time.Hour}
	esc := e.inState("stuck-job:1", model.StateEscalated) // default: one day
	f := sig("stuck-job:2")
	f.Project = "fast"
	res := e.ingest(f, model.Limits{})
	e.st.ClaimIncident(res.Incident.ID)
	e.m.ApplyVerdict(res.Incident, model.Verdict{Outcome: model.OutcomeBlocked}, model.Runbook{}, model.Limits{})
	e.inState("stuck-job:3", model.StateWaiting)

	ids := func() string {
		due, err := e.m.DueReminders()
		if err != nil {
			t.Fatal(err)
		}
		out := ""
		for _, i := range due {
			out += i.ID + " "
		}
		return out
	}
	if got := ids(); got != "" {
		t.Fatalf("due at once: %q", got)
	}
	e.clk.Add(time.Hour)
	if got := ids(); got != res.Incident.ID+" " {
		t.Fatalf("after 1h: %q", got)
	}
	e.st.RecordAlert(model.Alert{Kind: model.AlertReminder, Project: "fast", Incident: res.Incident.ID})
	if got := ids(); got != "" {
		t.Fatalf("after the reminder: %q", got)
	}
	e.clk.Add(23 * time.Hour)
	if got := ids(); got != esc.ID+" "+res.Incident.ID+" " {
		t.Fatalf("after 24h: %q", got)
	}
}

func TestRecoveryAfterRestart(t *testing.T) {
	e := newEnv(t)
	a := e.investigating("stuck-job:1")
	w := e.inState("stuck-job:2", model.StateWaiting)
	g := e.inState("stuck-job:3", model.StateGreenLight)
	run, _ := e.st.StartRun(a.ID, "seat-a")
	e.st.Close() // the daemon dies in the middle of a pass

	e.clk.Add(time.Hour)
	st, err := store.Open(e.dbPath, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := NewManager(st, e.clk.Now, nil, WithDossier(e.dossier))
	rec, err := st.RecoverInterrupted()
	if err != nil || len(rec) != 1 || rec[0].ID != a.ID || rec[0].State != model.StateQueued {
		t.Fatalf("recovered = %+v, %v", rec, err)
	}
	if runs, _ := st.ListRuns(a.ID); len(runs) != 1 || runs[0].ID != run.ID || runs[0].Status != model.RunCancelled {
		t.Fatalf("runs = %+v", runs)
	}
	for id, want := range map[string]model.IncidentState{w.ID: model.StateWaiting, g.ID: model.StateGreenLight} {
		if got, _ := st.GetIncident(id); got.State != want {
			t.Fatalf("%s is %s after the restart", id, got.State)
		}
	}
	// Life goes on: same identity, the interrupted pass was not counted,
	// the waiting incident is due, the signal still dedups.
	next, err := st.ClaimNextQueued()
	if err != nil || next == nil || next.ID != a.ID || next.AgentToken != a.AgentToken || next.Runs != 0 {
		t.Fatalf("next = %+v, %v", next, err)
	}
	if tr, err := m.ApplyVerdict(*next, model.Verdict{Outcome: model.OutcomeResolved}, model.Runbook{}, model.Limits{}); err != nil || tr.To != model.StateResolved {
		t.Fatalf("verdict after the restart: %+v, %v", tr, err)
	}
	if due, _ := st.DueRechecks(); len(due) != 1 || due[0].ID != w.ID {
		t.Fatalf("due = %+v", due)
	}
	if res, err := m.Ingest(sig("stuck-job:3"), model.Limits{}, "stuck-job", ""); err != nil || res.Kind != IngestAttached || res.Incident.ID != g.ID {
		t.Fatalf("ingest after the restart: %+v, %v", res, err)
	}
}

func TestDossier(t *testing.T) {
	e := newEnv(t)
	s := sig("stuck-job:1")
	s.At = t0.Add(-time.Minute)
	inc := e.ingest(s, model.Limits{}).Incident
	dir, err := e.dossier.Dir(inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(e.dbPath), "incidents", inc.ID); dir != want {
		t.Fatalf("dir = %s, want %s", dir, want)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, want := range []string{`"id": "INC-000001"`, `"fingerprint": "stuck-job:1"`, `"job_id": "1"`, `"at": "2026-11-18T09:59:00Z"`, `"runbook": "rb-stuck"`} {
		if !strings.Contains(doc, want) {
			t.Fatalf("incident.json misses %s:\n%s", want, doc)
		}
	}
	if strings.Contains(doc, inc.AgentToken) || strings.Contains(strings.ToLower(doc), "token") {
		t.Fatalf("incident.json leaks the agent token:\n%s", doc)
	}

	e.st.ClaimIncident(inc.ID)
	e.clk.Add(5 * time.Minute)
	v := model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Worker 3 holds the lock.", RootCause: "deadlock in the worker",
		Evidence: []string{"SELECT status FROM jobs → running", "log: lock wait timeout"}, RecheckMinutes: 10,
		ActionsRun: []string{"restart-job"}, Confidence: "medium"}
	if _, err := e.m.ApplyVerdict(inc, v, model.Runbook{}, model.Limits{}); err != nil {
		t.Fatal(err)
	}
	e.clk.Add(10 * time.Minute)
	e.m.Recheck(inc, true)
	e.st.ClaimIncident(inc.ID)
	e.m.RunFailed(inc, model.RunTimeout, model.Limits{})
	e.st.ClaimIncident(inc.ID)
	e.m.ApplyVerdict(inc, model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: "ssh-prod/42"}, model.Runbook{}, model.Limits{})
	e.m.GreenLightDecided(inc, model.TicketDenied)
	e.m.Resume(inc.ID)
	e.st.ClaimIncident(inc.ID)
	e.m.RunFailed(inc, model.RunQuota, model.Limits{})
	e.m.Close(inc.ID, "fixed by hand")

	journal, err := e.dossier.Journal(inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantInOrder := []string{
		"## 2026-11-18T09:59:00Z — signal", "job stuck: stuck-job:1", "state: queued",
		"## 2026-11-18T10:05:00Z — pass 1: verdict recheck", "Worker 3 holds the lock.", "**Root cause:** deadlock in the worker",
		"- SELECT status FROM jobs → running", "- log: lock wait timeout", "**Actions run:** restart-job",
		"State: investigating → waiting (agent asked for a recheck), recheck at 2026-11-18T10:15:00Z.",
		"## 2026-11-18T10:15:00Z — recheck: still firing", "State: waiting → queued",
		"— pass ended: timeout", "State: investigating → queued (pass failed, one retry).",
		"— pass 3: verdict green_light", "**Ticket:** ssh-prod/42", "State: investigating → green_light",
		"— green light: denied", "State: green_light → escalated (ticket ssh-prod/42 denied).",
		"— resumed by a human", "State: escalated → queued",
		"— pass ended: quota", "State: investigating → queued",
		"— closed by a human", "State: queued → resolved (fixed by hand).",
	}
	rest := journal
	for _, w := range wantInOrder {
		i := strings.Index(rest, w)
		if i < 0 {
			t.Fatalf("journal misses (or has out of order) %q:\n%s", w, journal)
		}
		rest = rest[i+len(w):]
	}
	if strings.Contains(journal, inc.AgentToken) {
		t.Fatal("journal leaks the agent token")
	}

	// Append-only: a later entry leaves the earlier bytes untouched.
	if err := e.dossier.Append(inc.ID, e.clk.Now(), "note\nwith a newline", ""); err != nil {
		t.Fatal(err)
	}
	after, _ := e.dossier.Journal(inc.ID)
	if !strings.HasPrefix(after, journal) || !strings.HasSuffix(after, "— note with a newline\n\n") {
		t.Fatalf("journal rewritten:\n%s", after)
	}

	run2, err := e.dossier.RunDir(inc.ID, 2)
	if err != nil || run2 != filepath.Join(dir, "runs", "2") {
		t.Fatalf("run dir = %s, %v", run2, err)
	}
	if again, err := e.dossier.RunDir(inc.ID, 2); err != nil || again != run2 {
		t.Fatalf("run dir twice = %s, %v", again, err)
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Dir(dir): 0o750, dir: 0o750, filepath.Join(dir, "runs"): 0o750, run2: 0o750,
		filepath.Join(dir, "incident.json"): 0o640, filepath.Join(dir, "journal.md"): 0o640,
	} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Fatalf("%s: mode %o, want %o", path, st.Mode().Perm(), mode)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "incident.json.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind: %v", err)
	}

	for _, bad := range []string{"", "../x", "INC-1/../..", "INC-", "inc-000001", "INC-000001/"} {
		if _, err := e.dossier.Dir(bad); !errors.Is(err, ErrDossier) {
			t.Fatalf("Dir(%q): err = %v", bad, err)
		}
		if err := e.dossier.Append(bad, t0, "x", ""); !errors.Is(err, ErrDossier) {
			t.Fatalf("Append(%q): err = %v", bad, err)
		}
	}
	if _, err := e.dossier.RunDir(inc.ID, 0); !errors.Is(err, ErrDossier) {
		t.Fatalf("RunDir 0: %v", err)
	}
	if j, err := e.dossier.Journal("INC-000999"); err != nil || j != "" {
		t.Fatalf("missing journal = %q, %v", j, err)
	}
}

func TestDossierFailureKeepsTheTransition(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "incidents")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: t0}
	st, err := store.Open(filepath.Join(dir, "d.db"), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := NewManager(st, clk.Now, nil, WithDossier(NewDossier(dir)))
	res, err := m.Ingest(sig("stuck-job:1"), model.Limits{}, "stuck-job", "")
	if !errors.Is(err, ErrDossier) || res.Kind != IngestCreated || res.Incident.ID == "" {
		t.Fatalf("ingest = %+v, %v", res, err)
	}
	st.ClaimIncident(res.Incident.ID)
	tr, err := m.ApplyVerdict(res.Incident, model.Verdict{Outcome: model.OutcomeEscalate}, model.Runbook{}, model.Limits{})
	if !errors.Is(err, ErrDossier) || tr.To != model.StateEscalated || tr.Alert != model.AlertEscalated {
		t.Fatalf("verdict = %+v, %v", tr, err)
	}
	if got, _ := st.GetIncident(res.Incident.ID); got.State != model.StateEscalated {
		t.Fatalf("stored state = %s", got.State)
	}
	// Without a dossier the manager works silently.
	m2 := NewManager(st, nil, nil)
	if m2.Dossier() != nil {
		t.Fatal("unexpected dossier")
	}
	if _, err := m2.Resume(res.Incident.ID); err != nil {
		t.Fatal(err)
	}
}
