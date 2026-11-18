package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func openInc(t *testing.T, s *Store, fp string) model.Incident {
	t.Helper()
	inc, err := s.CreateIncident(model.Incident{Project: "shop", Source: "chk", Fingerprint: fp, Family: "chk", Severity: model.SevLow})
	if err != nil {
		t.Fatal(err)
	}
	return inc
}

// Finding 17: an incident keeps its first signals as rows; later ones only
// move the counter and the last-seen time.
func TestSignalRowsAreCapped(t *testing.T) {
	s, clk := newStore(t)
	inc := openInc(t, s, "fp")
	for i := 0; i < MaxSignalRows+30; i++ {
		clk.Add(time.Minute)
		sev := model.SevLow
		if i == MaxSignalRows+5 {
			sev = model.SevCritical
		}
		id, err := s.RecordSignal(model.Signal{Project: "shop", Source: "chk", Fingerprint: "fp", Severity: sev,
			Summary: fmt.Sprintf("signal %d", i)}, inc.ID)
		if err != nil {
			t.Fatal(err)
		}
		if (id == 0) != (i >= MaxSignalRows) {
			t.Fatalf("signal %d: row id %d", i, id)
		}
	}
	rows, _ := s.ListSignals(inc.ID)
	got, _ := s.GetIncident(inc.ID)
	last, _ := s.LastSignalAt(inc.ID)
	if len(rows) != MaxSignalRows || got.SignalCount != MaxSignalRows+30 || got.Severity != model.SevCritical || !last.Equal(clk.Now()) {
		t.Errorf("rows = %d, count = %d, severity = %d, last seen %v", len(rows), got.SignalCount, got.Severity, last)
	}
	origin, err := s.OriginSignal(inc.ID)
	if err != nil || origin == nil || origin.Summary != "signal 0" {
		t.Errorf("origin = %+v, %v", origin, err)
	}
	if _, err := s.RecordSignal(model.Signal{Fingerprint: "fp"}, "INC-999999"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown incident: %v", err)
	}
}

// Finding 5: a ticket is recorded once, for one incident.
func TestTicketIsClaimedOnce(t *testing.T) {
	s, _ := newStore(t)
	a, b := openInc(t, s, "a"), openInc(t, s, "b")
	claim := func(id, ticket string) (ok bool) {
		_, err := s.Transition(id, nil, func(tx *Tx, _ *model.Incident) error {
			var err error
			ok, err = tx.ClaimTicket(ticket, id)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !claim(a.ID, "ask/1") || claim(b.ID, "ask/1") || claim(a.ID, "ask/1") || !claim(b.ID, "ask/2") {
		t.Fatal("ticket ownership is not exclusive")
	}
	if h, _ := s.TicketHolder("ask/1"); h != a.ID {
		t.Errorf("holder = %q", h)
	}
	// A claim made in a transition that fails is not kept.
	boom := errors.New("boom")
	if _, err := s.Transition(a.ID, nil, func(tx *Tx, _ *model.Incident) error {
		tx.ClaimTicket("ask/3", a.ID)
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if h, _ := s.TicketHolder("ask/3"); h != "" {
		t.Errorf("rolled-back claim kept: %q", h)
	}
}

// Finding 4: the outbox. An effect is stored with its transition, survives
// a restart, is retried, and an alert is recorded (and last_alert_at moved)
// only when it was delivered.
func TestOutbox(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)}
	s, err := Open(filepath.Join(dir, "d.db"), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	inc := openInc(t, s, "fp")
	alert := model.Alert{Kind: model.AlertEscalated, Project: "shop", Incident: inc.ID, Title: "t", Body: "b"}
	eff, _ := AlertEffect(alert)

	// Transition and effect are one transaction.
	boom := errors.New("boom")
	if _, err := s.Transition(inc.ID, nil, func(tx *Tx, i *model.Incident) error {
		i.State = model.StateEscalated
		tx.Enqueue(eff)
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if owed, _ := s.PendingEffects(""); len(owed) != 0 {
		t.Fatalf("an effect outlived its failed transition: %+v", owed)
	}
	if _, err := s.Transition(inc.ID, nil, func(tx *Tx, i *model.Incident) error {
		i.State = model.StateEscalated
		return tx.Enqueue(eff)
	}); err != nil {
		t.Fatal(err)
	}

	// Crash: the effect is still owed after a reopen.
	s.Close()
	if s, err = Open(filepath.Join(dir, "d.db"), clk.Now); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	due, _ := s.DueEffects(EffectAlert, 10)
	if len(due) != 1 || due[0].Incident != inc.ID || due[0].Kind != EffectAlert {
		t.Fatalf("due = %+v", due)
	}
	if pending, _ := s.HasPendingAlert(inc.ID); !pending {
		t.Error("HasPendingAlert = false")
	}

	// A failed delivery: not due before its next attempt, nothing recorded.
	if err := s.RetryEffect(due[0].ID, clk.Now().Add(time.Minute), "HTTP 503"); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.DueEffects(EffectAlert, 10); len(again) != 0 {
		t.Fatalf("retried before its time: %+v", again)
	}
	if got, _ := s.GetIncident(inc.ID); !got.LastAlertAt.IsZero() {
		t.Errorf("last_alert_at moved without a delivery: %v", got.LastAlertAt)
	}
	if a, _ := s.LastAlert(inc.ID, model.AlertEscalated); a != nil {
		t.Errorf("undelivered alert recorded: %+v", a)
	}
	clk.Add(2 * time.Minute)
	due, _ = s.DueEffects(EffectAlert, 10)
	if len(due) != 1 || due[0].Attempts != 1 || due[0].LastError != "HTTP 503" {
		t.Fatalf("due = %+v", due)
	}

	// Delivered: recorded once, last_alert_at moves, nothing is owed.
	alert.At = clk.Now()
	for i := 0; i < 2; i++ {
		if err := s.AlertDelivered(due[0].ID, alert); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.GetIncident(inc.ID)
	if !got.LastAlertAt.Equal(clk.Now()) {
		t.Errorf("last_alert_at = %v", got.LastAlertAt)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&n)
	if owed, _ := s.PendingEffects(""); n != 1 || len(owed) != 0 {
		t.Errorf("alerts recorded = %d, still owed = %d", n, len(owed))
	}
	// A later transition does not write a stale last_alert_at back.
	s.UpdateIncident(inc.ID, nil, func(i *model.Incident) error { i.LastAlertAt = time.Time{}; return nil })
	if got, _ := s.GetIncident(inc.ID); got.LastAlertAt.IsZero() {
		t.Error("a transition erased last_alert_at")
	}
}

// Step progress and its records are one transaction; finishing twice
// records nothing twice.
func TestEffectProgress(t *testing.T) {
	s, _ := newStore(t)
	inc := openInc(t, s, "fp")
	id, err := s.Enqueue(Effect{Kind: EffectTransition, Project: "shop", Incident: inc.ID, Payload: `{"event":"verdict"}`})
	if err != nil {
		t.Fatal(err)
	}
	kp := model.KnownProblem{Project: "shop", Family: "chk", MRURL: "https://x/1", MRID: "1", Incident: inc.ID}
	if err := s.SaveProgress(id, `{"mr":{"url":"https://x/1"}}`, func(tx *EffectTx) error { return tx.OpenKnownProblem(kp) }); err != nil {
		t.Fatal(err)
	}
	owed, _ := s.PendingEffects(EffectTransition)
	known, _ := s.ListOpenKnownProblems("shop")
	if len(owed) != 1 || owed[0].Progress != `{"mr":{"url":"https://x/1"}}` || len(known) != 1 {
		t.Fatalf("owed = %+v, known = %+v", owed, known)
	}
	a, _ := AlertEffect(model.Alert{Kind: model.NoticeMROpened, Project: "shop", Incident: inc.ID})
	for i := 0; i < 2; i++ {
		if err := s.FinishEffect(id, "done", "", func(tx *EffectTx) error { return tx.Enqueue(a) }); err != nil {
			t.Fatal(err)
		}
	}
	if alerts, _ := s.PendingEffects(EffectAlert); len(alerts) != 1 {
		t.Errorf("alerts owed = %d, want 1", len(alerts))
	}
	if toks, _ := s.OwedAgentTokens(); len(toks) != 0 {
		t.Errorf("tokens = %v", toks) // the test incident has no token
	}
}

// Finding 17: retention only deletes resolved incidents with nothing owed.
func TestDeleteIncident(t *testing.T) {
	s, clk := newStore(t)
	inc := openInc(t, s, "fp")
	s.RecordSignal(model.Signal{Project: "shop", Source: "chk", Fingerprint: "fp"}, inc.ID)
	s.StartRun(inc.ID, "seat")
	if err := s.DeleteIncident(inc.ID); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("open incident deleted: %v", err)
	}
	s.UpdateIncident(inc.ID, nil, func(i *model.Incident) error { i.State = model.StateResolved; return nil })
	id, _ := s.EnqueueAlert(model.Alert{Kind: model.AlertEscalated, Project: "shop", Incident: inc.ID})
	if err := s.DeleteIncident(inc.ID); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("incident with an owed alert deleted: %v", err)
	}
	s.AlertDelivered(id, model.Alert{Kind: model.AlertEscalated, Project: "shop", Incident: inc.ID})
	clk.Add(time.Hour)
	if ids, _ := s.ResolvedBefore(clk.Now(), 10); len(ids) != 1 {
		t.Fatalf("resolved before = %v", ids)
	}
	if err := s.DeleteIncident(inc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIncident(inc.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("still there: %v", err)
	}
	for _, table := range []string{"signals", "runs", "alerts", "outbox"} {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
		if n != 0 {
			t.Errorf("%d rows left in %s", n, table)
		}
	}
}
