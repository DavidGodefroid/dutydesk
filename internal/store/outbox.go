package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Effect kinds of the outbox.
const (
	// EffectTransition is what a lifecycle step owes: merge requests, a
	// known problem, alerts. Its payload is written by internal/incident.
	EffectTransition = "transition"
	// EffectAlert is one alert or notice to deliver; payload = model.Alert.
	EffectAlert = "alert"
)

// Effect is one row of the outbox: something the core owes after a state
// change. It is stored in the transaction of the change and marked done only
// when the effect succeeded, so a crash or a failing webhook never loses it.
type Effect struct {
	ID        int64
	Kind      string // EffectTransition | EffectAlert
	Project   string
	Incident  string // "" for effects that concern no incident
	Payload   string // JSON
	Progress  string // JSON: the steps of the effect already done
	State     string // "pending" | "done" | "dropped"
	Attempts  int
	NextAt    time.Time // not tried before this time
	LastError string
	CreatedAt time.Time
	DoneAt    time.Time
}

const effectCols = `id, kind, project, incident, payload, progress, state, attempts, next_at, last_error, created_at, done_at`

func scanEffect(sc scanner) (Effect, error) {
	var (
		e                   Effect
		next, created, done string
	)
	err := sc.Scan(&e.ID, &e.Kind, &e.Project, &e.Incident, &e.Payload, &e.Progress, &e.State, &e.Attempts, &next,
		&e.LastError, &created, &done)
	e.NextAt, e.CreatedAt, e.DoneAt = parseTime(next), parseTime(created), parseTime(done)
	return e, err
}

func (s *Store) enqueue(tx *sql.Tx, e Effect) (int64, error) {
	if e.Kind == "" {
		return 0, errors.New("store: effect without a kind")
	}
	if e.Payload == "" {
		e.Payload = "{}"
	}
	res, err := tx.Exec(`INSERT INTO outbox (kind, project, incident, payload, progress, next_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, e.Kind, e.Project, e.Incident, e.Payload, e.Progress, fmtTime(e.NextAt), fmtTime(s.now()))
	if err != nil {
		return 0, fmt.Errorf("store: enqueue effect: %w", err)
	}
	return res.LastInsertId()
}

// Enqueue stores an owed effect that hangs on no incident transition (a
// system alert).
func (s *Store) Enqueue(e Effect) (int64, error) {
	var id int64
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		id, err = s.enqueue(tx, e)
		return err
	})
	return id, err
}

// AlertEffect builds the outbox row of an alert.
func AlertEffect(a model.Alert) (Effect, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return Effect{}, err
	}
	return Effect{Kind: EffectAlert, Project: a.Project, Incident: a.Incident, Payload: string(b)}, nil
}

// EnqueueAlert stores an alert to deliver.
func (s *Store) EnqueueAlert(a model.Alert) (int64, error) {
	e, err := AlertEffect(a)
	if err != nil {
		return 0, err
	}
	return s.Enqueue(e)
}

// DueEffects returns the pending effects of a kind whose next attempt is
// due, oldest first.
func (s *Store) DueEffects(kind string, limit int) ([]Effect, error) {
	rows, err := s.db.Query(`SELECT `+effectCols+` FROM outbox
		WHERE state = 'pending' AND kind = ? AND (next_at = '' OR next_at <= ?) ORDER BY id ASC LIMIT ?`,
		kind, fmtTime(s.now()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Effect
	for rows.Next() {
		e, err := scanEffect(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PendingEffects returns every pending effect, due or not, oldest first
// ("" = every kind).
func (s *Store) PendingEffects(kind string) ([]Effect, error) {
	rows, err := s.db.Query(`SELECT `+effectCols+` FROM outbox
		WHERE state = 'pending' AND (? = '' OR kind = ?) ORDER BY id ASC`, kind, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Effect
	for rows.Next() {
		e, err := scanEffect(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// HasPendingAlert reports whether an alert (not a notice) for the incident
// still waits for delivery: no reminder is added on top of it.
func (s *Store) HasPendingAlert(incidentID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE incident = ? AND state = 'pending'`, incidentID).Scan(&n)
	return n > 0, err
}

// RetryEffect records a failed attempt: the effect stays pending and is not
// tried again before next.
func (s *Store) RetryEffect(id int64, next time.Time, lastError string) error {
	_, err := s.db.Exec(`UPDATE outbox SET attempts = attempts + 1, next_at = ?, last_error = ?
		WHERE id = ? AND state = 'pending'`, fmtTime(next), lastError, id)
	return err
}

// SaveProgress stores the steps of an effect already done, together with
// what those steps must record (fn may be nil), in one transaction.
func (s *Store) SaveProgress(id int64, progress string, fn func(*EffectTx) error) error {
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE outbox SET progress = ? WHERE id = ? AND state = 'pending'`, progress, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("store: effect %d: %w", id, ErrNotFound)
		}
		if fn == nil {
			return nil
		}
		return fn(&EffectTx{s: s, tx: tx})
	})
}

// EffectTx is the transaction that completes a step of an effect.
type EffectTx struct {
	s  *Store
	tx *sql.Tx
}

// Enqueue adds a follow-up effect (the alerts of a transition).
func (t *EffectTx) Enqueue(e Effect) error {
	_, err := t.s.enqueue(t.tx, e)
	return err
}

// OpenKnownProblem records an opened merge request as a known problem.
func (t *EffectTx) OpenKnownProblem(k model.KnownProblem) error {
	_, err := t.s.openKnownProblem(t.tx, k)
	return err
}

// RecordProposal records a merge request on the configuration repository.
func (t *EffectTx) RecordProposal(p Proposal) error {
	_, err := t.s.recordProposal(t.tx, p)
	return err
}

// FinishEffect marks an effect done ("done") or abandoned ("dropped"),
// together with what its completion must record, in one transaction.
func (s *Store) FinishEffect(id int64, state, note string, fn func(*EffectTx) error) error {
	if state != "done" && state != "dropped" {
		return fmt.Errorf("store: effect state %q", state)
	}
	return s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE outbox SET state = ?, done_at = ?, last_error = CASE WHEN ? <> '' THEN ? ELSE last_error END
			WHERE id = ? AND state = 'pending'`, state, fmtTime(s.now()), note, note, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil // already finished: nothing is recorded twice
		}
		if fn == nil {
			return nil
		}
		return fn(&EffectTx{s: s, tx: tx})
	})
}

// AlertDelivered marks the alert effect done and records the alert, which
// moves the incident's LastAlertAt: only a delivered alert restarts the
// reminder delay.
func (s *Store) AlertDelivered(id int64, a model.Alert) error {
	if a.At.IsZero() {
		a.At = s.now()
	}
	return s.FinishEffect(id, "done", "", func(t *EffectTx) error {
		_, err := recordAlert(t.tx, a)
		return err
	})
}

// PruneEffects deletes the finished effects older than the given time.
func (s *Store) PruneEffects(doneBefore time.Time) error {
	_, err := s.db.Exec(`DELETE FROM outbox WHERE state <> 'pending' AND done_at <> '' AND done_at <= ?`, fmtTime(doneBefore))
	return err
}

// OwedAgentTokens returns the agent tokens of the incidents that still have
// a pending effect: a resolved incident's token stays a secret to scan for
// while its merge request is not out yet.
func (s *Store) OwedAgentTokens() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT i.agent_token FROM outbox o JOIN incidents i ON i.id = o.incident
		WHERE o.state = 'pending' AND i.agent_token <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
