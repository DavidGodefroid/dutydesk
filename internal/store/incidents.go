package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const incidentCols = `id, project, source, fingerprint, family, severity, summary, state, mass, recurrent,
	runbook, signal_count, runs, agent_token, ticket, recheck_at, opened_at, updated_at, closed_at,
	last_alert_at, close_reason, green_lights, quota_runs, age_from`

type scanner interface {
	Scan(dest ...any) error
}

func scanIncident(sc scanner) (model.Incident, error) {
	var (
		i                                           model.Incident
		state                                       string
		mass, recurrent                             int
		recheck, opened, updated, closed, lastAlert string
		ageFrom                                     string
		sev                                         int
	)
	err := sc.Scan(&i.ID, &i.Project, &i.Source, &i.Fingerprint, &i.Family, &sev, &i.Summary, &state, &mass, &recurrent,
		&i.Runbook, &i.SignalCount, &i.Runs, &i.AgentToken, &i.Ticket, &recheck, &opened, &updated, &closed,
		&lastAlert, &i.CloseReason, &i.GreenLights, &i.QuotaRuns, &ageFrom)
	if err != nil {
		return i, err
	}
	i.Severity = model.Severity(sev)
	i.State = model.IncidentState(state)
	i.Mass = mass != 0
	i.Recurrent = recurrent != 0
	i.RecheckAt = parseTime(recheck)
	i.OpenedAt = parseTime(opened)
	i.UpdatedAt = parseTime(updated)
	i.ClosedAt = parseTime(closed)
	i.LastAlertAt = parseTime(lastAlert)
	i.AgeFrom = parseTime(ageFrom)
	return i, nil
}

func (s *Store) queryIncidents(query string, args ...any) ([]model.Incident, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Incident
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateIncident inserts a new incident and allocates its ID ("INC-%06d").
// ID, OpenedAt (when zero), UpdatedAt and the state timestamp are set by the
// store; State defaults to queued. It returns ErrDuplicateOpen when an open
// incident already has the same project and fingerprint.
func (s *Store) CreateIncident(inc model.Incident) (model.Incident, error) {
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		inc, err = s.createIncident(tx, inc)
		return err
	})
	return inc, createErr(err)
}

// OpenIncident creates an incident with its origin signal and the effects
// its creation owes (a storm or recurrence alert), in one transaction: a
// crash leaves either all of it or nothing. The effects get the incident's
// id and project.
func (s *Store) OpenIncident(inc model.Incident, sig model.Signal, owed ...Effect) (model.Incident, error) {
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		if inc, err = s.createIncident(tx, inc); err != nil {
			return err
		}
		id, err := insertSignal(tx, sig, s.signalTime(sig))
		if err != nil {
			return err
		}
		if err := attachSignal(tx, id, inc.ID, s.now()); err != nil {
			return err
		}
		for _, e := range owed {
			e.Incident, e.Project = inc.ID, inc.Project
			if _, err := s.enqueue(tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return model.Incident{}, createErr(err)
	}
	return s.GetIncident(inc.ID)
}

func createErr(err error) error {
	if isUniqueViolation(err) {
		return ErrDuplicateOpen
	}
	if err != nil {
		return fmt.Errorf("store: create incident: %w", err)
	}
	return nil
}

func (s *Store) createIncident(tx *sql.Tx, inc model.Incident) (model.Incident, error) {
	now := s.now()
	if inc.State == "" {
		inc.State = model.StateQueued
	}
	if inc.OpenedAt.IsZero() {
		inc.OpenedAt = now
	}
	inc.OpenedAt = inc.OpenedAt.UTC().Truncate(time.Second)
	inc.UpdatedAt = now.UTC().Truncate(time.Second)
	if inc.State == model.StateResolved && inc.ClosedAt.IsZero() {
		inc.ClosedAt = inc.UpdatedAt
	}
	inc.RecheckAt = normTime(inc.RecheckAt)
	inc.ClosedAt = normTime(inc.ClosedAt)
	inc.LastAlertAt = normTime(inc.LastAlertAt)
	inc.AgeFrom = normTime(inc.AgeFrom)
	var seq int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM incidents`).Scan(&seq); err != nil {
		return inc, err
	}
	inc.ID = fmt.Sprintf("INC-%06d", seq)
	_, err := tx.Exec(`INSERT INTO incidents (seq, `+incidentCols+`, state_since)
		VALUES (?, ?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?, ?,?, ?,?,?, ?)`,
		seq, inc.ID, inc.Project, inc.Source, inc.Fingerprint, inc.Family, int(inc.Severity), inc.Summary,
		string(inc.State), boolInt(inc.Mass), boolInt(inc.Recurrent),
		inc.Runbook, inc.SignalCount, inc.Runs, inc.AgentToken, inc.Ticket, fmtTime(inc.RecheckAt),
		fmtTime(inc.OpenedAt), fmtTime(inc.UpdatedAt), fmtTime(inc.ClosedAt),
		fmtTime(inc.LastAlertAt), inc.CloseReason, inc.GreenLights, inc.QuotaRuns, fmtTime(inc.AgeFrom), fmtTime(now))
	return inc, err
}

func normTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Second)
}

// GetIncident returns the incident or ErrNotFound.
func (s *Store) GetIncident(id string) (model.Incident, error) {
	i, err := scanIncident(s.db.QueryRow(`SELECT `+incidentCols+` FROM incidents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return i, ErrNotFound
	}
	return i, err
}

// IncidentFilter narrows ListIncidents. Zero fields do not filter.
type IncidentFilter struct {
	Project  string
	OpenOnly bool                  // every state but resolved
	States   []model.IncidentState // any of these
	Limit    int
}

// ListIncidents returns the matching incidents, oldest first.
func (s *Store) ListIncidents(f IncidentFilter) ([]model.Incident, error) {
	var (
		where []string
		args  []any
	)
	if f.Project != "" {
		where = append(where, "project = ?")
		args = append(args, f.Project)
	}
	if f.OpenOnly {
		where = append(where, "state <> 'resolved'")
	}
	if len(f.States) > 0 {
		where = append(where, "state IN ("+placeholders(len(f.States))+")")
		for _, st := range f.States {
			args = append(args, string(st))
		}
	}
	q := `SELECT ` + incidentCols + ` FROM incidents`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` ORDER BY seq ASC`
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	return s.queryIncidents(q, args...)
}

// Tx is the write transaction of an incident transition: what must be
// stored together with the new state (owed effects, the ownership of a
// ticket, the failure counter).
type Tx struct {
	s  *Store
	tx *sql.Tx
}

// Enqueue stores an owed effect in the transaction of the transition.
func (t *Tx) Enqueue(e Effect) error {
	_, err := t.s.enqueue(t.tx, e)
	return err
}

// ClaimTicket records that the incident holds the green-light ticket. It
// returns false when the ticket was already recorded, by this incident or
// by another one: a ticket is accepted once.
func (t *Tx) ClaimTicket(ticket, incidentID string) (bool, error) {
	res, err := t.tx.Exec(`INSERT INTO tickets (ticket, incident_id, at) VALUES (?, ?, ?)
		ON CONFLICT(ticket) DO NOTHING`, ticket, incidentID, fmtTime(t.s.now()))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// IncrementFailures adds one to the consecutive failed-run counter.
func (t *Tx) IncrementFailures(id string) (int, error) {
	var n int
	err := t.tx.QueryRow(`UPDATE incidents SET failures = failures + 1 WHERE id = ? RETURNING failures`, id).Scan(&n)
	return n, err
}

// ResetFailures clears the consecutive failed-run counter.
func (t *Tx) ResetFailures(id string) error {
	_, err := t.tx.Exec(`UPDATE incidents SET failures = 0 WHERE id = ?`, id)
	return err
}

// UpdateIncident atomically loads the incident, checks that its state is one
// of from (any state when from is empty), applies mutate and saves the
// result. The store maintains UpdatedAt, the state timestamp and ClosedAt
// (set when the incident becomes resolved, cleared when it leaves resolved);
// the identity fields (ID, Project, Source, Fingerprint, OpenedAt),
// SignalCount and LastAlertAt cannot be changed here. It returns ErrNotFound,
// ErrStateConflict, or the error mutate returned (nothing is saved then).
func (s *Store) UpdateIncident(id string, from []model.IncidentState, mutate func(*model.Incident) error) (model.Incident, error) {
	return s.Transition(id, from, func(_ *Tx, i *model.Incident) error {
		if mutate == nil {
			return nil
		}
		return mutate(i)
	})
}

// Transition is UpdateIncident with access to the transaction, so that the
// effects a transition owes are stored with it or not at all.
func (s *Store) Transition(id string, from []model.IncidentState, mutate func(*Tx, *model.Incident) error) (model.Incident, error) {
	var out model.Incident
	err := s.tx(func(tx *sql.Tx) error {
		cur, err := scanIncident(tx.QueryRow(`SELECT `+incidentCols+` FROM incidents WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if len(from) > 0 {
			ok := false
			for _, st := range from {
				if cur.State == st {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("%w: %s is %s", ErrStateConflict, id, cur.State)
			}
		}
		next := cur
		if mutate != nil {
			if err := mutate(&Tx{s: s, tx: tx}, &next); err != nil {
				return err
			}
		}
		now := s.now().UTC().Truncate(time.Second)
		next.ID, next.Project, next.Source, next.Fingerprint = cur.ID, cur.Project, cur.Source, cur.Fingerprint
		next.OpenedAt, next.SignalCount = cur.OpenedAt, cur.SignalCount
		next.UpdatedAt = now
		next.RecheckAt = normTime(next.RecheckAt)
		next.AgeFrom = normTime(next.AgeFrom)
		next.ClosedAt = normTime(next.ClosedAt)
		switch {
		case next.State == model.StateResolved && next.ClosedAt.IsZero():
			next.ClosedAt = now
		case next.State != model.StateResolved:
			next.ClosedAt = time.Time{}
		}
		since := ""
		if next.State != cur.State {
			since = fmtTime(now)
		}
		// last_alert_at and signal_count are owned by other writers (the
		// delivery of an alert, the attachment of a signal): they are not
		// written back here.
		_, err = tx.Exec(`UPDATE incidents SET family = ?, severity = ?, summary = ?, state = ?, mass = ?,
			recurrent = ?, runbook = ?, runs = ?, agent_token = ?, ticket = ?, recheck_at = ?, updated_at = ?,
			closed_at = ?, close_reason = ?, green_lights = ?, quota_runs = ?, age_from = ?,
			state_since = CASE WHEN ? <> '' THEN ? ELSE state_since END
			WHERE id = ?`,
			next.Family, int(next.Severity), next.Summary, string(next.State), boolInt(next.Mass),
			boolInt(next.Recurrent), next.Runbook, next.Runs, next.AgentToken, next.Ticket, fmtTime(next.RecheckAt),
			fmtTime(next.UpdatedAt), fmtTime(next.ClosedAt), next.CloseReason,
			next.GreenLights, next.QuotaRuns, fmtTime(next.AgeFrom),
			since, since, id)
		if isUniqueViolation(err) {
			// Reopening a resolved incident while another one is open
			// for the same fingerprint.
			return ErrDuplicateOpen
		}
		next.LastAlertAt = cur.LastAlertAt
		out = next
		return err
	})
	if err != nil {
		return model.Incident{}, err
	}
	return out, nil
}

// FindOpenIncident returns the open incident with this project and
// fingerprint, or nil when there is none.
func (s *Store) FindOpenIncident(project, fingerprint string) (*model.Incident, error) {
	i, err := scanIncident(s.db.QueryRow(`SELECT `+incidentCols+` FROM incidents
		WHERE project = ? AND fingerprint = ? AND state <> 'resolved'`, project, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// CountOpenIncidents counts the open incidents of one project and source.
// Mass (storm guard) incidents are not counted.
func (s *Store) CountOpenIncidents(project, source string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM incidents
		WHERE project = ? AND source = ? AND state <> 'resolved' AND mass = 0`, project, source).Scan(&n)
	return n, err
}

// CountIncidentsInState counts the incidents of a project ("" = all) in one state.
func (s *Store) CountIncidentsInState(project string, state model.IncidentState) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE state = ? AND (? = '' OR project = ?)`,
		string(state), project, project).Scan(&n)
	return n, err
}

// CountResolvedByFamily counts the incidents of a family resolved at or
// after since. Mass incidents are not counted.
func (s *Store) CountResolvedByFamily(project, family string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM incidents
		WHERE project = ? AND family = ? AND state = 'resolved' AND mass = 0 AND closed_at >= ?`,
		project, family, fmtTime(since)).Scan(&n)
	return n, err
}

// DueRechecks returns the waiting incidents whose recheck time has come.
func (s *Store) DueRechecks() ([]model.Incident, error) {
	return s.queryIncidents(`SELECT `+incidentCols+` FROM incidents
		WHERE state = 'waiting' AND recheck_at <> '' AND recheck_at <= ? ORDER BY recheck_at ASC, seq ASC`,
		fmtTime(s.now()))
}

// IncidentsNeedingReminder returns the incidents of a project ("" = all)
// that wait for a human (escalated, blocked, green_light) and whose last
// delivered alert (or, when none was delivered, entry into the state) is at
// or before notAlertedSince.
func (s *Store) IncidentsNeedingReminder(project string, notAlertedSince time.Time) ([]model.Incident, error) {
	return s.queryIncidents(`SELECT `+incidentCols+` FROM incidents
		WHERE state IN ('escalated', 'blocked', 'green_light') AND (? = '' OR project = ?)
		AND CASE WHEN last_alert_at <> '' THEN last_alert_at ELSE state_since END <= ?
		ORDER BY seq ASC`, project, project, fmtTime(notAlertedSince))
}

// IncidentsInStateSince returns the incidents that entered state at or
// before the given time and are still in it (green-light timeouts, high
// severity incidents stuck in the queue).
func (s *Store) IncidentsInStateSince(state model.IncidentState, before time.Time) ([]model.Incident, error) {
	return s.queryIncidents(`SELECT `+incidentCols+` FROM incidents
		WHERE state = ? AND state_since <> '' AND state_since <= ? ORDER BY seq ASC`,
		string(state), fmtTime(before))
}

// StateSince returns when the incident entered its current state.
func (s *Store) StateSince(id string) (time.Time, error) {
	var v string
	err := s.db.QueryRow(`SELECT state_since FROM incidents WHERE id = ?`, id).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	return parseTime(v), err
}

// LastSignalAt returns the time of the last signal attached to the incident.
func (s *Store) LastSignalAt(id string) (time.Time, error) {
	var v string
	err := s.db.QueryRow(`SELECT last_signal_at FROM incidents WHERE id = ?`, id).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	return parseTime(v), err
}

func queueFilter(excludeProjects []string) (string, []any) {
	if len(excludeProjects) == 0 {
		return "", nil
	}
	args := make([]any, len(excludeProjects))
	for i, p := range excludeProjects {
		args[i] = p
	}
	return " AND project NOT IN (" + placeholders(len(args)) + ")", args
}

const queueOrder = ` ORDER BY severity DESC, opened_at ASC, seq ASC LIMIT 1`

// NextQueued returns, without claiming it, the queued incident a worker
// would take next (severity descending, then oldest), skipping the given
// projects. It returns nil when the queue is empty.
func (s *Store) NextQueued(excludeProjects ...string) (*model.Incident, error) {
	cond, args := queueFilter(excludeProjects)
	i, err := scanIncident(s.db.QueryRow(`SELECT `+incidentCols+` FROM incidents WHERE state = 'queued'`+
		cond+queueOrder, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// ClaimNextQueued atomically moves the next queued incident (severity
// descending, then oldest) to investigating and returns it; two callers
// never get the same incident. Incidents of excludeProjects are skipped
// (projects at their parallel limit). It returns nil when nothing is queued.
func (s *Store) ClaimNextQueued(excludeProjects ...string) (*model.Incident, error) {
	cond, fargs := queueFilter(excludeProjects)
	now := fmtTime(s.now())
	args := append([]any{now, now}, fargs...)
	i, err := scanIncident(s.db.QueryRow(`UPDATE incidents
		SET state = 'investigating', state_since = ?, updated_at = ?
		WHERE seq = (SELECT seq FROM incidents WHERE state = 'queued'`+cond+queueOrder+`)
		RETURNING `+incidentCols, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: claim: %w", err)
	}
	return &i, nil
}

// ClaimIncident atomically moves one queued incident to investigating. It
// returns ErrStateConflict when the incident is not queued (already taken).
func (s *Store) ClaimIncident(id string) (model.Incident, error) {
	return s.UpdateIncident(id, []model.IncidentState{model.StateQueued}, func(i *model.Incident) error {
		i.State = model.StateInvestigating
		return nil
	})
}

// IncrementFailures adds one to the consecutive failed-run counter of the
// incident and returns the new value.
func (s *Store) IncrementFailures(id string) (int, error) {
	var n int
	err := s.db.QueryRow(`UPDATE incidents SET failures = failures + 1 WHERE id = ? RETURNING failures`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

// ResetFailures clears the consecutive failed-run counter.
func (s *Store) ResetFailures(id string) error {
	_, err := s.db.Exec(`UPDATE incidents SET failures = 0 WHERE id = ?`, id)
	return err
}

// Failures returns the consecutive failed-run counter.
func (s *Store) Failures(id string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT failures FROM incidents WHERE id = ?`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

// RecoverInterrupted is called once when the daemon starts: incidents left
// in investigating by a crash go back to the queue, and every unfinished
// run is marked cancelled. It returns the requeued incidents.
func (s *Store) RecoverInterrupted() ([]model.Incident, error) {
	var ids []string
	now := fmtTime(s.now())
	err := s.tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`UPDATE incidents SET state = 'queued', state_since = ?, updated_at = ?
			WHERE state = 'investigating' RETURNING id`, now, now)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE runs SET status = ?, ended_at = ?, error = 'interrupted by a daemon restart'
			WHERE status = ''`, string(model.RunCancelled), now)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: recover: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return s.queryIncidents(`SELECT `+incidentCols+` FROM incidents WHERE id IN (`+placeholders(len(ids))+`) ORDER BY seq`, args...)
}

// IncidentsPastAge returns the queued and waiting incidents of a project
// whose age limit started at or before the given time: they are escalated
// by a timer, not only when a verdict comes.
func (s *Store) IncidentsPastAge(project string, startedBefore time.Time) ([]model.Incident, error) {
	return s.queryIncidents(`SELECT `+incidentCols+` FROM incidents
		WHERE project = ? AND state IN ('queued', 'waiting') AND mass = 0
		AND CASE WHEN age_from > opened_at THEN age_from ELSE opened_at END <= ?
		ORDER BY seq ASC`, project, fmtTime(startedBefore))
}

// TicketHolder returns the incident a green-light ticket was recorded for
// ("" when the ticket was never accepted).
func (s *Store) TicketHolder(ticket string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT incident_id FROM tickets WHERE ticket = ?`, ticket).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// ResolvedBefore returns the ids of the resolved incidents closed at or
// before the given time, oldest first (retention).
func (s *Store) ResolvedBefore(closedBefore time.Time, limit int) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM incidents WHERE state = 'resolved' AND closed_at <> '' AND closed_at <= ?
		ORDER BY seq ASC LIMIT ?`, fmtTime(closedBefore), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeleteIncident removes a resolved incident and everything that hangs on
// it (signals, runs, actions, alerts, tickets, finished effects). It refuses
// an incident that is still open or still has a pending effect.
func (s *Store) DeleteIncident(id string) error {
	return s.tx(func(tx *sql.Tx) error {
		var state string
		err := tx.QueryRow(`SELECT state FROM incidents WHERE id = ?`, id).Scan(&state)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if state != string(model.StateResolved) {
			return fmt.Errorf("%w: %s is %s", ErrStateConflict, id, state)
		}
		var pending int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM outbox WHERE incident = ? AND state = 'pending'`, id).Scan(&pending); err != nil {
			return err
		}
		if pending > 0 {
			return fmt.Errorf("%w: %s still has pending effects", ErrStateConflict, id)
		}
		for _, q := range []string{
			`DELETE FROM signals WHERE incident_id = ?`, `DELETE FROM runs WHERE incident_id = ?`,
			`DELETE FROM actions WHERE incident_id = ?`, `DELETE FROM alerts WHERE incident = ?`,
			`DELETE FROM tickets WHERE incident_id = ?`, `DELETE FROM outbox WHERE incident = ?`,
			`DELETE FROM incidents WHERE id = ?`,
		} {
			if _, err := tx.Exec(q, id); err != nil {
				return err
			}
		}
		return nil
	})
}
