package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// ---------- signals ----------

// SignalRecord is a stored signal; IncidentID is "" until it is attached.
type SignalRecord struct {
	ID         int64
	IncidentID string
	model.Signal
}

func insertSignal(tx *sql.Tx, sig model.Signal, at time.Time) (int64, error) {
	fields := sig.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO signals (project, source, fingerprint, severity, summary, fields, at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sig.Project, sig.Source, sig.Fingerprint, int(sig.Severity), sig.Summary, string(b), fmtTime(at))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func attachSignal(tx *sql.Tx, signalID int64, incidentID string, now time.Time) error {
	var (
		at  string
		sev int
		cur sql.NullString
	)
	err := tx.QueryRow(`SELECT at, severity, incident_id FROM signals WHERE id = ?`, signalID).Scan(&at, &sev, &cur)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if cur.Valid && cur.String != "" {
		return fmt.Errorf("store: signal %d is already attached to %s", signalID, cur.String)
	}
	res, err := tx.Exec(`UPDATE incidents SET signal_count = signal_count + 1,
		last_signal_at = MAX(last_signal_at, ?), severity = MAX(severity, ?), updated_at = ?
		WHERE id = ?`, at, sev, fmtTime(now), incidentID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(`UPDATE signals SET incident_id = ? WHERE id = ?`, incidentID, signalID)
	return err
}

// InsertSignal stores a signal that is not attached to an incident yet and
// returns its id. A zero At becomes the current time.
func (s *Store) InsertSignal(sig model.Signal) (int64, error) {
	var id int64
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		id, err = insertSignal(tx, sig, s.signalTime(sig))
		return err
	})
	return id, err
}

// AttachSignal links a stored signal to an incident: the incident's signal
// count goes up by one, its last-seen time moves to the signal's time and
// its severity is raised to the signal's when that one is higher.
func (s *Store) AttachSignal(signalID int64, incidentID string) error {
	return s.tx(func(tx *sql.Tx) error {
		return attachSignal(tx, signalID, incidentID, s.now())
	})
}

// RecordSignal inserts a signal and attaches it to the incident in one
// transaction.
func (s *Store) RecordSignal(sig model.Signal, incidentID string) (int64, error) {
	var id int64
	err := s.tx(func(tx *sql.Tx) error {
		var err error
		if id, err = insertSignal(tx, sig, s.signalTime(sig)); err != nil {
			return err
		}
		return attachSignal(tx, id, incidentID, s.now())
	})
	return id, err
}

func (s *Store) signalTime(sig model.Signal) time.Time {
	if sig.At.IsZero() {
		return s.now()
	}
	return sig.At
}

// ListSignals returns the signals attached to an incident, oldest first.
func (s *Store) ListSignals(incidentID string) ([]SignalRecord, error) {
	rows, err := s.db.Query(`SELECT id, incident_id, project, source, fingerprint, severity, summary, fields, at
		FROM signals WHERE incident_id = ? ORDER BY id ASC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignalRecord
	for rows.Next() {
		var (
			r          SignalRecord
			inc        sql.NullString
			sev        int
			fields, at string
		)
		if err := rows.Scan(&r.ID, &inc, &r.Project, &r.Source, &r.Fingerprint, &sev, &r.Summary, &fields, &at); err != nil {
			return nil, err
		}
		r.IncidentID = inc.String
		r.Severity = model.Severity(sev)
		r.At = parseTime(at)
		if err := json.Unmarshal([]byte(fields), &r.Fields); err != nil {
			return nil, fmt.Errorf("store: signal %d fields: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---------- runs ----------

// StartRun records the start of an agent pass. The run has an empty Status
// until FinishRun.
func (s *Store) StartRun(incidentID, seat string) (model.Run, error) {
	now := s.now().UTC().Truncate(time.Second)
	res, err := s.db.Exec(`INSERT INTO runs (incident_id, seat, started_at) VALUES (?, ?, ?)`,
		incidentID, seat, fmtTime(now))
	if err != nil {
		return model.Run{}, fmt.Errorf("store: start run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Run{}, err
	}
	return model.Run{ID: id, IncidentID: incidentID, Seat: seat, StartedAt: now}, nil
}

// FinishRun records the result of a pass: status, verdict (as JSON), error,
// cost and token counts. A run can be finished only once.
func (s *Store) FinishRun(id int64, res model.RunResult) error {
	if res.Status == "" {
		return errors.New("store: finish run: empty status")
	}
	verdict := ""
	if res.Verdict != nil {
		b, err := json.Marshal(res.Verdict)
		if err != nil {
			return err
		}
		verdict = string(b)
	}
	r, err := s.db.Exec(`UPDATE runs SET status = ?, ended_at = ?, verdict = ?, error = ?, cost_usd = ?,
		turns = ?, input_tok = ?, output_tok = ? WHERE id = ? AND status = ''`,
		string(res.Status), fmtTime(s.now()), verdict, res.Error, res.CostUSD, res.Turns, res.InputTok, res.OutputTok, id)
	if err != nil {
		return fmt.Errorf("store: finish run: %w", err)
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("store: finish run %d: %w (unknown or already finished)", id, ErrNotFound)
	}
	return nil
}

// ListRuns returns the passes of an incident, oldest first.
func (s *Store) ListRuns(incidentID string) ([]model.Run, error) {
	rows, err := s.db.Query(`SELECT id, incident_id, seat, started_at, ended_at, status, verdict, error,
		cost_usd, turns, input_tok, output_tok FROM runs WHERE incident_id = ? ORDER BY id ASC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Run
	for rows.Next() {
		var (
			r                               model.Run
			started, ended, status, verdict string
		)
		if err := rows.Scan(&r.ID, &r.IncidentID, &r.Seat, &started, &ended, &status, &verdict, &r.Error,
			&r.CostUSD, &r.Turns, &r.InputTok, &r.OutputTok); err != nil {
			return nil, err
		}
		r.StartedAt, r.EndedAt, r.Status = parseTime(started), parseTime(ended), model.RunStatus(status)
		if verdict != "" {
			var v model.Verdict
			if err := json.Unmarshal([]byte(verdict), &v); err != nil {
				return nil, fmt.Errorf("store: run %d verdict: %w", r.ID, err)
			}
			r.Verdict = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRunsBySeat counts the unfinished runs per seat.
func (s *Store) ActiveRunsBySeat() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT seat, COUNT(*) FROM runs WHERE status = '' GROUP BY seat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var (
			seat string
			n    int
		)
		if err := rows.Scan(&seat, &n); err != nil {
			return nil, err
		}
		out[seat] = n
	}
	return out, rows.Err()
}

// SeatLastUsed returns, per seat, when its most recent run started (the
// dispatcher picks the least recently used seat).
func (s *Store) SeatLastUsed() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT seat, MAX(started_at) FROM runs GROUP BY seat`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var seat, at string
		if err := rows.Scan(&seat, &at); err != nil {
			return nil, err
		}
		out[seat] = parseTime(at)
	}
	return out, rows.Err()
}

// ---------- actions (optional log) ----------

// ActionRecord is one action an agent reported having run.
type ActionRecord struct {
	ID         int64
	IncidentID string
	RunID      int64
	Name       string
	At         time.Time
}

// RecordAction logs an action reported by a run (runID 0 = unknown).
func (s *Store) RecordAction(incidentID string, runID int64, name string) error {
	_, err := s.db.Exec(`INSERT INTO actions (incident_id, run_id, name, at) VALUES (?, ?, ?, ?)`,
		incidentID, runID, name, fmtTime(s.now()))
	return err
}

// ListActions returns the logged actions of an incident, oldest first.
func (s *Store) ListActions(incidentID string) ([]ActionRecord, error) {
	rows, err := s.db.Query(`SELECT id, incident_id, run_id, name, at FROM actions WHERE incident_id = ? ORDER BY id`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionRecord
	for rows.Next() {
		var (
			a  ActionRecord
			at string
		)
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.RunID, &a.Name, &at); err != nil {
			return nil, err
		}
		a.At = parseTime(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- known problems ----------

const knownProblemCols = `id, project, family, repo, mr_url, mr_id, incident, opened_at, closed_at`

func scanKnownProblem(sc scanner) (model.KnownProblem, error) {
	var (
		k              model.KnownProblem
		opened, closed string
	)
	err := sc.Scan(&k.ID, &k.Project, &k.Family, &k.Repo, &k.MRURL, &k.MRID, &k.Incident, &opened, &closed)
	k.OpenedAt, k.ClosedAt = parseTime(opened), parseTime(closed)
	return k, err
}

// OpenKnownProblem records an open merge request for an incident family.
// ID and OpenedAt (when zero) are set by the store.
func (s *Store) OpenKnownProblem(k model.KnownProblem) (model.KnownProblem, error) {
	if k.OpenedAt.IsZero() {
		k.OpenedAt = s.now()
	}
	k.OpenedAt = normTime(k.OpenedAt)
	k.ClosedAt = time.Time{}
	res, err := s.db.Exec(`INSERT INTO known_problems (project, family, repo, mr_url, mr_id, incident, opened_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, k.Project, k.Family, k.Repo, k.MRURL, k.MRID, k.Incident, fmtTime(k.OpenedAt))
	if err != nil {
		return k, fmt.Errorf("store: open known problem: %w", err)
	}
	k.ID, err = res.LastInsertId()
	return k, err
}

// FindOpenKnownProblem returns the oldest open known problem of a family,
// or nil when there is none.
func (s *Store) FindOpenKnownProblem(project, family string) (*model.KnownProblem, error) {
	k, err := scanKnownProblem(s.db.QueryRow(`SELECT `+knownProblemCols+` FROM known_problems
		WHERE project = ? AND family = ? AND closed_at = '' ORDER BY id ASC LIMIT 1`, project, family))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListOpenKnownProblems returns the open known problems of a project
// ("" = all), oldest first.
func (s *Store) ListOpenKnownProblems(project string) ([]model.KnownProblem, error) {
	rows, err := s.db.Query(`SELECT `+knownProblemCols+` FROM known_problems
		WHERE closed_at = '' AND (? = '' OR project = ?) ORDER BY id ASC`, project, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.KnownProblem
	for rows.Next() {
		k, err := scanKnownProblem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CloseKnownProblem closes a known problem (its merge request was merged or
// closed). Closing twice is not an error.
func (s *Store) CloseKnownProblem(id int64) error {
	res, err := s.db.Exec(`UPDATE known_problems SET closed_at = CASE WHEN closed_at = '' THEN ? ELSE closed_at END
		WHERE id = ?`, fmtTime(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- alerts ----------

// RecordAlert stores a sent alert or notice (a zero At becomes now). When
// it concerns an incident and is a real alert (not a notice), the incident's
// LastAlertAt moves to the alert's time, which restarts the reminder delay.
func (s *Store) RecordAlert(a model.Alert) (int64, error) {
	if a.At.IsZero() {
		a.At = s.now()
	}
	var id int64
	err := s.tx(func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO alerts (kind, project, incident, title, body, url, at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			string(a.Kind), a.Project, a.Incident, a.Title, a.Body, a.URL, fmtTime(a.At))
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		if a.Incident == "" || a.Kind == model.NoticeMROpened || a.Kind == model.NoticeConfigMR {
			return nil
		}
		_, err = tx.Exec(`UPDATE incidents SET last_alert_at = MAX(last_alert_at, ?) WHERE id = ?`, fmtTime(a.At), a.Incident)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("store: record alert: %w", err)
	}
	return id, nil
}

func (s *Store) lastAlert(where string, args ...any) (*model.Alert, error) {
	var (
		a        model.Alert
		kind, at string
	)
	err := s.db.QueryRow(`SELECT kind, project, incident, title, body, url, at FROM alerts WHERE `+where+
		` ORDER BY id DESC LIMIT 1`, args...).Scan(&kind, &a.Project, &a.Incident, &a.Title, &a.Body, &a.URL, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.Kind, a.At = model.AlertKind(kind), parseTime(at)
	return &a, nil
}

// LastAlert returns the most recent alert of a kind for an incident, or nil.
func (s *Store) LastAlert(incidentID string, kind model.AlertKind) (*model.Alert, error) {
	return s.lastAlert(`incident = ? AND kind = ?`, incidentID, string(kind))
}

// LastSystemAlert returns the most recent alert of a kind that is not tied
// to an incident (capacity, locks down, seat expiry) for a project ("" for
// alerts without a project), or nil.
func (s *Store) LastSystemAlert(project string, kind model.AlertKind) (*model.Alert, error) {
	return s.lastAlert(`incident = '' AND project = ? AND kind = ?`, project, string(kind))
}

// ---------- proposals (config merge requests) ----------

// Proposal kinds.
const (
	ProposalImprovement   = "improvement"
	ProposalMissingAction = "missing_action"
)

// Proposal is a merge request opened on the configuration repository.
type Proposal struct {
	ID        int64
	Project   string
	Incident  string
	Kind      string // ProposalImprovement | ProposalMissingAction
	Title     string
	MRURL     string
	MRID      string
	State     string // "open" | "merged" | "closed"
	CreatedAt time.Time
}

// RecordProposal stores a proposal; ID, CreatedAt (when zero) and State
// (default "open") are set by the store.
func (s *Store) RecordProposal(p Proposal) (Proposal, error) {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = s.now()
	}
	p.CreatedAt = normTime(p.CreatedAt)
	if p.State == "" {
		p.State = "open"
	}
	res, err := s.db.Exec(`INSERT INTO proposals (project, incident, kind, title, mr_url, mr_id, state, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, p.Project, p.Incident, p.Kind, p.Title, p.MRURL, p.MRID, p.State, fmtTime(p.CreatedAt))
	if err != nil {
		return p, fmt.Errorf("store: record proposal: %w", err)
	}
	p.ID, err = res.LastInsertId()
	return p, err
}

// SetProposalState updates the state of a proposal.
func (s *Store) SetProposalState(id int64, state string) error {
	res, err := s.db.Exec(`UPDATE proposals SET state = ? WHERE id = ?`, state, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListProposals returns the proposals of a project ("" = all), oldest
// first; openOnly keeps those still in state "open".
func (s *Store) ListProposals(project string, openOnly bool) ([]Proposal, error) {
	rows, err := s.db.Query(`SELECT id, project, incident, kind, title, mr_url, mr_id, state, created_at FROM proposals
		WHERE (? = '' OR project = ?) AND (? = 0 OR state = 'open') ORDER BY id ASC`, project, project, boolInt(openOnly))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		var (
			p  Proposal
			at string
		)
		if err := rows.Scan(&p.ID, &p.Project, &p.Incident, &p.Kind, &p.Title, &p.MRURL, &p.MRID, &p.State, &at); err != nil {
			return nil, err
		}
		p.CreatedAt = parseTime(at)
		out = append(out, p)
	}
	return out, rows.Err()
}
