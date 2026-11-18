// Package incident is the deterministic lifecycle of an incident on top of
// the store: ingestion of signals (dedup, storm guard, recurrence), the
// mapping of agent verdicts and run failures to states, rechecks, green
// lights and the human close / resume commands. It runs no agent and does
// no network I/O: every method returns what the caller has to do next
// (alert to send, merge request to open, ticket to withdraw).
package incident

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// Defaults used when the configuration leaves a value at zero.
const (
	// DefaultRecheck is the delay of a "recheck" verdict that gives no
	// delay when the runbook has no default either.
	DefaultRecheck = 15 * time.Minute
	// DefaultReminderEvery is the reminder interval when Limits.ReminderEvery is zero.
	DefaultReminderEvery = 24 * time.Hour
	// MaxFailedRuns is the number of consecutive failed passes (crash,
	// timeout, no valid verdict) after which the incident is escalated:
	// the first failure is retried once.
	MaxFailedRuns = 2
)

// Close reasons written by the core.
const (
	ReasonConditionCleared = "condition cleared"
	ReasonResolvedByAgent  = "resolved by agent"
	ReasonClosedByHuman    = "closed by human"
)

// MassSuffix is appended to the source to build the fingerprint of the
// storm guard incident: "<source>:mass".
const MassSuffix = ":mass"

// IngestKind tells what Ingest did with a signal.
type IngestKind string

const (
	IngestCreated      IngestKind = "created"       // new incident, queued
	IngestAttached     IngestKind = "attached"      // same fingerprint as an open incident
	IngestMassCreated  IngestKind = "mass_created"  // storm guard tripped: mass incident created, escalated
	IngestMassAttached IngestKind = "mass_attached" // new fingerprint during a storm: attached to the mass incident
)

// IngestResult is the outcome of Ingest.
type IngestResult struct {
	Kind     IngestKind
	Incident model.Incident
	// Alert is the alert the caller must send: AlertStorm when the mass
	// incident was just created, "" otherwise.
	Alert model.AlertKind
}

// Transition is the result of a lifecycle step: the incident after the
// step and the side effects the caller owes.
type Transition struct {
	Incident model.Incident // as stored after the step
	From, To model.IncidentState
	Reason   string // short human explanation, also written to the journal

	// Alert is the alert or notice to send, "" for none.
	Alert model.AlertKind
	// OpenMR is the merge request to open on a project repository.
	OpenMR *model.MRProposal
	// KnownProblem is set with OpenMR when the incident is resolved: the
	// caller records the opened merge request as a known problem.
	KnownProblem bool
	// MissingAction and Improvement are merge requests to open on the
	// configuration repository.
	MissingAction *model.MissingAction
	Improvement   *model.Improvement
	// RecheckAt is when the deterministic check is replayed (state waiting).
	RecheckAt time.Time
	// WithdrawTicket is a pending green-light ticket to withdraw at the hub.
	WithdrawTicket string
}

// Changed reports whether the step moved the incident to another state.
func (t Transition) Changed() bool { return t.From != t.To }

// Manager applies the lifecycle. Build it with NewManager; it is safe for
// concurrent use.
type Manager struct {
	st      *store.Store
	now     func() time.Time
	limits  func(project string) model.Limits
	dossier *Dossier
	ingest  sync.Mutex // serialises Ingest: find-then-create must not interleave
}

// Option configures a Manager.
type Option func(*Manager)

// WithDossier makes the manager write incident.json and the journal of
// every incident it touches.
func WithDossier(d *Dossier) Option { return func(m *Manager) { m.dossier = d } }

// NewManager builds a manager from the store, a clock (nil = time.Now) and
// a lookup of the limits of a project (nil = zero limits), used by the
// methods that do not receive limits (DueReminders).
func NewManager(st *store.Store, now func() time.Time, limits func(project string) model.Limits, opts ...Option) *Manager {
	if now == nil {
		now = time.Now
	}
	if limits == nil {
		limits = func(string) model.Limits { return model.Limits{} }
	}
	m := &Manager{st: st, now: now, limits: limits}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Dossier returns the dossier writer, nil when none was configured.
func (m *Manager) Dossier() *Dossier { return m.dossier }

func newAgentToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Ingest turns one signal into incident state:
//
//   - an open incident has the same project and fingerprint: the signal is
//     attached to it (count, last seen), nothing is queued;
//   - the storm guard is tripped (limits.MaxOpenPerCheck > 0 and that many
//     incidents are open for the project and source, or a mass incident is
//     already open): the signal goes to the single mass incident
//     ("<source>:mass", escalated), created if needed;
//   - otherwise a new incident is created and queued, marked Recurrent when
//     at least limits.RecurrenceCount incidents of the family were resolved
//     within limits.RecurrenceWindow.
//
// family is the fingerprint without its variable part and runbook the id
// of the matching runbook; both are stored on a created incident.
func (m *Manager) Ingest(sig model.Signal, limits model.Limits, family string, runbook string) (IngestResult, error) {
	if sig.Project == "" || sig.Source == "" || sig.Fingerprint == "" {
		return IngestResult{}, errors.New("incident: a signal needs a project, a source and a fingerprint")
	}
	if sig.At.IsZero() {
		sig.At = m.now()
	}
	m.ingest.Lock()
	defer m.ingest.Unlock()

	// A concurrent writer outside this manager can create the incident
	// between the lookup and the insert; the unique index reports it and
	// the second round attaches.
	for attempt := 0; ; attempt++ {
		res, err := m.ingestOnce(sig, limits, family, runbook)
		if errors.Is(err, store.ErrDuplicateOpen) && attempt == 0 {
			continue
		}
		return res, err
	}
}

func (m *Manager) ingestOnce(sig model.Signal, limits model.Limits, family, runbook string) (IngestResult, error) {
	attach := func(inc *model.Incident, kind IngestKind) (IngestResult, error) {
		if _, err := m.st.RecordSignal(sig, inc.ID); err != nil {
			return IngestResult{}, err
		}
		cur, err := m.st.GetIncident(inc.ID)
		return IngestResult{Kind: kind, Incident: cur}, err
	}

	open, err := m.st.FindOpenIncident(sig.Project, sig.Fingerprint)
	if err != nil {
		return IngestResult{}, err
	}
	if open != nil {
		return attach(open, IngestAttached)
	}

	token, err := newAgentToken()
	if err != nil {
		return IngestResult{}, fmt.Errorf("incident: agent token: %w", err)
	}

	if limits.MaxOpenPerCheck > 0 {
		massFP := sig.Source + MassSuffix
		mass, err := m.st.FindOpenIncident(sig.Project, massFP)
		if err != nil {
			return IngestResult{}, err
		}
		if mass != nil {
			return attach(mass, IngestMassAttached)
		}
		n, err := m.st.CountOpenIncidents(sig.Project, sig.Source)
		if err != nil {
			return IngestResult{}, err
		}
		if n >= limits.MaxOpenPerCheck {
			inc, err := m.create(model.Incident{
				Project: sig.Project, Source: sig.Source, Fingerprint: massFP, Family: sig.Source,
				Severity: sig.Severity, State: model.StateEscalated, Mass: true, Runbook: runbook,
				Summary:    fmt.Sprintf("Storm on %s: %d incidents already open, new signals are grouped here", sig.Source, n),
				AgentToken: token, OpenedAt: sig.At,
			}, sig)
			if err != nil && !errors.Is(err, ErrDossier) {
				return IngestResult{}, err
			}
			return IngestResult{Kind: IngestMassCreated, Incident: inc, Alert: model.AlertStorm}, err
		}
	}

	recurrent := false
	if limits.RecurrenceCount > 0 && limits.RecurrenceWindow > 0 && family != "" {
		n, err := m.st.CountResolvedByFamily(sig.Project, family, m.now().Add(-limits.RecurrenceWindow))
		if err != nil {
			return IngestResult{}, err
		}
		recurrent = n >= limits.RecurrenceCount
	}
	inc, err := m.create(model.Incident{
		Project: sig.Project, Source: sig.Source, Fingerprint: sig.Fingerprint, Family: family,
		Severity: sig.Severity, Summary: sig.Summary, State: model.StateQueued, Recurrent: recurrent,
		Runbook: runbook, AgentToken: token, OpenedAt: sig.At,
	}, sig)
	if err != nil && !errors.Is(err, ErrDossier) {
		return IngestResult{}, err
	}
	return IngestResult{Kind: IngestCreated, Incident: inc}, err
}

// create stores the incident with its origin signal and starts its dossier.
// A dossier failure is returned with the created incident.
func (m *Manager) create(inc model.Incident, sig model.Signal) (model.Incident, error) {
	created, err := m.st.CreateIncident(inc)
	if err != nil {
		return model.Incident{}, err
	}
	if _, err := m.st.RecordSignal(sig, created.ID); err != nil {
		return model.Incident{}, err
	}
	created, err = m.st.GetIncident(created.ID)
	if err != nil {
		return model.Incident{}, err
	}
	if m.dossier == nil {
		return created, nil
	}
	if err := m.dossier.Init(created, sig); err != nil {
		return created, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n- source: `%s`\n- fingerprint: `%s`\n- severity: %d\n", sig.Summary, sig.Source, sig.Fingerprint, sig.Severity)
	if created.Recurrent {
		b.WriteString("- recurrent: incidents of this family were resolved several times recently\n")
	}
	if created.Mass {
		fmt.Fprintf(&b, "- storm guard: %s\n", created.Summary)
	}
	fmt.Fprintf(&b, "- state: %s\n", created.State)
	return created, m.dossier.Append(created.ID, created.OpenedAt, "signal", b.String())
}

func (m *Manager) journal(id, title, body string) error {
	if m.dossier == nil {
		return nil
	}
	return m.dossier.Append(id, m.now(), title, body)
}

func stateLine(tr Transition) string {
	s := fmt.Sprintf("State: %s → %s", tr.From, tr.To)
	if !tr.Changed() {
		s = fmt.Sprintf("State unchanged: %s", tr.To)
	}
	if tr.Reason != "" {
		s += " (" + tr.Reason + ")"
	}
	if !tr.RecheckAt.IsZero() {
		s += ", recheck at " + stamp(tr.RecheckAt)
	}
	return s + "."
}

// decision is the pure outcome of a verdict, before it is stored.
type decision struct {
	state       model.IncidentState
	reason      string
	closeReason string
	ticket      string
	recheckAt   time.Time
	alert       model.AlertKind
	openMR      *model.MRProposal
	known       bool
}

func maxRuns(rb model.Runbook, limits model.Limits) int {
	if rb.MaxRuns > 0 {
		return rb.MaxRuns
	}
	return limits.MaxRunsPerIncident
}

// decide maps a verdict to the next state. inc.Runs already counts the
// pass that produced the verdict.
func decide(inc model.Incident, v model.Verdict, rb model.Runbook, limits model.Limits, now time.Time) decision {
	d := decision{openMR: v.MR}
	escalate := func(reason string) {
		d.state, d.reason, d.alert = model.StateEscalated, reason, model.AlertEscalated
	}
	switch v.Outcome {
	case model.OutcomeResolved:
		d.state, d.closeReason, d.reason = model.StateResolved, ReasonResolvedByAgent, ReasonResolvedByAgent
		if v.MR != nil {
			// Unblocked by an action and a fix proposed: the incident
			// is closed, the merge request lives on as a known problem.
			d.known, d.alert = true, model.NoticeMROpened
		}
		return d
	case model.OutcomeRecheck:
		switch limit := maxRuns(rb, limits); {
		case limit > 0 && inc.Runs >= limit:
			escalate(fmt.Sprintf("maximum of %d passes reached", limit))
		case limits.MaxIncidentAge > 0 && now.Sub(inc.OpenedAt) >= limits.MaxIncidentAge:
			escalate(fmt.Sprintf("maximum incident age of %s reached", limits.MaxIncidentAge))
		default:
			delay := time.Duration(v.RecheckMinutes) * time.Minute
			if delay <= 0 {
				delay = rb.RecheckDefault
			}
			if delay <= 0 {
				delay = DefaultRecheck
			}
			d.state, d.recheckAt, d.reason = model.StateWaiting, now.Add(delay), "agent asked for a recheck"
		}
	case model.OutcomeGreenLight:
		if strings.TrimSpace(v.Ticket) == "" {
			escalate("green light asked without a ticket")
			break
		}
		// The ticket must be followed to its decision whatever else the
		// verdict carries: the incident waits in green_light even with a
		// merge request (which the caller still opens).
		d.state, d.ticket, d.alert, d.reason = model.StateGreenLight, strings.TrimSpace(v.Ticket), model.AlertGreenLight, "waiting for a human decision on the ticket"
		return d
	case model.OutcomeEscalate:
		escalate("agent escalated")
	case model.OutcomeBlocked:
		// A missing action needs a human hand: the incident stays
		// blocked (and alerts) even with a merge request.
		d.state, d.alert, d.reason = model.StateBlocked, model.AlertBlocked, "an action is missing from the catalogue"
		return d
	default:
		escalate(fmt.Sprintf("unknown verdict outcome %q", v.Outcome))
		return d
	}
	if v.MR != nil {
		// Production is still affected and a fix is proposed.
		d.state, d.alert, d.recheckAt = model.StateMROpen, model.NoticeMROpened, time.Time{}
		d.reason = strings.TrimSpace("fix proposed, production still affected; " + d.reason)
	}
	return d
}

// ApplyVerdict records the valid verdict of a finished pass on an incident
// in investigating and moves it to its next state:
//
//	resolved     → resolved (with a merge request: still resolved, the MR
//	               is a known problem the caller records)
//	recheck      → waiting until now + RecheckMinutes (runbook default,
//	               then DefaultRecheck); escalated when the pass count
//	               (runbook MaxRuns, else limits.MaxRunsPerIncident) or
//	               limits.MaxIncidentAge is reached
//	green_light  → green_light with the ticket; escalated without a ticket
//	escalate     → escalated
//	blocked      → blocked
//
// A recheck or escalate verdict that carries a merge request gives mr_open
// instead. The pass is counted (Runs) and the failure counter is cleared.
// An error wrapping ErrDossier means the transition is stored but the
// journal could not be written.
func (m *Manager) ApplyVerdict(inc model.Incident, v model.Verdict, rb model.Runbook, limits model.Limits) (Transition, error) {
	now := m.now()
	var d decision
	updated, err := m.st.UpdateIncident(inc.ID, []model.IncidentState{model.StateInvestigating}, func(i *model.Incident) error {
		i.Runs++
		d = decide(*i, v, rb, limits, now)
		i.State, i.Ticket, i.RecheckAt, i.CloseReason = d.state, d.ticket, d.recheckAt, d.closeReason
		return nil
	})
	if err != nil {
		return Transition{}, err
	}
	if err := m.st.ResetFailures(inc.ID); err != nil {
		return Transition{}, err
	}
	tr := Transition{
		Incident: updated, From: model.StateInvestigating, To: d.state, Reason: d.reason, Alert: d.alert,
		OpenMR: d.openMR, KnownProblem: d.known, MissingAction: v.MissingAction, Improvement: v.Improvement,
		RecheckAt: updated.RecheckAt,
	}
	return tr, m.journal(inc.ID, fmt.Sprintf("pass %d: verdict %s", updated.Runs, v.Outcome), verdictEntry(v, tr))
}

func verdictEntry(v model.Verdict, tr Transition) string {
	var b strings.Builder
	if s := strings.TrimSpace(v.Summary); s != "" {
		b.WriteString(s + "\n\n")
	}
	if s := strings.TrimSpace(v.RootCause); s != "" {
		b.WriteString("**Root cause:** " + s + "\n\n")
	}
	if len(v.Evidence) > 0 {
		b.WriteString("**Evidence:**\n\n")
		for _, e := range v.Evidence {
			b.WriteString("- " + strings.ReplaceAll(strings.TrimSpace(e), "\n", "\n  ") + "\n")
		}
		b.WriteString("\n")
	}
	if len(v.ActionsRun) > 0 {
		b.WriteString("**Actions run:** " + strings.Join(v.ActionsRun, ", ") + "\n\n")
	}
	if v.Ticket != "" {
		b.WriteString("**Ticket:** " + oneLine(v.Ticket) + "\n\n")
	}
	if v.MR != nil {
		fmt.Fprintf(&b, "**Merge request proposed** on %s: %s\n\n", oneLine(v.MR.Repo), oneLine(v.MR.Title))
	}
	if v.MissingAction != nil {
		fmt.Fprintf(&b, "**Missing action:** %s. %s\n\n", oneLine(v.MissingAction.Name), oneLine(v.MissingAction.Why))
	}
	if v.Improvement != nil {
		fmt.Fprintf(&b, "**Configuration improvement proposed:** %s\n\n", oneLine(v.Improvement.Title))
	}
	if v.Confidence != "" {
		b.WriteString("**Confidence:** " + oneLine(v.Confidence) + "\n\n")
	}
	b.WriteString(stateLine(tr))
	return b.String()
}

// expect reads the incident and checks that it is in one of the states.
func (m *Manager) expect(id string, states []model.IncidentState) (model.Incident, error) {
	cur, err := m.st.GetIncident(id)
	if err != nil {
		return cur, err
	}
	for _, st := range states {
		if cur.State == st {
			return cur, nil
		}
	}
	return cur, fmt.Errorf("%w: %s is %s", store.ErrStateConflict, cur.ID, cur.State)
}

// step applies a simple transition and journals it.
func (m *Manager) step(id string, from []model.IncidentState, title string, fn func(i *model.Incident, tr *Transition) error) (Transition, error) {
	var tr Transition
	updated, err := m.st.UpdateIncident(id, from, func(i *model.Incident) error {
		tr = Transition{From: i.State}
		if err := fn(i, &tr); err != nil {
			return err
		}
		tr.To = i.State
		return nil
	})
	if err != nil {
		return Transition{}, err
	}
	tr.Incident = updated
	tr.RecheckAt = updated.RecheckAt
	return tr, m.journal(id, title, stateLine(tr))
}

func escalated(i *model.Incident, tr *Transition, reason string) {
	i.State, i.RecheckAt = model.StateEscalated, time.Time{}
	tr.Reason, tr.Alert = reason, model.AlertEscalated
}

// RunFailed handles a pass that ended without a valid verdict, on an
// incident in investigating:
//
//   - quota (seat exhausted) or cancelled: back to queued, the pass is not
//     counted;
//   - failed or timeout: the pass is counted; the first failure goes back
//     to queued for one retry, the second consecutive one escalates, and so
//     does reaching limits.MaxRunsPerIncident or limits.MaxIncidentAge.
func (m *Manager) RunFailed(inc model.Incident, status model.RunStatus, limits model.Limits) (Transition, error) {
	from := []model.IncidentState{model.StateInvestigating}
	title := "pass ended: " + string(status)
	switch status {
	case model.RunQuota, model.RunCancelled:
		return m.step(inc.ID, from, title, func(i *model.Incident, tr *Transition) error {
			i.State = model.StateQueued
			tr.Reason = "pass not counted, queued for another seat"
			if status == model.RunCancelled {
				tr.Reason = "pass cancelled, not counted"
			}
			return nil
		})
	case model.RunFailed, model.RunTimeout:
		// The incident is owned by the worker that calls us (it is in
		// investigating), so the counter and the state need no common
		// transaction.
		if _, err := m.expect(inc.ID, from); err != nil {
			return Transition{}, err
		}
		failures, err := m.st.IncrementFailures(inc.ID)
		if err != nil {
			return Transition{}, err
		}
		now := m.now()
		return m.step(inc.ID, from, title, func(i *model.Incident, tr *Transition) error {
			i.Runs++
			switch {
			case failures >= MaxFailedRuns:
				escalated(i, tr, fmt.Sprintf("%d consecutive failed passes", failures))
			case limits.MaxRunsPerIncident > 0 && i.Runs >= limits.MaxRunsPerIncident:
				escalated(i, tr, fmt.Sprintf("maximum of %d passes reached", limits.MaxRunsPerIncident))
			case limits.MaxIncidentAge > 0 && now.Sub(i.OpenedAt) >= limits.MaxIncidentAge:
				escalated(i, tr, fmt.Sprintf("maximum incident age of %s reached", limits.MaxIncidentAge))
			default:
				i.State = model.StateQueued
				tr.Reason = "pass failed, one retry"
			}
			return nil
		})
	default:
		return Transition{}, fmt.Errorf("incident: RunFailed called with status %q", status)
	}
}

// Recheck records the result of replaying the deterministic check:
//
//   - waiting: condition cleared → resolved ("condition cleared"), still
//     firing → queued for a new pass;
//   - escalated, blocked, mr_open: condition cleared → resolved, still
//     firing → unchanged.
//
// Any other state returns store.ErrStateConflict.
func (m *Manager) Recheck(inc model.Incident, stillFiring bool) (Transition, error) {
	from := []model.IncidentState{model.StateWaiting, model.StateEscalated, model.StateBlocked, model.StateMROpen}
	title := "recheck: condition cleared"
	if stillFiring {
		title = "recheck: still firing"
	}
	cur, err := m.expect(inc.ID, from)
	if err != nil {
		return Transition{}, err
	}
	if stillFiring && cur.State != model.StateWaiting {
		// Nothing to store and nothing worth a journal line each time
		// the check is replayed.
		return Transition{Incident: cur, From: cur.State, To: cur.State, Reason: "condition still present"}, nil
	}
	return m.step(inc.ID, from, title, func(i *model.Incident, tr *Transition) error {
		switch {
		case !stillFiring:
			i.State, i.CloseReason, i.RecheckAt = model.StateResolved, ReasonConditionCleared, time.Time{}
			tr.Reason = ReasonConditionCleared
		case i.State == model.StateWaiting:
			i.State, i.RecheckAt = model.StateQueued, time.Time{}
			tr.Reason = "condition still present, new pass"
		}
		return nil
	})
}

// GreenLightDecided records the decision read at the hub for the ticket of
// an incident in green_light: approved (or already consumed) → queued, the
// next pass replays the command with the ticket, which stays on the
// incident; denied, expired or withdrawn → escalated. Pending and unknown
// change nothing.
func (m *Manager) GreenLightDecided(inc model.Incident, state model.TicketState) (Transition, error) {
	from := []model.IncidentState{model.StateGreenLight}
	switch state {
	case model.TicketApproved, model.TicketConsumed:
		return m.step(inc.ID, from, "green light: "+string(state), func(i *model.Incident, tr *Transition) error {
			i.State = model.StateQueued
			tr.Reason = "ticket " + i.Ticket + " " + string(state) + ", new pass replays it"
			return nil
		})
	case model.TicketDenied, model.TicketExpired, model.TicketWithdrawn:
		return m.step(inc.ID, from, "green light: "+string(state), func(i *model.Incident, tr *Transition) error {
			escalated(i, tr, "ticket "+i.Ticket+" "+string(state))
			i.Ticket = ""
			return nil
		})
	case model.TicketPending, model.TicketUnknown:
		cur, err := m.expect(inc.ID, from)
		if err != nil {
			return Transition{}, err
		}
		return Transition{Incident: cur, From: cur.State, To: cur.State, Reason: "ticket " + string(state)}, nil
	default:
		return Transition{}, fmt.Errorf("incident: unknown ticket state %q", state)
	}
}

// GreenLightTimedOut escalates an incident whose ticket got no decision
// within limits.GreenLightTimeout; the caller withdraws the ticket
// (Transition.WithdrawTicket).
func (m *Manager) GreenLightTimedOut(inc model.Incident) (Transition, error) {
	return m.step(inc.ID, []model.IncidentState{model.StateGreenLight}, "green light: timed out", func(i *model.Incident, tr *Transition) error {
		tr.WithdrawTicket = i.Ticket
		escalated(i, tr, "no decision on ticket "+i.Ticket+" in time")
		i.Ticket = ""
		return nil
	})
}

// Close resolves an open incident on a human decision (dutydesk incident
// close). An empty reason becomes "closed by human". A pending green-light
// ticket is returned in WithdrawTicket.
func (m *Manager) Close(id, reason string) (Transition, error) {
	reason = oneLine(reason)
	if reason == "" {
		reason = ReasonClosedByHuman
	}
	from := []model.IncidentState{model.StateQueued, model.StateInvestigating, model.StateWaiting, model.StateGreenLight,
		model.StateMROpen, model.StateEscalated, model.StateBlocked}
	return m.step(id, from, "closed by a human", func(i *model.Incident, tr *Transition) error {
		if i.State == model.StateGreenLight {
			tr.WithdrawTicket = i.Ticket
		}
		i.State, i.CloseReason, i.RecheckAt, i.Ticket = model.StateResolved, reason, time.Time{}, ""
		tr.Reason = reason
		return nil
	})
}

// Resume queues a new pass on a human decision (dutydesk incident resume)
// for an incident that is escalated, blocked, mr_open, waiting or
// green_light (its pending ticket is then returned in WithdrawTicket). The
// failure counter restarts.
func (m *Manager) Resume(id string) (Transition, error) {
	from := []model.IncidentState{model.StateEscalated, model.StateBlocked, model.StateMROpen, model.StateWaiting, model.StateGreenLight}
	tr, err := m.step(id, from, "resumed by a human", func(i *model.Incident, tr *Transition) error {
		if i.State == model.StateGreenLight {
			tr.WithdrawTicket = i.Ticket
		}
		i.State, i.RecheckAt, i.Ticket = model.StateQueued, time.Time{}, ""
		tr.Reason = "resumed by a human, new pass"
		return nil
	})
	if err != nil && !errors.Is(err, ErrDossier) {
		return tr, err
	}
	if rerr := m.st.ResetFailures(id); rerr != nil {
		return tr, rerr
	}
	return tr, err
}

// DueReminders returns the incidents that wait for a human (escalated,
// blocked, green_light) and were last alerted at least ReminderEvery ago,
// per the limits of their project (DefaultReminderEvery when zero). The
// caller sends an AlertReminder and records it in the store, which restarts
// the delay.
func (m *Manager) DueReminders() ([]model.Incident, error) {
	now := m.now()
	all, err := m.st.IncidentsNeedingReminder("", now)
	if err != nil {
		return nil, err
	}
	every := map[string]time.Duration{}
	var due []model.Incident
	for _, inc := range all {
		e, ok := every[inc.Project]
		if !ok {
			if e = m.limits(inc.Project).ReminderEvery; e <= 0 {
				e = DefaultReminderEvery
			}
			every[inc.Project] = e
		}
		last := inc.LastAlertAt
		if last.IsZero() {
			if last, err = m.st.StateSince(inc.ID); err != nil {
				return nil, err
			}
		}
		if !now.Before(last.Add(e)) {
			due = append(due, inc)
		}
	}
	return due, nil
}
