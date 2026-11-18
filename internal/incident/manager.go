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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
	// DefaultMaxGreenLights bounds the green-light rounds of one incident
	// when Limits.MaxGreenLights is zero.
	DefaultMaxGreenLights = 3
	// DefaultMaxQuotaRuns bounds the passes one incident may lose to an
	// exhausted seat when Limits.MaxQuotaRuns is zero.
	DefaultMaxQuotaRuns = 3
)

// Events name the lifecycle step an owed effect comes from.
const (
	EventVerdict    = "verdict"
	EventRunFailed  = "run_failed"
	EventGreenLight = "green_light"
	EventStorm      = "storm"
	EventRecurrence = "recurrence"
	EventAge        = "age"
	EventHuman      = "human"
)

// Owed is the payload of the outbox row (store.EffectTransition) a lifecycle
// step writes in the transaction of its state change: everything the core
// needs to execute the side effects later, even after a crash.
type Owed struct {
	Event  string              `json:"event"`
	From   model.IncidentState `json:"from,omitempty"`
	To     model.IncidentState `json:"to"`
	Reason string              `json:"reason,omitempty"`
	Alert  model.AlertKind     `json:"alert,omitempty"`
	// Verdict is the verdict the step applied (EventVerdict): its merge
	// request, missing action and improvement are still to be proposed.
	Verdict      *model.Verdict `json:"verdict,omitempty"`
	KnownProblem bool           `json:"known_problem,omitempty"`
	// WithdrawTicket is a ticket recorded on this incident to withdraw.
	WithdrawTicket string `json:"withdraw_ticket,omitempty"`
	// Detail is the error of a failed pass (already scrubbed by the caller).
	Detail string `json:"detail,omitempty"`
	// Context is opaque to this package: what the caller needs to run the
	// effects of a pass (clone directories, base commits).
	Context json.RawMessage `json:"context,omitempty"`
}

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
	// IngestRecurrent: the family used up its pass budget (RecurrenceCount
	// incidents resolved within RecurrenceWindow): the incident is created
	// escalated, a human is alerted and no agent runs.
	IngestRecurrent IngestKind = "recurrent"
)

// IngestResult is the outcome of Ingest.
type IngestResult struct {
	Kind     IngestKind
	Incident model.Incident
	// Alert is the alert that is owed (it is already in the outbox):
	// AlertStorm when the mass incident was just created, AlertEscalated
	// for IngestRecurrent, "" otherwise.
	Alert model.AlertKind
}

// Transition is the result of a lifecycle step: the incident after the
// step and the side effects it owes. The effects are not left to the
// caller's memory: the step stored them in the outbox (store.Effect, payload
// Owed) in the transaction of the state change.
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
//   - the family used up its pass budget (limits.RecurrenceCount incidents
//     of the family resolved within limits.RecurrenceWindow): the incident
//     is created escalated and marked Recurrent, a human is alerted and no
//     agent runs;
//   - otherwise a new incident is created and queued.
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
			}, sig, &Owed{Event: EventStorm, To: model.StateEscalated, Alert: model.AlertStorm})
			if err != nil && !errors.Is(err, ErrDossier) {
				return IngestResult{}, err
			}
			return IngestResult{Kind: IngestMassCreated, Incident: inc, Alert: model.AlertStorm}, err
		}
	}

	// Pass budget of the family: once RecurrenceCount incidents of the
	// family were resolved within RecurrenceWindow (by an agent verdict, by
	// a cleared condition or by a human), the next one is not handed to an
	// agent again. A condition that keeps coming back, or an agent that
	// keeps answering "resolved", costs a bounded number of passes and ends
	// in front of a human.
	if limits.RecurrenceCount > 0 && limits.RecurrenceWindow > 0 && family != "" {
		n, err := m.st.CountResolvedByFamily(sig.Project, family, m.now().Add(-limits.RecurrenceWindow))
		if err != nil {
			return IngestResult{}, err
		}
		if n >= limits.RecurrenceCount {
			reason := fmt.Sprintf("%d incidents of this family were resolved within %s: no agent pass, a human must look at the cause",
				n, limits.RecurrenceWindow)
			inc, err := m.create(model.Incident{
				Project: sig.Project, Source: sig.Source, Fingerprint: sig.Fingerprint, Family: family,
				Severity: sig.Severity, Summary: sig.Summary, State: model.StateEscalated, Recurrent: true,
				Runbook: runbook, AgentToken: token, OpenedAt: sig.At,
			}, sig, &Owed{Event: EventRecurrence, To: model.StateEscalated, Alert: model.AlertEscalated, Reason: reason})
			if err != nil && !errors.Is(err, ErrDossier) {
				return IngestResult{}, err
			}
			return IngestResult{Kind: IngestRecurrent, Incident: inc, Alert: model.AlertEscalated}, err
		}
	}
	inc, err := m.create(model.Incident{
		Project: sig.Project, Source: sig.Source, Fingerprint: sig.Fingerprint, Family: family,
		Severity: sig.Severity, Summary: sig.Summary, State: model.StateQueued,
		Runbook: runbook, AgentToken: token, OpenedAt: sig.At,
	}, sig, nil)
	if err != nil && !errors.Is(err, ErrDossier) {
		return IngestResult{}, err
	}
	return IngestResult{Kind: IngestCreated, Incident: inc}, err
}

func owedEffect(o Owed) (store.Effect, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return store.Effect{}, err
	}
	return store.Effect{Kind: store.EffectTransition, Payload: string(b)}, nil
}

// create stores the incident with its origin signal and the effect its
// creation owes, in one transaction, and starts its dossier. A dossier
// failure is returned with the created incident.
func (m *Manager) create(inc model.Incident, sig model.Signal, owed *Owed) (model.Incident, error) {
	var effects []store.Effect
	if owed != nil {
		e, err := owedEffect(*owed)
		if err != nil {
			return model.Incident{}, err
		}
		effects = append(effects, e)
	}
	created, err := m.st.OpenIncident(inc, sig, effects...)
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
	fmt.Fprintf(&b, "%s\n\n- source: `%s`\n- fingerprint: `%s`\n- severity: %d\n",
		Quote(sig.Summary), inline(sig.Source), inline(sig.Fingerprint), sig.Severity)
	if created.Recurrent {
		b.WriteString("- recurrent: incidents of this family were resolved several times recently\n")
	}
	if created.Mass {
		fmt.Fprintf(&b, "- storm guard: %s\n", inline(created.Summary))
	}
	if owed != nil && owed.Reason != "" {
		fmt.Fprintf(&b, "- %s\n", owed.Reason)
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

// ---------- verdicts ----------

// CheckState is what replaying the deterministic check of an incident said
// when the agent answered "resolved".
type CheckState int

const (
	// CheckNone: the incident has no deterministic check (a webhook
	// incident whose runbook names no recheck_check): the verdict stands.
	CheckNone CheckState = iota
	// CheckCleared: the check no longer sees the condition.
	CheckCleared
	// CheckFiring: the check still fires: "resolved" is not believed.
	CheckFiring
	// CheckUnknown: the check could not be replayed now (locks down, lock
	// error): "resolved" is not believed either, the check is replayed at
	// the wake-up.
	CheckUnknown
)

type verdictOpts struct {
	check   CheckState
	context json.RawMessage
}

// VerdictOption tunes ApplyVerdict.
type VerdictOption func(*verdictOpts)

// WithCheck gives ApplyVerdict the result of replaying the deterministic
// check. It only matters for a "resolved" verdict: the agent is not
// trusted, so while the check fires (or cannot be replayed) the verdict is
// treated as a recheck with the default delay.
func WithCheck(c CheckState) VerdictOption { return func(o *verdictOpts) { o.check = c } }

// WithContext stores v (JSON) in the owed effect of the step: what the
// caller needs to execute the effects of this pass after a crash.
func WithContext(v any) VerdictOption {
	return func(o *verdictOpts) {
		if b, err := json.Marshal(v); err == nil {
			o.context = b
		}
	}
}

// decision is the pure outcome of a verdict, before it is stored.
type decision struct {
	state       model.IncidentState
	reason      string
	closeReason string
	ticket      string // well-formed green-light ticket, to claim for the incident
	withdraw    string // ticket to withdraw once claimed (the round is refused)
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

func maxGreenLights(limits model.Limits) int {
	if limits.MaxGreenLights > 0 {
		return limits.MaxGreenLights
	}
	return DefaultMaxGreenLights
}

func maxQuotaRuns(limits model.Limits) int {
	if limits.MaxQuotaRuns > 0 {
		return limits.MaxQuotaRuns
	}
	return DefaultMaxQuotaRuns
}

// budget says why no further pass may be planned for the incident ("" when
// one may): the pass count (runbook MaxRuns, else limits.MaxRunsPerIncident)
// or limits.MaxIncidentAge is reached. Every path that leads to another
// pass goes through it: recheck, green light, failed pass.
func budget(inc model.Incident, rb model.Runbook, limits model.Limits, now time.Time) string {
	if limit := maxRuns(rb, limits); limit > 0 && inc.Runs >= limit {
		return fmt.Sprintf("maximum of %d passes reached", limit)
	}
	if limits.MaxIncidentAge > 0 && now.Sub(inc.AgeStart()) >= limits.MaxIncidentAge {
		return fmt.Sprintf("maximum incident age of %s reached", limits.MaxIncidentAge)
	}
	return ""
}

var ticketIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidTicket reports whether ticket is "<askInstance>/<id>" with a strict
// id: the only tickets an incident of a runbook may hold are those of the
// runbook's own ask instance.
func ValidTicket(ticket, askInstance string) bool {
	if askInstance == "" {
		return false
	}
	id, ok := strings.CutPrefix(ticket, askInstance+"/")
	return ok && ticketIDRe.MatchString(id)
}

// decide maps a verdict to the next state. inc.Runs already counts the
// pass that produced the verdict.
func decide(inc model.Incident, v model.Verdict, rb model.Runbook, limits model.Limits, now time.Time, check CheckState) decision {
	d := decision{openMR: v.MR}
	escalate := func(reason string) {
		d.state, d.reason, d.alert = model.StateEscalated, reason, model.AlertEscalated
	}
	recheck := func(minutes int, why string) {
		if over := budget(inc, rb, limits, now); over != "" {
			if why != "agent asked for a recheck" {
				over = why + "; " + over
			}
			escalate(over)
			return
		}
		delay := time.Duration(minutes) * time.Minute
		if delay <= 0 {
			delay = rb.RecheckDefault
		}
		if delay <= 0 {
			delay = DefaultRecheck
		}
		d.state, d.recheckAt, d.reason = model.StateWaiting, now.Add(delay), why
	}
	switch v.Outcome {
	case model.OutcomeResolved:
		switch check {
		case CheckFiring:
			// The agent's word is not enough: the deterministic check
			// still sees the condition. Counted pass, default delay.
			recheck(0, "the agent answered resolved but the deterministic check still fires: treated as a recheck")
		case CheckUnknown:
			recheck(0, "the agent answered resolved but the deterministic check could not be replayed: treated as a recheck")
		default:
			d.state, d.closeReason, d.reason = model.StateResolved, ReasonResolvedByAgent, ReasonResolvedByAgent
			if v.MR != nil {
				// Unblocked by an action and a fix proposed: the incident
				// is closed, the merge request lives on as a known problem.
				d.known, d.alert = true, model.NoticeMROpened
			}
			return d
		}
	case model.OutcomeRecheck:
		recheck(v.RecheckMinutes, "agent asked for a recheck")
	case model.OutcomeGreenLight:
		t := strings.TrimSpace(v.Ticket)
		switch {
		case t == "":
			escalate("green light asked without a ticket")
		case rb.AskInstance == "":
			escalate("green light asked but the runbook has no ask instance")
		case !ValidTicket(t, rb.AskInstance):
			escalate("the ticket of the verdict is not a ticket of this runbook's ask instance (" + rb.AskInstance + ")")
		default:
			// A green light leads to another pass: same budget as a
			// recheck, plus a bound on the rounds.
			d.ticket = t
			over := budget(inc, rb, limits, now)
			if over == "" && inc.GreenLights >= maxGreenLights(limits) {
				over = fmt.Sprintf("maximum of %d green-light rounds reached", maxGreenLights(limits))
			}
			if over != "" {
				escalate("green light asked; " + over)
				d.withdraw = t
				break
			}
			// The ticket must be followed to its decision whatever else the
			// verdict carries: the incident waits in green_light even with a
			// merge request (which is still opened).
			d.state, d.alert, d.reason = model.StateGreenLight, model.AlertGreenLight, "waiting for a human decision on the ticket"
			return d
		}
	case model.OutcomeEscalate:
		escalate("agent escalated")
	case model.OutcomeBlocked:
		// A missing action needs a human hand: the incident stays
		// blocked (and alerts) even with a merge request.
		d.state, d.alert, d.reason = model.StateBlocked, model.AlertBlocked, "an action is missing from the catalogue"
		return d
	default:
		escalate(fmt.Sprintf("unknown verdict outcome %q", inline(string(v.Outcome))))
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
//	               is a known problem). With WithCheck(CheckFiring) or
//	               WithCheck(CheckUnknown) the verdict is not believed and
//	               is handled as a recheck with the default delay.
//	recheck      → waiting until now + RecheckMinutes (runbook default,
//	               then DefaultRecheck); escalated when the pass count
//	               (runbook MaxRuns, else limits.MaxRunsPerIncident) or
//	               limits.MaxIncidentAge is reached
//	green_light  → green_light with the ticket, under the same pass and age
//	               budget as a recheck and at most limits.MaxGreenLights
//	               rounds. The ticket must be "<runbook.AskInstance>/<id>"
//	               and must never have been recorded before, on this
//	               incident or another: otherwise escalated.
//	escalate     → escalated
//	blocked      → blocked
//
// A recheck or escalate verdict that carries a merge request gives mr_open
// instead. The pass is counted (Runs) and the failure counter is cleared.
// What the step owes (alert, merge requests, ticket to withdraw) is written
// to the outbox in the same transaction. An error wrapping ErrDossier means
// the transition is stored but the journal could not be written.
func (m *Manager) ApplyVerdict(inc model.Incident, v model.Verdict, rb model.Runbook, limits model.Limits, opts ...VerdictOption) (Transition, error) {
	var vo verdictOpts
	for _, o := range opts {
		o(&vo)
	}
	now := m.now()
	var d decision
	updated, err := m.st.Transition(inc.ID, []model.IncidentState{model.StateInvestigating}, func(tx *store.Tx, i *model.Incident) error {
		i.Runs++
		d = decide(*i, v, rb, limits, now, vo.check)
		held := ""
		if d.ticket != "" {
			ok, err := tx.ClaimTicket(d.ticket, i.ID)
			if err != nil {
				return err
			}
			switch {
			case !ok:
				// Presented twice, or held by another incident: the
				// ticket is not ours to follow, and not ours to withdraw.
				d.state, d.alert, d.withdraw = model.StateEscalated, model.AlertEscalated, ""
				d.reason = "the ticket of the verdict was already presented, by this incident or another one"
				if v.MR != nil {
					d.state, d.alert = model.StateMROpen, model.NoticeMROpened
					d.reason = "fix proposed, production still affected; " + d.reason
				}
			case d.state == model.StateGreenLight:
				i.GreenLights++
				held = d.ticket
			}
		}
		i.State, i.Ticket, i.RecheckAt, i.CloseReason = d.state, held, d.recheckAt, d.closeReason
		if err := tx.ResetFailures(i.ID); err != nil {
			return err
		}
		owed := Owed{Event: EventVerdict, From: model.StateInvestigating, To: d.state, Reason: d.reason, Alert: d.alert,
			KnownProblem: d.known, WithdrawTicket: d.withdraw, Context: vo.context}
		if owed.Alert == "" && d.withdraw == "" && v.MR == nil && v.MissingAction == nil && v.Improvement == nil {
			return nil
		}
		vc := v
		owed.Verdict = &vc
		e, err := owedEffect(owed)
		if err != nil {
			return err
		}
		e.Project, e.Incident = i.Project, i.ID
		return tx.Enqueue(e)
	})
	if err != nil {
		return Transition{}, err
	}
	tr := Transition{
		Incident: updated, From: model.StateInvestigating, To: d.state, Reason: d.reason, Alert: d.alert,
		OpenMR: d.openMR, KnownProblem: d.known, MissingAction: v.MissingAction, Improvement: v.Improvement,
		RecheckAt: updated.RecheckAt, WithdrawTicket: d.withdraw,
	}
	return tr, m.journal(inc.ID, fmt.Sprintf("pass %d: verdict %s", updated.Runs, inline(string(v.Outcome))), verdictEntry(v, tr))
}

// Quote renders untrusted text (an agent verdict, a signal, a tool error)
// for the journal: control characters are stripped and every line is
// prefixed with "> ", so that the text can never start a journal entry of
// its own ("## <time> — <title>") nor pass for a line the core wrote.
func Quote(text string) string {
	text = strings.TrimSpace(model.CleanText(text))
	if text == "" {
		return "> (empty)"
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight("> "+l, " ")
	}
	return strings.Join(lines, "\n")
}

// inline renders untrusted text inside a line the core writes: one line, no
// control character, bounded.
func inline(s string) string {
	s = model.CleanLine(s)
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// verdictEntry is the journal entry of a verdict: the state line and the
// labels are written by the core; everything the agent said is block-quoted.
func verdictEntry(v model.Verdict, tr Transition) string {
	var b strings.Builder
	b.WriteString(stateLine(tr) + "\n\n")
	section := func(label, text string) {
		if strings.TrimSpace(text) == "" {
			return
		}
		b.WriteString(label + " (agent, untrusted):\n\n" + Quote(text) + "\n\n")
	}
	section("Summary", v.Summary)
	section("Root cause", v.RootCause)
	if len(v.Evidence) > 0 {
		var ev []string
		for _, e := range v.Evidence {
			ev = append(ev, "- "+strings.ReplaceAll(strings.TrimSpace(model.CleanText(e)), "\n", "\n  "))
		}
		section("Evidence", strings.Join(ev, "\n"))
	}
	if len(v.ActionsRun) > 0 {
		var acts []string
		for _, a := range v.ActionsRun {
			acts = append(acts, "- "+inline(a))
		}
		section("Actions the agent says it ran", strings.Join(acts, "\n"))
	}
	if tr.Incident.Ticket != "" {
		b.WriteString("Ticket recorded for this incident: `" + tr.Incident.Ticket + "`\n\n")
	} else if v.Ticket != "" {
		section("Ticket named by the agent (not accepted)", inline(v.Ticket))
	}
	if v.MR != nil {
		section("Merge request proposed", "repository: "+inline(v.MR.Repo)+"\ntitle: "+inline(v.MR.Title))
	}
	if v.MissingAction != nil {
		section("Missing action", "name: "+inline(v.MissingAction.Name)+"\nwhy: "+inline(v.MissingAction.Why))
	}
	if v.Improvement != nil {
		section("Configuration improvement proposed", inline(v.Improvement.Title))
	}
	if v.Confidence != "" {
		section("Confidence", inline(v.Confidence))
	}
	return strings.TrimSpace(b.String())
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

// step applies a simple transition, stores what it owes (an alert, a ticket
// to withdraw) in the same transaction and journals it.
func (m *Manager) step(id string, from []model.IncidentState, event, title string, fn func(tx *store.Tx, i *model.Incident, tr *Transition, owed *Owed) error) (Transition, error) {
	var tr Transition
	updated, err := m.st.Transition(id, from, func(tx *store.Tx, i *model.Incident) error {
		tr = Transition{From: i.State}
		owed := Owed{Event: event}
		if err := fn(tx, i, &tr, &owed); err != nil {
			return err
		}
		tr.To = i.State
		if tr.Alert == "" && tr.WithdrawTicket == "" {
			return nil
		}
		owed.From, owed.To, owed.Reason, owed.Alert, owed.WithdrawTicket = tr.From, tr.To, tr.Reason, tr.Alert, tr.WithdrawTicket
		e, err := owedEffect(owed)
		if err != nil {
			return err
		}
		e.Project, e.Incident = i.Project, i.ID
		return tx.Enqueue(e)
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
//   - cancelled: back to queued, the pass is not counted;
//   - quota (seat exhausted): back to queued for another seat, the pass is
//     not counted in Runs but in QuotaRuns; at limits.MaxQuotaRuns the
//     incident escalates, so a forged or persistent quota outcome cannot
//     loop for ever;
//   - failed or timeout: the pass is counted; the first failure goes back
//     to queued for one retry, the second consecutive one escalates, and so
//     does reaching the pass budget (runbook MaxRuns, else
//     limits.MaxRunsPerIncident) or limits.MaxIncidentAge.
//
// detail is the error of the pass, for the alert (the caller scrubs it).
func (m *Manager) RunFailed(inc model.Incident, status model.RunStatus, rb model.Runbook, limits model.Limits, detail string) (Transition, error) {
	from := []model.IncidentState{model.StateInvestigating}
	title := "pass ended: " + string(status)
	now := m.now()
	switch status {
	case model.RunCancelled:
		return m.step(inc.ID, from, EventRunFailed, title, func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
			i.State = model.StateQueued
			tr.Reason = "pass cancelled, not counted"
			return nil
		})
	case model.RunQuota:
		return m.step(inc.ID, from, EventRunFailed, title, func(_ *store.Tx, i *model.Incident, tr *Transition, owed *Owed) error {
			i.QuotaRuns++
			owed.Detail = detail
			if limit := maxQuotaRuns(limits); i.QuotaRuns >= limit {
				escalated(i, tr, fmt.Sprintf("%d passes ended on an exhausted seat", i.QuotaRuns))
				return nil
			}
			i.State = model.StateQueued
			tr.Reason = "pass not counted, queued for another seat"
			return nil
		})
	case model.RunFailed, model.RunTimeout:
		return m.step(inc.ID, from, EventRunFailed, title, func(tx *store.Tx, i *model.Incident, tr *Transition, owed *Owed) error {
			failures, err := tx.IncrementFailures(i.ID)
			if err != nil {
				return err
			}
			i.Runs++
			owed.Detail = detail
			if failures >= MaxFailedRuns {
				escalated(i, tr, fmt.Sprintf("%d consecutive failed passes", failures))
			} else if over := budget(*i, rb, limits, now); over != "" {
				escalated(i, tr, over)
			} else {
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
	return m.step(inc.ID, from, "recheck", title, func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
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

// AgeOut escalates a queued or waiting incident whose age reached
// limits.MaxIncidentAge: the age limit is enforced by a timer, not only
// when a verdict happens to come. It returns store.ErrStateConflict when
// the incident moved, and an unchanged transition when it is not old enough.
func (m *Manager) AgeOut(inc model.Incident, limits model.Limits) (Transition, error) {
	from := []model.IncidentState{model.StateQueued, model.StateWaiting}
	now := m.now()
	if limits.MaxIncidentAge <= 0 || now.Sub(inc.AgeStart()) < limits.MaxIncidentAge {
		cur, err := m.expect(inc.ID, from)
		return Transition{Incident: cur, From: cur.State, To: cur.State}, err
	}
	return m.step(inc.ID, from, EventAge, "escalated: too old", func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
		if now.Sub(i.AgeStart()) < limits.MaxIncidentAge {
			return fmt.Errorf("%w: %s was resumed", store.ErrStateConflict, i.ID)
		}
		tr.WithdrawTicket = i.Ticket
		escalated(i, tr, fmt.Sprintf("maximum incident age of %s reached while %s", limits.MaxIncidentAge, tr.From))
		i.Ticket = ""
		return nil
	})
}

// GreenLightDecided records the decision read at the hub for the ticket of
// an incident in green_light: approved → queued, the next pass replays the
// command with the ticket, which stays on the incident; denied, expired or
// withdrawn → escalated. A ticket reported consumed while the incident
// waits in green_light escalates too: no pass of this incident ran since
// the ticket was presented, so the agent handed over a ticket that was
// already used. Pending and unknown change nothing.
func (m *Manager) GreenLightDecided(inc model.Incident, state model.TicketState) (Transition, error) {
	from := []model.IncidentState{model.StateGreenLight}
	switch state {
	case model.TicketApproved:
		return m.step(inc.ID, from, EventGreenLight, "green light: "+string(state), func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
			i.State = model.StateQueued
			tr.Reason = "ticket " + i.Ticket + " " + string(state) + ", new pass replays it"
			return nil
		})
	case model.TicketDenied, model.TicketExpired, model.TicketWithdrawn, model.TicketConsumed:
		return m.step(inc.ID, from, EventGreenLight, "green light: "+string(state), func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
			reason := "ticket " + i.Ticket + " " + string(state)
			if state == model.TicketConsumed {
				reason += " before any pass of this incident could replay it"
			}
			escalated(i, tr, reason)
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
// within limits.GreenLightTimeout; the ticket is withdrawn
// (Transition.WithdrawTicket, owed in the outbox).
func (m *Manager) GreenLightTimedOut(inc model.Incident) (Transition, error) {
	return m.step(inc.ID, []model.IncidentState{model.StateGreenLight}, EventGreenLight, "green light: timed out", func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
		tr.WithdrawTicket = i.Ticket
		escalated(i, tr, "no decision on ticket "+i.Ticket+" in time")
		i.Ticket = ""
		return nil
	})
}

// Close resolves an open incident on a human decision (dutydesk incident
// close) or on a "resolved" webhook of its source. An empty reason becomes
// "closed by human". A ticket the incident holds is returned in
// WithdrawTicket and owed in the outbox.
func (m *Manager) Close(id, reason string) (Transition, error) {
	reason = inline(reason)
	if reason == "" {
		reason = ReasonClosedByHuman
	}
	from := []model.IncidentState{model.StateQueued, model.StateInvestigating, model.StateWaiting, model.StateGreenLight,
		model.StateMROpen, model.StateEscalated, model.StateBlocked}
	return m.step(id, from, EventHuman, "closed by a human", func(_ *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
		tr.WithdrawTicket = i.Ticket
		i.State, i.CloseReason, i.RecheckAt, i.Ticket = model.StateResolved, reason, time.Time{}, ""
		tr.Reason = reason
		return nil
	})
}

// Resume queues a new pass on a human decision (dutydesk incident resume)
// for an incident that is escalated, blocked, mr_open, waiting or
// green_light (its pending ticket is then returned in WithdrawTicket). The
// failure counter, the quota counter and the age limit restart.
func (m *Manager) Resume(id string) (Transition, error) {
	from := []model.IncidentState{model.StateEscalated, model.StateBlocked, model.StateMROpen, model.StateWaiting, model.StateGreenLight}
	now := m.now()
	return m.step(id, from, EventHuman, "resumed by a human", func(tx *store.Tx, i *model.Incident, tr *Transition, _ *Owed) error {
		tr.WithdrawTicket = i.Ticket
		i.State, i.RecheckAt, i.Ticket = model.StateQueued, time.Time{}, ""
		i.QuotaRuns, i.AgeFrom = 0, now
		tr.Reason = "resumed by a human, new pass"
		return tx.ResetFailures(i.ID)
	})
}

// DueReminders returns the incidents that wait for a human (escalated,
// blocked, green_light) and were last alerted at least ReminderEvery ago,
// per the limits of their project (DefaultReminderEvery when zero). Only a
// delivered alert counts: an alert that failed to go out does not push the
// reminder back.
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
