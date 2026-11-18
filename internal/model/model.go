// Package model holds the types shared by every DutyDesk package.
// It has no dependency on the other internal packages and no behaviour
// beyond small pure helpers, so packages can be built and tested alone.
package model

import (
	"context"
	"time"
)

// ---------- configuration (loaded from the protected branch of the config repo) ----------

// Severity orders the queue: higher first.
type Severity int

const (
	SevLow Severity = iota + 1
	SevMedium
	SevHigh
	SevCritical
)

// Project is projects/<slug>/project.yaml plus everything under that directory.
type Project struct {
	Slug     string
	Name     string
	Repos    []Repo             // code repositories the agent may read and patch
	Locks    Locks              // lock instances this project uses
	Limits   Limits             // budgets; zero values fall back to defaults
	Alerts   AlertConfig        // where alerts go
	Seats    []string           // seat names allowed for this project; empty = all
	Checks   []Check            // checks/*.yaml
	Runbooks []Runbook          // runbooks/*.md
	Actions  map[string]Action  // actions/<name>/action.yaml, by name
	MRRules  string             // mr-rules.md, or the standard text
	Webhooks map[string]Webhook // inbound webhook sources, by source id
}

type Repo struct {
	Name          string // short name used in verdicts
	Forge         string // "gitlab" | "github"
	URL           string // https clone URL
	Project       string // forge project path, e.g. "group/app"
	DefaultBranch string
	TokenFile     string // file holding the service account token (read by the core only)
}

// Locks names the lock instances (as declared in lockfamily.yaml).
type Locks struct {
	Workspace string // directory holding .lockfamily/ (where lox live runs)
	SQL       string // locksql instance, "" if none
	Log       string // locklog instance
	MQ        string // lockmq instance
	File      string // lockfile instance
	// SSH action profiles are per runbook: see Runbook.ActionInstance.
}

type Limits struct {
	MaxOpenPerCheck    int           // storm guard: above this, one "mass" incident
	MaxRunsPerIncident int           // agent passes per incident
	MaxIncidentAge     time.Duration // then escalate
	RunTimeout         time.Duration // wall clock per pass
	MaxTurns           int           // claude --max-turns
	MaxParallelRuns    int           // per project
	GreenLightTimeout  time.Duration // wait for a human decision before withdraw + escalate
	QueueAlertAfter    time.Duration // high severity waiting for a seat
	RecurrenceCount    int           // resolved incidents of one family within RecurrenceWindow
	RecurrenceWindow   time.Duration
	ReminderEvery      time.Duration // re-alert while an incident needs a human
}

type AlertConfig struct {
	WebhookURLFile string // file holding the outgoing webhook URL (Teams-compatible)
	HeartbeatURL   string // dead-man switch ping, "" = off
}

type Webhook struct {
	Kind       string // "sentry" | "generic"
	SecretFile string // HMAC secret
	Severity   Severity
	// Generic adapter: JSON pointer-ish paths into the payload.
	FingerprintTemplate string            // e.g. "sentry:{issue_id}"
	Fields              map[string]string // allow-listed output field -> payload path
	Runbook             string            // runbook id to use, "" = match by Runbook.AppliesTo
}

// CheckKind is the deterministic source of a check.
type CheckKind string

const (
	CheckSQL    CheckKind = "sql"    // each returned row is a signal
	CheckLog    CheckKind = "log"    // count of a pattern over a window, compared to a threshold
	CheckExpect CheckKind = "expect" // signal when the expected thing is ABSENT at the due time
)

type Check struct {
	ID          string
	Project     string
	Kind        CheckKind
	Schedule    string // cron, 5 fields
	Severity    Severity
	Fingerprint string // template over row fields, e.g. "stuck-job:{job_id}"
	Summary     string // template, human one-liner
	// sql / expect(sql)
	Query string
	// log / expect(log)
	LogQuery  string
	LogWindow time.Duration
	Threshold int    // log: signal when count >= Threshold; expect: signal when count < Threshold
	Source    string // expect: "sql" | "log"
}

// Runbook is runbooks/<id>.md: YAML front matter + Markdown body.
type Runbook struct {
	ID             string
	Project        string        // "" for standard/
	AppliesTo      []string      // check ids or webhook source ids; "*" = generic fallback
	Actions        []string      // action names this runbook may run
	ActionInstance string        // lockssh instance whose profile carries exactly this runbook's AUTO actions
	AskInstance    string        // lockssh instance (profile in "ask" mode) carrying its GREEN-LIGHT actions
	RecheckDefault time.Duration // when the agent says "recheck" without a delay
	RecheckCheck   string        // check id replayed at wake-up (webhook incidents); "" = the origin check
	MaxRuns        int           // overrides Limits.MaxRunsPerIncident when > 0
	Body           string        // Markdown
}

type ActionLevel string

const (
	ActionAuto       ActionLevel = "auto"        // lockssh allow rule, runs at once
	ActionGreenLight ActionLevel = "green-light" // lockssh "ask" rule: ticket, a human decides
)

// Action is actions/<name>/action.yaml next to its script.
type Action struct {
	Name        string
	Description string
	Level       ActionLevel
	Script      string        // file name inside the action directory
	Params      []ActionParam // positional, rendered as --name value
	RateLimit   RateLimit
	Timeout     time.Duration
}

type ActionParam struct {
	Name    string
	Type    string // "int" | "string" | "enum"
	Pattern string // string: full-match regexp; values never contain "/" or whitespace
	Enum    []string
	Min     *int64
	Max     *int64
}

type RateLimit struct {
	Count  int
	Window time.Duration
}

// Seat is one Claude subscription (service account) with its long-lived token.
type Seat struct {
	Name        string
	TokenFile   string
	MaxParallel int
	ExpiresOn   time.Time // token expiry, zero = unknown
}

// ---------- runtime ----------

// Signal is one deterministic observation: a row of a check, or an inbound webhook.
type Signal struct {
	Project     string
	Source      string // check id or webhook source id
	Fingerprint string // dedup key
	Severity    Severity
	Summary     string
	Fields      map[string]string // masked / allow-listed values only
	At          time.Time
}

type IncidentState string

const (
	StateQueued        IncidentState = "queued"
	StateInvestigating IncidentState = "investigating"
	StateWaiting       IncidentState = "waiting"     // recheck at RecheckAt
	StateGreenLight    IncidentState = "green_light" // a ticket waits for a human
	StateMROpen        IncidentState = "mr_open"     // production still affected, fix proposed
	StateEscalated     IncidentState = "escalated"
	StateBlocked       IncidentState = "blocked" // an action is missing from the catalogue
	StateResolved      IncidentState = "resolved"
)

// Open reports whether signals with the same fingerprint attach to the incident.
func (s IncidentState) Open() bool { return s != StateResolved }

// NeedsHuman reports whether the incident waits for a person.
func (s IncidentState) NeedsHuman() bool {
	return s == StateEscalated || s == StateBlocked || s == StateGreenLight
}

type Incident struct {
	ID          string // "INC-000123"
	Project     string
	Source      string
	Fingerprint string
	Family      string // fingerprint without its variable part: recurrence and known problems
	Severity    Severity
	Summary     string
	State       IncidentState
	Mass        bool // storm guard incident
	Recurrent   bool
	Runbook     string
	SignalCount int
	Runs        int
	AgentToken  string // per-incident secret: lock agent identity token (never shown to humans)
	Ticket      string // pending green-light ticket "instance/id"
	RecheckAt   time.Time
	OpenedAt    time.Time
	UpdatedAt   time.Time
	ClosedAt    time.Time
	LastAlertAt time.Time
	CloseReason string
}

// Outcome is the agent's conclusion for one pass.
type Outcome string

const (
	OutcomeResolved   Outcome = "resolved"
	OutcomeRecheck    Outcome = "recheck"
	OutcomeGreenLight Outcome = "green_light"
	OutcomeEscalate   Outcome = "escalate"
	OutcomeBlocked    Outcome = "blocked"
)

// Verdict is the structured output of one agent pass (validated against VerdictSchema).
type Verdict struct {
	Outcome        Outcome        `json:"outcome"`
	Summary        string         `json:"summary"`
	RootCause      string         `json:"root_cause,omitempty"`
	Evidence       []string       `json:"evidence,omitempty"`
	RecheckMinutes int            `json:"recheck_minutes,omitempty"`
	Ticket         string         `json:"ticket,omitempty"`
	MR             *MRProposal    `json:"mr,omitempty"`
	MissingAction  *MissingAction `json:"missing_action,omitempty"`
	Improvement    *Improvement   `json:"improvement,omitempty"`
	ActionsRun     []string       `json:"actions_run,omitempty"`
	Confidence     string         `json:"confidence"` // low | medium | high
}

// MRProposal: the agent edited the local clone of Repo; the core pushes and opens the MR.
type MRProposal struct {
	Repo        string `json:"repo"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// MissingAction: the agent wrote actions/<name>/ in the throwaway clone of the config repo.
type MissingAction struct {
	Name   string `json:"name"`
	Why    string `json:"why"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// Improvement: the agent edited checks/runbooks/actions in the config repo clone.
type Improvement struct {
	Title       string `json:"title"`
	Observation string `json:"observation"`
	Change      string `json:"change"`
	Effect      string `json:"effect"`
	Risk        string `json:"risk"`
}

// Run is one agent pass.
type Run struct {
	ID         int64
	IncidentID string
	Seat       string
	StartedAt  time.Time
	EndedAt    time.Time
	Status     RunStatus
	Verdict    *Verdict
	Error      string
	CostUSD    float64
	Turns      int
	InputTok   int64
	OutputTok  int64
}

type RunStatus string

const (
	RunOK        RunStatus = "ok"
	RunFailed    RunStatus = "failed" // crash, no valid verdict
	RunTimeout   RunStatus = "timeout"
	RunQuota     RunStatus = "quota" // seat exhausted: retry on another seat, not counted as a pass
	RunCancelled RunStatus = "cancelled"
)

// KnownProblem links an open merge request to an incident family.
type KnownProblem struct {
	ID       int64
	Project  string
	Family   string
	Repo     string
	MRURL    string
	MRID     string
	Incident string
	OpenedAt time.Time
	ClosedAt time.Time
}

// AlertKind lists what makes DutyDesk call a human.
type AlertKind string

const (
	AlertEscalated  AlertKind = "escalated"
	AlertBlocked    AlertKind = "blocked"
	AlertGreenLight AlertKind = "green_light"
	AlertCapacity   AlertKind = "capacity"
	AlertLocksDown  AlertKind = "locks_down"
	AlertSeatExpiry AlertKind = "seat_expiry"
	AlertStorm      AlertKind = "storm"
	AlertReminder   AlertKind = "reminder"
	AlertSystem     AlertKind = "system"    // DutyDesk itself needs attention: failing check, rejected configuration
	NoticeMROpened  AlertKind = "mr_opened" // notification, not an alert
	NoticeConfigMR  AlertKind = "config_mr_opened"
)

type Alert struct {
	Kind     AlertKind
	Project  string
	Incident string // "" for system alerts
	Title    string // one line
	Body     string // a few lines: what happens, what is expected from the human
	URL      string // MR or ticket location, optional
	At       time.Time
}

// ---------- ports (implemented in other packages, faked in tests) ----------

// Row is one masked result row; values are strings as the lock printed them.
type Row map[string]string

// LockReader is how the core's deterministic checks read production, through the locks.
type LockReader interface {
	// SQL runs one read-only statement through the project's locksql instance.
	SQL(ctx context.Context, p *Project, query string) ([]Row, error)
	// LogCount counts matches of a locklog query over the last window.
	LogCount(ctx context.Context, p *Project, query string, window time.Duration) (int, error)
}

// LockHealth is the state lox live exposes on its read-only status socket.
type LockHealth struct {
	Serving bool              // hub up and every lock of the workspace serves
	Locks   map[string]string // instance -> "serving" | "needs_enrolment" | "missing_secret" | "refused" | "down"
	Pending int               // tickets waiting
	Detail  string
}

type TicketState string

const (
	TicketPending   TicketState = "pending"
	TicketApproved  TicketState = "approved"
	TicketDenied    TicketState = "denied"
	TicketExpired   TicketState = "expired"
	TicketWithdrawn TicketState = "withdrawn"
	TicketConsumed  TicketState = "consumed"
	TicketUnknown   TicketState = "unknown"
)

// LockStatus reads lox live; it can never decide a ticket.
type LockStatus interface {
	Health(ctx context.Context, workspace string) (LockHealth, error)
	Ticket(ctx context.Context, workspace, ticket string) (TicketState, error)
	Withdraw(ctx context.Context, workspace, ticket string) error
}

// RunRequest is everything the agent launcher needs for one pass.
type RunRequest struct {
	Incident   Incident
	Run        int // pass number, 1-based, unique per incident (quota retries included)
	Project    *Project
	Runbook    Runbook
	Seat       Seat
	Prompt     string
	DossierDir string            // read-only mount
	RepoDirs   map[string]string // repo name -> local clone (read-write)
	ConfigDir  string            // throwaway clone of the config repo (read-write), "" if none
	OutDir     string            // transcript and verdict are written here by the launcher
}

type RunResult struct {
	Status     RunStatus
	Verdict    *Verdict
	Error      string
	CostUSD    float64
	Turns      int
	InputTok   int64
	OutputTok  int64
	QuotaReset time.Time // RunQuota: when the seat is usable again, zero = unknown
}

// AgentLauncher runs one agent pass in an isolated container and returns its verdict.
type AgentLauncher interface {
	Run(ctx context.Context, req RunRequest) RunResult
}

// MRInfo is the state of a merge request on the forge.
type MRInfo struct {
	ID     string
	URL    string
	State  string // "open" | "merged" | "closed"
	Branch string
}

// Forge clones, pushes and opens merge requests with the service account. It never merges.
type Forge interface {
	// Clone makes a fresh clone of the default branch in dir.
	Clone(ctx context.Context, repo Repo, dir string) error
	// Propose commits the working tree of dir on branch, pushes it and opens a merge request.
	// It refuses (ErrNoChange, ErrSecretFound, ErrForbiddenPath) before pushing anything.
	Propose(ctx context.Context, repo Repo, dir, branch, title, description string, draft bool, labels []string) (MRInfo, error)
	Status(ctx context.Context, repo Repo, id string) (MRInfo, error)
}

// Notifier sends alerts and notices to humans.
type Notifier interface {
	Send(ctx context.Context, p *Project, a Alert) error
}
