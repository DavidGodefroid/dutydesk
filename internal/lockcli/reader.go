package lockcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// DefaultAgent is the lock agent label of DutyDesk's core.
const DefaultAgent = "dutydesk:core"

// DefaultTimeout bounds one lock call.
const DefaultTimeout = 30 * time.Second

// Errors a caller can test with errors.Is.
var (
	// ErrNeedsDecision: the lock did not decide the read by its auto rules
	// and opened a ticket. A check must be an auto-decided read.
	ErrNeedsDecision = errors.New("lockcli: the lock asks for a human decision (not an auto-decided read)")
	// ErrNoConsole: no console serves (lox run / lox live is not up).
	ErrNoConsole = errors.New("lockcli: no lock console is running")
	// ErrNoInstance: the project names no lock instance of that type.
	ErrNoInstance = errors.New("lockcli: the project has no lock instance of this type")
	// ErrIncomplete: locklog could not finish the count within its budgets.
	ErrIncomplete = errors.New("lockcli: the count is incomplete (over the lock's free budgets)")
)

// NeedsDecisionError carries the ticket the lock opened, so that the caller
// can withdraw it. errors.Is(err, ErrNeedsDecision) is true.
type NeedsDecisionError struct {
	Instance string
	Ticket   string
}

func (e *NeedsDecisionError) Error() string {
	return fmt.Sprintf("%v: ticket %s/%s", ErrNeedsDecision, e.Instance, e.Ticket)
}
func (e *NeedsDecisionError) Is(target error) bool { return target == ErrNeedsDecision }

// ClientError is a failure the lock client reported ({"error": ...} with
// --json, or an MCP tool error). Message is the lock's own text, which
// never quotes database or log values.
type ClientError struct {
	Tool    string // "locksql plan", "locksql run", "locklog_count"
	Kind    string // locksql: refused, denied, timeout, no_such_plan, ...
	Code    string // refusal code (E_...), when any
	Message string
	Exit    int
}

func (e *ClientError) Error() string {
	s := "lockcli: " + e.Tool + " failed"
	if e.Kind != "" {
		s += " (" + e.Kind + ")"
	}
	if e.Code != "" {
		s += " [" + e.Code + "]"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Config configures a Reader. Zero values take the defaults.
//
// The command templates are argument vectors in which "{instance}" is
// replaced by the project's lock instance and, for SQLRun, "{plan_id}" by
// the plan id. The defaults call the launchers lox installs on the host
// (lockhub docs/lox-run.md "Host agents: the locks' launchers"): they find
// <workspace>/.lockfamily/up.json up from the working directory, so every
// command runs with the project's Locks.Workspace as working directory.
type Config struct {
	// SQLPlan reads the statement on stdin ("-").
	// Default: locksql plan --instance {instance} --json -
	SQLPlan []string
	// Default: locksql run --instance {instance} --json {plan_id}
	SQLRun []string
	// LogMCP starts the locklog client's MCP server on stdio.
	// Default: locklog mcp --instance {instance}
	LogMCP []string
	// Agent and Token are the lock agent identity (LEA_AGENT,
	// LEA_AGENT_TOKEN). Agent defaults to DefaultAgent.
	Agent string
	Token string
	// Env holds extra KEY=VALUE entries for the clients.
	Env []string
	// Timeout bounds one SQL or LogCount call (default DefaultTimeout).
	Timeout time.Duration
	// Exec runs the clients (default OSExec).
	Exec Exec
}

// Reader implements model.LockReader with the locks' clients.
type Reader struct {
	cfg Config
}

var _ model.LockReader = (*Reader)(nil)

// NewReader returns a Reader with the defaults filled in.
func NewReader(cfg Config) *Reader {
	if len(cfg.SQLPlan) == 0 {
		cfg.SQLPlan = []string{"locksql", "plan", "--instance", "{instance}", "--json", "-"}
	}
	if len(cfg.SQLRun) == 0 {
		cfg.SQLRun = []string{"locksql", "run", "--instance", "{instance}", "--json", "{plan_id}"}
	}
	if len(cfg.LogMCP) == 0 {
		cfg.LogMCP = []string{"locklog", "mcp", "--instance", "{instance}"}
	}
	if cfg.Agent == "" {
		cfg.Agent = DefaultAgent
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Exec == nil {
		cfg.Exec = OSExec{}
	}
	return &Reader{cfg: cfg}
}

// env is the identity the clients read, then the configured extras.
func (r *Reader) env() []string {
	env := []string{"LEA_AGENT=" + r.cfg.Agent}
	if r.cfg.Token != "" {
		env = append(env, "LEA_AGENT_TOKEN="+r.cfg.Token)
	}
	// VERIFY: the host launchers run the client in a container and (locksql
	// v0.20.0 scripts/locksql) do not forward LEA_AGENT / LEA_AGENT_TOKEN
	// to it. locksql's launcher documents LOCKSQL_DOCKER_ARGS ("extra
	// docker run arguments", docs/launcher.md "Overrides"), used here to
	// pass both by name (never by value). locklog's launcher (v0.4.1) has
	// no such override that could be found: through it the identity does
	// not reach the locklog client. Harmless when the template runs the
	// client binary directly.
	args := "-e LEA_AGENT -e LEA_AGENT_TOKEN"
	if cur := strings.TrimSpace(os.Getenv("LOCKSQL_DOCKER_ARGS")); cur != "" {
		args = cur + " " + args
	}
	env = append(env, "LOCKSQL_DOCKER_ARGS="+args)
	return append(env, r.cfg.Env...)
}

func expand(tmpl []string, repl ...string) []string {
	rp := strings.NewReplacer(repl...)
	out := make([]string, len(tmpl))
	for i, a := range tmpl {
		out[i] = rp.Replace(a)
	}
	return out
}

// validName reports whether s is safe as one command argument naming an
// instance or a plan: letters, digits, '-', '_' and '.', not starting with
// '-' (so it can never be read as an option).
func validName(s string) bool {
	if s == "" || len(s) > 128 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// ---------- locksql ----------

// planResult is `locksql plan --json` (locksql v0.20.0 internal/ipc
// PlanResult): the fields read here.
type planResult struct {
	PlanID  string   `json:"plan_id"`
	Verdict string   `json:"verdict"` // OK | WARN | REFUSE
	Reasons []string `json:"reasons"`
}

// runResult is `locksql run --json` (locksql v0.20.0 internal/ipc
// RunResult): the fields read here.
type runResult struct {
	Columns   []string            `json:"columns"`
	Rows      [][]json.RawMessage `json:"rows"`
	Truncated bool                `json:"truncated"`
	Status    string              `json:"status"` // "" | pending | stale
	Ticket    string              `json:"ticket"`
	Instance  string              `json:"instance"`
}

// cliError is the {"error": ...} object of a failed --json command
// (locksql docs/usage.md §3 CLI; internal/client ErrorInfo).
type cliError struct {
	Error *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
		Refusal *struct {
			Code string `json:"code"`
		} `json:"refusal"`
	} `json:"error"`
}

// SQL plans the statement, then runs the plan. The lock must decide the
// read by its auto rules: a pending ticket is ErrNeedsDecision.
func (r *Reader) SQL(ctx context.Context, p *model.Project, query string) ([]model.Row, error) {
	if p == nil || p.Locks.SQL == "" {
		return nil, ErrNoInstance
	}
	inst := p.Locks.SQL
	if !validName(inst) {
		return nil, fmt.Errorf("lockcli: invalid locksql instance name")
	}
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("lockcli: empty statement")
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	var plan planResult
	argv := expand(r.cfg.SQLPlan, "{instance}", inst)
	if err := r.runJSON(ctx, "locksql plan", Cmd{Argv: argv, Dir: p.Locks.Workspace, Env: r.env(), Stdin: []byte(query)}, &plan); err != nil {
		return nil, err
	}
	if plan.Verdict == "REFUSE" || plan.PlanID == "" {
		// docs/usage.md: "A REFUSE verdict gives no plan id."
		return nil, &ClientError{Tool: "locksql plan", Kind: "refused", Message: "verdict " + plan.Verdict + ": no plan id"}
	}
	if !validName(plan.PlanID) {
		return nil, errors.New("lockcli: locksql plan answered a malformed plan id")
	}

	var res runResult
	argv = expand(r.cfg.SQLRun, "{instance}", inst, "{plan_id}", plan.PlanID)
	if err := r.runJSON(ctx, "locksql run", Cmd{Argv: argv, Dir: p.Locks.Workspace, Env: r.env()}, &res); err != nil {
		return nil, err
	}
	switch res.Status {
	case "":
	case "pending":
		// docs/usage.md "Approving in lockhub": an auto-decided read
		// answers the rows in the same call; pending means a human is asked.
		return nil, &NeedsDecisionError{Instance: inst, Ticket: res.Ticket}
	default:
		return nil, &ClientError{Tool: "locksql run", Kind: res.Status, Message: "unexpected run status"}
	}
	return rowsOf(res)
}

// runJSON runs one --json client command and decodes its answer into v.
// Exit codes (locksql docs/usage.md §3): 0 ok, 1 refused/denied/failed,
// 2 no console, 3 usage or configuration.
func (r *Reader) runJSON(ctx context.Context, tool string, c Cmd, v any) error {
	out, err := r.cfg.Exec.Run(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("lockcli: %s: %w", tool, ctx.Err())
		}
		return fmt.Errorf("lockcli: %s: %w", tool, err)
	}
	if out.ExitCode == 0 {
		dec := json.NewDecoder(bytes.NewReader(out.Stdout))
		dec.UseNumber()
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("lockcli: %s: unreadable answer: %w", tool, err)
		}
		return nil
	}
	ce := &ClientError{Tool: tool, Exit: out.ExitCode}
	var e cliError
	if json.Unmarshal(out.Stdout, &e) == nil && e.Error != nil {
		ce.Kind, ce.Message = e.Error.Kind, e.Error.Message
		if e.Error.Refusal != nil {
			ce.Code = e.Error.Refusal.Code
		}
	}
	switch out.ExitCode {
	case 2:
		return fmt.Errorf("%w: %w", ErrNoConsole, ce)
	case 3:
		if ce.Kind == "" {
			ce.Kind = "usage"
		}
	}
	return ce
}

// rowsOf turns columns and rows into model.Row values, every cell as a
// string. A masked cell stays as the lock printed it ("<redacted>").
func rowsOf(res runResult) ([]model.Row, error) {
	seen := make(map[string]bool, len(res.Columns))
	for _, c := range res.Columns {
		if seen[c] {
			// Two columns of one name cannot be told apart in a Row: a
			// check names its columns (AS ...).
			return nil, fmt.Errorf("lockcli: the result has two columns named %q: alias them", c)
		}
		seen[c] = true
	}
	rows := make([]model.Row, 0, len(res.Rows))
	for _, cells := range res.Rows {
		if len(cells) != len(res.Columns) {
			return nil, errors.New("lockcli: a result row does not match the columns")
		}
		row := make(model.Row, len(cells))
		for i, cell := range cells {
			row[res.Columns[i]] = cellString(cell)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// cellString renders one JSON cell: a string as is, a number with its
// digits untouched, true/false, NULL for null (as locksql prints it), any
// other value as compact JSON.
func cellString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "NULL"
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) == nil {
		return buf.String()
	}
	return string(raw)
}
