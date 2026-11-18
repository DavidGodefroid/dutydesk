// Command dutydesk is the DutyDesk daemon (`dutydesk serve`) and its
// operator CLI. The CLI works directly on the data directory: the database
// is SQLite in WAL mode, so reads are safe while the daemon runs, and the
// few writes (close, resume, check run) go through the incident manager.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/actions"
	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/core"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/lockcli"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

const usageText = `DutyDesk: autonomous incident manager.

Usage: dutydesk [--config FILE] <command> [arguments]

  serve                                   run the daemon (core + webhook endpoint)
  status [--json]                         locks, seats, queue, open incidents by state
  incidents [--project P] [--all] [--json]
  incident show ID [--json]               state, journal, passes, signals
  incident close ID [--reason TEXT]       resolve on a human decision
  incident resume ID                      queue a new agent pass
  seats                                   seats and their quota state
  check run ID --project P [--dry-run]    evaluate a check through the locks; ingest unless --dry-run
  config validate [DIR]                   validate a config repository
  config lockssh-rules --project P [--dir DIR] [--install-dir DIR]
                                          print the lockssh rules a human reviews in lox
  version

--config defaults to $DUTYDESK_CONFIG, then ./dutydesk.yaml, then /etc/dutydesk/dutydesk.yaml.
Exit codes: 0 ok, 1 error, 2 usage.
`

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	err := dispatch(args, stdout, stderr)
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprint(stdout, usageText)
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "dutydesk: %s\n\n%s", ue.msg, usageText)
		return 2
	}
	fmt.Fprintf(stderr, "dutydesk: %v\n", err)
	return 1
}

// cli holds the parsed command line: flags may come before or after the
// positional arguments.
type cli struct {
	stdout, stderr io.Writer
	configPath     string
	json, all, dry bool
	project        string
	reason         string
	dir            string
	installDir     string
	pos            []string
}

func parse(args []string, stderr io.Writer) (*cli, error) {
	c := &cli{}
	fs := flag.NewFlagSet("dutydesk", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.configPath, "config", "", "")
	fs.BoolVar(&c.json, "json", false, "")
	fs.BoolVar(&c.all, "all", false, "")
	fs.BoolVar(&c.dry, "dry-run", false, "")
	fs.StringVar(&c.project, "project", "", "")
	fs.StringVar(&c.reason, "reason", "", "")
	fs.StringVar(&c.dir, "dir", "", "")
	fs.StringVar(&c.installDir, "install-dir", "", "")
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usagef("%v", err)
		}
		args = fs.Args()
		if len(args) > 0 {
			c.pos = append(c.pos, args[0])
			args = args[1:]
		}
	}
	return c, nil
}

func dispatch(args []string, stdout, stderr io.Writer) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	c.stdout, c.stderr = stdout, stderr
	if len(c.pos) == 0 {
		return usagef("no command")
	}
	cmd, rest := c.pos[0], c.pos[1:]
	sub := ""
	if len(rest) > 0 {
		sub = rest[0]
	}
	need := func(n int, what string) error {
		if len(rest) != n {
			return usagef("%s", what)
		}
		return nil
	}
	switch cmd {
	case "help":
		return flag.ErrHelp
	case "version":
		fmt.Fprintf(stdout, "dutydesk %s\n", version)
		return nil
	case "serve":
		if err := need(0, "serve takes no argument"); err != nil {
			return err
		}
		return c.serve()
	case "status":
		if err := need(0, "status takes no argument"); err != nil {
			return err
		}
		return c.status()
	case "incidents":
		if err := need(0, "incidents takes no argument"); err != nil {
			return err
		}
		return c.incidents()
	case "seats":
		if err := need(0, "seats takes no argument"); err != nil {
			return err
		}
		return c.seats()
	case "incident":
		if err := need(2, "usage: dutydesk incident show|close|resume ID"); err != nil {
			return err
		}
		switch sub {
		case "show":
			return c.incidentShow(rest[1])
		case "close":
			return c.incidentClose(rest[1])
		case "resume":
			return c.incidentResume(rest[1])
		}
		return usagef("unknown command: incident %s", sub)
	case "check":
		if sub != "run" || len(rest) != 2 || c.project == "" {
			return usagef("usage: dutydesk check run ID --project P [--dry-run]")
		}
		return c.checkRun(rest[1])
	case "config":
		switch sub {
		case "validate":
			if len(rest) > 2 {
				return usagef("usage: dutydesk config validate [DIR]")
			}
			if len(rest) == 2 {
				c.dir = rest[1]
			}
			return c.configValidate()
		case "lockssh-rules":
			if len(rest) != 1 || c.project == "" {
				return usagef("usage: dutydesk config lockssh-rules --project P [--dir DIR] [--install-dir DIR]")
			}
			return c.locksshRules()
		}
		return usagef("unknown command: config %s", sub)
	}
	return usagef("unknown command: %s", cmd)
}

// ---------- shared loading ----------

func (c *cli) daemonPath() (string, bool) {
	if c.configPath != "" {
		return c.configPath, true
	}
	if p := os.Getenv("DUTYDESK_CONFIG"); p != "" {
		return p, true
	}
	for _, p := range []string{"dutydesk.yaml", "/etc/dutydesk/dutydesk.yaml"} {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func (c *cli) daemon() (*config.Daemon, error) {
	path, ok := c.daemonPath()
	if !ok {
		return nil, errors.New("no daemon configuration: pass --config FILE or set DUTYDESK_CONFIG")
	}
	return config.LoadDaemon(path)
}

// open opens the database of the data directory. The CLI never creates it.
func (c *cli) open() (*config.Daemon, *store.Store, error) {
	d, err := c.daemon()
	if err != nil {
		return nil, nil, err
	}
	db := filepath.Join(d.DataDir, core.DBName)
	if _, err := os.Stat(db); err != nil {
		return nil, nil, fmt.Errorf("no database at %s (has the daemon ever run with this data_dir?)", db)
	}
	st, err := store.Open(db, nil)
	return d, st, err
}

func (c *cli) manager(d *config.Daemon, st *store.Store) (*incident.Manager, *config.Repo) {
	repo, _ := config.LoadRepo(d.ConfigRepo)
	limits := func(project string) model.Limits {
		if repo != nil {
			if p := repo.Project(project); p != nil {
				return p.Limits
			}
		}
		return config.DefaultLimits()
	}
	return incident.NewManager(st, nil, limits, incident.WithDossier(incident.NewDossier(d.DataDir))), repo
}

func (c *cli) printJSON(v any) error {
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func severity(s model.Severity) string {
	switch s {
	case model.SevLow:
		return "low"
	case model.SevMedium:
		return "medium"
	case model.SevHigh:
		return "high"
	case model.SevCritical:
		return "critical"
	}
	return "?"
}

// incidentView is an incident as the CLI shows it: never the agent token.
type incidentView struct {
	ID          string    `json:"id"`
	Project     string    `json:"project"`
	Source      string    `json:"source"`
	Fingerprint string    `json:"fingerprint"`
	Family      string    `json:"family"`
	Severity    string    `json:"severity"`
	State       string    `json:"state"`
	Summary     string    `json:"summary"`
	Runbook     string    `json:"runbook"`
	Mass        bool      `json:"mass,omitempty"`
	Recurrent   bool      `json:"recurrent,omitempty"`
	Signals     int       `json:"signals"`
	Runs        int       `json:"runs"`
	Ticket      string    `json:"ticket,omitempty"`
	RecheckAt   time.Time `json:"recheck_at,omitzero"`
	OpenedAt    time.Time `json:"opened_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ClosedAt    time.Time `json:"closed_at,omitzero"`
	CloseReason string    `json:"close_reason,omitempty"`
}

func view(i model.Incident) incidentView {
	return incidentView{ID: i.ID, Project: i.Project, Source: i.Source, Fingerprint: i.Fingerprint, Family: i.Family,
		Severity: severity(i.Severity), State: string(i.State), Summary: i.Summary, Runbook: i.Runbook, Mass: i.Mass,
		Recurrent: i.Recurrent, Signals: i.SignalCount, Runs: i.Runs, Ticket: i.Ticket, RecheckAt: i.RecheckAt,
		OpenedAt: i.OpenedAt, UpdatedAt: i.UpdatedAt, ClosedAt: i.ClosedAt, CloseReason: i.CloseReason}
}

// ---------- status, incidents, seats ----------

type seatView struct {
	Name           string    `json:"name"`
	MaxParallel    int       `json:"max_parallel"`
	Running        int       `json:"running"`
	ExhaustedUntil time.Time `json:"exhausted_until,omitzero"`
	LastUsed       time.Time `json:"last_used,omitzero"`
	ExpiresOn      time.Time `json:"expires_on,omitzero"`
}

func seatViews(d *config.Daemon, st *store.Store) ([]seatView, error) {
	active, err := st.ActiveRunsBySeat()
	if err != nil {
		return nil, err
	}
	last, err := st.SeatLastUsed()
	if err != nil {
		return nil, err
	}
	var out []seatView
	for _, s := range d.Seats {
		v := seatView{Name: s.Name, MaxParallel: s.MaxParallel, Running: active[s.Name], LastUsed: last[s.Name], ExpiresOn: s.ExpiresOn}
		if until, err := st.SeatExhaustedUntil(s.Name); err == nil && until.After(time.Now()) {
			v.ExhaustedUntil = until
		}
		out = append(out, v)
	}
	return out, nil
}

func (c *cli) printSeats(seats []seatView) {
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEAT\tRUNNING\tQUOTA\tLAST USED\tTOKEN EXPIRES")
	for _, s := range seats {
		quota := "ok"
		if !s.ExhaustedUntil.IsZero() {
			quota = "exhausted until " + stamp(s.ExhaustedUntil)
		}
		expires := "-"
		if !s.ExpiresOn.IsZero() {
			expires = s.ExpiresOn.Format("2006-01-02")
		}
		fmt.Fprintf(tw, "%s\t%d/%d\t%s\t%s\t%s\n", s.Name, s.Running, s.MaxParallel, quota, stamp(s.LastUsed), expires)
	}
	tw.Flush()
}

func (c *cli) seats() error {
	d, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	seats, err := seatViews(d, st)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSON(seats)
	}
	c.printSeats(seats)
	return nil
}

type lockView struct {
	Workspace string            `json:"workspace"`
	Projects  []string          `json:"projects"`
	Serving   bool              `json:"serving"`
	Locks     map[string]string `json:"locks,omitempty"`
	Pending   int               `json:"pending_tickets"`
	Detail    string            `json:"detail,omitempty"`
}

var states = []model.IncidentState{model.StateQueued, model.StateInvestigating, model.StateWaiting, model.StateGreenLight,
	model.StateMROpen, model.StateEscalated, model.StateBlocked}

func (c *cli) status() error {
	d, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()

	var locks []lockView
	if repo, err := config.LoadRepo(d.ConfigRepo); err == nil {
		byWS := map[string]*lockView{}
		for _, p := range repo.Projects {
			v := byWS[p.Locks.Workspace]
			if v == nil {
				v = &lockView{Workspace: p.Locks.Workspace}
				byWS[p.Locks.Workspace] = v
			}
			v.Projects = append(v.Projects, p.Slug)
		}
		status := lockcli.NewStatus(d.LoxStatusSocket)
		for _, v := range byWS {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			h, err := status.Health(ctx, v.Workspace)
			cancel()
			if err != nil {
				v.Detail = "status socket not reachable"
			} else {
				v.Serving, v.Locks, v.Pending, v.Detail = h.Serving, h.Locks, h.Pending, h.Detail
			}
			locks = append(locks, *v)
		}
		sort.Slice(locks, func(i, j int) bool { return locks[i].Workspace < locks[j].Workspace })
	}
	seats, err := seatViews(d, st)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, s := range states {
		n, err := st.CountIncidentsInState("", s)
		if err != nil {
			return err
		}
		counts[string(s)] = n
	}
	known, err := st.ListOpenKnownProblems("")
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSON(map[string]any{"locks": locks, "seats": seats, "incidents": counts, "known_problems": len(known)})
	}
	fmt.Fprintln(c.stdout, "LOCKS")
	if len(locks) == 0 {
		fmt.Fprintln(c.stdout, "  (configuration repository not readable)")
	}
	for _, l := range locks {
		state := "NOT SERVING: no agent starts, checks are skipped"
		if l.Serving {
			state = "serving"
		}
		fmt.Fprintf(c.stdout, "  %s (%s): %s", l.Workspace, strings.Join(l.Projects, ", "), state)
		if l.Detail != "" {
			fmt.Fprintf(c.stdout, " (%s)", l.Detail)
		}
		fmt.Fprintf(c.stdout, ", %d tickets pending\n", l.Pending)
		names := make([]string, 0, len(l.Locks))
		for n := range l.Locks {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(c.stdout, "    %-28s %s\n", n, l.Locks[n])
		}
	}
	fmt.Fprintln(c.stdout, "\nSEATS")
	c.printSeats(seats)
	fmt.Fprintln(c.stdout, "\nOPEN INCIDENTS")
	for _, s := range states {
		fmt.Fprintf(c.stdout, "  %-14s %d\n", s, counts[string(s)])
	}
	fmt.Fprintf(c.stdout, "\nKNOWN PROBLEMS (open merge requests): %d\n", len(known))
	return nil
}

func (c *cli) incidents() error {
	_, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	list, err := st.ListIncidents(store.IncidentFilter{Project: c.project, OpenOnly: !c.all})
	if err != nil {
		return err
	}
	if c.json {
		views := make([]incidentView, 0, len(list))
		for _, i := range list {
			views = append(views, view(i))
		}
		return c.printJSON(views)
	}
	if len(list) == 0 {
		fmt.Fprintln(c.stdout, "no incident")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tSEV\tPROJECT\tSOURCE\tPASSES\tSIGNALS\tOPENED\tSUMMARY")
	for _, i := range list {
		sum := i.Summary
		if r := []rune(sum); len(r) > 70 {
			sum = string(r[:69]) + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", i.ID, i.State, severity(i.Severity), i.Project, i.Source,
			i.Runs, i.SignalCount, stamp(i.OpenedAt), sum)
	}
	return tw.Flush()
}

// ---------- incident show / close / resume ----------

type runView struct {
	N         int       `json:"n"`
	Seat      string    `json:"seat"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
	Outcome   string    `json:"outcome,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Error     string    `json:"error,omitempty"`
	Turns     int       `json:"turns"`
	CostUSD   float64   `json:"cost_usd"`
}

func (c *cli) incidentShow(id string) error {
	d, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	inc, err := st.GetIncident(id)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no incident %s", id)
	}
	if err != nil {
		return err
	}
	runs, err := st.ListRuns(id)
	if err != nil {
		return err
	}
	var rv []runView
	for n, r := range runs {
		v := runView{N: n + 1, Seat: r.Seat, Status: string(r.Status), StartedAt: r.StartedAt, EndedAt: r.EndedAt,
			Error: r.Error, Turns: r.Turns, CostUSD: r.CostUSD}
		if r.Status == "" {
			v.Status = "running"
		}
		if r.Verdict != nil {
			v.Outcome, v.Summary = string(r.Verdict.Outcome), r.Verdict.Summary
		}
		rv = append(rv, v)
	}
	acts, _ := st.ListActions(id)
	journal, _ := incident.NewDossier(d.DataDir).Journal(id)
	if c.json {
		names := make([]string, 0, len(acts))
		for _, a := range acts {
			names = append(names, a.Name)
		}
		return c.printJSON(map[string]any{"incident": view(inc), "runs": rv, "actions": names, "journal": journal})
	}
	w := c.stdout
	fmt.Fprintf(w, "%s  %s  %s  %s\n%s\n\n", inc.ID, inc.State, severity(inc.Severity), inc.Project, inc.Summary)
	fmt.Fprintf(w, "source:       %s\nfingerprint:  %s\nrunbook:      %s\nsignals:      %d\npasses:       %d\nopened:       %s\nupdated:      %s\n",
		inc.Source, inc.Fingerprint, inc.Runbook, inc.SignalCount, inc.Runs, stamp(inc.OpenedAt), stamp(inc.UpdatedAt))
	if !inc.RecheckAt.IsZero() {
		fmt.Fprintf(w, "recheck at:   %s\n", stamp(inc.RecheckAt))
	}
	if inc.Ticket != "" {
		fmt.Fprintf(w, "ticket:       %s\n", inc.Ticket)
	}
	if !inc.ClosedAt.IsZero() {
		fmt.Fprintf(w, "closed:       %s (%s)\n", stamp(inc.ClosedAt), inc.CloseReason)
	}
	if inc.Mass {
		fmt.Fprintln(w, "mass:         yes (storm guard)")
	}
	if inc.Recurrent {
		fmt.Fprintln(w, "recurrent:    yes")
	}
	fmt.Fprintln(w, "\nPASSES")
	if len(rv) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, r := range rv {
		line := fmt.Sprintf("  %d  %s  seat %s  %s", r.N, stamp(r.StartedAt), r.Seat, r.Status)
		if r.Outcome != "" {
			line += "  verdict " + r.Outcome
		}
		if r.Turns > 0 {
			line += fmt.Sprintf("  %d turns  $%.2f", r.Turns, r.CostUSD)
		}
		if r.Error != "" {
			line += "  (" + r.Error + ")"
		}
		fmt.Fprintln(w, line)
	}
	if len(acts) > 0 {
		fmt.Fprintln(w, "\nACTIONS RUN")
		for _, a := range acts {
			fmt.Fprintf(w, "  %s  %s\n", stamp(a.At), a.Name)
		}
	}
	fmt.Fprintln(w, "\nJOURNAL")
	if strings.TrimSpace(journal) == "" {
		journal = "(empty)"
	}
	fmt.Fprintln(w, strings.TrimSpace(journal))
	return nil
}

// withdraw withdraws a pending green-light ticket through the read-only
// status socket (the only ticket operation DutyDesk has), best effort.
func (c *cli) withdraw(d *config.Daemon, repo *config.Repo, inc model.Incident, ticket string) {
	if ticket == "" {
		return
	}
	ws := ""
	if repo != nil {
		if p := repo.Project(inc.Project); p != nil {
			ws = p.Locks.Workspace
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lockcli.NewStatus(d.LoxStatusSocket).Withdraw(ctx, ws, ticket); err != nil {
		fmt.Fprintf(c.stderr, "warning: ticket %s was not withdrawn (%v); withdraw it with `lox withdraw`\n", ticket, err)
		return
	}
	fmt.Fprintf(c.stdout, "ticket %s withdrawn\n", ticket)
}

func (c *cli) incidentClose(id string) error {
	d, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	mgr, repo := c.manager(d, st)
	tr, err := mgr.Close(id, c.reason)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		return lifecycleError(id, err)
	}
	fmt.Fprintf(c.stdout, "%s: %s → resolved (%s)\n", id, tr.From, tr.Reason)
	c.withdraw(d, repo, tr.Incident, tr.WithdrawTicket)
	return nil
}

func (c *cli) incidentResume(id string) error {
	d, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	mgr, repo := c.manager(d, st)
	tr, err := mgr.Resume(id)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		return lifecycleError(id, err)
	}
	fmt.Fprintf(c.stdout, "%s: %s → queued; the daemon starts a new pass\n", id, tr.From)
	c.withdraw(d, repo, tr.Incident, tr.WithdrawTicket)
	return nil
}

func lifecycleError(id string, err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("no incident %s", id)
	case errors.Is(err, store.ErrStateConflict):
		return fmt.Errorf("%s cannot be changed in its current state (%v)", id, err)
	}
	return err
}

// ---------- check run ----------

func lockReader(d *config.Daemon) (*lockcli.Reader, error) {
	token, err := coreAgentToken(d.DataDir)
	if err != nil {
		return nil, err
	}
	return lockcli.NewReader(lockcli.Config{
		SQLPlan: d.LockClients.SQLPlan, SQLRun: d.LockClients.SQLRun, LogMCP: d.LockClients.LogMCP,
		Env: d.LockClients.Env, Timeout: d.LockClients.Timeout, Token: token,
	}), nil
}

func (c *cli) checkRun(id string) error {
	d, err := c.daemon()
	if err != nil {
		return err
	}
	repo, err := config.LoadRepo(d.ConfigRepo)
	if err != nil {
		return err
	}
	p := repo.Project(c.project)
	if p == nil {
		return fmt.Errorf("no project %q in %s", c.project, d.ConfigRepo)
	}
	var chk *model.Check
	for i := range p.Checks {
		if p.Checks[i].ID == id {
			chk = &p.Checks[i]
		}
	}
	if chk == nil {
		return fmt.Errorf("no check %q in project %s", id, p.Slug)
	}
	reader, err := lockReader(d)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := check.Run(ctx, *chk, p, reader, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "check %s/%s: %d signal(s)", p.Slug, chk.ID, len(res.Signals))
	if res.Truncated {
		fmt.Fprintf(c.stdout, " (truncated at %d rows)", check.MaxRows)
	}
	fmt.Fprintln(c.stdout)
	for _, s := range res.Signals {
		fmt.Fprintf(c.stdout, "  %s  [%s]  %s\n", s.Fingerprint, severity(s.Severity), s.Summary)
	}
	if c.dry {
		fmt.Fprintln(c.stdout, "dry run: nothing ingested")
		return nil
	}
	if len(res.Signals) == 0 {
		return nil
	}
	_, st, err := c.open()
	if err != nil {
		return err
	}
	defer st.Close()
	mgr, _ := c.manager(d, st)
	for _, s := range res.Signals {
		r, err := core.Ingest(mgr, p, s)
		if err != nil && !errors.Is(err, incident.ErrDossier) {
			return err
		}
		fmt.Fprintf(c.stdout, "  %s → %s (%s)\n", s.Fingerprint, r.Incident.ID, r.Kind)
	}
	return nil
}

// ---------- config ----------

func (c *cli) configDir() (string, *config.Daemon, error) {
	if c.dir != "" {
		// A daemon file is optional here: CI validates a bare config repository.
		if c.configPath != "" {
			d, err := c.daemon()
			return c.dir, d, err
		}
		return c.dir, nil, nil
	}
	d, err := c.daemon()
	if err != nil {
		return "", nil, fmt.Errorf("%w (or name the config repository directory)", err)
	}
	return d.ConfigRepo, d, nil
}

func (c *cli) configValidate() error {
	dir, d, err := c.configDir()
	if err != nil {
		return err
	}
	repo, err := config.LoadRepo(dir)
	if err == nil && d != nil {
		err = d.CheckRepo(repo)
	}
	if err == nil {
		// The lockssh rules must be derivable: CI publishes them for review.
		for _, p := range repo.Projects {
			install := actions.DefaultInstallDir
			if d != nil {
				install = d.ActionInstallDir
			}
			if _, rerr := actions.LockSSHRules(p, install); rerr != nil {
				err = errors.Join(err, fmt.Errorf("projects/%s: lockssh rules: %w", p.Slug, rerr))
			}
		}
	}
	if err != nil {
		n := len(strings.Split(err.Error(), "\n"))
		return fmt.Errorf("%s is not valid (%d problem(s)):\n%w", dir, n, err)
	}
	fmt.Fprintf(c.stdout, "%s: valid\n", dir)
	for _, p := range repo.Projects {
		own := 0
		for _, rb := range p.Runbooks {
			if rb.Project != "" {
				own++
			}
		}
		fmt.Fprintf(c.stdout, "  project %s: %d checks, %d runbooks (+%d standard), %d actions, %d webhooks\n",
			p.Slug, len(p.Checks), own, len(p.Runbooks)-own, len(p.Actions), len(p.Webhooks))
	}
	return nil
}

func (c *cli) locksshRules() error {
	dir, d, err := c.configDir()
	if err != nil {
		return err
	}
	repo, err := config.LoadRepo(dir)
	if err != nil {
		return err
	}
	p := repo.Project(c.project)
	if p == nil {
		return fmt.Errorf("no project %q in %s", c.project, dir)
	}
	install := c.installDir
	if install == "" {
		install = actions.DefaultInstallDir
		if d != nil {
			install = d.ActionInstallDir
		}
	}
	rules, err := actions.LockSSHRules(p, install)
	if err != nil {
		return err
	}
	fmt.Fprint(c.stdout, actions.RenderTOML(p.Slug, rules))
	return nil
}
