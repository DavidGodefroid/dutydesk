package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/forge"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/notify"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// Secrets of the test world. None may ever show up in a journal, an alert,
// the database or a remote repository.
const (
	seatTokenA   = "sk-ant-oat01-seat-a-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	seatTokenB   = "sk-ant-oat01-seat-b-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	forgeToken   = "glpat-forge-service-account-0123456789"
	configToken  = "glpat-config-service-account-9876543210"
	sentrySecret = "sentry-client-secret-e2e"
)

var t0 = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)

const stuckSpec = "*/5 * * * *" // schedule of the example's stuck-job check

// ---------- controllable clock ----------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// ---------- fake cron: the test fires the schedules ----------

type fakeCron struct {
	mu      sync.Mutex
	jobs    map[string][]func()
	started bool
}

func (f *fakeCron) Add(spec string, job func()) error {
	if err := check.ValidSchedule(spec); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.jobs == nil {
		f.jobs = map[string][]func(){}
	}
	f.jobs[spec] = append(f.jobs[spec], job)
	return nil
}
func (f *fakeCron) Start() { f.mu.Lock(); f.started = true; f.mu.Unlock() }
func (f *fakeCron) Stop()  { f.mu.Lock(); f.started = false; f.mu.Unlock() }

type cronSet struct {
	mu   sync.Mutex
	list []*fakeCron
}

func (c *cronSet) new() check.Cron {
	f := &fakeCron{}
	c.mu.Lock()
	c.list = append(c.list, f)
	c.mu.Unlock()
	return f
}

// fire runs the jobs of spec on the started cron, synchronously.
func (c *cronSet) fire(spec string) int {
	c.mu.Lock()
	list := append([]*fakeCron(nil), c.list...)
	c.mu.Unlock()
	n := 0
	for _, f := range list {
		f.mu.Lock()
		var jobs []func()
		if f.started {
			jobs = f.jobs[spec]
		}
		f.mu.Unlock()
		for _, j := range jobs {
			j()
			n++
		}
	}
	return n
}

// ---------- fake locks ----------

type fakeReader struct {
	mu    sync.Mutex
	rows  []model.Row
	count int
	calls int
	// block makes every SQL call wait until it is closed (a slow lock).
	block   chan struct{}
	live    int
	maxLive int
}

func (r *fakeReader) SQL(ctx context.Context, _ *model.Project, query string) ([]model.Row, error) {
	r.mu.Lock()
	block := r.block
	r.live++
	if r.live > r.maxLive {
		r.maxLive = r.live
	}
	r.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.live--
	r.calls++
	if !strings.Contains(query, "FROM jobs") {
		return []model.Row{{"id": "1"}}, nil // the morning load is there
	}
	return append([]model.Row(nil), r.rows...), nil
}

func (r *fakeReader) LogCount(context.Context, *model.Project, string, time.Duration) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.count, nil
}

func (r *fakeReader) set(rows ...model.Row) {
	r.mu.Lock()
	r.rows = rows
	r.mu.Unlock()
}

func (r *fakeReader) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func job(id string) model.Row {
	return model.Row{"job_id": id, "job_kind": "export", "started_at": "2026-11-18 08:10:00"}
}

type fakeStatus struct {
	mu        sync.Mutex
	serving   bool
	locks     map[string]string
	tickets   map[string]model.TicketState
	withdrawn []string
	always    model.TicketState // state of a ticket that was not set, "" = unknown
}

func (f *fakeStatus) Health(context.Context, string) (model.LockHealth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return model.LockHealth{Serving: f.serving, Locks: f.locks}, nil
}

func (f *fakeStatus) Ticket(_ context.Context, _, ticket string) (model.TicketState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st, ok := f.tickets[ticket]; ok {
		return st, nil
	}
	if f.always != "" {
		return f.always, nil
	}
	return model.TicketUnknown, nil
}

func (f *fakeStatus) Withdraw(_ context.Context, _, ticket string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.withdrawn = append(f.withdrawn, ticket)
	return nil
}

func (f *fakeStatus) setServing(v bool) { f.mu.Lock(); f.serving = v; f.mu.Unlock() }
func (f *fakeStatus) setTicket(id string, st model.TicketState) {
	f.mu.Lock()
	f.tickets[id] = st
	f.mu.Unlock()
}
func (f *fakeStatus) withdrawnTickets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.withdrawn...)
}

// ---------- scripted agent ----------

// step plays one agent pass: it may edit the mounted clones, like an agent.
type step func(req model.RunRequest) model.RunResult

type fakeLauncher struct {
	t        *testing.T
	mu       sync.Mutex
	script   []step
	fallback step
	reqs     []model.RunRequest
	live     int
	maxLive  int
	// hang makes every pass wait until the daemon cancels it.
	hang bool
	// reader is the production the agent acts on: a pass that answers
	// "resolved" really fixed the condition (the deterministic check no
	// longer fires), unless lies is set.
	reader *fakeReader
	lies   bool
}

func (l *fakeLauncher) queue(steps ...step) {
	l.mu.Lock()
	l.script = append(l.script, steps...)
	l.mu.Unlock()
}

func (l *fakeLauncher) Run(ctx context.Context, req model.RunRequest) model.RunResult {
	l.mu.Lock()
	l.reqs = append(l.reqs, req)
	l.live++
	if l.live > l.maxLive {
		l.maxLive = l.live
	}
	var st step
	if len(l.script) > 0 {
		st, l.script = l.script[0], l.script[1:]
	} else {
		st = l.fallback
	}
	l.mu.Unlock()
	defer func() { l.mu.Lock(); l.live--; l.mu.Unlock() }()
	if st == nil {
		l.t.Errorf("unscripted agent pass for %s (run %d)", req.Incident.ID, req.Run)
		return model.RunResult{Status: model.RunFailed, Error: "unscripted pass"}
	}
	l.mu.Lock()
	hang := l.hang
	l.mu.Unlock()
	if hang {
		<-ctx.Done()
	}
	if ctx.Err() != nil {
		return model.RunResult{Status: model.RunCancelled, Error: "pass cancelled; container killed"}
	}
	res := st(req)
	l.mu.Lock()
	honest := l.reader != nil && !l.lies
	l.mu.Unlock()
	if honest && res.Verdict != nil && res.Verdict.Outcome == model.OutcomeResolved {
		l.reader.set()
	}
	return res
}

func (l *fakeLauncher) requests() []model.RunRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]model.RunRequest(nil), l.reqs...)
}

func (l *fakeLauncher) passes() int { return len(l.requests()) }

func verdict(v model.Verdict) step {
	return func(model.RunRequest) model.RunResult {
		if v.Confidence == "" {
			v.Confidence = "medium"
		}
		c := v
		return model.RunResult{Status: model.RunOK, Verdict: &c, Turns: 7, CostUSD: 0.12, InputTok: 1200, OutputTok: 300}
	}
}

// ---------- fake container runtime ----------

type fakeRuntime struct {
	mu    sync.Mutex
	names string
	rm    []string
	stuck map[string]bool // containers `rm -f` does not remove
}

func (f *fakeRuntime) Run(_ context.Context, c agent.Command) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch c.Args[0] {
	case "ps":
		io.WriteString(c.Stdout, f.names)
	case "rm":
		f.rm = append(f.rm, c.Args[2:]...)
	case "inspect":
		if f.stuck[c.Args[len(c.Args)-1]] {
			io.WriteString(c.Stdout, "[{}]")
			return 0, nil
		}
		io.WriteString(c.Stderr, "Error: no such container")
		return 125, nil
	}
	return 0, nil
}

func (f *fakeRuntime) setStuck(name string, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stuck == nil {
		f.stuck = map[string]bool{}
	}
	f.stuck[name] = v
}

func (f *fakeRuntime) removed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.rm...)
}

// ---------- fake GitLab ----------

type mrCall struct {
	Project string
	Body    map[string]any
}

type fakeGitLab struct {
	*httptest.Server
	mu     sync.Mutex
	opened []mrCall
	states map[string]string // "<project>!<iid>" -> state
	// down makes the API answer 503 to everything (the forge is unreachable).
	down bool
}

func newFakeGitLab(t *testing.T) *fakeGitLab {
	g := &fakeGitLab{states: map[string]string{}}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		// /api/v4/projects/<url-escaped path>/merge_requests[/<iid>]
		rest := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v4/projects/")
		parts := strings.Split(rest, "/")
		project := strings.ReplaceAll(parts[0], "%2F", "/")
		w.Header().Set("Content-Type", "application/json")
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case g.down:
			http.Error(w, `{"message":"503 down"}`, http.StatusServiceUnavailable)
		case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "merge_requests":
			// Open merge requests of a source branch.
			list := []map[string]any{}
			for i, c := range g.opened {
				if c.Project == project && c.Body["source_branch"] == r.URL.Query().Get("source_branch") &&
					g.states[fmt.Sprintf("%s!%d", project, i+1)] == "opened" {
					list = append(list, map[string]any{"iid": i + 1, "state": "opened", "source_branch": c.Body["source_branch"],
						"web_url": fmt.Sprintf("https://gitlab.example.com/%s/-/merge_requests/%d", project, i+1)})
				}
			}
			json.NewEncoder(w).Encode(list)
		case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "merge_requests":
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			g.opened = append(g.opened, mrCall{Project: project, Body: body})
			iid := len(g.opened)
			g.states[fmt.Sprintf("%s!%d", project, iid)] = "opened"
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"iid": iid, "state": "opened", "source_branch": body["source_branch"],
				"web_url": fmt.Sprintf("https://gitlab.example.com/%s/-/merge_requests/%d", project, iid)})
		case r.Method == http.MethodGet && len(parts) == 3 && parts[1] == "merge_requests":
			var iid int
			fmt.Sscanf(parts[2], "%d", &iid)
			json.NewEncoder(w).Encode(map[string]any{"iid": iid, "state": g.states[project+"!"+parts[2]],
				"web_url": fmt.Sprintf("https://gitlab.example.com/%s/-/merge_requests/%d", project, iid)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGitLab) calls() []mrCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]mrCall(nil), g.opened...)
}

func (g *fakeGitLab) setDown(v bool) { g.mu.Lock(); g.down = v; g.mu.Unlock() }

func (g *fakeGitLab) setState(project string, iid int, state string) {
	g.mu.Lock()
	g.states[fmt.Sprintf("%s!%d", project, iid)] = state
	g.mu.Unlock()
}

// ---------- the world ----------

type world struct {
	t        *testing.T
	dir      string
	daemon   *config.Daemon
	clock    *fakeClock
	crons    *cronSet
	reader   *fakeReader
	status   *fakeStatus
	agent    *fakeLauncher
	rec      *notify.Recorder
	gitlab   *fakeGitLab
	appBare  string
	confBare string
	logs     *syncBuffer

	svc    *Service
	cancel context.CancelFunc
	done   chan error
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.com", "GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// bareFrom makes a bare repository whose main branch holds the content of src.
func bareFrom(t *testing.T, root, name, src string) string {
	t.Helper()
	bare := filepath.Join(root, name+".git")
	git(t, root, "init", "-q", "--bare", "--initial-branch=main", bare)
	git(t, src, "init", "-q", "--initial-branch=main")
	git(t, src, "add", "-A")
	git(t, src, "commit", "-q", "-m", "initial")
	git(t, src, "push", "-q", bare, "main")
	return bare
}

func branches(t *testing.T, bare string) []string {
	t.Helper()
	return strings.Fields(git(t, bare, "for-each-ref", "--format=%(refname:short)", "refs/heads"))
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, _ := d.Info()
		return os.WriteFile(filepath.Join(dst, rel), data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

type worldOpt func(w *world, projectYAML *string)

// newWorld builds everything around the service: the example configuration
// copied and adapted, served from a local bare repository; a project
// repository; a fake GitLab; two seats; fake locks and a scripted agent.
func newWorld(t *testing.T, opts ...worldOpt) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, dir: dir, clock: &fakeClock{now: t0}, crons: &cronSet{}, reader: &fakeReader{},
		status: &fakeStatus{serving: true, tickets: map[string]model.TicketState{}},
		rec:    &notify.Recorder{}, gitlab: newFakeGitLab(t), logs: &syncBuffer{}}
	w.agent = &fakeLauncher{t: t, reader: w.reader}

	secrets := filepath.Join(dir, "secrets")
	writeFile(t, filepath.Join(secrets, "seat-a.token"), seatTokenA+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "seat-b.token"), seatTokenB+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "forge.token"), forgeToken+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "config.token"), configToken+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "sentry.secret"), sentrySecret+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "alerts.url"), "https://alerts.example.com/hook/abcdef\n", 0o600)

	// The project's code repository.
	appSrc := filepath.Join(dir, "app-src")
	writeFile(t, filepath.Join(appSrc, "README.md"), "docflow\n", 0o644)
	writeFile(t, filepath.Join(appSrc, "src", "worker.txt"), "retry = never\n", 0o644)
	w.appBare = bareFrom(t, dir, "app", appSrc)

	// The example configuration, adapted to this world.
	confSrc := filepath.Join(dir, "config-src")
	copyTree(t, filepath.Join("..", "..", "example", "config"), confSrc)
	pfile := filepath.Join(confSrc, "projects", "docflow", "project.yaml")
	raw, err := os.ReadFile(pfile)
	if err != nil {
		t.Fatal(err)
	}
	py := string(raw)
	for old, new := range map[string]string{
		"/etc/dutydesk/secrets/gitlab-docflow.token": filepath.Join(secrets, "forge.token"),
		"/etc/dutydesk/secrets/docflow-alerts.url":   filepath.Join(secrets, "alerts.url"),
		"/srv/locks/docflow":                         filepath.Join(dir, "locks"),
	} {
		if !strings.Contains(py, old) {
			t.Fatalf("example project.yaml no longer holds %q", old)
		}
		py = strings.ReplaceAll(py, old, new)
	}
	py += "\nwebhooks:\n  sentry:\n    kind: sentry\n    secret_file: " + filepath.Join(secrets, "sentry.secret") + "\n    severity: high\n"

	w.daemon = &config.Daemon{
		DataDir:    filepath.Join(dir, "data"),
		ConfigRepo: filepath.Join(dir, "config"),
		Runtime:    "podman", AgentImage: "dutydesk-agent:test",
		LoxStatusSocket: filepath.Join(dir, "status.sock"), ActionInstallDir: "/opt/dutydesk/bin",
		Seats: []model.Seat{
			{Name: "seat-a", TokenFile: filepath.Join(secrets, "seat-a.token"), MaxParallel: 1},
			{Name: "seat-b", TokenFile: filepath.Join(secrets, "seat-b.token"), MaxParallel: 1},
		},
		MaxParallelRuns: 2,
	}
	for _, o := range opts {
		o(w, &py)
	}
	writeFile(t, pfile, py, 0o644)
	w.confBare = bareFrom(t, dir, "config-remote", confSrc)
	git(t, dir, "clone", "-q", w.confBare, w.daemon.ConfigRepo)
	w.daemon.ConfigRemote = &config.Remote{URL: "file://" + w.confBare, Branch: "main",
		TokenFile: filepath.Join(secrets, "config.token"), Forge: "gitlab", Project: "ops/dutydesk-config"}
	return w
}

func withProjectYAML(old, new string) worldOpt {
	return func(w *world, py *string) {
		if !strings.Contains(*py, old) {
			w.t.Fatalf("project.yaml does not hold %q", old)
		}
		*py = strings.Replace(*py, old, new, 1)
	}
}

// start builds and runs the service.
func (w *world) start() { w.t.Helper(); w.startWith(nil) }

func (w *world) startWith(tune func(*Options)) {
	w.t.Helper()
	o := Options{
		Daemon: w.daemon, Reader: w.reader, Status: w.status, Launcher: w.agent, Notifier: w.rec,
		ForgeConfig: forge.Config{AllowLocal: true, TempDir: w.t.TempDir(),
			APIBase: map[string]string{"gitlab": w.gitlab.URL + "/api/v4"}},
		LoadRepo: func(dir string) (*config.Repo, error) {
			repo, err := config.LoadRepo(dir)
			if err == nil {
				// The loader only accepts https clone URLs; the test forge is a local bare repository.
				for _, p := range repo.Projects {
					for i := range p.Repos {
						p.Repos[i].URL = "file://" + w.appBare
					}
				}
			}
			return repo, err
		},
		Now:    w.clock.Now,
		Logger: slog.New(slog.NewTextHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Tick:   3 * time.Millisecond,
		Periods: Periods{Health: -1, Tickets: -1, Cleared: -1, KnownProblems: -1, Reminders: -1, RecheckRetry: -1,
			ConfigSync: 10000 * time.Hour},
		NewCron: w.crons.new, CheckJitter: -1,
	}
	if tune != nil {
		tune(&o)
	}
	svc, err := New(o)
	if err != nil {
		w.t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.svc, w.cancel, w.done = svc, cancel, make(chan error, 1)
	go func() { w.done <- svc.Run(ctx) }()
	w.t.Cleanup(w.stop)
	// The scheduler and the lock gate are up once a first turn has run.
	w.eventually("service up", func() bool { return svc.Healthy() && w.cronStarted() && svc.gateKnown() })
}

func (w *world) cronStarted() bool {
	w.crons.mu.Lock()
	defer w.crons.mu.Unlock()
	for _, f := range w.crons.list {
		f.mu.Lock()
		on := f.started
		f.mu.Unlock()
		if on {
			return true
		}
	}
	return false
}

func (w *world) stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	select {
	case err := <-w.done:
		if err != nil {
			w.t.Errorf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		w.t.Errorf("the service did not stop")
	}
	w.cancel = nil
	if w.t.Failed() {
		w.t.Logf("service log:\n%s", w.logs.String())
	}
}

// reader opens the database read-only-style for assertions once stopped, or
// uses the live store.
func (w *world) store() *store.Store { return w.svc.Store() }

func (w *world) eventually(what string, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatalf("timeout waiting for: %s\nalerts: %v\nlog:\n%s", what, w.rec.Kinds(), w.logs.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// settle lets the owed effects go out (when they can) and the loops turn a
// few times before a negative assertion.
func (w *world) settle() {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if owed, err := w.store().PendingEffects(""); err != nil || len(owed) == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(40 * time.Millisecond)
}

// gateKnown reports whether the lock gate was polled once.
func (s *Service) gateKnown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gate) > 0
}

func (w *world) incidents() []model.Incident {
	w.t.Helper()
	list, err := w.store().ListIncidents(store.IncidentFilter{})
	if err != nil {
		w.t.Fatal(err)
	}
	return list
}

func (w *world) incident(id string) model.Incident {
	w.t.Helper()
	inc, err := w.store().GetIncident(id)
	if err != nil {
		w.t.Fatalf("incident %s: %v", id, err)
	}
	return inc
}

func (w *world) waitState(id string, want model.IncidentState) model.Incident {
	w.t.Helper()
	// The incident is returned as it was seen in the state: it may move on
	// at once (an escalated incident whose condition cleared is closed).
	var seen model.Incident
	w.eventually(fmt.Sprintf("%s in state %s", id, want), func() bool {
		inc, err := w.store().GetIncident(id)
		seen = inc
		return err == nil && inc.State == want
	})
	return seen
}

func (w *world) waitIncidents(n int) {
	w.t.Helper()
	w.eventually(fmt.Sprintf("%d incidents", n), func() bool {
		list, err := w.store().ListIncidents(store.IncidentFilter{})
		return err == nil && len(list) >= n
	})
}

func (w *world) waitAlerts(n int) {
	w.t.Helper()
	w.eventually(fmt.Sprintf("%d alerts", n), func() bool { return len(w.rec.Sent()) >= n })
}

func (w *world) journal(id string) string {
	w.t.Helper()
	text, err := w.svc.Manager().Dossier().Journal(id)
	if err != nil {
		w.t.Fatal(err)
	}
	return text
}

func (w *world) wantKinds(want ...model.AlertKind) {
	w.t.Helper()
	got := w.rec.Kinds()
	if len(got) != len(want) {
		w.t.Fatalf("alerts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			w.t.Fatalf("alerts = %v, want %v", got, want)
		}
	}
}

func (w *world) wantJournal(id string, parts ...string) {
	w.t.Helper()
	// The journal is written right after the transaction of a transition:
	// it is given a moment.
	deadline := time.Now().Add(2 * time.Second)
	for {
		text := w.journal(id)
		var missing []string
		for _, p := range parts {
			if !strings.Contains(text, p) {
				missing = append(missing, p)
			}
		}
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			for _, p := range missing {
				w.t.Errorf("journal of %s lacks %q:\n%s", id, p, text)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// noSecrets checks that no secret of the world reached a journal, an alert,
// a log line, the database or a remote repository.
func (w *world) noSecrets() {
	w.t.Helper()
	secrets := map[string]string{"seat token A": seatTokenA, "seat token B": seatTokenB, "forge token": forgeToken,
		"config token": configToken, "sentry secret": sentrySecret}
	for _, inc := range w.incidents() {
		secrets["agent token of "+inc.ID] = inc.AgentToken
	}
	hay := map[string]string{"log": w.logs.String()}
	for _, inc := range w.incidents() {
		hay["journal of "+inc.ID] = w.journal(inc.ID)
		dir, _ := w.svc.Manager().Dossier().Dir(inc.ID)
		if b, err := os.ReadFile(filepath.Join(dir, "incident.json")); err == nil {
			hay["incident.json of "+inc.ID] = string(b)
		}
		runs, _ := w.store().ListRuns(inc.ID)
		for _, r := range runs {
			b, _ := json.Marshal(r)
			hay[fmt.Sprintf("run %d of %s", r.ID, inc.ID)] = string(b)
		}
		copyInc := inc
		copyInc.AgentToken = "" // its only legitimate place
		b, _ := json.Marshal(copyInc)
		hay["row of "+inc.ID] = string(b)
	}
	for i, s := range w.rec.Sent() {
		b, _ := json.Marshal(s.Alert)
		hay[fmt.Sprintf("alert %d (%s)", i, s.Alert.Kind)] = string(b)
	}
	for _, call := range w.gitlab.calls() {
		b, _ := json.Marshal(call.Body)
		hay["merge request on "+call.Project] = string(b)
	}
	for _, bare := range []string{w.appBare, w.confBare} {
		for _, br := range branches(w.t, bare) {
			hay["branch "+br+" of "+filepath.Base(bare)] = git(w.t, bare, "log", "-p", "--format=%B", br)
		}
	}
	for where, text := range hay {
		for name, sec := range secrets {
			if sec != "" && strings.Contains(text, sec) {
				w.t.Errorf("%s appears in %s", name, where)
			}
		}
	}
}

// restart stops the service cleanly and starts a new one on the same data
// directory: a new store handle, a new forge (no memory of the clones), a
// new scripted agent.
func (w *world) restart(tune func(*Options)) *world {
	w.t.Helper()
	w.stop()
	w2 := *w
	w2.agent = &fakeLauncher{t: w.t, reader: w.reader}
	w2.crons = &cronSet{}
	w2.startWith(tune)
	return &w2
}

// flaky is a notifier whose channel can be down.
type flaky struct {
	mu   sync.Mutex
	down bool
	fail int
	next model.Notifier
}

func (f *flaky) Send(ctx context.Context, p *model.Project, a model.Alert) error {
	f.mu.Lock()
	down := f.down
	if down {
		f.fail++
	}
	f.mu.Unlock()
	if down {
		return fmt.Errorf("notify: webhook answered HTTP 503")
	}
	return f.next.Send(ctx, p, a)
}

func (f *flaky) set(down bool) { f.mu.Lock(); f.down = down; f.mu.Unlock() }
func (f *flaky) failures() int { f.mu.Lock(); defer f.mu.Unlock(); return f.fail }
