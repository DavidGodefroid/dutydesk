package lockcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeExec answers Run calls in order and records every command.
type fakeExec struct {
	mu      sync.Mutex
	cmds    []Cmd
	results []Result
	runErr  error
	block   bool // Run waits for ctx
	start   func(Cmd) (Process, error)
}

func (f *fakeExec) Run(ctx context.Context, c Cmd) (Result, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, c)
	i := len(f.cmds) - 1
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	if f.runErr != nil {
		return Result{}, f.runErr
	}
	if i >= len(f.results) {
		return Result{}, errors.New("unexpected command")
	}
	return f.results[i], nil
}

func (f *fakeExec) Start(_ context.Context, c Cmd) (Process, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, c)
	f.mu.Unlock()
	return f.start(c)
}

var project = &model.Project{Slug: "shop", Locks: model.Locks{Workspace: "/srv/locks/shop", SQL: "sql-prod", Log: "log-prod"}}

func TestSQLPlansThenRuns(t *testing.T) {
	fx := &fakeExec{results: []Result{{Stdout: golden(t, "plan_ok.json")}, {Stdout: golden(t, "run_rows.json")}}}
	r := NewReader(Config{Exec: fx, Token: "s3cret"})
	rows, err := r.SQL(context.Background(), project, "SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Row{
		{"job_id": "4812", "status": "running", "customer_email": "<redacted>", "started_at": "2026-11-18T05:02:11Z", "retries": "3", "big": "9007199254740993", "note": "NULL"},
		{"job_id": "4813", "status": "running", "customer_email": "<redacted>", "started_at": "2026-11-18T05:07:40Z", "retries": "0", "big": "12.50", "note": "a<b & c"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows:\n got %v\nwant %v", rows, want)
	}
	if len(fx.cmds) != 2 {
		t.Fatalf("commands: %d", len(fx.cmds))
	}
	plan, run := fx.cmds[0], fx.cmds[1]
	if got := strings.Join(plan.Argv, " "); got != "locksql plan --instance sql-prod --json -" {
		t.Errorf("plan argv: %s", got)
	}
	if string(plan.Stdin) != "SELECT 1" {
		t.Errorf("plan stdin: %q", plan.Stdin)
	}
	if got := strings.Join(run.Argv, " "); got != "locksql run --instance sql-prod --json 9f2c41d07ab35e68" {
		t.Errorf("run argv: %s", got)
	}
	for _, c := range fx.cmds {
		if c.Dir != "/srv/locks/shop" {
			t.Errorf("dir: %q", c.Dir)
		}
		env := strings.Join(c.Env, "\n")
		for _, w := range []string{"LEA_AGENT=dutydesk:core", "LEA_AGENT_TOKEN=s3cret"} {
			if !strings.Contains(env, w) {
				t.Errorf("env lacks %s", w)
			}
		}
		// The token is passed by name to docker, never by value in argv.
		if strings.Contains(strings.Join(c.Argv, " "), "s3cret") || strings.Contains(env, "-e LEA_AGENT_TOKEN=") {
			t.Errorf("the token leaks into a command line")
		}
	}
}

func TestSQLPendingIsNeedsDecision(t *testing.T) {
	fx := &fakeExec{results: []Result{{Stdout: golden(t, "plan_ok.json")}, {Stdout: golden(t, "run_pending.json")}}}
	_, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
	if !errors.Is(err, ErrNeedsDecision) {
		t.Fatalf("err = %v", err)
	}
	var nd *NeedsDecisionError
	if !errors.As(err, &nd) || nd.Ticket != "01JCQ8Z5T3M0V9K2R7XW4HN6PD" || nd.Instance != "sql-prod" {
		t.Fatalf("ticket: %+v", nd)
	}
}

func TestSQLFailures(t *testing.T) {
	t.Run("refused plan", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{Stdout: golden(t, "error_refused.json"), ExitCode: 1}}}
		_, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
		var ce *ClientError
		if !errors.As(err, &ce) || ce.Kind != "refused" || ce.Code != "E_PLACEHOLDER" || ce.Exit != 1 {
			t.Fatalf("err = %v", err)
		}
		if len(fx.cmds) != 1 {
			t.Fatal("run must not follow a refused plan")
		}
	})
	t.Run("no console", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{Stdout: golden(t, "error_no_console.json"), ExitCode: 2}}}
		_, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
		if !errors.Is(err, ErrNoConsole) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("usage without json", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{ExitCode: 3}}}
		_, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
		var ce *ClientError
		if !errors.As(err, &ce) || ce.Kind != "usage" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("refuse verdict without plan id", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{Stdout: []byte(`{"plan_id":"","verdict":"REFUSE"}`)}}}
		_, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
		var ce *ClientError
		if !errors.As(err, &ce) || len(fx.cmds) != 1 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("plan id that looks like an option", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{Stdout: []byte(`{"plan_id":"--profile","verdict":"OK"}`)}}}
		if _, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1"); err == nil || len(fx.cmds) != 1 {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate columns", func(t *testing.T) {
		fx := &fakeExec{results: []Result{{Stdout: golden(t, "plan_ok.json")}, {Stdout: []byte(`{"columns":["id","id"],"rows":[[1,2]]}`)}}}
		if _, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1"); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("no instance", func(t *testing.T) {
		_, err := NewReader(Config{Exec: &fakeExec{}}).SQL(context.Background(), &model.Project{}, "SELECT 1")
		if !errors.Is(err, ErrNoInstance) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		fx := &fakeExec{block: true}
		_, err := NewReader(Config{Exec: fx, Timeout: 20 * time.Millisecond}).SQL(context.Background(), project, "SELECT 1")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSQLEmptyResult(t *testing.T) {
	fx := &fakeExec{results: []Result{{Stdout: golden(t, "plan_ok.json")}, {Stdout: []byte(`{"columns":["id"],"rows":[],"truncated":false}`)}}}
	rows, err := NewReader(Config{Exec: fx}).SQL(context.Background(), project, "SELECT 1")
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
}

// ---------- fake locklog MCP server ----------

type pipeProc struct {
	inW  *io.PipeWriter
	outR *io.PipeReader
	once sync.Once
	stop func()
}

func (p *pipeProc) Stdin() io.WriteCloser { return p.inW }
func (p *pipeProc) Stdout() io.Reader     { return p.outR }
func (p *pipeProc) Close() error {
	p.once.Do(p.stop)
	return nil
}

type rpcReq struct {
	ID     *int            `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// mcpServer serves the handshake and answers each tools/call with the next
// of results. It records the tools/call params.
type mcpServer struct {
	results [][]byte
	silent  bool // never answers tools/call
	mu      sync.Mutex
	calls   []json.RawMessage
	seen    []string
}

func (s *mcpServer) start(Cmd) (Process, error) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	p := &pipeProc{inW: inW, outR: outR, stop: func() {
		inR.CloseWithError(io.ErrClosedPipe)
		outW.CloseWithError(io.EOF)
	}}
	go func() {
		defer outW.Close()
		sc := bufio.NewScanner(inR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		n := 0
		for sc.Scan() {
			var req rpcReq
			if json.Unmarshal(sc.Bytes(), &req) != nil {
				continue
			}
			s.mu.Lock()
			s.seen = append(s.seen, req.Method)
			s.mu.Unlock()
			switch req.Method {
			case "initialize":
				// A notification first: the client must skip it.
				io.WriteString(outW, `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}`+"\n")
				reply(outW, *req.ID, []byte(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"locklog mcp 0.4.1","version":"0.4.1"}}`))
			case "tools/call":
				s.mu.Lock()
				s.calls = append(s.calls, append(json.RawMessage(nil), req.Params...))
				s.mu.Unlock()
				if s.silent {
					continue
				}
				reply(outW, *req.ID, s.results[n])
				n++
			}
		}
	}()
	return p, nil
}

func reply(w io.Writer, id int, result []byte) {
	var compact json.RawMessage = result
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": compact})
	w.Write(append(b, '\n'))
}

func TestLogCount(t *testing.T) {
	srv := &mcpServer{results: [][]byte{golden(t, "count_complete.json")}}
	fx := &fakeExec{start: srv.start}
	n, err := NewReader(Config{Exec: fx}).LogCount(context.Background(), project, "PDF render failed", 15*time.Minute)
	if err != nil || n != 42 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if got := strings.Join(fx.cmds[0].Argv, " "); got != "locklog mcp --instance log-prod" {
		t.Errorf("argv: %s", got)
	}
	if got := strings.Join(srv.seen, ","); got != "initialize,notifications/initialized,tools/call" {
		t.Errorf("methods: %s", got)
	}
	var call struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(srv.calls[0], &call); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"text": "PDF render failed", "last": "900s"}
	if call.Name != "locklog_count" || !reflect.DeepEqual(call.Arguments, want) {
		t.Errorf("call: %s %v", call.Name, call.Arguments)
	}
}

func TestLogCountStructuredQueryAndCursor(t *testing.T) {
	srv := &mcpServer{results: [][]byte{golden(t, "count_partial.json"), golden(t, "count_complete.json")}}
	q := `{"sources":["nginx"],"where":[{"field":"status","op":">=","value":500}]}`
	n, err := NewReader(Config{Exec: &fakeExec{start: srv.start}}).LogCount(context.Background(), project, q, time.Hour)
	if err != nil || n != 42 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(srv.calls) != 2 {
		t.Fatalf("calls: %d", len(srv.calls))
	}
	var second struct {
		Arguments map[string]any `json:"arguments"`
	}
	json.Unmarshal(srv.calls[1], &second)
	if second.Arguments["cursor"] != "c-8f31" || second.Arguments["last"] != "3600s" || second.Arguments["sources"] == nil {
		t.Errorf("continuation arguments: %v", second.Arguments)
	}
}

func TestLogCountTextOnlyAnswer(t *testing.T) {
	srv := &mcpServer{results: [][]byte{golden(t, "count_text_only.json")}}
	n, err := NewReader(Config{Exec: &fakeExec{start: srv.start}}).LogCount(context.Background(), project, "x", time.Minute)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestLogCountRefused(t *testing.T) {
	srv := &mcpServer{results: [][]byte{golden(t, "count_refused.json")}}
	_, err := NewReader(Config{Exec: &fakeExec{start: srv.start}}).LogCount(context.Background(), project, "x", time.Minute)
	var ce *ClientError
	if !errors.As(err, &ce) || ce.Code != "E_PRODUCTION_HOST_AGENT" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(ce.Message, "\n") {
		t.Errorf("message keeps more than one line: %q", ce.Message)
	}
}

func TestLogCountIncompleteWithoutCursor(t *testing.T) {
	srv := &mcpServer{results: [][]byte{[]byte(`{"structuredContent":{"data":{"groups":[],"complete":false}}}`)}}
	_, err := NewReader(Config{Exec: &fakeExec{start: srv.start}}).LogCount(context.Background(), project, "x", time.Minute)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v", err)
	}
}

func TestLogCountTimeout(t *testing.T) {
	srv := &mcpServer{silent: true}
	start := time.Now()
	_, err := NewReader(Config{Exec: &fakeExec{start: srv.start}, Timeout: 50 * time.Millisecond}).LogCount(context.Background(), project, "x", time.Minute)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the call did not stop at its timeout")
	}
}

func TestLogArgsRefusesRangeAndGrouping(t *testing.T) {
	for _, q := range []string{`{"from":"2026-01-01T00:00:00Z"}`, `{"last":"24h"}`, `{"by":["status"]}`, `{"cursor":"x"}`, `{"bucket":"1m"}`, `{not json`, ``} {
		if _, err := logArgs(q, time.Minute); err == nil {
			t.Errorf("%s: want an error", q)
		}
	}
	if _, err := logArgs("x", 500*time.Millisecond); err == nil {
		t.Error("sub-second window: want an error")
	}
}

func TestOSExec(t *testing.T) {
	ctx := context.Background()
	res, err := OSExec{}.Run(ctx, Cmd{Argv: []string{"sh", "-c", `cat; printf "%s" "$DD_TEST"; exit 2`}, Env: []string{"DD_TEST=!"}, Stdin: []byte("in")})
	if err != nil || string(res.Stdout) != "in!" || res.ExitCode != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := (OSExec{}).Run(ctx, Cmd{Argv: []string{"/nonexistent/dutydesk-client"}}); err == nil {
		t.Fatal("want an error for a missing program")
	}
	p, err := OSExec{}.Start(ctx, Cmd{Argv: []string{"cat"}})
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(p.Stdin(), "ping\n")
	line, err := bufio.NewReader(p.Stdout()).ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	p.Close()
	p.Close()
}
