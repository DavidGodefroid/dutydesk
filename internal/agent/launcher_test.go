package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const (
	seatToken  = "sk-ant-oat01-SEAT-TOKEN-do-not-leak"
	agentToken = "agent-secret-7f3a9c"
)

type fakeTokens struct {
	token string
	err   error
}

func (f fakeTokens) Token(string) (string, error) { return f.token, f.err }

// fakeRuntime writes a shell script standing for the container runtime. On
// `run` it records its arguments, stdin and the env-file (content and mode),
// prints the canned transcript and exits with the canned code; with a "sleep"
// marker it hangs instead. On `kill` it only records the call.
type fakeRuntime struct {
	dir    string
	script string
}

func newFakeRuntime(t *testing.T) *fakeRuntime {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "runtime")
	body := `#!/bin/sh
D='` + dir + `'
if [ "$1" = kill ]; then
  printf '%s\n' "$*" >> "$D/kill.log"
  exit 0
fi
printf '%s\n' "$@" > "$D/argv"
prev=
for a in "$@"; do
  if [ "$prev" = --env-file ]; then
    stat -c %a "$a" > "$D/envmode"
    cp "$a" "$D/envcopy"
    printf '%s' "$a" > "$D/envpath"
  fi
  prev=$a
done
cat > "$D/stdin"
if [ -f "$D/sleep" ]; then
  exec sleep 30
fi
[ -f "$D/stdout" ] && cat "$D/stdout"
[ -f "$D/stderr" ] && cat "$D/stderr" >&2
exit "$(cat "$D/exit" 2>/dev/null || echo 0)"
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return &fakeRuntime{dir: dir, script: script}
}

func (f *fakeRuntime) set(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeRuntime) get(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatalf("fake runtime left no %s: %v", name, err)
	}
	return string(b)
}

type fixture struct {
	rt  *fakeRuntime
	l   *Launcher
	req model.RunRequest
	tmp string
}

func newFixture(t *testing.T, mut func(*Config)) *fixture {
	t.Helper()
	rt := newFakeRuntime(t)
	base := t.TempDir()
	mk := func(name string) string {
		p := filepath.Join(base, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mcp := filepath.Join(base, "mcp.json")
	if err := os.WriteFile(mcp, []byte(`{"mcpServers":{"locksql-docflow":{"command":"/opt/locks/locksql"},"lockssh-actions":{"command":"/opt/locks/lockssh"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Runtime: rt.script, Image: "dutydesk-agent:test", Network: "dutydesk-agents",
		HTTPSProxy: "http://egress:3128", MCPConfigPath: mcp,
		ExtraMounts: []string{"/run/locks/{project}/{action_instance}:/run/locks", "/opt/locks:/opt/locks:ro"},
		RunArgs:     []string{"--userns=keep-id:uid=10001,gid=10001"},
		Model:       "sonnet", KillGrace: 200 * time.Millisecond, TempDir: mk("tmp"),
		Tokens: fakeTokens{token: seatToken + "\n"},
		Now:    func() time.Time { return time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC) },
	}
	if mut != nil {
		mut(&cfg)
	}
	l, err := NewLauncher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{rt: rt, l: l, tmp: cfg.TempDir, req: model.RunRequest{
		Incident: model.Incident{ID: "INC-000123", Runs: 1, AgentToken: agentToken},
		Run:      2,
		Project: &model.Project{Slug: "docflow", Limits: model.Limits{
			MaxTurns: 40, RunTimeout: 20 * time.Second,
		}},
		Runbook:    model.Runbook{ID: "stuck-job", ActionInstance: "actions-stuck-job"},
		Seat:       model.Seat{Name: "seat-a"},
		Prompt:     "investigate INC-000123",
		DossierDir: mk("dossier"),
		RepoDirs:   map[string]string{"worker": mk("worker"), "app": mk("app")},
		ConfigDir:  mk("config"),
		OutDir:     filepath.Join(base, "out", "run-2"),
	}}
}

func (f *fixture) run(t *testing.T) model.RunResult {
	t.Helper()
	return f.l.Run(context.Background(), f.req)
}

func (f *fixture) assertEnvFileGone(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(f.tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("env-file not cleaned up: %d file(s) left in %s", len(entries), f.tmp)
	}
}

const initLine = `{"type":"system","subtype":"init","session_id":"s1","tools":["Read"]}` + "\n"

func resultLine(extra string) string {
	return `{"type":"result","subtype":"success","is_error":false,"num_turns":7,"total_cost_usd":0.42,` +
		`"usage":{"input_tokens":1000,"output_tokens":300,"cache_creation_input_tokens":200,"cache_read_input_tokens":5000},` +
		extra + `}` + "\n"
}

func TestRunSuccessStructuredOutput(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", initLine+
		`{"type":"assistant","message":{"content":[{"type":"text","text":"reading"}]}}`+"\n"+
		resultLine(`"result":"done","structured_output":{"outcome":"recheck","summary":"Job still progressing.","recheck_minutes":20,"confidence":"medium"}`))
	res := f.run(t)
	if res.Status != model.RunOK {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	if res.Verdict == nil || res.Verdict.Outcome != model.OutcomeRecheck || res.Verdict.RecheckMinutes != 20 {
		t.Fatalf("verdict = %+v", res.Verdict)
	}
	if res.CostUSD != 0.42 || res.Turns != 7 || res.InputTok != 6200 || res.OutputTok != 300 {
		t.Errorf("accounting = cost %v turns %d in %d out %d", res.CostUSD, res.Turns, res.InputTok, res.OutputTok)
	}
	if !res.QuotaReset.IsZero() {
		t.Errorf("unexpected quota reset %v", res.QuotaReset)
	}

	// Files written in OutDir.
	tr, err := os.ReadFile(filepath.Join(f.req.OutDir, "transcript.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(tr), "\n"); got != 3 {
		t.Errorf("transcript has %d lines, want 3", got)
	}
	vb, err := os.ReadFile(filepath.Join(f.req.OutDir, "verdict.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := ParseVerdict(vb); err != nil || v.Summary != "Job still progressing." {
		t.Errorf("verdict.json = %s (%v)", vb, err)
	}
	for _, name := range []string{"transcript.jsonl", "verdict.json"} {
		st, _ := os.Stat(filepath.Join(f.req.OutDir, name))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o", name, st.Mode().Perm())
		}
	}

	// The prompt went through stdin.
	if got := f.rt.get(t, "stdin"); got != f.req.Prompt {
		t.Errorf("stdin = %q", got)
	}

	// Env-file: owner-only while the container runs, removed afterwards.
	if mode := strings.TrimSpace(f.rt.get(t, "envmode")); mode != "600" {
		t.Errorf("env-file mode = %s, want 600", mode)
	}
	env := f.rt.get(t, "envcopy")
	for _, want := range []string{
		"CLAUDE_CODE_OAUTH_TOKEN=" + seatToken + "\n",
		"LEA_AGENT=dutydesk:INC-000123\n",
		"LEA_AGENT_TOKEN=" + agentToken + "\n",
		"HTTPS_PROXY=http://egress:3128\n",
		"https_proxy=http://egress:3128\n",
		"HOME=/home/agent\n",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("env-file lacks %q", want)
		}
	}
	if _, err := os.Stat(f.rt.get(t, "envpath")); !os.IsNotExist(err) {
		t.Errorf("env-file still exists after the run (err=%v)", err)
	}
	f.assertEnvFileGone(t)
}

func TestRunArgs(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", resultLine(`"structured_output":{"outcome":"resolved","summary":"ok","confidence":"high"}`))
	if res := f.run(t); res.Status != model.RunOK {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	argv := strings.Split(strings.TrimSuffix(f.rt.get(t, "argv"), "\n"), "\n")
	joined := strings.Join(argv, " ")

	// No secret on the command line.
	for _, secret := range []string{seatToken, agentToken, "CLAUDE_CODE_OAUTH_TOKEN", "LEA_AGENT_TOKEN"} {
		if strings.Contains(joined, secret) {
			t.Errorf("argv leaks %q", secret)
		}
	}
	if strings.Contains(joined, f.req.Prompt) {
		t.Error("the prompt is on argv; it must go on stdin")
	}

	pair := func(flag, value string) bool {
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == flag && argv[i+1] == value {
				return true
			}
		}
		return false
	}
	has := func(flag string) bool {
		for _, a := range argv {
			if a == flag {
				return true
			}
		}
		return false
	}
	if argv[0] != "run" {
		t.Fatalf("argv[0] = %q", argv[0])
	}
	for _, flag := range []string{"--rm", "-i", "--read-only", "--strict-mcp-config", "-p", "--verbose", "--userns=keep-id:uid=10001,gid=10001"} {
		if !has(flag) {
			t.Errorf("argv lacks %s", flag)
		}
	}
	d := f.req
	for _, p := range [][2]string{
		{"--name", "dutydesk-inc-000123-2"},
		{"--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777"},
		{"--tmpfs", "/home/agent:rw,nosuid,nodev,size=256m,mode=1777"},
		{"--user", "10001:10001"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--memory", "4g"},
		{"--cpus", "2"},
		{"--pids-limit", "512"},
		{"--network", "dutydesk-agents"},
		{"--workdir", "/work"},
		{"-v", d.DossierDir + ":/work/dossier:ro"},
		{"-v", d.RepoDirs["app"] + ":/work/repos/app:rw"},
		{"-v", d.RepoDirs["worker"] + ":/work/repos/worker:rw"},
		{"-v", d.ConfigDir + ":/work/config:rw"},
		{"-v", f.l.cfg.MCPConfigPath + ":/etc/dutydesk/mcp.json:ro"},
		{"-v", "/run/locks/docflow/actions-stuck-job:/run/locks:ro"},
		{"-v", "/opt/locks:/opt/locks:ro"},
		{"--output-format", "stream-json"},
		{"--json-schema", VerdictSchema},
		{"--mcp-config", "/etc/dutydesk/mcp.json"},
		{"--permission-mode", "dontAsk"},
		{"--allowedTools", "Read,Grep,Glob,Edit,Write,Bash,StructuredOutput,mcp__locksql-docflow__*,mcp__lockssh-actions__*"},
		{"--max-turns", "40"},
		{"--model", "sonnet"},
	} {
		if !pair(p[0], p[1]) {
			t.Errorf("argv lacks %s %s", p[0], p[1])
		}
	}

	// Runtime flags come before the image, claude flags after it.
	img := -1
	for i, a := range argv {
		if a == "dutydesk-agent:test" {
			img = i
		}
	}
	if img < 0 || argv[img+1] != "-p" {
		t.Fatalf("image is not followed by the claude arguments: %v", argv)
	}
	for i, a := range argv {
		if (a == "--network" || a == "-v" || a == "--env-file" || strings.HasPrefix(a, "--userns")) && i > img {
			t.Errorf("runtime flag %s after the image", a)
		}
	}
	// The env-file is referenced by path only.
	if !has("--env-file") {
		t.Error("argv lacks --env-file")
	}
	for _, a := range argv {
		if a == "-e" || a == "--env" || strings.HasPrefix(a, "--env=") {
			t.Errorf("environment passed on argv: %s", a)
		}
	}
}

func TestClaudeArgsOptional(t *testing.T) {
	l, err := NewLauncher(Config{Image: "img", Network: "net", MCPConfigPath: "/etc/x.json", Tokens: fakeTokens{}})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(l.ClaudeArgs(model.RunRequest{}, nil), " ")
	if strings.Contains(args, "--max-turns") || strings.Contains(args, "--model") {
		t.Errorf("optional flags present: %s", args)
	}
	if !strings.HasSuffix(args, "--allowedTools Read,Grep,Glob,Edit,Write,Bash,StructuredOutput") {
		t.Errorf("args = %s", args)
	}
}

func TestNewLauncherRefusals(t *testing.T) {
	ok := Config{Image: "img", Network: "net", MCPConfigPath: "/etc/x.json", Tokens: fakeTokens{}}
	for name, mut := range map[string]func(*Config){
		"no image":     func(c *Config) { c.Image = "" },
		"no network":   func(c *Config) { c.Network = "" },
		"host network": func(c *Config) { c.Network = "host" },
		"bridge":       func(c *Config) { c.Network = "bridge" },
		"no mcp":       func(c *Config) { c.MCPConfigPath = "" },
		"no tokens":    func(c *Config) { c.Tokens = nil },
		"root user":    func(c *Config) { c.User = "0:0" },
	} {
		c := ok
		mut(&c)
		if _, err := NewLauncher(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	l, err := NewLauncher(ok)
	if err != nil {
		t.Fatal(err)
	}
	if l.cfg.Runtime != "podman" {
		t.Errorf("default runtime = %s", l.cfg.Runtime)
	}
}

func TestRunResultTextFallback(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", resultLine(`"result":"`+"```json\\n"+`{\"outcome\":\"escalate\",\"summary\":\"Cannot conclude.\",\"confidence\":\"low\"}`+"\\n```"+`"`))
	res := f.run(t)
	if res.Status != model.RunOK || res.Verdict.Outcome != model.OutcomeEscalate {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
}

func TestRunInvalidVerdicts(t *testing.T) {
	tests := []struct {
		name, stdout, exit, wantErr string
	}{
		{"not json", resultLine(`"result":"I could not finish"`), "0", "invalid JSON"},
		{"semantically invalid", resultLine(`"structured_output":{"outcome":"green_light","summary":"s","confidence":"high"}`), "0", "ticket"},
		{"no verdict", resultLine(`"result":""`), "0", "no verdict"},
		{"no result event", initLine, "0", "no result event"},
		{"garbage", "not json at all\n{broken\n", "0", "no result event"},
		{"max turns", `{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":40,"total_cost_usd":1.5}` + "\n", "1", "error_max_turns"},
		{"non-zero exit with a verdict", resultLine(`"structured_output":{"outcome":"resolved","summary":"ok","confidence":"high"}`), "3", "exited with code 3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rt.set(t, "stdout", tc.stdout)
			f.rt.set(t, "exit", tc.exit)
			res := f.run(t)
			if res.Status != model.RunFailed {
				t.Fatalf("status = %s, want failed (error = %s)", res.Status, res.Error)
			}
			if res.Verdict != nil {
				t.Errorf("a failed pass carries a verdict")
			}
			if !strings.Contains(res.Error, tc.wantErr) {
				t.Errorf("error %q does not contain %q", res.Error, tc.wantErr)
			}
			if _, err := os.Stat(filepath.Join(f.req.OutDir, "verdict.json")); !os.IsNotExist(err) {
				t.Errorf("verdict.json written for a failed pass")
			}
			if _, err := os.Stat(filepath.Join(f.req.OutDir, "transcript.jsonl")); err != nil {
				t.Errorf("no transcript: %v", err)
			}
			f.assertEnvFileGone(t)
		})
	}
}

func TestRunFailedKeepsAccounting(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", `{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":40,"total_cost_usd":1.5,"usage":{"input_tokens":10,"output_tokens":4}}`+"\n")
	f.rt.set(t, "exit", "1")
	res := f.run(t)
	if res.Status != model.RunFailed || res.Turns != 40 || res.CostUSD != 1.5 || res.InputTok != 10 || res.OutputTok != 4 {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunQuota(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	reset := now.Add(3 * time.Hour)
	tests := []struct {
		name, stdout, stderr, exit string
		wantReset                  time.Time
	}{
		{
			name: "rate limit event then error result",
			stdout: initLine +
				fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d,"rateLimitType":"five_hour"}}`, reset.Unix()) + "\n" +
				`{"type":"result","subtype":"success","is_error":true,"num_turns":1,"total_cost_usd":0,"result":"You've hit your session limit · resets 1pm (UTC)"}` + "\n",
			exit: "1", wantReset: reset,
		},
		{
			name:   "legacy message with epoch",
			stdout: initLine + fmt.Sprintf(`{"type":"result","subtype":"success","is_error":true,"result":"Claude AI usage limit reached|%d"}`, reset.Unix()) + "\n",
			exit:   "1", wantReset: reset,
		},
		{
			name:   "clock time in the message",
			stdout: initLine + `{"type":"result","subtype":"success","is_error":true,"result":"You've hit your weekly limit · resets 2:30pm (Europe/Brussels)"}` + "\n",
			exit:   "1", wantReset: time.Date(2026, 11, 18, 13, 30, 0, 0, time.UTC),
		},
		{
			name:   "http 429 without reset",
			stdout: initLine + `{"type":"result","subtype":"error_during_execution","is_error":true,"api_error_status":429,"errors":["API Error"]}` + "\n",
			exit:   "1",
		},
		{
			name:   "stderr only",
			stdout: initLine, stderr: "Error: usage limit reached\n", exit: "1",
		},
		{
			name:   "rejected event and no result",
			stdout: initLine + `{"type":"rate_limit_event","rate_limit_info":{"status":"rejected"}}` + "\n", exit: "1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rt.set(t, "stdout", tc.stdout)
			f.rt.set(t, "stderr", tc.stderr)
			f.rt.set(t, "exit", tc.exit)
			res := f.run(t)
			if res.Status != model.RunQuota {
				t.Fatalf("status = %s, want quota (error = %s)", res.Status, res.Error)
			}
			if !res.QuotaReset.Equal(tc.wantReset) {
				t.Errorf("quota reset = %v, want %v", res.QuotaReset, tc.wantReset)
			}
			if res.Verdict != nil {
				t.Error("quota result carries a verdict")
			}
		})
	}
}

func TestRunQuotaFalsePositives(t *testing.T) {
	// A rejected window with a successful verdict (overage in use) is a success.
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", initLine+
		`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1795000000}}`+"\n"+
		// Tool output and model text that talk about limits are data.
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"ERROR rate limit exceeded: usage limit reached"}]}}`+"\n"+
		resultLine(`"structured_output":{"outcome":"resolved","summary":"The API rate limit incident is over.","confidence":"high"}`))
	if res := f.run(t); res.Status != model.RunOK {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}

	// The runtime failing before claude starts (registry pull limit) is a failure, not a seat problem.
	f = newFixture(t, nil)
	f.rt.set(t, "stderr", "toomanyrequests: You have reached your pull rate limit\n")
	f.rt.set(t, "exit", "125")
	res := f.run(t)
	if res.Status != model.RunFailed || !strings.Contains(res.Error, "exited with code 125") {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunTimeout(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "sleep", "1")
	f.req.Project.Limits.RunTimeout = 300 * time.Millisecond
	start := time.Now()
	res := f.run(t)
	if res.Status != model.RunTimeout {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("timeout took %s", d)
	}
	if got := strings.TrimSpace(f.rt.get(t, "kill.log")); got != "kill dutydesk-inc-000123-2" {
		t.Errorf("kill call = %q", got)
	}
	if res.Verdict != nil {
		t.Error("a timed-out pass carries a verdict")
	}
	f.assertEnvFileGone(t)
}

func TestRunCancelled(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "sleep", "1")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	res := f.l.Run(ctx, f.req)
	if res.Status != model.RunCancelled {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	if got := strings.TrimSpace(f.rt.get(t, "kill.log")); got != "kill dutydesk-inc-000123-2" {
		t.Errorf("kill call = %q", got)
	}
	f.assertEnvFileGone(t)
}

func TestRunNeverLeaksSecrets(t *testing.T) {
	// The agent printed its environment: the transcript and the error must not keep the tokens.
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", initLine+
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"CLAUDE_CODE_OAUTH_TOKEN=`+seatToken+` LEA_AGENT_TOKEN=`+agentToken+`"}]}}`+"\n"+
		`{"type":"result","subtype":"success","is_error":false,"result":"token is `+seatToken+` and `+agentToken+`"}`+"\n")
	f.rt.set(t, "stderr", "fatal: "+seatToken+"\n")
	f.rt.set(t, "exit", "2")
	res := f.run(t)
	if res.Status != model.RunFailed {
		t.Fatalf("status = %s", res.Status)
	}
	tr, _ := os.ReadFile(filepath.Join(f.req.OutDir, "transcript.jsonl"))
	for _, s := range []string{seatToken, agentToken} {
		if strings.Contains(res.Error, s) {
			t.Errorf("error leaks a secret: %s", res.Error)
		}
		if strings.Contains(string(tr), s) {
			t.Errorf("transcript leaks a secret")
		}
	}
	if !strings.Contains(string(tr), "[redacted]") {
		t.Error("transcript was not scrubbed")
	}

	// Invalid verdict whose text holds the token.
	f = newFixture(t, nil)
	f.rt.set(t, "stdout", resultLine(`"structured_output":{"outcome":"`+seatToken+`","summary":"s","confidence":"high"}`))
	res = f.run(t)
	if res.Status != model.RunFailed || strings.Contains(res.Error, seatToken) {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunPreflightFailures(t *testing.T) {
	t.Run("token error", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Tokens = fakeTokens{err: fmt.Errorf("token file mode 0644")} })
		res := f.run(t)
		if res.Status != model.RunFailed || !strings.Contains(res.Error, "seat seat-a") {
			t.Fatalf("result = %+v", res)
		}
		if _, err := os.Stat(filepath.Join(f.rt.dir, "argv")); !os.IsNotExist(err) {
			t.Error("the runtime was started without a token")
		}
	})
	t.Run("token with a line break", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Tokens = fakeTokens{token: "abc\nINJECTED=1"} })
		res := f.run(t)
		if res.Status != model.RunFailed || strings.Contains(res.Error, "INJECTED") {
			t.Fatalf("result = %+v", res)
		}
		f.assertEnvFileGone(t)
	})
	t.Run("missing mcp config", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.MCPConfigPath = "/nonexistent/mcp.json" })
		if res := f.run(t); res.Status != model.RunFailed || !strings.Contains(res.Error, "mcp config") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("bad mcp server name", func(t *testing.T) {
		f := newFixture(t, nil)
		if err := os.WriteFile(f.l.cfg.MCPConfigPath, []byte(`{"mcpServers":{"a,Bash(*)":{}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := f.run(t); res.Status != model.RunFailed || !strings.Contains(res.Error, "server name") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("bad repo name", func(t *testing.T) {
		f := newFixture(t, nil)
		f.req.RepoDirs = map[string]string{"../etc": f.req.DossierDir}
		if res := f.run(t); res.Status != model.RunFailed || !strings.Contains(res.Error, "repo name") {
			t.Fatalf("result = %+v", res)
		}
		f.assertEnvFileGone(t)
	})
	t.Run("relative dossier", func(t *testing.T) {
		f := newFixture(t, nil)
		f.req.DossierDir = "dossier"
		if res := f.run(t); res.Status != model.RunFailed || !strings.Contains(res.Error, "not absolute") {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("runtime missing", func(t *testing.T) {
		f := newFixture(t, func(c *Config) { c.Runtime = "/nonexistent/podman" })
		if res := f.run(t); res.Status != model.RunFailed || !strings.Contains(res.Error, "container runtime") {
			t.Fatalf("result = %+v", res)
		}
		f.assertEnvFileGone(t)
	})
}

func TestTranscriptSplitWrites(t *testing.T) {
	// Lines arrive in arbitrary chunks; the last one has no newline.
	var out strings.Builder
	tr := newTranscript(&out, "SECRET")
	full := initLine + `{"type":"result","subtype":"success","result":"SECRET","num_turns":3}`
	for i := 0; i < len(full); i += 7 {
		end := min(i+7, len(full))
		if _, err := tr.Write([]byte(full[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if tr.result == nil || tr.result.NumTurns != 3 {
		t.Fatalf("result = %+v", tr.result)
	}
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), "[redacted]") {
		t.Errorf("output = %s", out.String())
	}
}

func TestResetFromText(t *testing.T) {
	now := time.Date(2026, 11, 18, 22, 0, 0, 0, time.UTC)
	for text, want := range map[string]time.Time{
		"usage limit reached · resets at 3am (UTC)": time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC),
		"resets 11:15pm (UTC)":                      time.Date(2026, 11, 18, 23, 15, 0, 0, time.UTC),
		"limit reached|1":                           {},
		"no time here":                              {},
		"resets 13pm":                               {},
	} {
		if got := resetFromText(text, now); !got.Equal(want) {
			t.Errorf("%q: got %v, want %v", text, got, want)
		}
	}
}

func TestVerdictFileIsNormalised(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", resultLine(`"structured_output":{"confidence":"high","summary":"ok","outcome":"resolved","actions_run":["restart-job --job-id 4"]}`))
	if res := f.run(t); res.Status != model.RunOK {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	b, _ := os.ReadFile(filepath.Join(f.req.OutDir, "verdict.json"))
	var v model.Verdict
	if err := json.Unmarshal(b, &v); err != nil || len(v.ActionsRun) != 1 {
		t.Fatalf("verdict.json = %s (%v)", b, err)
	}
}
