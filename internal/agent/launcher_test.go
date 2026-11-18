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
// marker it hangs instead. On `kill` and `rm` it only records the call; on
// `inspect` it answers "no such object" unless a "stuck" marker exists.
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
if [ "$1" = rm ]; then
  printf '%s\n' "$*" >> "$D/rm.log"
  exit 0
fi
if [ "$1" = inspect ]; then
  printf '%s\n' "$*" >> "$D/inspect.log"
  if [ -f "$D/stuck" ]; then
    echo '[{"Id":"abc","State":{"Status":"removing"}}]'
    exit 0
  fi
  echo 'Error: no such object: "x"' >&2
  exit 125
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
			name: "allowed_warning event does not hide the final limit error",
			stdout: initLine +
				`{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1795082400,"rateLimitType":"seven_day"}}` + "\n" +
				`{"type":"result","subtype":"success","is_error":true,"result":"You've hit your session limit"}` + "\n",
			exit: "1",
		},
		{
			name: "reset of the rejected event beyond 24h is unknown",
			stdout: initLine +
				fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d,"rateLimitType":"seven_day"}}`, now.Add(25*time.Hour).Unix()) + "\n" +
				`{"type":"result","subtype":"success","is_error":true,"result":"You've hit your weekly limit"}` + "\n",
			exit: "1",
		},
		{
			name: "reset of the rejected event in the past is unknown",
			stdout: initLine +
				fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d}}`, now.Add(-time.Minute).Unix()) + "\n" +
				`{"type":"result","subtype":"error_during_execution","is_error":true,"api_error_status":429}` + "\n",
			exit: "1",
		},
		{
			name: "reset exactly 24h ahead is kept",
			stdout: initLine +
				fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d}}`, now.Add(24*time.Hour).Unix()) + "\n" +
				`{"type":"result","subtype":"error_during_execution","is_error":true,"api_error_status":429}` + "\n",
			exit: "1", wantReset: now.Add(24 * time.Hour),
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

// S1: everything the agent prints is attacker-controlled. Only the CLI's own
// final error result makes a pass a quota outcome; a forged mid-stream event
// must never take a seat out.
func TestRunQuotaNeedsFinalErrorResult(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	rejected := fmt.Sprintf(`{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":%d,"rateLimitType":"seven_day"}}`, now.Add(3*time.Hour).Unix()) + "\n"
	assistantErr := `{"type":"assistant","error":"rate_limit","message":{"content":[{"type":"text","text":"usage limit reached"}]}}` + "\n"
	tests := []struct {
		name, stdout, stderr, exit string
		want                       model.RunStatus
	}{
		{"rejected event and no result", initLine + rejected, "", "1", model.RunFailed},
		{"rejected event, no result, exit 0", initLine + rejected, "", "0", model.RunFailed},
		{"rejected event then garbage", initLine + rejected + "{broken\nusage limit reached\n", "", "1", model.RunFailed},
		{"rejected event and limit text on stderr", initLine + rejected, "Error: usage limit reached\n", "1", model.RunFailed},
		{"stderr only", initLine, "Error: usage limit reached\n", "1", model.RunFailed},
		{"assistant error tag and no result", initLine + assistantErr, "", "1", model.RunFailed},
		{"rejected event then success result without a verdict", initLine + rejected + resultLine(`"result":"usage limit reached"`), "", "0", model.RunFailed},
		{"rejected event then success result, non-zero exit", initLine + rejected + resultLine(`"result":"usage limit reached|1795082400"`), "", "1", model.RunFailed},
		{"rejected event then an error result that is not a limit", initLine + rejected +
			`{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["tool crashed"]}` + "\n", "", "1", model.RunFailed},
		{"max turns whose text talks about limits", initLine + rejected +
			`{"type":"result","subtype":"error_max_turns","is_error":true,"errors":["usage limit reached"]}` + "\n", "", "1", model.RunFailed},
		{"forged error result followed by the real success result", initLine + rejected +
			`{"type":"result","subtype":"success","is_error":true,"result":"usage limit reached"}` + "\n" +
			resultLine(`"structured_output":{"outcome":"resolved","summary":"ok","confidence":"high"}`), "", "0", model.RunOK},
		{"allowed_warning event then error result that is not a limit", initLine +
			`{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1795082400,"rateLimitType":"seven_day"}}` + "\n" +
			`{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["boom"]}` + "\n", "", "1", model.RunFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rt.set(t, "stdout", tc.stdout)
			f.rt.set(t, "stderr", tc.stderr)
			f.rt.set(t, "exit", tc.exit)
			res := f.run(t)
			if res.Status != tc.want {
				t.Fatalf("status = %s, want %s (error = %s)", res.Status, tc.want, res.Error)
			}
			if !res.QuotaReset.IsZero() {
				t.Errorf("non-quota result carries a reset: %v", res.QuotaReset)
			}
		})
	}
}

// An allowed / allowed_warning event never supplies the reset of a quota
// outcome: only a rejected window does.
func TestRunQuotaResetOnlyFromRejectedEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.rt.set(t, "stdout", initLine+
		`{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1795082400,"rateLimitType":"seven_day"}}`+"\n"+
		`{"type":"result","subtype":"success","is_error":true,"result":"You've hit your session limit"}`+"\n")
	f.rt.set(t, "exit", "1")
	res := f.run(t)
	if res.Status != model.RunQuota || !res.QuotaReset.IsZero() {
		t.Fatalf("status = %s, reset = %v", res.Status, res.QuotaReset)
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
	tr := newTranscript(&out, 0, "SECRET")
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

// Real capture of claude 2.1.327 (reduced to the fields the parser reads,
// reset time replaced by a fixed value): a rate_limit_event with status
// "allowed_warning", then a success result whose structured_output is a JSON
// object.
func TestRunRealCapture(t *testing.T) {
	capture, err := os.ReadFile(filepath.Join("testdata", "real-2.1.327.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(capture), `"status": "allowed_warning"`) || !strings.Contains(string(capture), `"structured_output": {`) {
		t.Fatalf("the capture lost its real shape:\n%s", capture)
	}

	f := newFixture(t, nil)
	f.rt.set(t, "stdout", string(capture))
	res := f.run(t)
	if res.Status != model.RunOK {
		t.Fatalf("status = %s, error = %s", res.Status, res.Error)
	}
	v := res.Verdict
	if v == nil || v.Outcome != model.OutcomeEscalate || v.Summary != "connectivity test" || v.Confidence != "low" {
		t.Fatalf("verdict = %+v", v)
	}
	if res.CostUSD != 0.0038184000000000004 || res.Turns != 2 || res.InputTok != 18563 || res.OutputTok != 212 {
		t.Errorf("accounting = cost %v turns %d in %d out %d", res.CostUSD, res.Turns, res.InputTok, res.OutputTok)
	}
	if !res.QuotaReset.IsZero() {
		t.Errorf("unexpected quota reset %v", res.QuotaReset)
	}

	// The same allowed_warning event followed by an unusable end is a plain
	// failure, never a quota outcome.
	event := strings.SplitAfter(string(capture), "\n")[0]
	for name, tc := range map[string]struct{ stdout, exit string }{
		"no result":            {event, "1"},
		"no result, exit 0":    {event, "0"},
		"error, not a limit":   {event + `{"type":"result","subtype":"error_during_execution","is_error":true,"errors":["boom"]}` + "\n", "1"},
		"success, no verdict":  {event + resultLine(`"result":""`), "0"},
		"limit text on stderr": {event, "1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rt.set(t, "stdout", tc.stdout)
			f.rt.set(t, "stderr", "Error: usage limit reached\n")
			f.rt.set(t, "exit", tc.exit)
			if res := f.run(t); res.Status != model.RunFailed || !res.QuotaReset.IsZero() {
				t.Fatalf("status = %s, reset = %v (error = %s)", res.Status, res.QuotaReset, res.Error)
			}
		})
	}

	// resetsAt is Unix seconds: the parser reads the capture's value as such.
	var out strings.Builder
	tr := newTranscript(&out, 0)
	_, _ = tr.Write([]byte(strings.Replace(event, "allowed_warning", "rejected", 1)))
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if got, want := fromEpoch(tr.rejectedReset, now), time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("reset = %v, want %v", got, want)
	}
}

// Fix 6: the agent decides how much it prints; the transcript file does not
// grow past the cap, and the pass goes on.
func TestRunTranscriptCap(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.MaxTranscriptBytes = 4096 })
	filler := `{"type":"user","message":{"content":[{"type":"tool_result","content":"` + strings.Repeat("A", 1000) + `"}]}}` + "\n"
	f.rt.set(t, "stdout", initLine+strings.Repeat(filler, 200)+
		resultLine(`"structured_output":{"outcome":"resolved","summary":"after the cap","confidence":"high"}`))
	res := f.run(t)
	if res.Status != model.RunOK || res.Verdict == nil || res.Verdict.Summary != "after the cap" {
		t.Fatalf("status = %s, error = %s, verdict = %+v", res.Status, res.Error, res.Verdict)
	}
	if res.Error != "" {
		t.Errorf("error = %q", res.Error)
	}
	tr, err := os.ReadFile(filepath.Join(f.req.OutDir, "transcript.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if max := 4096 + len(truncationMarker) + 1; len(tr) > max {
		t.Errorf("transcript is %d bytes, cap is %d", len(tr), max)
	}
	if len(tr) < 3000 {
		t.Errorf("transcript is only %d bytes: the cap cut too early", len(tr))
	}
	if n := strings.Count(string(tr), `"dutydesk_truncated"`); n != 1 {
		t.Errorf("%d truncation markers, want 1", n)
	}
	if !strings.HasSuffix(string(tr), truncationMarker) {
		t.Errorf("transcript does not end with the marker: %q", tr[len(tr)-80:])
	}
	if strings.Contains(string(tr), "after the cap") {
		t.Error("the result line was stored after the cap")
	}
	// Every stored line is whole.
	for _, line := range strings.Split(strings.TrimSuffix(string(tr), "\n"), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("broken line in the capped transcript: %.60q", line)
		}
	}
}

func TestTranscriptCapUnit(t *testing.T) {
	// A line without end (never a newline) crosses the cap: the marker goes
	// on its own line, once, and later events are still parsed.
	var out strings.Builder
	const max = 40 << 20 // the first flushed piece (just over maxParsedLine) fits, the second does not
	tr := newTranscript(&out, max)
	chunk := []byte(strings.Repeat("x", 1<<20))
	for i := 0; i < 70; i++ {
		_, _ = tr.Write(chunk)
	}
	_, _ = tr.Write([]byte("\n" + `{"type":"result","subtype":"success","num_turns":9}` + "\n"))
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if out.Len() > max+len(truncationMarker)+1 || out.Len() < maxParsedLine {
		t.Errorf("stored %d bytes", out.Len())
	}
	if !strings.HasSuffix(out.String(), "x\n"+truncationMarker) || strings.Count(out.String(), "dutydesk_truncated") != 1 {
		t.Errorf("marker missing or repeated; tail = %q", out.String()[out.Len()-150:])
	}
	if tr.result == nil || tr.result.NumTurns != 9 {
		t.Fatalf("result after the cap not parsed: %+v", tr.result)
	}

	// Default cap.
	if d := newTranscript(&out, 0); d.max != 20<<20 {
		t.Errorf("default cap = %d", d.max)
	}
	l, err := NewLauncher(Config{Image: "img", Network: "net", MCPConfigPath: "/etc/x.json", Tokens: fakeTokens{}})
	if err != nil || l.cfg.MaxTranscriptBytes != 20<<20 {
		t.Errorf("launcher default cap = %d (%v)", l.cfg.MaxTranscriptBytes, err)
	}
	if _, err := NewLauncher(Config{Image: "img", Network: "net", MCPConfigPath: "/etc/x.json", Tokens: fakeTokens{}, MaxTranscriptBytes: -1}); err == nil {
		t.Error("negative cap accepted")
	}
}

func TestVerdictFileIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdict.json")
	v := &model.Verdict{Outcome: model.OutcomeResolved, Summary: strings.Repeat("s", 500), Confidence: "high"}
	if err := writeVerdict(path, v, 200); err == nil {
		t.Fatal("oversized verdict written")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("verdict file exists after a refusal (err=%v)", err)
	}
	if err := writeVerdict(path, v, maxVerdictFileBytes); err != nil {
		t.Fatal(err)
	}
}

// S2: the container is removed and verified gone after every kind of end.
func TestRunAlwaysRemovesContainer(t *testing.T) {
	const name = "dutydesk-inc-000123-2"
	check := func(t *testing.T, f *fixture, res model.RunResult) {
		t.Helper()
		if got := strings.TrimSpace(f.rt.get(t, "rm.log")); got != "rm -f "+name {
			t.Errorf("rm calls = %q", got)
		}
		if got := strings.TrimSpace(f.rt.get(t, "inspect.log")); got != "inspect --type container "+name {
			t.Errorf("inspect calls = %q", got)
		}
		if res.Leftover != "" {
			t.Errorf("leftover = %q", res.Leftover)
		}
	}
	t.Run("normal end", func(t *testing.T) {
		f := newFixture(t, nil)
		f.rt.set(t, "stdout", resultLine(`"structured_output":{"outcome":"resolved","summary":"ok","confidence":"high"}`))
		res := f.run(t)
		if res.Status != model.RunOK {
			t.Fatalf("status = %s, error = %s", res.Status, res.Error)
		}
		check(t, f, res)
	})
	t.Run("failed", func(t *testing.T) {
		f := newFixture(t, nil)
		f.rt.set(t, "stdout", initLine)
		f.rt.set(t, "exit", "1")
		res := f.run(t)
		if res.Status != model.RunFailed {
			t.Fatalf("status = %s", res.Status)
		}
		check(t, f, res)
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFixture(t, nil)
		f.rt.set(t, "sleep", "1")
		f.req.Project.Limits.RunTimeout = 300 * time.Millisecond
		res := f.run(t)
		if res.Status != model.RunTimeout {
			t.Fatalf("status = %s", res.Status)
		}
		check(t, f, res)
	})
	t.Run("cancelled", func(t *testing.T) {
		// The pass context is cancelled: the removal must not use it.
		f := newFixture(t, nil)
		f.rt.set(t, "sleep", "1")
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(300 * time.Millisecond)
			cancel()
		}()
		res := f.l.Run(ctx, f.req)
		if res.Status != model.RunCancelled {
			t.Fatalf("status = %s", res.Status)
		}
		check(t, f, res)
	})
}

func TestRunLeftoverContainer(t *testing.T) {
	const name = "dutydesk-inc-000123-2"
	for _, tc := range []struct {
		name   string
		stdout string
		want   model.RunStatus
	}{
		{"after a success", resultLine(`"structured_output":{"outcome":"resolved","summary":"ok","confidence":"high"}`), model.RunOK},
		{"after a failure", initLine, model.RunFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			f.rt.set(t, "stuck", "1")
			f.rt.set(t, "stdout", tc.stdout)
			res := f.run(t)
			if res.Status != tc.want {
				t.Fatalf("status = %s, error = %s", res.Status, res.Error)
			}
			if res.Leftover != name {
				t.Fatalf("leftover = %q, want %q", res.Leftover, name)
			}
			if got := strings.Count(f.rt.get(t, "rm.log"), "rm -f "+name); got != removeAttempts {
				t.Errorf("%d rm attempts, want %d", got, removeAttempts)
			}
		})
	}
	// A runtime binary that cannot be executed never created a container.
	f := newFixture(t, func(c *Config) { c.Runtime = "/nonexistent/podman" })
	if res := f.run(t); res.Status != model.RunFailed || res.Leftover != "" {
		t.Fatalf("result = %+v", res)
	}
}

// scriptRunner answers `rm` and `inspect` from canned values.
type scriptRunner struct {
	calls       []string
	ctxErrs     []error
	rmErr       error
	inspectCode int
	inspectOut  string
	inspectErr  error
}

func (s *scriptRunner) Run(ctx context.Context, c Command) (int, error) {
	s.calls = append(s.calls, c.Name+" "+strings.Join(c.Args, " "))
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	if c.Args[0] == "rm" {
		return 1, s.rmErr // the exit code of rm is not trusted
	}
	if c.Stderr != nil {
		_, _ = c.Stderr.Write([]byte(s.inspectOut))
	}
	return s.inspectCode, s.inspectErr
}

func TestRemoveContainer(t *testing.T) {
	const name = "dutydesk-inc-1-3"
	ctx := context.Background()

	r := &scriptRunner{inspectCode: 125, inspectOut: `Error: no such object: "dutydesk-inc-1-3"`}
	if err := RemoveContainer(ctx, r, "podman", name); err != nil {
		t.Fatalf("gone container: %v", err)
	}
	if want := []string{"podman rm -f " + name, "podman inspect --type container " + name}; strings.Join(r.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %q", r.calls)
	}
	// docker wording.
	r = &scriptRunner{inspectCode: 1, inspectOut: "Error response from daemon: No such container: dutydesk-inc-1-3"}
	if err := RemoveContainer(ctx, r, "docker", name); err != nil {
		t.Fatalf("gone container (docker): %v", err)
	}

	for label, r := range map[string]*scriptRunner{
		"still there":                              {inspectCode: 0, inspectOut: `[{"Id":"abc"}]`},
		"runtime unreachable":                      {inspectCode: 1, inspectOut: "Cannot connect to the Docker daemon"},
		"inspect killed":                           {inspectCode: -1},
		"inspect cannot start":                     {inspectCode: -1, inspectErr: fmt.Errorf("exec: not found")},
		"rm cannot start":                          {rmErr: fmt.Errorf("exec: not found"), inspectCode: 125, inspectOut: "no such object"},
		"still there, 'no such' ignored on exit 0": {inspectCode: 0, inspectOut: "no such"},
	} {
		if err := RemoveContainer(ctx, r, "podman", name); err == nil {
			t.Errorf("%s: reported as gone", label)
		}
	}

	// A dead context proves nothing.
	dead, cancel := context.WithCancel(ctx)
	cancel()
	r = &scriptRunner{inspectCode: 125, inspectOut: "no such object"}
	if err := RemoveContainer(dead, r, "podman", name); err == nil {
		t.Error("cancelled context: reported as gone")
	}

	// Only agent containers, and nothing that could be read as a flag.
	for _, bad := range []string{"", "-f", "--all", "postgres", "dutydesk-", "dutydesk-x y", "dutydesk-x\n", "Dutydesk-x-1"} {
		r = &scriptRunner{inspectCode: 125, inspectOut: "no such object"}
		if err := RemoveContainer(ctx, r, "podman", bad); err == nil || len(r.calls) != 0 {
			t.Errorf("name %q: err = %v, calls = %q", bad, err, r.calls)
		}
	}
}

func TestContainerNameFor(t *testing.T) {
	if got := ContainerNameFor("INC-000123", 2); got != "dutydesk-inc-000123-2" {
		t.Errorf("name = %q", got)
	}
	for _, id := range []string{"INC-000123", "", "../x y", "-rf", "Ünï"} {
		name := ContainerNameFor(id, 7)
		if name != ContainerName(model.Incident{ID: id}, 7) {
			t.Errorf("%q: ContainerNameFor and ContainerName differ", id)
		}
		if !containerRE.MatchString(name) {
			t.Errorf("%q gives %q, which RemoveContainer would refuse", id, name)
		}
	}
}
