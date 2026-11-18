package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type host struct {
	t                     *testing.T
	root, actions, envDir string
	state, audit          string
	extraEnv              map[string]string
}

func newHost(t *testing.T) *host {
	root := t.TempDir()
	h := &host{t: t, root: root, actions: filepath.Join(root, "actions"), envDir: filepath.Join(root, "env"),
		state: filepath.Join(root, "state"), audit: filepath.Join(root, "state", "audit.log"), extraEnv: map[string]string{}}
	if err := os.MkdirAll(h.envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *host) install(name, manifest, script string) {
	h.t.Helper()
	dir := filepath.Join(h.actions, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "action.yaml"), []byte(manifest), 0o644); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) run(argv ...string) (code int, stdout, stderr string) {
	env := map[string]string{
		"DUTYDESK_ACTIONS_DIR":       h.actions,
		"DUTYDESK_ACTIONS_STATE_DIR": h.state,
		"DUTYDESK_ACTIONS_ENV_DIR":   h.envDir,
		"PATH":                       os.Getenv("PATH"),
		"SECRET_OF_THE_LAUNCHER":     "leak",
	}
	for k, v := range h.extraEnv {
		env[k] = v
	}
	var out, errb bytes.Buffer
	code = run(argv, func(k string) string { return env[k] }, &out, &errb)
	return code, out.String(), errb.String()
}

func (h *host) auditLines() []auditRecord {
	h.t.Helper()
	f, err := os.Open(h.audit)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	var recs []auditRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r auditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			h.t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	return recs
}

func manifest(count int, window, timeout string) string {
	return `description: Test action
level: auto
script: run.sh
params:
  - name: job-id
    type: int
    min: 1
    max: 1000
  - name: mode
    type: enum
    enum: [soft, hard]
rate_limit:
  count: ` + string(rune('0'+count)) + `
  window: ` + window + `
timeout: ` + timeout + "\n"
}

func TestRunsScriptWithValidatedArgv(t *testing.T) {
	h := newHost(t)
	h.install("requeue-job", manifest(5, "1h", "10s"), `#!/bin/sh
echo "argc=$# argv=$*"
echo "action=$DUTYDESK_ACTION token=$API_TOKEN quoted=$QUOTED leak=${SECRET_OF_THE_LAUNCHER:-none}"
echo "cwd=$(basename "$PWD")"
echo "warn" >&2
exit 3
`)
	if err := os.WriteFile(filepath.Join(h.envDir, "requeue-job.env"),
		[]byte("# credentials\nAPI_TOKEN=s3cr3t\nexport QUOTED=\"a b\"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Arguments in another order than the manifest: the script still gets manifest order.
	code, out, errb := h.run("requeue-job", "--mode", "soft", "--job-id", "42")
	if code != 3 {
		t.Errorf("exit code = %d, want the script's 3 (stderr %q)", code, errb)
	}
	want := "argc=4 argv=--job-id 42 --mode soft\naction=requeue-job token=s3cr3t quoted=a b leak=none\ncwd=requeue-job\n"
	if out != want {
		t.Errorf("stdout = %q\nwant     %q", out, want)
	}
	if errb != "warn\n" {
		t.Errorf("stderr = %q", errb)
	}
	recs := h.auditLines()
	if len(recs) != 1 {
		t.Fatalf("audit lines = %d", len(recs))
	}
	r := recs[0]
	if r.Action != "requeue-job" || r.Outcome != "failed" || r.ExitCode != 3 || r.Args["job-id"] != "42" ||
		r.Args["mode"] != "soft" || r.User == "" || r.Time == "" {
		t.Errorf("audit = %+v", r)
	}
	raw, _ := os.ReadFile(h.audit)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Error("the audit log holds a credential")
	}
}

func TestNoShell(t *testing.T) {
	// The script is run without a shell, and no shell syntax can reach it
	// anyway: an installed manifest whose pattern admits shell
	// metacharacters is refused as a whole, nothing runs.
	h := newHost(t)
	marker := filepath.Join(h.root, "ran")
	h.install("echo-tag", `description: Echo
level: auto
script: run.sh
params:
  - name: tag
    type: string
    pattern: "^[a-z$;()|&>*]{1,20}$"
rate_limit: {count: 9, window: 1h}
`, "#!/bin/sh\ntouch "+marker+"\nprintf '%s\\n' \"$2\"\n")
	for _, v := range []string{"$(id);ls|a>b&*", "abc"} {
		code, out, errb := h.run("echo-tag", "--tag", v)
		if code != exitInternal || out != "" || !strings.Contains(errb, "installed manifest refused") {
			t.Errorf("%q: code %d, stdout %q, stderr %q; want the manifest refused (exit 70)", v, code, out, errb)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the script ran under a manifest that admits shell metacharacters")
	}
}

func TestRejections(t *testing.T) {
	h := newHost(t)
	marker := filepath.Join(h.root, "ran")
	h.install("requeue-job", manifest(5, "1h", "10s"), "#!/bin/sh\ntouch "+marker+"\n")
	cases := [][]string{
		{},
		{"--help"},
		{"unknown-action"},
		{"../requeue-job", "--job-id", "1", "--mode", "soft"},
		{"Requeue-Job"},
		{"requeue-job"},
		{"requeue-job", "--job-id", "1"},
		{"requeue-job", "--job-id", "1", "--mode"},
		{"requeue-job", "--job-id", "1", "--mode", "soft", "extra"},
		{"requeue-job", "job-id", "1", "--mode", "soft"},
		{"requeue-job", "--job-id=1", "--mode", "soft"},
		{"requeue-job", "--job-id", "1", "--job-id", "2", "--mode", "soft"},
		{"requeue-job", "--job-id", "0", "--mode", "soft"},
		{"requeue-job", "--job-id", "1001", "--mode", "soft"},
		{"requeue-job", "--job-id", "1;id", "--mode", "soft"},
		{"requeue-job", "--job-id", "1", "--mode", "medium"},
		{"requeue-job", "--job-id", "1", "--mode", "soft/hard"},
		{"requeue-job", "--job-id", "1", "--mode", "soft hard"},
		{"requeue-job", "--job-id", "1", "--mode", "soft", "--force", "yes"},
	}
	for _, argv := range cases {
		code, out, errb := h.run(argv...)
		if code != exitUsage || out != "" || !strings.HasPrefix(errb, "dutydesk-act: ") {
			t.Errorf("%q: code %d, stdout %q, stderr %q; want exit 64", argv, code, out, errb)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the script ran on a rejected invocation")
	}
	recs := h.auditLines()
	if len(recs) != len(cases)-2 { // the two pure usage calls are not invocations
		t.Errorf("audit lines = %d, want %d", len(recs), len(cases)-2)
	}
	for _, r := range recs {
		if r.Outcome != "rejected" || r.ExitCode != exitUsage || r.Args != nil || r.Error == "" {
			t.Errorf("audit = %+v", r)
		}
	}
	raw, _ := os.ReadFile(h.audit)
	if strings.Contains(string(raw), "1;id") || strings.Contains(string(raw), "soft/hard") {
		t.Error("a rejected value is in the audit log")
	}
}

func TestRateLimit(t *testing.T) {
	h := newHost(t)
	h.install("requeue-job", manifest(2, "1h", "10s"), "#!/bin/sh\necho ran\n")
	base := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	clock := base
	now = func() time.Time { return clock }
	defer func() { now = time.Now }()
	argv := []string{"requeue-job", "--job-id", "7", "--mode", "hard"}

	for i := 0; i < 2; i++ {
		if code, out, errb := h.run(argv...); code != 0 || out != "ran\n" {
			t.Fatalf("run %d: code %d, stderr %q", i, code, errb)
		}
		clock = clock.Add(10 * time.Minute)
	}
	code, out, errb := h.run(argv...)
	if code != exitRateLimited || out != "" || !strings.Contains(errb, "rate limited (2 per 1h0m0s)") {
		t.Errorf("third run: code %d, stdout %q, stderr %q", code, out, errb)
	}
	// A refused attempt does not extend the window: 61 minutes after the first run, one slot is free.
	clock = base.Add(61 * time.Minute)
	if code, _, errb := h.run(argv...); code != 0 {
		t.Errorf("after the window: code %d, stderr %q", code, errb)
	}
	if code, _, _ := h.run(argv...); code != exitRateLimited {
		t.Errorf("slot taken twice: code %d", code)
	}
	// A rejected invocation takes no slot.
	clock = base.Add(3 * time.Hour)
	for i := 0; i < 5; i++ {
		h.run("requeue-job", "--job-id", "bad", "--mode", "hard")
	}
	if code, _, _ := h.run(argv...); code != 0 {
		t.Errorf("rejected invocations consumed the limit: code %d", code)
	}
	var outcomes []string
	for _, r := range h.auditLines() {
		outcomes = append(outcomes, r.Outcome)
	}
	if got := strings.Join(outcomes, ","); got != "ok,ok,rate_limited,ok,rate_limited,rejected,rejected,rejected,rejected,rejected,ok" {
		t.Errorf("audit outcomes = %s", got)
	}
	// A corrupt state file fails closed.
	if err := os.WriteFile(filepath.Join(h.state, "requeue-job.rate"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := h.run(argv...); code != exitInternal || out != "" {
		t.Errorf("corrupt state: code %d, stdout %q", code, out)
	}
}

func TestRateLimitConcurrent(t *testing.T) {
	h := newHost(t)
	h.install("requeue-job", manifest(3, "1h", "10s"), "#!/bin/sh\necho ran\n")
	var wg sync.WaitGroup
	codes := make([]int, 12)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = h.run("requeue-job", "--job-id", "7", "--mode", "hard")
		}(i)
	}
	wg.Wait()
	ok, limited := 0, 0
	for _, c := range codes {
		switch c {
		case 0:
			ok++
		case exitRateLimited:
			limited++
		}
	}
	if ok != 3 || limited != 9 {
		t.Errorf("ok %d, rate limited %d; want 3 and 9 (%v)", ok, limited, codes)
	}
	if n := len(h.auditLines()); n != 12 {
		t.Errorf("audit lines = %d, want 12 whole lines", n)
	}
}

func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	h := newHost(t)
	marker := filepath.Join(h.root, "survivor")
	h.install("requeue-job", manifest(5, "1h", "300ms"),
		"#!/bin/sh\necho started\n(sleep 2; touch "+marker+") &\nsleep 30\n")
	start := time.Now()
	code, out, errb := h.run("requeue-job", "--job-id", "7", "--mode", "hard")
	if code != exitTimeout || out != "started\n" || !strings.Contains(errb, "exceeded its timeout") {
		t.Errorf("code %d, stdout %q, stderr %q", code, out, errb)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("returned after %s", d)
	}
	if r := h.auditLines()[0]; r.Outcome != "timeout" || r.ExitCode != exitTimeout {
		t.Errorf("audit = %+v", r)
	}
	time.Sleep(2500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("a child of the script survived the timeout")
	}
}

func TestOutputIsCapped(t *testing.T) {
	h := newHost(t)
	h.install("requeue-job", manifest(5, "1h", "20s"),
		"#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' 'o'\nhead -c 100000 /dev/zero | tr '\\0' 'e' >&2\nexit 0\n")
	code, out, errb := h.run("requeue-job", "--job-id", "7", "--mode", "hard")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if len(out) != maxOutput || strings.Trim(out, "o") != "" {
		t.Errorf("stdout is %d bytes, want %d", len(out), maxOutput)
	}
	if strings.Count(errb, "e") < maxOutput || len(errb) > maxOutput+200 ||
		!strings.Contains(errb, "stdout truncated at 65536 bytes") || !strings.Contains(errb, "stderr truncated at 65536 bytes") {
		t.Errorf("stderr is %d bytes: %q", len(errb), errb[max(0, len(errb)-120):])
	}
}

func TestSignalExit(t *testing.T) {
	h := newHost(t)
	h.install("requeue-job", manifest(5, "1h", "10s"), "#!/bin/sh\nkill -TERM $$\n")
	if code, _, errb := h.run("requeue-job", "--job-id", "7", "--mode", "hard"); code != 128+15 {
		t.Errorf("code %d, stderr %q", code, errb)
	}
}

func TestFailsClosed(t *testing.T) {
	argv := []string{"requeue-job", "--job-id", "7", "--mode", "hard"}
	marker := func(h *host) string { return filepath.Join(h.root, "ran") }
	script := func(h *host) string { return "#!/bin/sh\ntouch " + marker(h) + "\n" }
	ran := func(h *host) bool { _, err := os.Stat(marker(h)); return err == nil }

	t.Run("env file too open", func(t *testing.T) {
		h := newHost(t)
		h.install("requeue-job", manifest(5, "1h", "10s"), script(h))
		p := filepath.Join(h.envDir, "requeue-job.env")
		os.WriteFile(p, []byte("A=b\n"), 0o600)
		os.Chmod(p, 0o644)
		if code, _, errb := h.run(argv...); code != exitInternal || ran(h) || !strings.Contains(errb, "too open") {
			t.Errorf("code %d, ran %v, stderr %q", code, ran(h), errb)
		}
	})
	t.Run("env file malformed", func(t *testing.T) {
		h := newHost(t)
		h.install("requeue-job", manifest(5, "1h", "10s"), script(h))
		os.WriteFile(filepath.Join(h.envDir, "requeue-job.env"), []byte("TOKEN s3cr3t\n"), 0o600)
		code, _, errb := h.run(argv...)
		if code != exitInternal || ran(h) || strings.Contains(errb, "s3cr3t") {
			t.Errorf("code %d, ran %v, stderr %q", code, ran(h), errb)
		}
	})
	t.Run("installed manifest invalid", func(t *testing.T) {
		h := newHost(t)
		h.install("requeue-job", manifest(5, "1h", "10s")+"shell: true\n", script(h))
		if code, _, _ := h.run(argv...); code != exitInternal || ran(h) {
			t.Errorf("code %d, ran %v", code, ran(h))
		}
	})
	t.Run("audit log unwritable", func(t *testing.T) {
		h := newHost(t)
		h.install("requeue-job", manifest(5, "1h", "10s"), script(h))
		h.extraEnv["DUTYDESK_ACTIONS_AUDIT_LOG"] = filepath.Join(h.root, "no", "such", "dir", "audit.log")
		if code, _, errb := h.run(argv...); code != exitInternal || ran(h) || !strings.Contains(errb, "audit log") {
			t.Errorf("code %d, ran %v, stderr %q", code, ran(h), errb)
		}
	})
	t.Run("script not executable", func(t *testing.T) {
		h := newHost(t)
		h.install("requeue-job", manifest(5, "1h", "10s"), script(h))
		os.Chmod(filepath.Join(h.actions, "requeue-job", "run.sh"), 0o644)
		if code, _, _ := h.run(argv...); code != exitInternal || ran(h) {
			t.Errorf("code %d, ran %v", code, ran(h))
		}
	})
}

func TestExampleCatalogue(t *testing.T) {
	// The example scripts run under the launcher against a stub of their placeholder CLI.
	h := newHost(t)
	h.actions = "../../example/config/projects/docflow/actions"
	bin := filepath.Join(h.root, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "docflowctl"), []byte("#!/bin/sh\necho \"docflowctl $*\"\n"), 0o755)
	h.extraEnv["PATH"] = bin + ":" + os.Getenv("PATH")
	code, out, errb := h.run("skip-document", "--job-id", "12", "--document-id", "doc-0123abcd")
	want := "docflowctl documents quarantine --job 12 --id doc-0123abcd --reason dutydesk\n" +
		"docflowctl jobs show --id 12 --fields id,status,processed_count,updated_at\n"
	if code != 0 || out != want {
		t.Errorf("code %d\nstdout %q\nstderr %q", code, out, errb)
	}
	if code, _, _ := h.run("skip-document", "--job-id", "12", "--document-id", "../etc"); code != exitUsage {
		t.Errorf("code %d", code)
	}
	for _, argv := range [][]string{
		{"requeue-job", "--job-id", "12"},
		{"reset-job-status", "--job-id", "12", "--status", "failed"},
	} {
		if code, _, errb := h.run(argv...); code != 0 {
			t.Errorf("%q: code %d, stderr %q", argv, code, errb)
		}
	}
}
