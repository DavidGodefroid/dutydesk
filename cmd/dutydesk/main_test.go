package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/core"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

const example = "../../example/config"

// rig writes a daemon file over the example configuration and fills a data
// directory the way the daemon would.
func rig(t *testing.T) (cfg string) {
	t.Helper()
	dir := t.TempDir()
	abs, err := filepath.Abs(example)
	if err != nil {
		t.Fatal(err)
	}
	cfg = filepath.Join(dir, "dutydesk.yaml")
	yaml := "data_dir: " + filepath.Join(dir, "data") + "\nconfig_repo: " + abs + "\nagent_image: dutydesk-agent:test\n" +
		"lox_status_socket: " + filepath.Join(dir, "status.sock") + "\nseats:\n  - name: seat-a\n    token_file: a.token\n" +
		"    expires_on: 2027-10-31\n  - name: seat-b\n    token_file: b.token\nagent:\n  network: dutydesk-agents\n  mcp_config: /etc/dutydesk/mcp.json\n"
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "data", core.DBName), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	repo, err := config.LoadRepo(abs)
	if err != nil {
		t.Fatal(err)
	}
	p := repo.Project("docflow")
	mgr := incident.NewManager(st, nil, nil, incident.WithDossier(incident.NewDossier(filepath.Join(dir, "data"))))
	for _, id := range []string{"4812", "4813"} {
		if _, err := core.Ingest(mgr, p, model.Signal{Source: "stuck-job", Fingerprint: "stuck-job:" + id, Severity: model.SevHigh,
			Summary: "Job " + id + " has been running for too long", At: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	// INC-000001 went through one pass and was escalated.
	inc, err := st.ClaimIncident("INC-000001")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := st.StartRun(inc.ID, "seat-a")
	v := model.Verdict{Outcome: model.OutcomeEscalate, Summary: "The worker is deadlocked.", Confidence: "medium"}
	_ = st.FinishRun(r.ID, model.RunResult{Status: model.RunOK, Verdict: &v, Turns: 9})
	if _, err := mgr.ApplyVerdict(inc, v, config.RunbookFor(p, "stuck-job"), p.Limits); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func dutydesk(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestCLI(t *testing.T) {
	cfg := rig(t)
	ok := func(args ...string) string {
		t.Helper()
		code, out, errOut := dutydesk(t, append([]string{"--config", cfg}, args...)...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, out, errOut)
		}
		return out
	}
	want := func(out string, parts ...string) {
		t.Helper()
		for _, p := range parts {
			if !strings.Contains(out, p) {
				t.Errorf("output lacks %q:\n%s", p, out)
			}
		}
	}

	want(ok("status"), "NOT SERVING", "status socket not reachable", "seat-a", "escalated      1", "queued         1")
	var status struct {
		Locks     []struct{ Serving bool }
		Seats     []struct{ Name string }
		Incidents map[string]int
	}
	if err := json.Unmarshal([]byte(ok("status", "--json")), &status); err != nil || len(status.Locks) != 1 || status.Locks[0].Serving ||
		len(status.Seats) != 2 || status.Incidents["escalated"] != 1 {
		t.Errorf("status --json = %+v, %v", status, err)
	}
	want(ok("incidents"), "INC-000001", "escalated", "INC-000002", "queued", "stuck-job")
	want(ok("seats"), "seat-a", "0/1", "2027-10-31", "seat-b")

	show := ok("incident", "show", "INC-000001")
	want(show, "INC-000001  escalated  high  docflow", "PASSES", "seat seat-a  ok  verdict escalate  9 turns", "JOURNAL",
		"pass 1: verdict escalate", "The worker is deadlocked.")
	var doc struct {
		Incident map[string]any
		Runs     []map[string]any
		Journal  string
	}
	raw := ok("incident", "show", "INC-000001", "--json")
	if err := json.Unmarshal([]byte(raw), &doc); err != nil || doc.Incident["state"] != "escalated" || len(doc.Runs) != 1 ||
		!strings.Contains(doc.Journal, "verdict escalate") {
		t.Errorf("incident show --json: %v\n%s", err, raw)
	}
	if strings.Contains(strings.ToLower(raw), "token") {
		t.Errorf("incident show --json leaks the agent token:\n%s", raw)
	}

	want(ok("incident", "resume", "INC-000001"), "INC-000001: escalated → queued")
	want(ok("incident", "close", "INC-000002", "--reason", "handled by hand"), "INC-000002: queued → resolved (handled by hand)")
	want(ok("incidents"), "INC-000001", "queued")
	if out := ok("incidents"); strings.Contains(out, "INC-000002") {
		t.Errorf("a closed incident is listed without --all:\n%s", out)
	}
	want(ok("incidents", "--all", "--project", "docflow"), "INC-000002", "resolved")
	want(ok("incident", "show", "INC-000002"), "closed:", "handled by hand", "closed by a human")

	want(ok("config", "validate"), "valid", "project docflow: 3 checks")
	want(ok("config", "lockssh-rules", "--project", "docflow"), "[profiles.docflow-stuck-job]", `run  = "auto"`,
		"[profiles.docflow-stuck-job-ask.auto]", `run  = "ask"`)
	if code, out, _ := dutydesk(t, "config", "lockssh-rules", "--project", "docflow", "--dir", example, "--install-dir", "/srv/act"); code != 0 ||
		!strings.Contains(out, `"/srv/act/dutydesk-act requeue-job --job-id [0-9]*"`) {
		t.Errorf("lockssh-rules --install-dir: %d\n%s", code, out)
	}
	if code, out, _ := dutydesk(t, "config", "validate", example); code != 0 || !strings.Contains(out, "valid") {
		t.Errorf("config validate DIR: %d %s", code, out)
	}
	if code, out, _ := dutydesk(t, "version"); code != 0 || !strings.HasPrefix(out, "dutydesk ") {
		t.Errorf("version: %d %q", code, out)
	}

	// Errors: exit 1. Usage: exit 2.
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--config", cfg, "incident", "show", "INC-000099"}, 1, "no incident INC-000099"},
		{[]string{"--config", cfg, "incident", "close", "INC-000002"}, 1, "cannot be changed in its current state"},
		{[]string{"--config", cfg, "check", "run", "nope", "--project", "docflow", "--dry-run"}, 1, `no check "nope"`},
		{[]string{"--config", cfg, "config", "lockssh-rules", "--project", "nope"}, 1, `no project "nope"`},
		{[]string{"--config", filepath.Join(t.TempDir(), "absent.yaml"), "status"}, 1, "absent.yaml"},
		{[]string{"config", "validate", t.TempDir() + "/nothing"}, 1, "not a directory"},
		{nil, 2, "no command"},
		{[]string{"frobnicate"}, 2, "unknown command"},
		{[]string{"incident", "show"}, 2, "usage: dutydesk incident"},
		{[]string{"check", "run", "stuck-job"}, 2, "usage: dutydesk check run"},
		{[]string{"status", "--bogus"}, 2, "flag provided but not defined"},
	} {
		code, _, errOut := dutydesk(t, c.args...)
		if code != c.code || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: exit %d, stderr %q; want %d, %q", c.args, code, errOut, c.code, c.want)
		}
	}
}

func TestConfigValidateReportsEveryProblem(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(example)); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "projects/docflow/checks/stuck-job.yaml")
	b, _ := os.ReadFile(f)
	_ = os.WriteFile(f, []byte(strings.Replace(string(b), "severity: high", "severity: urgent", 1)), 0o644)
	_ = os.Remove(filepath.Join(dir, "standard/method.md"))
	code, _, errOut := dutydesk(t, "config", "validate", dir)
	if code != 1 || !strings.Contains(errOut, "2 problem(s)") || !strings.Contains(errOut, "stuck-job.yaml: severity:") ||
		!strings.Contains(errOut, "standard/method.md") {
		t.Errorf("exit %d\n%s", code, errOut)
	}
}

func TestCoreAgentToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	a, err := coreAgentToken(dir)
	if err != nil || len(a) != 64 {
		t.Fatalf("token %q, %v", a, err)
	}
	b, _ := coreAgentToken(dir)
	if a != b {
		t.Error("the core identity changes between starts")
	}
	if st, err := os.Stat(filepath.Join(dir, "core-agent.token")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode: %v %v", st, err)
	}
}

// Finding 8: nothing the CLI prints can drive the terminal.
func TestTerminalOutputIsSafe(t *testing.T) {
	var out bytes.Buffer
	w := termSafe{&out}
	in := "ok\tfine\n\x1b[2J\x1b]0;title\x07evil\r\u009b31m é ✓\x7f\n"
	if n, err := w.Write([]byte(in)); err != nil || n != len(in) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got, want := out.String(), "ok\tfine\n[2J]0;titleevil31m é ✓\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
