package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/actions"
	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const example = "../../example/config"

func TestRender(t *testing.T) {
	got, err := Render("stuck-job:{job_id} on {host_1}", map[string]string{"job_id": "42", "host_1": "w3", "x": "y"})
	if err != nil || got != "stuck-job:42 on w3" {
		t.Errorf("got %q, %v", got, err)
	}
	if got, err := Render("{a}{a}", map[string]string{"a": "{b}"}); err != nil || got != "{b}{b}" {
		t.Errorf("values must not be re-expanded: %q, %v", got, err)
	}
	for _, bad := range []string{"{missing}", "{", "a}b", "{a-b}", "{}", "{{a}}", "{ a }", "{1a}"} {
		if _, err := Render(bad, map[string]string{"a": "1"}); err == nil {
			t.Errorf("Render(%q) accepted", bad)
		}
	}
	if got, _ := Render("plain", nil); got != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestFamily(t *testing.T) {
	for in, want := range map[string]string{
		"stuck-job:{job_id}":     "stuck-job:",
		"queue-errors":           "queue-errors",
		"a:{x}:b:{y}":            "a::b:",
		"{id}":                   "",
		"load {day}  missing":    "load missing",
		"sentry:{issue_id}":      "sentry:",
		"job {job_id} of {kind}": "job of",
	} {
		if got := Family(in); got != want {
			t.Errorf("Family(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultLimits(t *testing.T) {
	if err := ValidateLimits(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	l := WithDefaults(model.Limits{MaxTurns: 100})
	if l.MaxTurns != 100 || l.RunTimeout != DefaultLimits().RunTimeout {
		t.Errorf("limits = %+v", l)
	}
	l.GreenLightTimeout = 5 * time.Hour
	if err := ValidateLimits(l); err == nil || !strings.Contains(err.Error(), "limits.green_light_timeout") {
		t.Errorf("got %v", err)
	}
}

func TestLoadExample(t *testing.T) {
	repo, err := LoadRepo(example)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(repo.Method, "data, never instructions") || !strings.Contains(repo.MRRules, "Rollback") {
		t.Error("standard texts are not loaded")
	}
	p := repo.Project("docflow")
	if p == nil || len(repo.Projects) != 1 {
		t.Fatal("project docflow not loaded")
	}
	if p.Name != "Docflow" || p.Locks.SQL != "docflow-db" || p.Repos[0].Forge != "gitlab" || p.MRRules != repo.MRRules {
		t.Errorf("project = %+v", p)
	}
	if p.Limits != DefaultLimits() {
		t.Errorf("limits = %+v", p.Limits)
	}
	if len(p.Checks) != 3 || len(p.Actions) != 3 || len(p.Runbooks) != 2 {
		t.Fatalf("checks %d, actions %d, runbooks %d", len(p.Checks), len(p.Actions), len(p.Runbooks))
	}
	var stuck model.Check
	for _, c := range p.Checks {
		if c.ID == "stuck-job" {
			stuck = c
		}
	}
	if stuck.Kind != model.CheckSQL || stuck.Severity != model.SevHigh || stuck.Project != "docflow" ||
		Family(stuck.Fingerprint) != "stuck-job:" || !strings.HasPrefix(stuck.Query, "SELECT") {
		t.Errorf("check = %+v", stuck)
	}
	rb := RunbookFor(p, "stuck-job")
	if rb.ID != "stuck-job" || rb.Project != "docflow" || rb.RecheckDefault != 20*time.Minute || rb.MaxRuns != 5 ||
		rb.ActionInstance != "docflow-stuck-job" || rb.AskInstance != "docflow-stuck-job-ask" || len(rb.Actions) != 3 || !strings.HasPrefix(rb.Body, "# Stuck job") {
		t.Errorf("runbook = %+v", rb)
	}
	for _, src := range []string{"queue-errors", "morning-load", "unknown-source"} {
		if g := RunbookFor(p, src); g.ID != "generic" || g.Project != "" || len(g.Actions) != 0 {
			t.Errorf("RunbookFor(%s) = %s", src, g.ID)
		}
	}
	if a := p.Actions["reset-job-status"]; a.Level != model.ActionGreenLight || a.Params[1].Type != "enum" {
		t.Errorf("action = %+v", a)
	}
	rules, err := actions.LockSSHRules(p, actions.DefaultInstallDir)
	if err != nil || len(rules["docflow-stuck-job"].Rules) != 2 || rules["docflow-stuck-job"].Run != "auto" ||
		len(rules["docflow-stuck-job-ask"].Rules) != 1 || rules["docflow-stuck-job-ask"].Run != "ask" {
		t.Errorf("lockssh rules: %v %+v", err, rules)
	}

	d, err := LoadDaemon("../../example/dutydesk.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if abs, _ := filepath.Abs(example); d.ConfigRepo != filepath.Clean("../../example/config") && d.ConfigRepo != abs {
		t.Errorf("config_repo = %q", d.ConfigRepo)
	}
	if len(d.Seats) != 2 || d.Seats[0].ExpiresOn.Format("2006-01-02") != "2027-10-31" || !d.Seats[1].ExpiresOn.IsZero() ||
		d.Seats[1].MaxParallel != 1 || d.MaxParallelRuns != 3 || d.Runtime != "podman" || d.ConfigRemote.Branch != "main" ||
		d.Heartbeat.Every != time.Minute || d.ActionInstallDir != "/opt/dutydesk/bin" {
		t.Errorf("daemon = %+v", d)
	}
	if d.ConfigRemote.Forge != "gitlab" || d.ConfigRemote.Project != "ops/dutydesk-config" ||
		d.Agent.Network != "dutydesk-agents" || !strings.Contains(d.Agent.MCPConfig, "{runbook}") || len(d.Agent.ExtraMounts) == 0 ||
		len(d.LockClients.SQLRun) == 0 || len(d.LockClients.LogMCP) == 0 || len(d.LockClients.Env) != 1 {
		t.Errorf("daemon agent / lock clients = %+v %+v %+v", d.ConfigRemote, d.Agent, d.LockClients)
	}
	if err := d.CheckRepo(repo); err != nil {
		t.Error(err)
	}
}

// copyExample copies the example repository to a temp dir.
func copyExample(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(example, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(example, path)
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
	return dst
}

func edit(t *testing.T, dir, rel, old, new string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%s does not contain %q", rel, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), old, new, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

const (
	pj      = "projects/docflow/project.yaml"
	chk     = "projects/docflow/checks/stuck-job.yaml"
	rbk     = "projects/docflow/runbooks/stuck-job.md"
	act     = "projects/docflow/actions/requeue-job/action.yaml"
	generic = "standard/runbooks/generic.md"
)

func TestLoadRepoErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(t *testing.T, dir string)
		want []string // every string must be in the error
	}{
		{"unknown key in project", func(t *testing.T, d string) { edit(t, d, pj, "name: Docflow", "name: Docflow\nowner: me") },
			[]string{pj + ":", "field owner not found"}},
		{"unknown key in check", func(t *testing.T, d string) { edit(t, d, chk, "kind: sql", "kind: sql\nevery: 5m") },
			[]string{chk + ":", "field every not found"}},
		{"unknown key in runbook", func(t *testing.T, d string) { edit(t, d, rbk, "max_runs: 5", "max_run: 5") },
			[]string{rbk + ": front matter:", "field max_run not found"}},
		{"unknown key in action", func(t *testing.T, d string) { edit(t, d, act, "level: auto", "level: auto\nsudo: true") },
			[]string{act + ":", "field sudo not found"}},
		{"bad cron", func(t *testing.T, d string) { edit(t, d, chk, `"*/5 * * * *"`, `"*/5 * * 13 *"`) },
			[]string{chk + ": schedule:"}},
		{"six-field cron", func(t *testing.T, d string) { edit(t, d, chk, `"*/5 * * * *"`, `"0 */5 * * * *"`) },
			[]string{chk + ": schedule: want a 5-field"}},
		{"cron descriptor", func(t *testing.T, d string) { edit(t, d, chk, `"*/5 * * * *"`, `"@hourly"`) },
			[]string{chk + ": schedule:"}},
		{"severity", func(t *testing.T, d string) { edit(t, d, chk, "severity: high", "severity: urgent") },
			[]string{chk + ": severity:", "low, medium, high or critical"}},
		{"fingerprint syntax", func(t *testing.T, d string) { edit(t, d, chk, "stuck-job:{job_id}", "stuck-job:{{job_id}}") },
			[]string{chk + ": fingerprint:", "only {name} placeholders"}},
		{"fingerprint without literal", func(t *testing.T, d string) { edit(t, d, chk, "stuck-job:{job_id}", "{job_id}") },
			[]string{chk + ": fingerprint:"}},
		{"summary syntax", func(t *testing.T, d string) { edit(t, d, chk, "({job_kind})", "({job.kind})") },
			[]string{chk + ": summary:"}},
		{"check id mismatch", func(t *testing.T, d string) { edit(t, d, chk, "id: stuck-job", "id: queue-errors") },
			[]string{chk + ": id:", "does not match the file name"}},
		{"check kind", func(t *testing.T, d string) { edit(t, d, chk, "kind: sql", "kind: http") },
			[]string{chk + ": kind:"}},
		{"sql without query", func(t *testing.T, d string) {
			write(t, d, "projects/docflow/checks/empty.yaml", "kind: sql\nschedule: \"* * * * *\"\nseverity: low\nfingerprint: empty\nsummary: x\n")
		}, []string{"projects/docflow/checks/empty.yaml: query: required"}},
		{"sql check without sql lock", func(t *testing.T, d string) { edit(t, d, pj, "  sql: docflow-db", "") },
			[]string{chk + ": kind: reads SQL but project docflow has no locks.sql"}},
		{"log threshold", func(t *testing.T, d string) {
			edit(t, d, "projects/docflow/checks/queue-errors.yaml", "threshold: 20", "threshold: 0")
		}, []string{"projects/docflow/checks/queue-errors.yaml: threshold:"}},
		{"log window", func(t *testing.T, d string) {
			edit(t, d, "projects/docflow/checks/queue-errors.yaml", "log_window: 15m", "log_window: 15")
		}, []string{"projects/docflow/checks/queue-errors.yaml:", "not a duration"}},
		{"expect source", func(t *testing.T, d string) {
			edit(t, d, "projects/docflow/checks/morning-load.yaml", "source: sql", "source: http")
		}, []string{"projects/docflow/checks/morning-load.yaml: source:"}},
		{"yml extension", func(t *testing.T, d string) { write(t, d, "projects/docflow/checks/other.yml", "kind: sql\n") },
			[]string{"projects/docflow/checks/other.yml: unexpected entry"}},
		{"runbook unknown action", func(t *testing.T, d string) { edit(t, d, rbk, "requeue-job, skip", "restart-all, skip") },
			[]string{rbk + ": actions:", `"restart-all" is not an action of project docflow`}},
		{"runbook without instance", func(t *testing.T, d string) {
			edit(t, d, rbk, "action_instance: docflow-stuck-job ", "recheck_check: stuck-job #")
		},
			[]string{rbk + ": action_instance: required"}},
		{"runbook without ask instance", func(t *testing.T, d string) {
			edit(t, d, rbk, "ask_instance: docflow-stuck-job-ask ", "recheck_check: stuck-job #")
		},
			[]string{rbk + ": ask_instance: required when the runbook has green-light actions"}},
		{"same instance for auto and ask", func(t *testing.T, d string) {
			edit(t, d, rbk, "ask_instance: docflow-stuck-job-ask ", "ask_instance: docflow-stuck-job ")
		},
			[]string{rbk + ": ask_instance: must differ from action_instance"}},
		{"ask instance without green-light action", func(t *testing.T, d string) {
			edit(t, d, rbk, "actions: [requeue-job, skip-document, reset-job-status]", "actions: [requeue-job, skip-document]")
		}, []string{rbk + ": ask_instance: set, but the runbook has no green-light action"}},
		{"runbook unknown source", func(t *testing.T, d string) { edit(t, d, rbk, "applies_to: [stuck-job]", "applies_to: [stuck-jobs]") },
			[]string{rbk + ": applies_to:", "neither a check nor a webhook source"}},
		{"runbook recheck check", func(t *testing.T, d string) { edit(t, d, rbk, "max_runs: 5", "recheck_check: nope") },
			[]string{rbk + ": recheck_check:"}},
		{"runbook duration", func(t *testing.T, d string) { edit(t, d, rbk, "recheck_default: 20m", "recheck_default: 20") },
			[]string{rbk + ": front matter:", "not a duration"}},
		{"runbook no front matter", func(t *testing.T, d string) { write(t, d, rbk, "# Stuck job\n") },
			[]string{rbk + ": front matter:"}},
		{"runbook id mismatch", func(t *testing.T, d string) { edit(t, d, rbk, "id: stuck-job", "id: other") },
			[]string{rbk + ": id:"}},
		{"source claimed twice", func(t *testing.T, d string) {
			write(t, d, "projects/docflow/runbooks/twin.md", "---\napplies_to: [stuck-job]\n---\nText.\n")
		}, []string{"projects/docflow/runbooks/twin.md: applies_to:", "already claimed"}},
		{"shared instance, other actions", func(t *testing.T, d string) {
			write(t, d, "projects/docflow/runbooks/errors.md",
				"---\napplies_to: [queue-errors]\nactions: [requeue-job]\naction_instance: docflow-stuck-job\n---\nText.\n")
		}, []string{rbk + ": action_instance:", `shared with runbook "errors"`}},
		{"instance auto here, ask there", func(t *testing.T, d string) {
			write(t, d, "projects/docflow/runbooks/errors.md",
				"---\napplies_to: [queue-errors]\nactions: [reset-job-status]\nask_instance: docflow-stuck-job\n---\nText.\n")
		}, []string{rbk + ": action_instance:", `already the green-light instance of runbook "errors"`}},
		{"standard runbook with actions", func(t *testing.T, d string) { edit(t, d, generic, "max_runs: 2", "actions: [requeue-job]") },
			[]string{generic + ": actions:"}},
		{"no generic", func(t *testing.T, d string) { os.Remove(filepath.Join(d, generic)) },
			[]string{generic + ": missing"}},
		{"generic not fallback", func(t *testing.T, d string) { edit(t, d, generic, `["*"]`, `[x]`) },
			[]string{generic + ": applies_to:"}},
		{"no method", func(t *testing.T, d string) { os.Remove(filepath.Join(d, "standard/method.md")) },
			[]string{"standard/method.md: missing"}},
		{"action param type", func(t *testing.T, d string) { edit(t, d, act, "type: int", "type: number") },
			[]string{act + ": params.job-id.type:"}},
		{"action level", func(t *testing.T, d string) { edit(t, d, act, "level: auto", "level: free") },
			[]string{act + ": level:"}},
		{"action loose pattern", func(t *testing.T, d string) {
			edit(t, d, "projects/docflow/actions/skip-document/action.yaml", `"^doc-[0-9a-f]{8,32}$"`, `"^doc-.*$"`)
		}, []string{"projects/docflow/actions/skip-document/action.yaml: params.document-id.pattern:", "wildcard"}},
		{"action unanchored pattern", func(t *testing.T, d string) {
			edit(t, d, "projects/docflow/actions/skip-document/action.yaml", `"^doc-[0-9a-f]{8,32}$"`, `"doc-[0-9a-f]+"`)
		}, []string{"params.document-id.pattern:", "anchored"}},
		{"action script missing", func(t *testing.T, d string) {
			os.Remove(filepath.Join(d, "projects/docflow/actions/requeue-job/requeue-job.sh"))
		}, []string{act + ": script:"}},
		{"action without rate limit", func(t *testing.T, d string) { edit(t, d, act, "  count: 6\n", "") },
			[]string{act + ": rate_limit.count:"}},
		{"repo forge", func(t *testing.T, d string) { edit(t, d, pj, "forge: gitlab", "forge: gitea") },
			[]string{pj + ": repos.app.forge:"}},
		{"repo url with credentials", func(t *testing.T, d string) { edit(t, d, pj, "https://gitlab", "https://user:pw@gitlab") },
			[]string{pj + ": repos.app.url:"}},
		{"limits", func(t *testing.T, d string) { edit(t, d, pj, "green_light_timeout: 2h", "green_light_timeout: 6h") },
			[]string{pj + ": limits.green_light_timeout:"}},
		{"limit duration", func(t *testing.T, d string) { edit(t, d, pj, "run_timeout: 20m", "run_timeout: twenty") },
			[]string{pj + ":", "not a duration"}},
		{"alerts", func(t *testing.T, d string) {
			edit(t, d, pj, "  webhook_url_file: /etc", "  heartbeat_url: ftp://x\n  webhook_url_file: etc")
		},
			[]string{pj + ": alerts.webhook_url_file:", pj + ": alerts.heartbeat_url:"}},
		{"webhook", func(t *testing.T, d string) {
			edit(t, d, pj, "seats: [seat-a, seat-b]", "webhooks:\n  stuck-job:\n    kind: pagerduty\n    secret_file: x\n    severity: major\n    runbook: nope\n")
		}, []string{pj + ": webhooks.stuck-job: a check has the same id", "webhooks.stuck-job.kind:", "webhooks.stuck-job.secret_file:",
			"webhooks.stuck-job.severity:", "webhooks.stuck-job.fingerprint:", "webhooks.stuck-job.runbook:"}},
		{"generic webhook fingerprint field", func(t *testing.T, d string) {
			edit(t, d, pj, "seats: [seat-a, seat-b]", "webhooks:\n  mon:\n    kind: generic\n    secret_file: /s\n    severity: low\n    fingerprint: \"mon:{alert_id}\"\n    fields: {host: /host}\n")
		}, []string{pj + ": webhooks.mon.fingerprint: {alert_id} is not one of the allow-listed fields"}},
		{"bad slug", func(t *testing.T, d string) { os.Mkdir(filepath.Join(d, "projects/Bad Slug"), 0o755) },
			[]string{"projects/Bad Slug: invalid project slug"}},
		{"several errors at once", func(t *testing.T, d string) {
			edit(t, d, chk, "severity: high", "severity: urgent")
			edit(t, d, act, "level: auto", "level: free")
		}, []string{chk + ": severity:", act + ": level:"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyExample(t)
			c.mut(t, dir)
			_, err := LoadRepo(dir)
			if err == nil {
				t.Fatal("LoadRepo accepted it")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error lacks %q:\n%v", w, err)
				}
			}
		})
	}
}

func TestOverridesAndWebhooks(t *testing.T) {
	dir := copyExample(t)
	write(t, dir, "projects/docflow/mr-rules.md", "Project rules.\n")
	write(t, dir, "projects/docflow/runbooks/generic.md", "---\napplies_to: [\"*\"]\n---\nProject generic.\n")
	write(t, dir, "standard/runbooks/sentry-error.md", "---\napplies_to: [sentry]\nrecheck_default: 1h\n---\nStandard sentry runbook.\n")
	edit(t, dir, pj, "seats: [seat-a, seat-b]", `webhooks:
  sentry:
    kind: sentry
    secret_file: /etc/dutydesk/secrets/sentry.secret
    severity: critical
  monitor:
    kind: generic
    secret_file: /etc/dutydesk/secrets/monitor.secret
    severity: low
    fingerprint: "monitor:{alert_id}"
    fields: {alert_id: /alert/id, host: /alert/host}
    runbook: stuck-job
`)
	repo, err := LoadRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := repo.Project("docflow")
	if p.MRRules != "Project rules.\n" {
		t.Errorf("mr rules = %q", p.MRRules)
	}
	if len(p.Runbooks) != 3 {
		t.Fatalf("runbooks = %d, want 3 (stuck-job, project generic, standard sentry-error)", len(p.Runbooks))
	}
	if g := RunbookFor(p, "queue-errors"); g.ID != "generic" || g.Project != "docflow" || g.Body != "Project generic.\n" || g.RecheckDefault != DefaultRecheck {
		t.Errorf("generic = %+v", g)
	}
	if rb := RunbookFor(p, "sentry"); rb.ID != "sentry-error" || rb.Project != "" || rb.RecheckDefault != time.Hour {
		t.Errorf("sentry runbook = %+v", rb)
	}
	if rb := RunbookFor(p, "monitor"); rb.ID != "stuck-job" {
		t.Errorf("webhook-named runbook = %s", rb.ID)
	}
	w := p.Webhooks["sentry"]
	if w.Kind != "sentry" || w.Severity != model.SevCritical || w.FingerprintTemplate != "sentry:{issue_id}" {
		t.Errorf("webhook = %+v", w)
	}
	if len(p.Seats) != 0 {
		t.Errorf("seats = %v", p.Seats)
	}
	if rb := RunbookFor(&model.Project{}, "x"); rb.ID != GenericRunbookID || rb.Body == "" {
		t.Errorf("built-in fallback = %+v", rb)
	}
}

func TestParseRunbook(t *testing.T) {
	rb, err := ParseRunbook([]byte("---\r\nid: a\r\napplies_to: [x, y]\r\n---\r\n\r\n# Title\r\n\r\n---\r\nrule\r\n"))
	if err != nil || rb.ID != "a" || len(rb.AppliesTo) != 2 || rb.Body != "# Title\n\n---\nrule\n" {
		t.Errorf("got %+v, %v", rb, err)
	}
	for _, bad := range []string{"", "# no front matter", "---\nid: a\n", "---\nid: [\n---\nx", "---\nid: a\n---\nid: b\n---\n"} {
		if rb, err := ParseRunbook([]byte(bad)); err == nil && bad != "---\nid: a\n---\nid: b\n---\n" {
			t.Errorf("ParseRunbook(%q) = %+v, want an error", bad, rb)
		}
	}
}

func TestLoadDaemonErrors(t *testing.T) {
	good := `data_dir: /var/lib/dutydesk
config_repo: config
runtime: docker
agent_image: registry.example.com/agent:1
lox_status_socket: /run/lox/status.sock
seats:
  - name: a
    token_file: secrets/a.token
agent:
  network: dutydesk-agents
  mcp_config: /etc/dutydesk/mcp/{project}.json
`
	dir := t.TempDir()
	path := filepath.Join(dir, "dutydesk.yaml")
	load := func(content string) (*Daemon, error) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadDaemon(path)
	}
	d, err := load(good)
	if err != nil {
		t.Fatal(err)
	}
	if d.ConfigRepo != filepath.Join(dir, "config") || d.Seats[0].TokenFile != filepath.Join(dir, "secrets/a.token") ||
		d.Runtime != "docker" || d.MaxParallelRuns != 1 || d.ConfigRemote != nil || d.Listen != "" || d.ClaudeModel != "" {
		t.Errorf("daemon = %+v", d)
	}
	cases := []struct{ old, new, want string }{
		{"runtime: docker", "runtime: lxc", "runtime:"},
		{"data_dir: /var/lib/dutydesk\n", "", "data_dir: required"},
		{"agent_image: registry.example.com/agent:1\n", "", "agent_image:"},
		{"lox_status_socket: /run/lox/status.sock\n", "", "lox_status_socket: required"},
		{"runtime: docker", "runtime: docker\nlisten: 8787", "listen:"},
		{"runtime: docker", "runtime: docker\ndebug: true", "field debug not found"},
		{"runtime: docker", "runtime: docker\nmax_parallel_runs: 100", "max_parallel_runs:"},
		{"runtime: docker", "runtime: docker\nheartbeat: {url: \"ftp://x\", every: 1s}", "heartbeat.url:"},
		{"runtime: docker", "runtime: docker\nheartbeat: {every: 1s}", "heartbeat.every:"},
		{"runtime: docker", "runtime: docker\nclaude_model: \"--dangerous\"", "claude_model:"},
		{"runtime: docker", "runtime: docker\naction_install_dir: \"/opt/my dir\"", "action_install_dir:"},
		{"runtime: docker", "runtime: docker\nconfig_remote: {url: \"git@host:x.git\"}", "config_remote.url:"},
		{"runtime: docker", "runtime: docker\nconfig_remote: {url: \"https://t:x@host/x.git\"}", "config_remote.url:"},
		{"    token_file: secrets/a.token\n", "", "seats.a.token_file: required"},
		{"  - name: a", "  - name: A B", "seats[0].name:"},
		{"    token_file: secrets/a.token", "    token_file: s\n    expires_on: next year", "seats.a.expires_on:"},
		{"    token_file: secrets/a.token", "    token_file: s\n    max_parallel: 99", "seats.a.max_parallel:"},
		{"    token_file: secrets/a.token", "    token_file: s\n  - name: a\n    token_file: t", "seats.a: declared twice"},
		{"seats:\n  - name: a\n    token_file: secrets/a.token\n", "", "seats: at least one"},
		{"  network: dutydesk-agents\n", "", "agent.network: required"},
		{"  network: dutydesk-agents", "  network: host", "agent.network:"},
		{"  mcp_config: /etc/dutydesk/mcp/{project}.json\n", "  user: \"0:0\"\n", "agent.mcp_config:"},
		{"  network: dutydesk-agents", "  network: dutydesk-agents\n  user: root", "agent.user:"},
		{"  network: dutydesk-agents", "  network: dutydesk-agents\n  run_args: [\"--privileged\"]", "agent.run_args[0]:"},
		{"  network: dutydesk-agents", "  network: dutydesk-agents\n  run_args: [\"--network=host\"]", "agent.run_args[0]:"},
		{"  network: dutydesk-agents", "  network: dutydesk-agents\n  extra_mounts: [\"locks:/run/locks\"]", "agent.extra_mounts[0]:"},
		{"  network: dutydesk-agents", "  network: dutydesk-agents\n  https_proxy: egress", "agent.https_proxy:"},
		{"runtime: docker", "runtime: docker\nlock_clients: {sql_run: [locksql, run, \"{instance}\"]}", "lock_clients.sql_run: no {plan_id}"},
		{"runtime: docker", "runtime: docker\nlock_clients: {log_mcp: [locklog, mcp]}", "lock_clients.log_mcp: no {instance}"},
		{"runtime: docker", "runtime: docker\nlock_clients: {env: {LEA_AGENT: x}}", "lock_clients.env.LEA_AGENT:"},
		{"runtime: docker", "runtime: docker\nlock_clients: {timeout: 1h}", "lock_clients.timeout:"},
		{"runtime: docker", "runtime: docker\nconfig_remote: {url: \"https://host/x.git\", forge: svn}", "config_remote.forge:"},
	}
	for _, c := range cases {
		if !strings.Contains(good, c.old) {
			t.Fatalf("bad test case %q", c.old)
		}
		_, err := load(strings.Replace(good, c.old, c.new, 1))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want %q", c.new, err, c.want)
		}
	}
	if _, err := LoadDaemon(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Error("missing file accepted")
	}
	repo := &Repo{Projects: []*model.Project{{Slug: "p", Seats: []string{"a", "zz"}}}}
	if err := d.CheckRepo(repo); err == nil || !strings.Contains(err.Error(), `"zz" is not a seat`) {
		t.Errorf("CheckRepo = %v", err)
	}
}
