package actions

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func i64(n int64) *int64 { return &n }

func requeue() model.Action {
	return model.Action{
		Name: "requeue-job", Description: "Requeue one job", Level: model.ActionAuto, Script: "requeue-job.sh",
		Params: []model.ActionParam{
			{Name: "job-id", Type: "int", Min: i64(1), Max: i64(999999)},
			{Name: "reason", Type: "enum", Enum: []string{"stalled", "worker-lost"}},
			{Name: "tag", Type: "string", Pattern: `^[a-z0-9_.-]{1,16}$`},
		},
		RateLimit: model.RateLimit{Count: 5, Window: time.Hour},
		Timeout:   time.Minute,
	}
}

func TestValidatePattern(t *testing.T) {
	good := []string{`^[a-z0-9-]+$`, `^\d{1,9}$`, `^\w+$`, `^(doc|job)-[0-9]{4}$`, `^[A-Z]{2}\.[0-9]+$`, `^a$`, `^[a-z]+(-[a-z]+)*$`}
	for _, p := range good {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) = %v, want ok", p, err)
		}
	}
	bad := []string{
		`[a-z]+`, `^[a-z]+`, `[a-z]+$`, `^$`, `^.+$`, `^.*$`, `^\S+$`, `^[^a]+$`, `^a/b$`, `^a\/b$`,
		`^[+-9]+$`, `^[!-~]+$`, `^a b$`, `^a\sb$`, `^[a-z\s]+$`, `^a$|^b$`, `(?m)^a$`, `(?i)^[a-z]+$`,
		`^\pL+$`, `^a\tb$`, `^[a-z`, `^a\bb$`, `^é$`, `^\D+$`, `^\W+$`, `^[[:space:]]+$`, `^[[:print:]]+$`,
	}
	for _, p := range bad {
		if err := ValidatePattern(p); err == nil {
			t.Errorf("ValidatePattern(%q) = nil, want an error", p)
		}
	}
}

func TestValidateAction(t *testing.T) {
	if err := ValidateAction(requeue()); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mut  func(a *model.Action)
		want string
	}{
		{"name", func(a *model.Action) { a.Name = "Bad_Name" }, "name:"},
		{"level", func(a *model.Action) { a.Level = "manual" }, "level:"},
		{"script path", func(a *model.Action) { a.Script = "../x.sh" }, "script:"},
		{"no rate", func(a *model.Action) { a.RateLimit.Count = 0 }, "rate_limit.count:"},
		{"no window", func(a *model.Action) { a.RateLimit.Window = 0 }, "rate_limit.window:"},
		{"timeout", func(a *model.Action) { a.Timeout = time.Hour }, "timeout:"},
		{"type", func(a *model.Action) { a.Params[0].Type = "float" }, "params.job-id.type:"},
		{"neg min", func(a *model.Action) { a.Params[0].Min = i64(-1) }, "params.job-id.min:"},
		{"max<min", func(a *model.Action) { a.Params[0].Max = i64(0) }, "params.job-id.max:"},
		{"enum empty", func(a *model.Action) { a.Params[1].Enum = nil }, "params.reason.enum:"},
		{"enum slash", func(a *model.Action) { a.Params[1].Enum = []string{"a/b"} }, "params.reason.enum:"},
		{"enum space", func(a *model.Action) { a.Params[1].Enum = []string{"a b"} }, "params.reason.enum:"},
		{"enum dash", func(a *model.Action) { a.Params[1].Enum = []string{"-x"} }, "params.reason.enum:"},
		{"pattern missing", func(a *model.Action) { a.Params[2].Pattern = "" }, "params.tag.pattern:"},
		{"pattern loose", func(a *model.Action) { a.Params[2].Pattern = "^.*$" }, "params.tag.pattern:"},
		{"dup", func(a *model.Action) { a.Params[2].Name = "reason" }, "params.reason: declared twice"},
		{"param name", func(a *model.Action) { a.Params[2].Name = "--x" }, "params[2].name:"},
	}
	for _, c := range cases {
		a := requeue()
		a.Params = append([]model.ActionParam(nil), a.Params...)
		c.mut(&a)
		err := ValidateAction(a)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}

func TestValidateArgs(t *testing.T) {
	a := requeue()
	ok := map[string]string{"job-id": "42", "reason": "stalled", "tag": "night_run.1"}
	if err := ValidateArgs(a, ok); err != nil {
		t.Fatal(err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		if v == "<del>" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	bad := []map[string]string{
		with("job-id", "<del>"), with("extra", "1"), with("job-id", ""), with("job-id", "0"),
		with("job-id", "1000000"), with("job-id", "-1"), with("job-id", "+1"), with("job-id", "1e3"),
		with("job-id", "007"), with("job-id", "4 2"), with("job-id", "99999999999999999999"),
		with("reason", "other"), with("reason", "Stalled"), with("tag", "A"), with("tag", "a/b"),
		with("tag", "a b"), with("tag", "a\n"), with("tag", ".."), with("tag", "."), with("tag", "-rf"),
		with("tag", "aaaaaaaaaaaaaaaaa"), with("tag", "é"), with("tag", "a\tb"), with("tag", "a\x00"),
	}
	for _, m := range bad {
		if err := ValidateArgs(a, m); err == nil {
			t.Errorf("ValidateArgs(%v) = nil, want an error", m)
		}
	}
	// A manifest that slipped past review with a loose pattern still never lets "/" or a space through.
	loose := a
	loose.Params = []model.ActionParam{{Name: "tag", Type: "string", Pattern: `.*`}}
	for _, v := range []string{"a/b", "a b", "ok"} {
		if err := ValidateArgs(loose, map[string]string{"tag": v}); err == nil {
			t.Errorf("loose pattern accepted %q", v)
		}
	}
	// Errors never quote the value.
	err := ValidateArgs(a, with("tag", "SECRETVALUE"))
	if err == nil || strings.Contains(err.Error(), "SECRETVALUE") || !strings.Contains(err.Error(), "--tag") {
		t.Errorf("error = %v", err)
	}
}

func TestCommandLine(t *testing.T) {
	a := requeue()
	got := CommandLine(a, "/opt/dutydesk/bin", map[string]string{"tag": "x", "job-id": "42", "reason": "stalled"})
	want := []string{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	noParams := model.Action{Name: "flush"}
	if got := CommandLine(noParams, "/opt/dutydesk/bin", nil); !reflect.DeepEqual(got, []string{"/opt/dutydesk/bin/dutydesk-act", "flush"}) {
		t.Errorf("got %q", got)
	}
}

// locksshMatch is lockssh's allow-rule matching (see realLocksshMatch).
func locksshMatch(rule string, argv []string) bool { return realLocksshMatch(rule, argv) }

// skipRules are the rules of project()'s skip-document: one per length.
func skipRules() []string {
	var out []string
	for n := 1; n <= 12; n++ {
		out = append(out, "/opt/dutydesk/bin/dutydesk-act skip-document --document-id doc-"+strings.Repeat("[0-9]", n))
	}
	return out
}

func project() *model.Project {
	a := requeue()
	skip := model.Action{
		Name: "skip-document", Description: "Skip", Level: model.ActionAuto, Script: "s.sh",
		Params:    []model.ActionParam{{Name: "document-id", Type: "string", Pattern: `^doc-[0-9]{1,12}$`}},
		RateLimit: model.RateLimit{Count: 1, Window: time.Hour}, Timeout: time.Minute,
	}
	reset := model.Action{
		Name: "reset-job-status", Description: "Reset", Level: model.ActionGreenLight, Script: "r.sh",
		Params: []model.ActionParam{
			{Name: "job-id", Type: "int", Min: i64(1)},
			{Name: "status", Type: "enum", Enum: []string{"queued", "failed"}},
		},
		RateLimit: model.RateLimit{Count: 1, Window: time.Hour}, Timeout: time.Minute,
	}
	return &model.Project{
		Slug:    "docflow",
		Actions: map[string]model.Action{a.Name: a, skip.Name: skip, reset.Name: reset},
		Runbooks: []model.Runbook{
			{ID: "stuck-job", Actions: []string{"skip-document", "requeue-job"}, ActionInstance: "docflow-stuck-job"},
			{ID: "bad-status", Actions: []string{"reset-job-status"}, AskInstance: "docflow-bad-status"},
			{ID: "mixed", Actions: []string{"requeue-job", "reset-job-status"}, ActionInstance: "docflow-mixed", AskInstance: "docflow-mixed-ask"},
			{ID: "generic", AppliesTo: []string{"*"}},
		},
	}
}

func TestLockSSHRules(t *testing.T) {
	p := project()
	rules, err := LockSSHRules(p, "/opt/dutydesk/bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d profiles, want 4", len(rules))
	}
	auto := rules["docflow-stuck-job"]
	// One rule per enum value; the tag is too long for one rule per length.
	wantAllow := append([]string{
		"/opt/dutydesk/bin/dutydesk-act requeue-job --job-id [0-9]* --reason stalled --tag [.0-9_a-z]*",
		"/opt/dutydesk/bin/dutydesk-act requeue-job --job-id [0-9]* --reason worker-lost --tag [.0-9_a-z]*",
	}, skipRules()...)
	if !reflect.DeepEqual(auto.Allow(), wantAllow) || auto.Run != "auto" || auto.Exec {
		t.Errorf("auto profile = %+v", auto)
	}
	ask := rules["docflow-bad-status"]
	if !reflect.DeepEqual(ask.Allow(), []string{
		"/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id [0-9]* --status queued",
		"/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id [0-9]* --status failed",
	}) || ask.Run != "ask" || ask.Exec {
		t.Errorf("ask profile = %+v", ask)
	}
	// A runbook with both levels gets two profiles: its auto actions stay free.
	if m, k := rules["docflow-mixed"], rules["docflow-mixed-ask"]; m.Run != "auto" || len(m.Rules) != 2 || m.Rules[0].Action != "requeue-job" ||
		k.Run != "ask" || len(k.Rules) != 2 || k.Rules[1].Action != "reset-job-status" {
		t.Errorf("mixed runbook profiles = %+v / %+v", m, k)
	}

	// The command line of valid args matches its rule; hostile argvs do not.
	// (A tag of ".." is left to the launcher: a glob cannot exclude it.)
	a := p.Actions["requeue-job"]
	args := map[string]string{"job-id": "42", "reason": "stalled", "tag": "t1"}
	if err := ValidateArgs(a, args); err != nil {
		t.Fatal(err)
	}
	rule := wantAllow[0]
	if !locksshMatch(rule, CommandLine(a, "/opt/dutydesk/bin", args)) {
		t.Errorf("rule %q does not match its own command line", rule)
	}
	if locksshMatch(wantAllow[1], CommandLine(a, "/opt/dutydesk/bin", args)) {
		t.Errorf("rule %q matches another enum value", wantAllow[1])
	}
	for _, argv := range [][]string{
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "a/b"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "-1", "--reason", "stalled", "--tag", "t"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "x", "--reason", "stalled", "--tag", "t"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "t", "extra"},
		{"/opt/dutydesk/bin/dutydesk-act", "other", "--job-id", "42", "--reason", "stalled", "--tag", "t"},
		{"/tmp/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "t"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--tag", "t", "--reason", "stalled", "--job-id", "42"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "other", "--tag", "t"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "-rf"},
		{"/opt/dutydesk/bin/dutydesk-act", "requeue-job", "--job-id", "42", "--reason", "stalled", "--tag", "$(id)"},
	} {
		if locksshMatch(rule, argv) {
			t.Errorf("rule %q matches %q", rule, argv)
		}
	}
}

func TestLockSSHRulesErrors(t *testing.T) {
	for _, dir := range []string{"opt/bin", "/opt/my dir", "/opt/*/bin", "/opt/bin/", "/opt/../bin", ""} {
		if _, err := LockSSHRules(project(), dir); err == nil {
			t.Errorf("install dir %q accepted", dir)
		}
	}
	p := project()
	p.Runbooks[0].Actions = []string{"nope"}
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil || !strings.Contains(err.Error(), "runbook stuck-job: action nope") {
		t.Errorf("got %v", err)
	}
	p = project()
	p.Runbooks[0].ActionInstance = ""
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil {
		t.Error("missing action_instance accepted")
	}
	p = project()
	p.Runbooks[1].AskInstance = ""
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil || !strings.Contains(err.Error(), "no ask_instance") {
		t.Errorf("missing ask_instance: %v", err)
	}
	p = project()
	p.Runbooks[2].AskInstance = "docflow-mixed"
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Errorf("same instance twice: %v", err)
	}
	p = project()
	p.Runbooks[1].AskInstance = "docflow-stuck-job"
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil || !strings.Contains(err.Error(), "auto or ask as a whole") {
		t.Errorf("got %v", err)
	}
	p = project()
	p.Runbooks[2].ActionInstance = "docflow-stuck-job"
	if _, err := LockSSHRules(p, "/opt/dutydesk/bin"); err == nil || !strings.Contains(err.Error(), "shared") {
		t.Errorf("got %v", err)
	}
	p = project()
	p.Runbooks = append(p.Runbooks, model.Runbook{ID: "twin", Actions: []string{"requeue-job", "skip-document"}, ActionInstance: "docflow-stuck-job"})
	rules, err := LockSSHRules(p, "/opt/dutydesk/bin")
	if err != nil || !reflect.DeepEqual(rules["docflow-stuck-job"].Runbooks, []string{"stuck-job", "twin"}) {
		t.Errorf("shared instance with the same actions: %v %+v", err, rules["docflow-stuck-job"])
	}
}

func TestRenderTOML(t *testing.T) {
	p := project()
	p.Runbooks = p.Runbooks[:2]
	rules, err := LockSSHRules(p, "/opt/dutydesk/bin")
	if err != nil {
		t.Fatal(err)
	}
	want := `# DutyDesk: proposed lockssh rules for project docflow.
# Generated from the action manifests. A new rule loosens the policy:
# review it, then approve it in the lockssh console (:review).

# runbook: bad-status
#   green-light  reset-job-status
# green-light: every command is a ticket decided by a human.
[profiles.docflow-bad-status]
exec  = false
allow = [
  "/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id [0-9]* --status queued",
  "/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id [0-9]* --status failed",
]

[profiles.docflow-bad-status.auto]
run  = "ask"
exec = "deny"

# runbook: stuck-job
#   auto         requeue-job
#   auto         skip-document
# auto: an allow-listed command runs without a ticket.
[profiles.docflow-stuck-job]
exec  = false
allow = [
  "/opt/dutydesk/bin/dutydesk-act requeue-job --job-id [0-9]* --reason stalled --tag [.0-9_a-z]*",
  "/opt/dutydesk/bin/dutydesk-act requeue-job --job-id [0-9]* --reason worker-lost --tag [.0-9_a-z]*",
SKIPRULES]

[profiles.docflow-stuck-job.auto]
run  = "auto"
exec = "deny"
`
	var skip strings.Builder
	for _, r := range skipRules() {
		skip.WriteString("  \"" + r + "\",\n")
	}
	want = strings.Replace(want, "SKIPRULES", skip.String(), 1)
	if got := RenderTOML("docflow", rules); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	mixed, _ := LockSSHRules(project(), "/opt/dutydesk/bin")
	got := RenderTOML("docflow", mixed)
	if strings.Contains(got, "WARNING") || !strings.Contains(got, "[profiles.docflow-mixed]") ||
		!strings.Contains(got, "[profiles.docflow-mixed-ask.auto]\nrun  = \"ask\"") {
		t.Errorf("runbook with both levels:\n%s", got)
	}
}

func writeAction(t *testing.T, root, name, manifest string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

const goodManifest = `description: Requeue one job
level: auto
script: run.sh
params:
  - name: job-id
    type: int
    min: 1
rate_limit:
  count: 3
  window: 1h
`

func TestLoadAction(t *testing.T) {
	root := t.TempDir()
	a, err := LoadAction(writeAction(t, root, "requeue-job", goodManifest, 0o755))
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "requeue-job" || a.Timeout != DefaultTimeout || a.RateLimit.Window != time.Hour ||
		len(a.Params) != 1 || *a.Params[0].Min != 1 || a.Level != model.ActionAuto {
		t.Errorf("action = %+v", a)
	}
	cases := []struct{ name, manifest, want string }{
		{"unknown-key", goodManifest + "shell: true\n", "field shell not found"},
		{"bad-duration", strings.Replace(goodManifest, "1h", "soon", 1), "not a duration"},
		{"name-mismatch", "name: other\n" + goodManifest, "name:"},
		{"no-script", strings.Replace(goodManifest, "run.sh", "absent.sh", 1), "script:"},
		{"empty", "", "empty manifest"},
	}
	for _, c := range cases {
		_, err := LoadAction(writeAction(t, root, c.name, c.manifest, 0o755))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := LoadAction(writeAction(t, root, "not-exec", goodManifest, 0o644)); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Errorf("got %v", err)
	}
}

func TestLoadCatalogue(t *testing.T) {
	root := t.TempDir()
	writeAction(t, root, "requeue-job", goodManifest, 0o755)
	writeAction(t, root, "skip-document", goodManifest, 0o755)
	cat, err := LoadCatalogue(root)
	if err != nil || len(cat) != 2 {
		t.Fatalf("got %d actions, err %v", len(cat), err)
	}
	writeAction(t, root, "broken", "level: auto\n", 0o755)
	if _, err := LoadCatalogue(root); err == nil || !strings.Contains(err.Error(), "broken/action.yaml: description") {
		t.Errorf("got %v", err)
	}
	if cat, err := LoadCatalogue(filepath.Join(root, "absent")); err != nil || len(cat) != 0 {
		t.Errorf("missing dir: %v %v", cat, err)
	}
}
