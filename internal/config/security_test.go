package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const repoLine = "    token_file: /etc/dutydesk/secrets/gitlab-docflow.token"

// A1: repos[].deny_paths / allow_paths, with the nil-vs-empty rule.
func TestRepoPathPolicy(t *testing.T) {
	load := func(t *testing.T, extra string) (*model.Project, error) {
		t.Helper()
		dir := copyExample(t)
		if extra != "" {
			edit(t, dir, pj, repoLine, repoLine+"\n"+extra)
		}
		repo, err := LoadRepo(dir)
		if err != nil {
			return nil, err
		}
		return repo.Project("docflow"), nil
	}

	p, err := load(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Repos[0].DenyPaths != nil || p.Repos[0].AllowPaths != nil {
		t.Errorf("keys absent: DenyPaths %#v, AllowPaths %#v, want nil (the core applies its built-in deny-list)",
			p.Repos[0].DenyPaths, p.Repos[0].AllowPaths)
	}

	p, err = load(t, "    deny_paths: []")
	if err != nil {
		t.Fatal(err)
	}
	if p.Repos[0].DenyPaths == nil || len(p.Repos[0].DenyPaths) != 0 {
		t.Errorf("deny_paths: []: DenyPaths = %#v, want a non-nil empty slice (restriction lifted)", p.Repos[0].DenyPaths)
	}

	// A null value is not "lift the restriction": it is the built-in list.
	p, err = load(t, "    deny_paths:")
	if err != nil {
		t.Fatal(err)
	}
	if p.Repos[0].DenyPaths != nil {
		t.Errorf("deny_paths: (null): DenyPaths = %#v, want nil", p.Repos[0].DenyPaths)
	}

	p, err = load(t, "    deny_paths: [\".gitlab-ci.yml\", \".github/**\", \"ci/*.y?ml\"]\n    allow_paths: [\"src/**\", \"docs/**/*.md\"]")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Repos[0].DenyPaths, " "); got != ".gitlab-ci.yml .github/** ci/*.y?ml" {
		t.Errorf("DenyPaths = %q", got)
	}
	if got := strings.Join(p.Repos[0].AllowPaths, " "); got != "src/** docs/**/*.md" {
		t.Errorf("AllowPaths = %q", got)
	}

	for _, bad := range []string{
		`""`, `"/etc/passwd"`, `"../other"`, `"src/../.gitlab-ci.yml"`, `"src\\ci"`, `"src/[a-"`,
		`"src//x"`, `"src/"`, `"./src"`, `"src/**x"`, `"a\nb"`,
	} {
		for _, key := range []string{"deny_paths", "allow_paths"} {
			_, err := load(t, "    "+key+": ["+bad+"]")
			if err == nil || !strings.Contains(err.Error(), pj+": repos.app."+key+"[0]:") {
				t.Errorf("%s: [%s]: got %v, want an error naming the pattern", key, bad, err)
			}
		}
	}
}

// A2: limits.max_green_lights and limits.max_quota_runs.
func TestLimitsGreenLightsAndQuotaRuns(t *testing.T) {
	d := DefaultLimits()
	if d.MaxGreenLights != 3 || d.MaxQuotaRuns != 3 {
		t.Errorf("defaults: MaxGreenLights %d, MaxQuotaRuns %d, want 3 and 3", d.MaxGreenLights, d.MaxQuotaRuns)
	}
	if l := WithDefaults(model.Limits{MaxGreenLights: 7}); l.MaxGreenLights != 7 || l.MaxQuotaRuns != 3 {
		t.Errorf("WithDefaults = %+v", l)
	}
	for _, c := range []struct {
		mut  func(l *model.Limits)
		want string
	}{
		{func(l *model.Limits) { l.MaxGreenLights = 21 }, "limits.max_green_lights:"},
		{func(l *model.Limits) { l.MaxGreenLights = -1 }, "limits.max_green_lights:"},
		{func(l *model.Limits) { l.MaxQuotaRuns = 21 }, "limits.max_quota_runs:"},
		{func(l *model.Limits) { l.MaxQuotaRuns = -1 }, "limits.max_quota_runs:"},
	} {
		l := DefaultLimits()
		c.mut(&l)
		if err := ValidateLimits(l); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("got %v, want %q", err, c.want)
		}
	}

	dir := copyExample(t)
	edit(t, dir, pj, "max_green_lights: 3", "max_green_lights: 5")
	edit(t, dir, pj, "max_quota_runs: 3", "max_quota_runs: 20")
	repo, err := LoadRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l := repo.Project("docflow").Limits; l.MaxGreenLights != 5 || l.MaxQuotaRuns != 20 {
		t.Errorf("limits = %+v", l)
	}
	edit(t, dir, pj, "max_green_lights: 5", "max_green_lights: 50")
	if _, err := LoadRepo(dir); err == nil || !strings.Contains(err.Error(), pj+": limits.max_green_lights:") {
		t.Errorf("got %v", err)
	}
}

// A3 (fix 11): no symbolic link anywhere under projects/ and standard/.
func TestLoadRepoRefusesSymlinks(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.md"), []byte("---\napplies_to: [\"*\"]\n---\nsecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "evil.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	replace := func(t *testing.T, path, target string) {
		t.Helper()
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		mut  func(t *testing.T, dir string)
		want string // the path named by the error
	}{
		{"standard text", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "standard/method.md"), filepath.Join(outside, "secret.md"))
		}, "standard/method.md"},
		{"standard runbook", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, generic), filepath.Join(outside, "secret.md"))
		}, generic},
		{"project.yaml", func(t *testing.T, d string) {
			orig := filepath.Join(d, "project.yaml.orig")
			if err := os.Rename(filepath.Join(d, pj), orig); err != nil {
				t.Fatal(err)
			}
			replace(t, filepath.Join(d, pj), orig)
		}, pj},
		{"check", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/checks/extra.yaml"), "stuck-job.yaml")
		}, "projects/docflow/checks/extra.yaml"},
		{"project runbook", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/runbooks/leak.md"), filepath.Join(outside, "secret.md"))
		}, "projects/docflow/runbooks/leak.md"},
		{"action script", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/actions/requeue-job/requeue-job.sh"), filepath.Join(outside, "evil.sh"))
		}, "projects/docflow/actions/requeue-job/requeue-job.sh"},
		{"action manifest", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, act), "../skip-document/action.yaml")
		}, act},
		{"action directory", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/actions/alias-job"), "requeue-job")
		}, "projects/docflow/actions/alias-job"},
		{"directory inside an action directory", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/actions/requeue-job/lib"), outside)
		}, "projects/docflow/actions/requeue-job/lib"},
		{"project directory", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/twin"), "docflow")
		}, "projects/twin"},
		{"runbooks directory", func(t *testing.T, d string) {
			moved := filepath.Join(d, "moved-runbooks")
			if err := os.Rename(filepath.Join(d, "projects/docflow/runbooks"), moved); err != nil {
				t.Fatal(err)
			}
			replace(t, filepath.Join(d, "projects/docflow/runbooks"), moved)
		}, "projects/docflow/runbooks"},
		{"hidden link", func(t *testing.T, d string) {
			replace(t, filepath.Join(d, "projects/docflow/.cache"), outside)
		}, "projects/docflow/.cache"},
		{"standard itself", func(t *testing.T, d string) {
			moved := filepath.Join(d, "std")
			if err := os.Rename(filepath.Join(d, "standard"), moved); err != nil {
				t.Fatal(err)
			}
			replace(t, filepath.Join(d, "standard"), moved)
		}, "standard"},
		{"projects itself", func(t *testing.T, d string) {
			moved := filepath.Join(d, "prj")
			if err := os.Rename(filepath.Join(d, "projects"), moved); err != nil {
				t.Fatal(err)
			}
			replace(t, filepath.Join(d, "projects"), moved)
		}, "projects"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyExample(t)
			c.mut(t, dir)
			_, err := LoadRepo(dir)
			if err == nil {
				t.Fatal("LoadRepo accepted a symbolic link")
			}
			if !strings.Contains(err.Error(), c.want+": ") || !strings.Contains(err.Error(), "symbolic link") {
				t.Errorf("error does not name %q as a symbolic link:\n%v", c.want, err)
			}
		})
	}

	// A FIFO or any other special file is refused as well (and never opened).
	t.Run("regular files and directories only", func(t *testing.T) {
		dir := copyExample(t)
		if err := syscall.Mkfifo(filepath.Join(dir, "projects/docflow/checks/pipe.yaml"), 0o644); err != nil {
			t.Skip(err)
		}
		_, err := LoadRepo(dir)
		if err == nil || !strings.Contains(err.Error(), "projects/docflow/checks/pipe.yaml: ") || !strings.Contains(err.Error(), "regular file") {
			t.Errorf("got %v", err)
		}
	})
}

const goodDaemon = `data_dir: /var/lib/dutydesk
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

func loadDaemonText(t *testing.T, content string) (*Daemon, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dutydesk.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadDaemon(path)
}

// A4 (fix 13): agent.run_args is an allow-list.
func TestRunArgsAllowList(t *testing.T) {
	with := func(arg string) string {
		return strings.Replace(goodDaemon, "  network: dutydesk-agents", "  network: dutydesk-agents\n  run_args:\n    - '"+arg+"'", 1)
	}
	for _, arg := range []string{
		"--userns=keep-id",
		"--userns=keep-id:uid=10001,gid=10001",
		"--security-opt=label=disable",
		"--security-opt=label=type:container_runtime_t",
		"--security-opt=label=level:s0:c100,c200",
		"--security-opt=label=user:system_u",
		"--security-opt=label=role:system_r",
		"--annotation=com.example.owner=ops-team",
		"--label=com.example/team=sre",
		"--label=dutydesk=1",
	} {
		d, err := loadDaemonText(t, with(arg))
		if err != nil {
			t.Errorf("%s: refused: %v", arg, err)
			continue
		}
		if len(d.Agent.RunArgs) != 1 || d.Agent.RunArgs[0] != arg {
			t.Errorf("%s: RunArgs = %q", arg, d.Agent.RunArgs)
		}
	}
	for _, arg := range []string{
		"--privileged", "--privileged=true", "--cap-add=ALL", "--cap-add=SYS_ADMIN", "--cap-drop=ALL",
		"--security-opt=seccomp=unconfined", "--security-opt=apparmor=unconfined",
		"--security-opt=no-new-privileges=false", "--security-opt=no-new-privileges", "--security-opt=unmask=ALL",
		"--security-opt=label=nested", "--security-opt=label=filetype:usr_t", "--security-opt=label=type:",
		"--security-opt=label=type:a b", "--security-opt=label=disable,seccomp=unconfined", "--security-opt",
		"--security-opt=label:disable", "--security-opt=systempaths=unconfined", "--security-opt=mask=/x",
		"--userns=host", "--userns=keep-id:uid=0;x", "--userns=auto", "--userns=keep-id:", "--userns", "--userns=keep-id:UID=1",
		"--pid=host", "--ipc=host", "--uts=host", "--network=host", "--net=host", "--cgroupns=host",
		"-v=/:/host", "-v", "--volume=/:/host", "--mount=type=bind,src=/,dst=/host", "--device=/dev/sda",
		"--user=0", "--env=A=b", "--env-file=/x", "--entrypoint=/bin/sh", "--volumes-from=x", "--group-add=keep-groups",
		"--rm", "--init", "--read-only=false", "--tmpfs=/x", "--pull=always", "--hostname=x", "--add-host=a:1.2.3.4",
		"--annotation", "--annotation=novalue", "--annotation=key=a b", "--annotation=a b=c", "--annotation= k=v",
		"--annotation=k=v\tw", "--annotation==v", "--annotation=k=$(id)", "--annotation=run.oci.keep_original_groups=1",
		"--annotation=io.podman.annotations.privileged=TRUE", "--annotation=k=v --privileged",
		"--label", "--label=novalue", "--label=k=a b", "--label=k=v;w", "--label=io.containers.autoupdate=registry",
		"--label-file=/x", "--annotation=k=/etc/shadow",
		"userns=keep-id", " --userns=keep-id", "--userns=keep-id ", "", "--", "--userns=keep-id\n--privileged",
	} {
		_, err := loadDaemonText(t, strings.Replace(goodDaemon, "  network: dutydesk-agents",
			"  network: dutydesk-agents\n  run_args: ["+yamlQuote(arg)+"]", 1))
		if err == nil || !strings.Contains(err.Error(), "agent.run_args[0]:") {
			t.Errorf("%q: got %v, want agent.run_args[0] refused", arg, err)
		}
	}
	// Each allowed flag is one argument: a split "--flag value" pair is refused.
	_, err := loadDaemonText(t, strings.Replace(goodDaemon, "  network: dutydesk-agents",
		"  network: dutydesk-agents\n  run_args: [\"--security-opt\", \"label=disable\"]", 1))
	if err == nil || !strings.Contains(err.Error(), "agent.run_args[0]:") || !strings.Contains(err.Error(), "agent.run_args[1]:") {
		t.Errorf("split pair: got %v", err)
	}
}

// yamlQuote renders s as a double-quoted YAML scalar.
func yamlQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}

// A5: quota_cap, agent.max_transcript_bytes, retention.
func TestDaemonKnobs(t *testing.T) {
	d, err := loadDaemonText(t, goodDaemon)
	if err != nil {
		t.Fatal(err)
	}
	if d.QuotaCap != 5*time.Hour || d.Agent.MaxTranscriptBytes != 20<<20 ||
		d.Retention.Transcripts != 720*time.Hour || d.Retention.Incidents != 4320*time.Hour {
		t.Errorf("defaults: quota cap %s, transcript bytes %d, retention %+v", d.QuotaCap, d.Agent.MaxTranscriptBytes, d.Retention)
	}
	var _ Retention = d.Retention

	set := strings.Replace(goodDaemon, "runtime: docker",
		"runtime: docker\nquota_cap: 90m\nretention: {transcripts: 7d, incidents: 2160h}", 1)
	set = strings.Replace(set, "  network: dutydesk-agents", "  network: dutydesk-agents\n  max_transcript_bytes: 1048576", 1)
	d, err = loadDaemonText(t, set)
	if err != nil {
		t.Fatal(err)
	}
	if d.QuotaCap != 90*time.Minute || d.Agent.MaxTranscriptBytes != 1<<20 ||
		d.Retention.Transcripts != 7*24*time.Hour || d.Retention.Incidents != 2160*time.Hour {
		t.Errorf("set: quota cap %s, transcript bytes %d, retention %+v", d.QuotaCap, d.Agent.MaxTranscriptBytes, d.Retention)
	}
	// Day units: "30d", "1d12h".
	d, err = loadDaemonText(t, strings.Replace(goodDaemon, "runtime: docker",
		"runtime: docker\nretention: {transcripts: 1d12h, incidents: 365d}", 1))
	if err != nil {
		t.Fatal(err)
	}
	if d.Retention.Transcripts != 36*time.Hour || d.Retention.Incidents != 365*24*time.Hour {
		t.Errorf("day units: %+v", d.Retention)
	}
	// One key of the block set: the other keeps its default.
	d, err = loadDaemonText(t, strings.Replace(goodDaemon, "runtime: docker", "runtime: docker\nretention: {transcripts: 48h}", 1))
	if err != nil || d.Retention.Transcripts != 48*time.Hour || d.Retention.Incidents != 4320*time.Hour {
		t.Errorf("partial block: %v %+v", err, d)
	}

	agent := func(line string) string {
		return strings.Replace(goodDaemon, "  network: dutydesk-agents", "  network: dutydesk-agents\n  "+line, 1)
	}
	top := func(line string) string {
		return strings.Replace(goodDaemon, "runtime: docker", "runtime: docker\n"+line, 1)
	}
	for _, c := range []struct{ content, want string }{
		{top("quota_cap: 5m"), "quota_cap:"},
		{top("quota_cap: 25h"), "quota_cap:"},
		{top("quota_cap: 2d"), "quota_cap:"},
		{top("quota_cap: soon"), "not a duration"},
		{top("quota_cap: -1h"), "quota_cap:"},
		{agent("max_transcript_bytes: 1024"), "agent.max_transcript_bytes:"},
		{agent("max_transcript_bytes: 2147483648"), "agent.max_transcript_bytes:"},
		{agent("max_transcript_bytes: -1"), "agent.max_transcript_bytes:"},
		{top("retention: {transcripts: 30m}"), "retention.transcripts:"},
		{top("retention: {transcripts: 1000h, incidents: 999h}"), "retention.incidents:"},
		{top("retention: {transcripts: 5000h}"), "retention.incidents:"},
		{top("retention: {incidents: 100h}"), "retention.incidents:"},
		{top("retention: {transcripts: 1dd}"), "not a duration"},
		{top("retention: {transcripts: d}"), "not a duration"},
		{top("retention: {transcripts: 99999999999d}"), "not a duration"},
		{top("retention: {logs: 1h}"), "field logs not found"},
	} {
		if _, err := loadDaemonText(t, c.content); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("got %v, want %q", err, c.want)
		}
	}
	lo, err := loadDaemonText(t, strings.Replace(agent("max_transcript_bytes: 65536"), "runtime: docker", "runtime: docker\nquota_cap: 10m", 1))
	if err != nil || lo.Agent.MaxTranscriptBytes != 64<<10 || lo.QuotaCap != 10*time.Minute {
		t.Errorf("lower bounds: %v", err)
	}
	hi, err := loadDaemonText(t, strings.Replace(agent("max_transcript_bytes: 1073741824"), "runtime: docker", "runtime: docker\nquota_cap: 24h", 1))
	if err != nil || hi.Agent.MaxTranscriptBytes != 1<<30 || hi.QuotaCap != 24*time.Hour {
		t.Errorf("upper bounds: %v", err)
	}
}
