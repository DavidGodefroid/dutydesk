package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/actions"
	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Daemon is dutydeskd's own configuration file (dutydesk.yaml).
type Daemon struct {
	DataDir          string       // database, incident dossiers, clones
	ConfigRepo       string       // local checkout of the config repo's protected branch
	ConfigRemote     *Remote      // nil: the checkout is managed outside the daemon
	Listen           string       // host:port of the inbound webhook endpoint, "" = off
	Runtime          string       // "docker" | "podman"
	AgentImage       string       // image of the agent container
	LoxStatusSocket  string       // lox live's read-only status socket
	ActionInstallDir string       // where dutydesk-act is installed on the action hosts
	Seats            []model.Seat // at least one
	MaxParallelRuns  int          // across all projects
	ClaudeModel      string       // "" = the claude CLI's default
	Heartbeat        Heartbeat    // dead-man switch of the daemon itself
	Agent            AgentConfig  // how the agent container is launched
	LockClients      LockClients  // how the core calls the lock clients for its checks
}

// AgentConfig is the "agent:" block: the container of one agent pass.
// MCPConfig and ExtraMounts accept the placeholders {project}, {runbook},
// {action_instance}, {ask_instance} and {incident}.
type AgentConfig struct {
	Network     string   // pre-created internal container network (required)
	HTTPSProxy  string   // egress proxy as seen from that network, "" = none
	NoProxy     string   // NO_PROXY in the container
	MCPConfig   string   // host path (template) of the MCP config mounted in the container (required)
	ExtraMounts []string // "host:container[:opts]" templates: lock client binaries and sockets
	User        string   // uid:gid in the container, "" = the launcher's default (10001:10001)
	RunArgs     []string // extra `run` flags, e.g. --userns=keep-id:uid=10001,gid=10001
	Memory      string   // "" = launcher default
	CPUs        string
	PidsLimit   int
}

// LockClients is the "lock_clients:" block. Each command is an argument
// vector in which "{instance}" is the project's lock instance and, for
// SQLRun, "{plan_id}" the plan to run. Empty: the defaults of
// internal/lockcli (the launchers lox installs on the host).
type LockClients struct {
	SQLPlan []string
	SQLRun  []string
	LogMCP  []string
	Env     []string      // extra KEY=VALUE entries for the clients, sorted
	Timeout time.Duration // one lock call, 0 = lockcli's default
}

// Remote is the git remote the core pulls the config repo from.
type Remote struct {
	URL       string
	Branch    string
	TokenFile string
	Forge     string // "gitlab" (default) | "github": where configuration merge requests are opened
	Project   string // forge project path; default: the URL path without ".git"
}

// Heartbeat pings URL every Every; URL "" turns it off.
type Heartbeat struct {
	URL   string
	Every time.Duration
}

type daemonFile struct {
	DataDir      string `yaml:"data_dir"`
	ConfigRepo   string `yaml:"config_repo"`
	ConfigRemote *struct {
		URL       string `yaml:"url"`
		Branch    string `yaml:"branch"`
		TokenFile string `yaml:"token_file"`
		Forge     string `yaml:"forge"`
		Project   string `yaml:"project"`
	} `yaml:"config_remote"`
	Listen           string `yaml:"listen"`
	Runtime          string `yaml:"runtime"`
	AgentImage       string `yaml:"agent_image"`
	LoxStatusSocket  string `yaml:"lox_status_socket"`
	ActionInstallDir string `yaml:"action_install_dir"`
	Seats            []struct {
		Name        string `yaml:"name"`
		TokenFile   string `yaml:"token_file"`
		MaxParallel int    `yaml:"max_parallel"`
		ExpiresOn   string `yaml:"expires_on"`
	} `yaml:"seats"`
	MaxParallelRuns int    `yaml:"max_parallel_runs"`
	ClaudeModel     string `yaml:"claude_model"`
	Heartbeat       struct {
		URL   string   `yaml:"url"`
		Every duration `yaml:"every"`
	} `yaml:"heartbeat"`
	Agent struct {
		Network     string   `yaml:"network"`
		HTTPSProxy  string   `yaml:"https_proxy"`
		NoProxy     string   `yaml:"no_proxy"`
		MCPConfig   string   `yaml:"mcp_config"`
		ExtraMounts []string `yaml:"extra_mounts"`
		User        string   `yaml:"user"`
		RunArgs     []string `yaml:"run_args"`
		Memory      string   `yaml:"memory"`
		CPUs        string   `yaml:"cpus"`
		PidsLimit   int      `yaml:"pids_limit"`
	} `yaml:"agent"`
	LockClients struct {
		SQLPlan []string          `yaml:"sql_plan"`
		SQLRun  []string          `yaml:"sql_run"`
		LogMCP  []string          `yaml:"log_mcp"`
		Env     map[string]string `yaml:"env"`
		Timeout duration          `yaml:"timeout"`
	} `yaml:"lock_clients"`
}

var (
	envNameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	userRe     = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)
	resourceRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?[a-zA-Z]{0,2}$`)
)

// LoadDaemon loads and validates dutydesk.yaml. Relative paths are taken
// from the file's directory. Defaults: runtime "podman", seat max_parallel
// 1, max_parallel_runs = the sum of the seats', heartbeat every 1m,
// config_remote.branch "main" and forge "gitlab", action_install_dir
// /opt/dutydesk/bin, lock_clients = the defaults of internal/lockcli.
func LoadDaemon(path string) (*Daemon, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var el errlist
	var df daemonFile
	if err := decodeStrict(data, &df); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	base := filepath.Dir(path)
	abs := func(key, p string, required bool) string {
		if p == "" {
			if required {
				el.addf(path, "%s: required", key)
			}
			return ""
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return filepath.Clean(p)
	}
	d := &Daemon{
		DataDir:          abs("data_dir", df.DataDir, true),
		ConfigRepo:       abs("config_repo", df.ConfigRepo, true),
		Listen:           df.Listen,
		Runtime:          df.Runtime,
		AgentImage:       df.AgentImage,
		LoxStatusSocket:  abs("lox_status_socket", df.LoxStatusSocket, true),
		ActionInstallDir: df.ActionInstallDir,
		MaxParallelRuns:  df.MaxParallelRuns,
		ClaudeModel:      df.ClaudeModel,
		Heartbeat:        Heartbeat{URL: df.Heartbeat.URL, Every: time.Duration(df.Heartbeat.Every)},
	}
	if r := df.ConfigRemote; r != nil {
		d.ConfigRemote = &Remote{URL: r.URL, Branch: r.Branch, TokenFile: abs("config_remote.token_file", r.TokenFile, false),
			Forge: r.Forge, Project: strings.Trim(r.Project, "/")}
		if d.ConfigRemote.Forge == "" {
			d.ConfigRemote.Forge = "gitlab"
		}
		if d.ConfigRemote.Forge != "gitlab" && d.ConfigRemote.Forge != "github" {
			el.addf(path, "config_remote.forge: want \"gitlab\" or \"github\"")
		}
		if d.ConfigRemote.Project == "" {
			if u, err := url.Parse(r.URL); err == nil {
				d.ConfigRemote.Project = strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
			}
		}
		if d.ConfigRemote.Project == "" || strings.ContainsAny(d.ConfigRemote.Project, " \t") {
			el.addf(path, "config_remote.project: want the forge project path, e.g. \"ops/dutydesk-config\"")
		}
		if d.ConfigRemote.Branch == "" {
			d.ConfigRemote.Branch = "main"
		}
		if !httpURL(r.URL) || !strings.HasPrefix(r.URL, "https://") || strings.Contains(r.URL, "@") {
			el.addf(path, "config_remote.url: want an https git URL without credentials")
		}
		if strings.ContainsAny(d.ConfigRemote.Branch, " \t~^:?*[\\") || strings.HasPrefix(d.ConfigRemote.Branch, "-") {
			el.addf(path, "config_remote.branch: not a branch name")
		}
	}
	if d.Listen != "" {
		if _, _, err := net.SplitHostPort(d.Listen); err != nil {
			el.addf(path, "listen: want host:port, e.g. \"127.0.0.1:8787\"")
		}
	}
	if d.Runtime == "" {
		d.Runtime = "podman"
	}
	if d.Runtime != "docker" && d.Runtime != "podman" {
		el.addf(path, "runtime: want \"docker\" or \"podman\"")
	}
	if d.AgentImage == "" || strings.ContainsAny(d.AgentImage, " \t") || strings.HasPrefix(d.AgentImage, "-") {
		el.addf(path, "agent_image: required, an image reference")
	}
	if d.ActionInstallDir == "" {
		d.ActionInstallDir = actions.DefaultInstallDir
	}
	if !filepath.IsAbs(d.ActionInstallDir) || filepath.Clean(d.ActionInstallDir) != d.ActionInstallDir ||
		strings.ContainsAny(d.ActionInstallDir, " \t*?[]\\\"'") {
		el.addf(path, "action_install_dir: want a clean absolute path without whitespace or glob characters")
	}
	if strings.ContainsAny(d.ClaudeModel, " \t") || strings.HasPrefix(d.ClaudeModel, "-") {
		el.addf(path, "claude_model: not a model name")
	}
	if len(df.Seats) == 0 {
		el.addf(path, "seats: at least one seat is required")
	}
	names := map[string]bool{}
	sum := 0
	for i, s := range df.Seats {
		f := "seats[" + itoa(i) + "]"
		if !idRe.MatchString(s.Name) {
			el.addf(path, "%s.name: required; %s", f, idRule)
		} else {
			f = "seats." + s.Name
			if names[s.Name] {
				el.addf(path, "%s: declared twice", f)
			}
			names[s.Name] = true
		}
		seat := model.Seat{Name: s.Name, TokenFile: abs(f+".token_file", s.TokenFile, true), MaxParallel: s.MaxParallel}
		if seat.MaxParallel == 0 {
			seat.MaxParallel = 1
		}
		if seat.MaxParallel < 1 || seat.MaxParallel > 16 {
			el.addf(path, "%s.max_parallel: %d is outside [1, 16]", f, seat.MaxParallel)
		}
		if s.ExpiresOn != "" {
			t, err := time.Parse("2006-01-02", s.ExpiresOn)
			if err != nil {
				el.addf(path, "%s.expires_on: want a date as YYYY-MM-DD", f)
			}
			seat.ExpiresOn = t
		}
		sum += seat.MaxParallel
		d.Seats = append(d.Seats, seat)
	}
	if d.MaxParallelRuns == 0 {
		d.MaxParallelRuns = sum
	}
	if len(df.Seats) > 0 && (d.MaxParallelRuns < 1 || d.MaxParallelRuns > 64) {
		el.addf(path, "max_parallel_runs: %d is outside [1, 64]", d.MaxParallelRuns)
	}
	if d.Heartbeat.URL != "" && !httpURL(d.Heartbeat.URL) {
		el.addf(path, "heartbeat.url: want an http(s) URL")
	}
	if d.Heartbeat.Every == 0 {
		d.Heartbeat.Every = time.Minute
	}
	if d.Heartbeat.Every < 10*time.Second || d.Heartbeat.Every > time.Hour {
		el.addf(path, "heartbeat.every: want a duration in [10s, 1h]")
	}
	d.Agent = AgentConfig{
		Network: df.Agent.Network, HTTPSProxy: df.Agent.HTTPSProxy, NoProxy: df.Agent.NoProxy,
		MCPConfig: df.Agent.MCPConfig, ExtraMounts: df.Agent.ExtraMounts, User: df.Agent.User,
		RunArgs: df.Agent.RunArgs, Memory: df.Agent.Memory, CPUs: df.Agent.CPUs, PidsLimit: df.Agent.PidsLimit,
	}
	a := d.Agent
	switch {
	case a.Network == "":
		el.addf(path, "agent.network: required (a pre-created internal container network)")
	case !idRe.MatchString(a.Network), a.Network == "host", a.Network == "bridge", a.Network == "default",
		a.Network == "none", a.Network == "private", a.Network == "pasta", a.Network == "slirp4netns":
		el.addf(path, "agent.network: %q is not the name of an isolated network", a.Network)
	}
	if a.HTTPSProxy != "" && !httpURL(a.HTTPSProxy) {
		el.addf(path, "agent.https_proxy: want an http(s) URL")
	}
	if strings.ContainsAny(a.NoProxy, " \t\n") {
		el.addf(path, "agent.no_proxy: want a comma-separated list without spaces")
	}
	if !filepath.IsAbs(a.MCPConfig) || strings.ContainsAny(a.MCPConfig, ":,\n") || strings.Contains(a.MCPConfig, "..") {
		el.addf(path, "agent.mcp_config: required, an absolute host path (placeholders {project}, {runbook}, ... allowed)")
	}
	for i, m := range a.ExtraMounts {
		parts := strings.Split(m, ":")
		if len(parts) < 2 || len(parts) > 3 || !filepath.IsAbs(parts[0]) || !filepath.IsAbs(parts[1]) ||
			strings.Contains(m, "..") || strings.ContainsAny(m, ",\n ") {
			el.addf(path, "agent.extra_mounts[%d]: want \"/host/path:/container/path[:ro|rw]\"", i)
		}
	}
	if a.User != "" && (!userRe.MatchString(a.User) || a.User == "0" || strings.HasPrefix(a.User, "0:")) {
		el.addf(path, "agent.user: want a non-root numeric uid[:gid]")
	}
	for i, arg := range a.RunArgs {
		// The isolation of the container is not negotiable from this file.
		name, _, _ := strings.Cut(arg, "=")
		switch {
		case !strings.HasPrefix(arg, "--"):
			el.addf(path, "agent.run_args[%d]: want a --flag[=value]", i)
		case name == "--privileged", name == "--network", name == "--net", name == "--cap-add", name == "--pid",
			name == "--ipc", name == "--device", name == "--volume", name == "--mount", name == "--user",
			name == "--security-opt", name == "--env", name == "--env-file", name == "--entrypoint", name == "--volumes-from":
			el.addf(path, "agent.run_args[%d]: %s is not allowed here", i, name)
		}
	}
	for key, v := range map[string]string{"memory": a.Memory, "cpus": a.CPUs} {
		if v != "" && !resourceRe.MatchString(v) {
			el.addf(path, "agent.%s: not a container resource value", key)
		}
	}
	if a.PidsLimit < 0 || a.PidsLimit > 65536 {
		el.addf(path, "agent.pids_limit: %d is outside [0, 65536]", a.PidsLimit)
	}

	lc := df.LockClients
	d.LockClients = LockClients{SQLPlan: lc.SQLPlan, SQLRun: lc.SQLRun, LogMCP: lc.LogMCP, Timeout: time.Duration(lc.Timeout)}
	for key, argv := range map[string][]string{"sql_plan": lc.SQLPlan, "sql_run": lc.SQLRun, "log_mcp": lc.LogMCP} {
		if argv == nil {
			continue
		}
		joined := strings.Join(argv, "\x00")
		switch {
		case len(argv) == 0 || argv[0] == "" || strings.HasPrefix(argv[0], "-"):
			el.addf(path, "lock_clients.%s: want an argument vector starting with the program", key)
		case !strings.Contains(joined, "{instance}"):
			el.addf(path, "lock_clients.%s: no {instance} placeholder", key)
		case key == "sql_run" && !strings.Contains(joined, "{plan_id}"):
			el.addf(path, "lock_clients.sql_run: no {plan_id} placeholder")
		}
	}
	for k, v := range lc.Env {
		switch {
		case !envNameRe.MatchString(k) || strings.ContainsAny(v, "\n\x00"):
			el.addf(path, "lock_clients.env.%s: not an environment variable", k)
		case k == "LEA_AGENT" || k == "LEA_AGENT_TOKEN":
			el.addf(path, "lock_clients.env.%s: the agent identity is set by the daemon", k)
		default:
			d.LockClients.Env = append(d.LockClients.Env, k+"="+v)
		}
	}
	sort.Strings(d.LockClients.Env)
	if d.LockClients.Timeout != 0 && (d.LockClients.Timeout < time.Second || d.LockClients.Timeout > 10*time.Minute) {
		el.addf(path, "lock_clients.timeout: want a duration in [1s, 10m]")
	}
	if err := el.err(); err != nil {
		return nil, err
	}
	return d, nil
}

// CheckRepo reports what the daemon file and a config repository disagree
// on: a project naming a seat the daemon does not have.
func (d *Daemon) CheckRepo(r *Repo) error {
	var el errlist
	have := map[string]bool{}
	for _, s := range d.Seats {
		have[s.Name] = true
	}
	for _, p := range r.Projects {
		for _, s := range p.Seats {
			if !have[s] {
				el.addf("projects/"+p.Slug+"/project.yaml", "seats: %q is not a seat of the daemon", s)
			}
		}
	}
	return el.err()
}
