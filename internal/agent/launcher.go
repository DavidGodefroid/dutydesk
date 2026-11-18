package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// TokenSource gives the long-lived token of a seat (seat.Pool implements it).
type TokenSource interface {
	Token(seat string) (string, error)
}

// Config is the launcher configuration (host side).
//
// Network expectation (not created here): Network names a container network
// made beforehand as an internal network (no route to the outside, e.g.
// `podman network create --internal dutydesk-agents`). The only other member
// is an egress proxy that allows CONNECT to api.anthropic.com:443 and nothing
// else; HTTPSProxy is its URL as seen from that network (e.g.
// "http://egress:3128"). The launcher refuses to run without a network name,
// so an agent never lands on the default bridge.
type Config struct {
	Runtime    string // "podman" (default) or "docker"; same CLI flags
	Image      string // agent image (see agent/Containerfile); entrypoint is claude
	Network    string // pre-created internal network, required
	HTTPSProxy string // value of HTTPS_PROXY in the container, "" = none
	NoProxy    string // value of NO_PROXY, "" = none

	// MCPConfigPath is the host file mounted read-only at
	// /etc/dutydesk/mcp.json. It declares the lock clients (and only them):
	// its mcpServers keys give the mcp__<server>__* tools that are allowed.
	// ExtraMounts are "-v" specs ("host:container[:opts]", read-only unless
	// opts say otherwise) for the lock client sockets and launch material.
	// Both accept the placeholders {project}, {runbook}, {action_instance},
	// {ask_instance} and {incident}, so each runbook can get only the lockssh
	// sockets of its own profiles.
	MCPConfigPath string
	ExtraMounts   []string

	// RunArgs are extra `run` flags placed before the image, e.g.
	// "--userns=keep-id:uid=10001,gid=10001" with rootless podman so the
	// agent user can write the mounted clones.
	RunArgs []string

	User      string // uid:gid inside the container, default "10001:10001"
	Memory    string // default "4g"
	CPUs      string // default "2"
	PidsLimit int    // default 512
	Model     string // claude --model, "" = CLI default

	DefaultRunTimeout time.Duration // when the project sets none; default 30m
	KillGrace         time.Duration // wait after `kill` before killing the client; default 10s
	TempDir           string        // where the 0600 env-file lives; default os.TempDir()

	// MaxTranscriptBytes caps the transcript the launcher writes to OutDir
	// (the agent decides how much it prints). 0 = DefaultMaxTranscriptBytes
	// (20 MiB). At the cap one truncation marker line is written and the
	// file stops growing; the pass continues and the stream is still parsed,
	// so a verdict that arrives later is honoured.
	MaxTranscriptBytes int64

	Tokens TokenSource      // required
	Runner Runner           // default ExecRunner{}
	Now    func() time.Time // default time.Now
}

// Launcher implements model.AgentLauncher.
type Launcher struct {
	cfg Config
}

var _ model.AgentLauncher = (*Launcher)(nil)

// NewLauncher validates the configuration and applies the defaults.
func NewLauncher(cfg Config) (*Launcher, error) {
	if cfg.Runtime == "" {
		cfg.Runtime = "podman"
	}
	if cfg.Image == "" {
		return nil, errors.New("agent: Image is required")
	}
	if cfg.Network == "" {
		return nil, errors.New("agent: Network is required (a pre-created internal network)")
	}
	switch cfg.Network {
	case "host", "bridge", "default", "slirp4netns", "pasta", "private":
		return nil, fmt.Errorf("agent: network %q is not an isolated network", cfg.Network)
	}
	if strings.HasPrefix(cfg.Network, "container:") || strings.HasPrefix(cfg.Network, "ns:") {
		return nil, fmt.Errorf("agent: network %q is not an isolated network", cfg.Network)
	}
	if cfg.MCPConfigPath == "" {
		return nil, errors.New("agent: MCPConfigPath is required")
	}
	if cfg.Tokens == nil {
		return nil, errors.New("agent: Tokens is required")
	}
	if cfg.User == "" {
		cfg.User = "10001:10001"
	}
	if u := strings.SplitN(cfg.User, ":", 2)[0]; u == "0" || u == "root" {
		return nil, errors.New("agent: the container user must not be root")
	}
	if cfg.Memory == "" {
		cfg.Memory = "4g"
	}
	if cfg.CPUs == "" {
		cfg.CPUs = "2"
	}
	if cfg.PidsLimit <= 0 {
		cfg.PidsLimit = 512
	}
	if cfg.DefaultRunTimeout <= 0 {
		cfg.DefaultRunTimeout = 30 * time.Minute
	}
	if cfg.KillGrace <= 0 {
		cfg.KillGrace = 10 * time.Second
	}
	if cfg.MaxTranscriptBytes < 0 {
		return nil, errors.New("agent: MaxTranscriptBytes must not be negative")
	}
	if cfg.MaxTranscriptBytes == 0 {
		cfg.MaxTranscriptBytes = DefaultMaxTranscriptBytes
	}
	if cfg.Runner == nil {
		cfg.Runner = ExecRunner{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Launcher{cfg: cfg}, nil
}

// Built-in tools the agent may use. Everything else is denied by the
// permission mode, including web tools and subagents.
var builtinTools = []string{"Read", "Grep", "Glob", "Edit", "Write", "Bash"}

// structuredOutputTool is the synthetic tool claude uses to return the
// --json-schema answer.
// VERIFY: whether it needs an allow rule under --permission-mode dontAsk. It
// is listed to be safe; an unknown rule name is harmless.
const structuredOutputTool = "StructuredOutput"

// permissionMode never prompts: what --allowedTools does not allow is denied.
const permissionMode = "dontAsk"

var (
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	mcpNameRE   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	unsafeName  = regexp.MustCompile(`[^a-z0-9_.-]+`)
	containerRE = regexp.MustCompile(`^` + ContainerPrefix + `[a-z0-9_.-]+$`)
)

// ContainerPrefix starts the name of every agent container.
const ContainerPrefix = "dutydesk-"

// ContainerName is the name of the container of pass number run (1-based,
// unique per incident, quota retries included) of an incident.
func ContainerName(inc model.Incident, run int) string {
	return ContainerNameFor(inc.ID, run)
}

// ContainerNameFor is ContainerName from the incident id alone: the name of
// the container of pass number run of that incident. The core uses it to
// remove the container of an incident that left "investigating".
func ContainerNameFor(incidentID string, run int) string {
	id := strings.Trim(unsafeName.ReplaceAllString(strings.ToLower(incidentID), "-"), "-.")
	if id == "" {
		id = "incident"
	}
	return fmt.Sprintf("%s%s-%d", ContainerPrefix, id, run)
}

// RemoveContainer force-removes an agent container and verifies that it is
// gone: `<runtime> rm -f <name>`, then `<runtime> inspect --type container
// <name>`. It returns nil only when the inspection proves the container no
// longer exists (non-zero exit with the runtime's "no such ..." answer). Any
// other outcome is an error: the container may still be there, and so may
// what it holds (the seat token, the lock sockets).
//
// The exit code of `rm -f` is not trusted either way: a container started
// with --rm is usually gone already. ctx must be alive and bounded: after a
// pass that was cancelled or timed out, give a fresh context, never the pass
// context. name must be an agent container name (ContainerName); anything
// else is refused, so the helper cannot remove a foreign container.
func RemoveContainer(ctx context.Context, r Runner, runtime, name string) error {
	if !containerRE.MatchString(name) {
		return fmt.Errorf("agent: %q is not an agent container name", name)
	}
	if r == nil {
		r = ExecRunner{}
	}
	if runtime == "" {
		runtime = "podman"
	}
	rmOut := &tailBuffer{max: 512}
	if _, err := r.Run(ctx, Command{Name: runtime, Args: []string{"rm", "-f", name}, Stdout: rmOut, Stderr: rmOut}); err != nil {
		return fmt.Errorf("agent: remove container %s: %s", name, short(err.Error()))
	}
	out := &tailBuffer{max: 2048}
	code, err := r.Run(ctx, Command{Name: runtime, Args: []string{"inspect", "--type", "container", name}, Stdout: out, Stderr: out})
	if err != nil {
		return fmt.Errorf("agent: inspect container %s: %s", name, short(err.Error()))
	}
	if ctx.Err() != nil {
		return fmt.Errorf("agent: inspect container %s: %v", name, ctx.Err())
	}
	if code == 0 {
		return fmt.Errorf("agent: container %s still exists after rm -f (%s)", name, short(rmOut.String()))
	}
	if !strings.Contains(strings.ToLower(out.String()), "no such") {
		return fmt.Errorf("agent: cannot tell whether container %s is gone: inspect exited with code %d: %s", name, code, short(out.String()))
	}
	return nil
}

// Removal of the container after a pass: a few attempts (the runtime may
// still be tearing a --rm container down), all within one bounded context.
const (
	removeAttempts = 3
	removeTimeout  = 45 * time.Second
)

var removeRetryDelay = 500 * time.Millisecond

// cleanup removes the container of a finished pass and returns "" when it is
// verified gone, else its name (RunResult.Leftover).
func (l *Launcher) cleanup(name string) string {
	// A fresh context: the pass context may be cancelled or expired.
	ctx, cancel := context.WithTimeout(context.Background(), removeTimeout)
	defer cancel()
	for i := 0; i < removeAttempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return name
			case <-time.After(removeRetryDelay):
			}
		}
		if RemoveContainer(ctx, l.cfg.Runner, l.cfg.Runtime, name) == nil {
			return ""
		}
	}
	return name
}

// ClaudeArgs returns the arguments given to the image entrypoint (claude).
// The prompt is not among them: it goes on stdin.
func (l *Launcher) ClaudeArgs(req model.RunRequest, mcpServers []string) []string {
	tools := append([]string(nil), builtinTools...)
	tools = append(tools, structuredOutputTool)
	for _, s := range mcpServers {
		tools = append(tools, "mcp__"+s+"__*")
	}
	args := []string{
		"-p",
		"--output-format", "stream-json",
		"--verbose",
		"--json-schema", VerdictSchema,
		"--mcp-config", ContainerMCPConfig,
		"--strict-mcp-config",
		"--permission-mode", permissionMode,
		"--allowedTools", strings.Join(tools, ","),
	}
	if req.Project != nil && req.Project.Limits.MaxTurns > 0 {
		// --max-turns is not listed by `claude --help` in 2.1.327 but is in
		// the option table of the binary (print mode).
		// VERIFY: accepted by the pinned CLI version of the image.
		args = append(args, "--max-turns", strconv.Itoa(req.Project.Limits.MaxTurns))
	}
	if l.cfg.Model != "" {
		args = append(args, "--model", l.cfg.Model)
	}
	return args
}

// runArgs builds the full `<runtime> run` argument list.
func (l *Launcher) runArgs(req model.RunRequest, envFile string, mcpServers []string) ([]string, error) {
	c := l.cfg
	expand := placeholders(req)
	args := []string{
		"run", "--rm", "-i",
		"--name", ContainerName(req.Incident, req.Run),
		"--read-only",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
		"--tmpfs", "/home/agent:rw,nosuid,nodev,size=256m,mode=1777",
		"--user", c.User,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", c.Memory,
		"--cpus", c.CPUs,
		"--pids-limit", strconv.Itoa(c.PidsLimit),
		"--network", c.Network,
		"--workdir", ContainerWorkDir,
		"--env-file", envFile,
	}
	mount := func(host, target, mode string) error {
		if err := checkHostPath(host); err != nil {
			return err
		}
		args = append(args, "-v", host+":"+target+":"+mode)
		return nil
	}
	if req.DossierDir == "" {
		return nil, errors.New("no dossier directory")
	}
	if err := mount(req.DossierDir, ContainerDossierDir, "ro"); err != nil {
		return nil, fmt.Errorf("dossier: %w", err)
	}
	repos := make([]string, 0, len(req.RepoDirs))
	for name := range req.RepoDirs {
		repos = append(repos, name)
	}
	sort.Strings(repos)
	for _, name := range repos {
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("repo name %q is not usable as a mount point", name)
		}
		if err := mount(req.RepoDirs[name], ContainerReposDir+"/"+name, "rw"); err != nil {
			return nil, fmt.Errorf("repo %s: %w", name, err)
		}
	}
	if req.ConfigDir != "" {
		if err := mount(req.ConfigDir, ContainerConfigDir, "rw"); err != nil {
			return nil, fmt.Errorf("config clone: %w", err)
		}
	}
	if err := mount(expand(c.MCPConfigPath), ContainerMCPConfig, "ro"); err != nil {
		return nil, fmt.Errorf("mcp config: %w", err)
	}
	for _, m := range c.ExtraMounts {
		spec, err := extraMount(expand(m))
		if err != nil {
			return nil, err
		}
		args = append(args, "-v", spec)
	}
	args = append(args, c.RunArgs...)
	args = append(args, c.Image)
	args = append(args, l.ClaudeArgs(req, mcpServers)...)
	return args, nil
}

func placeholders(req model.RunRequest) func(string) string {
	project := ""
	if req.Project != nil {
		project = req.Project.Slug
	}
	r := strings.NewReplacer(
		"{project}", project,
		"{runbook}", req.Runbook.ID,
		"{action_instance}", req.Runbook.ActionInstance,
		"{ask_instance}", req.Runbook.AskInstance,
		"{incident}", req.Incident.ID,
	)
	return r.Replace
}

func checkHostPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("host path %q is not absolute", p)
	}
	if strings.ContainsAny(p, ":,\n\r") || strings.Contains(p, "..") {
		return fmt.Errorf("host path %q has characters a mount cannot carry", p)
	}
	return nil
}

// extraMount validates "host:container[:opts]" and makes it read-only when no
// option is given.
func extraMount(spec string) (string, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("extra mount %q is not host:container[:opts]", spec)
	}
	if err := checkHostPath(parts[0]); err != nil {
		return "", fmt.Errorf("extra mount: %w", err)
	}
	if !filepath.IsAbs(parts[1]) || strings.ContainsAny(parts[1], ",\n\r") {
		return "", fmt.Errorf("extra mount %q: container path must be absolute", spec)
	}
	if len(parts) == 2 {
		return spec + ":ro", nil
	}
	return spec, nil
}

// mcpServerNames reads the names of the servers declared in an MCP config
// file. They are the only MCP tools the agent is allowed to call.
func mcpServerNames(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mcp config: %w", err)
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("mcp config %s: %w", path, err)
	}
	names := make([]string, 0, len(cfg.MCPServers))
	for n := range cfg.MCPServers {
		// claude normalises other characters to "_" in tool names; refusing
		// them keeps the allow list exact.
		if !mcpNameRE.MatchString(n) {
			return nil, fmt.Errorf("mcp config %s: server name %q must match [A-Za-z0-9_-]+", path, n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// writeEnvFile writes the container environment to a 0600 temp file. Secrets
// reach the container this way only: never through argv.
func (l *Launcher) writeEnvFile(req model.RunRequest, token string) (string, error) {
	env := [][2]string{
		{"CLAUDE_CODE_OAUTH_TOKEN", token},
		// Lock agent identity: the label and the secret are those of the
		// incident, so a later pass can replay an approved ticket.
		{"LEA_AGENT", "dutydesk:" + req.Incident.ID},
		{"LEA_AGENT_TOKEN", req.Incident.AgentToken},
		{"HOME", "/home/agent"},
		{"DISABLE_AUTOUPDATER", "1"},
		{"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"},
	}
	if p := l.cfg.HTTPSProxy; p != "" {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			env = append(env, [2]string{k, p})
		}
	}
	if p := l.cfg.NoProxy; p != "" {
		env = append(env, [2]string{"NO_PROXY", p}, [2]string{"no_proxy", p})
	}
	var b bytes.Buffer
	for _, kv := range env {
		if strings.ContainsAny(kv[1], "\n\r\x00") {
			return "", fmt.Errorf("environment value of %s holds a line break", kv[0])
		}
		b.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	f, err := os.CreateTemp(l.cfg.TempDir, "dutydesk-env-*")
	if err != nil {
		return "", fmt.Errorf("env file: %w", err)
	}
	name := f.Name()
	// CreateTemp already uses 0600; be explicit against an odd umask or ACL default.
	err = f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(b.Bytes())
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", fmt.Errorf("env file: %w", err)
	}
	return name, nil
}

// tailBuffer keeps the last bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = append(t.b[:0], t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

// Run executes one agent pass. It never returns the seat token or the agent
// token in RunResult.Error, and scrubs them from the transcript.
func (l *Launcher) Run(ctx context.Context, req model.RunRequest) model.RunResult {
	secrets := []string{req.Incident.AgentToken}
	fail := func(format string, a ...any) model.RunResult {
		return model.RunResult{Status: model.RunFailed, Error: redact(fmt.Sprintf(format, a...), secrets)}
	}
	if req.OutDir == "" {
		return fail("no output directory")
	}
	if strings.TrimSpace(req.Prompt) == "" {
		return fail("empty prompt")
	}
	if req.Incident.ID == "" {
		return fail("incident has no id")
	}
	if req.Run < 1 {
		return fail("no pass number")
	}
	if err := os.MkdirAll(req.OutDir, 0o700); err != nil {
		return fail("output directory: %v", err)
	}
	token, err := l.cfg.Tokens.Token(req.Seat.Name)
	if err != nil {
		return fail("seat %s: %v", req.Seat.Name, err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fail("seat %s: empty token", req.Seat.Name)
	}
	secrets = append(secrets, token)

	servers, err := mcpServerNames(placeholders(req)(l.cfg.MCPConfigPath))
	if err != nil {
		return fail("%v", err)
	}
	envFile, err := l.writeEnvFile(req, token)
	if err != nil {
		return fail("%v", err)
	}
	defer os.Remove(envFile)

	args, err := l.runArgs(req, envFile, servers)
	if err != nil {
		return fail("%v", err)
	}

	tf, err := os.OpenFile(filepath.Join(req.OutDir, "transcript.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fail("transcript: %v", err)
	}
	tr := newTranscript(tf, l.cfg.MaxTranscriptBytes, secrets...)
	stderr := &tailBuffer{max: 4096}

	timeout := l.cfg.DefaultRunTimeout
	if req.Project != nil && req.Project.Limits.RunTimeout > 0 {
		timeout = req.Project.Limits.RunTimeout
	}

	// The client process gets its own context: on timeout or cancellation
	// the container is killed first, the client only if it lingers.
	procCtx, killProc := context.WithCancel(context.WithoutCancel(ctx))
	defer killProc()
	type exit struct {
		code int
		err  error
	}
	done := make(chan exit, 1)
	go func() {
		code, err := l.cfg.Runner.Run(procCtx, Command{
			Name: l.cfg.Runtime, Args: args,
			Stdin: strings.NewReader(req.Prompt), Stdout: tr, Stderr: stderr,
		})
		done <- exit{code, err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var ex exit
	stopped := model.RunStatus("")
	select {
	case ex = <-done:
	case <-timer.C:
		stopped = model.RunTimeout
	case <-ctx.Done():
		stopped = model.RunCancelled
	}
	if stopped != "" {
		l.kill(ContainerName(req.Incident, req.Run))
		grace := time.NewTimer(l.cfg.KillGrace)
		select {
		case ex = <-done:
			grace.Stop()
		case <-grace.C:
			killProc()
			ex = <-done
		}
	}
	// The Runner has returned: nothing writes to the transcript any more.
	werr := tr.Close()
	if cerr := tf.Close(); werr == nil {
		werr = cerr
	}

	// However the pass ended, its container must not outlive it: it holds
	// the seat token and the lock sockets. --rm is not relied upon. The only
	// case skipped is a runtime binary that could not be executed at all: no
	// container was ever created.
	leftover := ""
	if !neverExecuted(ex.err) {
		leftover = l.cleanup(ContainerName(req.Incident, req.Run))
	}

	res := l.interpret(tr, ex.code, ex.err, stderr.String(), stopped, timeout)
	if res.Status == model.RunOK && werr != nil {
		// The verdict is valid; a truncated transcript is not worth a failed pass.
		res.Error = "transcript incomplete: " + werr.Error()
	}
	if res.Verdict != nil {
		if err := writeVerdict(filepath.Join(req.OutDir, "verdict.json"), res.Verdict, maxVerdictFileBytes); err != nil {
			res = model.RunResult{
				Status: model.RunFailed, Error: "verdict file: " + err.Error(),
				CostUSD: res.CostUSD, Turns: res.Turns, InputTok: res.InputTok, OutputTok: res.OutputTok,
			}
		}
	}
	res.Error = redact(res.Error, secrets)
	res.Leftover = leftover
	return res
}

// neverExecuted tells whether the Runner failed because the runtime binary
// could not be executed (missing, not executable).
func neverExecuted(err error) bool {
	return err != nil && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission))
}

// kill stops the container, best effort. It uses a fresh context: the pass
// context may already be cancelled.
func (l *Launcher) kill(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var sink tailBuffer
	sink.max = 512
	_, _ = l.cfg.Runner.Run(ctx, Command{Name: l.cfg.Runtime, Args: []string{"kill", name}, Stdout: &sink, Stderr: &sink})
}

// interpret turns what the pass produced into a RunResult.
func (l *Launcher) interpret(tr *transcript, code int, runErr error, stderr string, stopped model.RunStatus, timeout time.Duration) model.RunResult {
	var res model.RunResult
	r := tr.result
	if r != nil {
		res.CostUSD = r.TotalCostUSD
		res.Turns = r.NumTurns
		if u := r.Usage; u != nil {
			// Cache reads and writes are input too: the report shows one figure.
			res.InputTok = u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
			res.OutputTok = u.OutputTokens
		}
	}
	switch stopped {
	case model.RunTimeout:
		res.Status = model.RunTimeout
		res.Error = fmt.Sprintf("pass exceeded %s; container killed", timeout)
		return res
	case model.RunCancelled:
		res.Status = model.RunCancelled
		res.Error = "pass cancelled; container killed"
		return res
	}
	if runErr != nil {
		res.Status = model.RunFailed
		res.Error = "container runtime: " + short(runErr.Error())
		return res
	}

	usable := r != nil && !r.IsError && r.Subtype == "success"
	if usable && code == 0 {
		raw := verdictBytes(r)
		v, err := ParseVerdict(raw)
		if err == nil {
			res.Status = model.RunOK
			res.Verdict = v
			return res
		}
		res.Status = model.RunFailed
		if len(raw) == 0 {
			res.Error = "no verdict in the result"
		} else {
			res.Error = short(err.Error())
		}
		return res
	}

	// No usable result: seat exhausted, or plain failure?
	now := l.cfg.Now()
	var errText string
	if r != nil {
		errText = strings.TrimSpace(rawString(r.Result) + " " + rawString(r.Errors))
	}
	if quotaResult(r, errText) {
		res.Status = model.RunQuota
		// The rate_limit_event only supplies the reset time; both sources
		// are clamped (past or more than 24h ahead = unknown).
		res.QuotaReset = fromEpoch(tr.rejectedReset, now)
		if res.QuotaReset.IsZero() {
			res.QuotaReset = resetFromText(errText+" "+stderr, now)
		}
		res.Error = "seat exhausted"
		if errText != "" {
			res.Error += ": " + short(errText)
		}
		return res
	}

	res.Status = model.RunFailed
	switch {
	case r != nil && r.Subtype != "" && r.Subtype != "success":
		res.Error = "claude ended with " + r.Subtype
		if errText != "" {
			res.Error += ": " + short(errText)
		}
	case r != nil && r.IsError:
		res.Error = "claude reported an error: " + short(errText)
	case r == nil && code == 0:
		res.Error = "no result event in the output"
	default:
		res.Error = fmt.Sprintf("agent container exited with code %d", code)
		if s := strings.TrimSpace(stderr); s != "" {
			res.Error += ": " + short(s)
		}
	}
	return res
}

// quotaResult tells whether the CLI's own final outcome is a usage-limit
// error. The whole stream is attacker-controlled (prompt injection), so the
// rule is strict: the LAST result event must be an error result, and that
// result must be recognisably a usage limit (HTTP 429, or the limit wording
// in its own text). A mid-stream rate_limit_event, an assistant-level error
// tag, stderr or the exit code never make a quota outcome: without such a
// final result the pass is RunFailed (or RunOK when the final result is a
// valid success). Endings that are known not to be a limit (max turns, max
// budget, structured-output retries) are never quota, whatever their text.
func quotaResult(r *streamEvent, errText string) bool {
	if r == nil || !(r.IsError || strings.HasPrefix(r.Subtype, "error")) {
		return false
	}
	switch r.Subtype {
	case "error_max_turns", "error_max_budget_usd", "error_max_structured_output_retries":
		return false
	}
	if r.APIErrorStatus != nil && *r.APIErrorStatus == 429 {
		return true
	}
	return looksLikeQuota(errText)
}

// verdictBytes picks the verdict out of a success result: the structured
// output when present, else the result text (bare JSON or one fenced block).
func verdictBytes(r *streamEvent) []byte {
	if so := bytes.TrimSpace(r.StructuredOutput); len(so) > 0 && !bytes.Equal(so, []byte("null")) {
		// structured_output is the JSON value itself, an object (confirmed on
		// claude 2.1.327, testdata/real-2.1.327.jsonl). A JSON string holding
		// the object is accepted too.
		if so[0] == '"' {
			var s string
			if json.Unmarshal(so, &s) == nil {
				return []byte(s)
			}
		}
		return so
	}
	text := strings.TrimSpace(rawString(r.Result))
	if strings.HasPrefix(text, "```") {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		}
		text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "```"))
	}
	return []byte(text)
}

// maxVerdictFileBytes bounds verdict.json. A verdict that passed
// ParseVerdict is far smaller (its fields are length-checked, about 120 000
// code points in all); the cap keeps the file bounded even if a bound is
// loosened one day.
const maxVerdictFileBytes = 1 << 20

func writeVerdict(path string, v *model.Verdict, max int) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if len(b)+1 > max {
		return fmt.Errorf("verdict is %d bytes, over the %d bytes limit", len(b)+1, max)
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// short keeps an error message on one line and under 300 characters.
func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

func redact(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}
