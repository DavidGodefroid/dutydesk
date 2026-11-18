// Command dutydesk-act is the common launcher installed on the action
// host. It is the only program the lockssh rules of DutyDesk allow:
//
//	dutydesk-act <action> [--param value ...]
//
// It loads the action from the installed catalogue (actions/<name>/
// action.yaml + script), validates the arguments against the manifest,
// enforces the action's rate limit, then runs the script, without a shell,
// with the validated arguments as argv ("--param value" in manifest
// order), under the manifest's timeout and with a minimal environment.
// The script's stdout and stderr are passed through, each capped at
// 64 KiB, and the launcher exits with the script's exit code.
//
// Only regular files run: the catalogue directory, the action directory,
// the manifest and the script are checked with Lstat, and a symbolic link
// (or a device, a FIFO, a directory in place of a file) is refused.
//
// Environment of the launcher (set by the host's administrator):
//
//	DUTYDESK_ACTIONS_DIR        catalogue, default /opt/dutydesk/actions
//	DUTYDESK_ACTIONS_STATE_DIR  rate-limit state, default /var/lib/dutydesk-act
//	DUTYDESK_ACTIONS_AUDIT_LOG  audit log, default <state dir>/audit.log
//	DUTYDESK_ACTIONS_ENV_DIR    per-action env files, default /etc/dutydesk/actions.env.d
//
// When the launcher is invoked through SSH (SSH_CONNECTION or SSH_CLIENT is
// set), which is how an agent reaches it through lockssh, these four
// variables are IGNORED and the defaults apply: whoever comes through SSH
// must not choose the catalogue or the audit log. The administrator can
// allow them again in /etc/dutydesk/act.conf, a regular file owned by root
// that is neither group- nor world-writable:
//
//	allow_env_overrides = true
//
// An act.conf that is present but not trustworthy (a link, another owner,
// too open, an unknown key) stops the launcher: nothing runs.
//
// The script receives only PATH, HOME, USER, LOGNAME, LANG, LC_ALL and TZ
// from the launcher's environment, DUTYDESK_ACTION, and the KEY=VALUE
// lines of <env dir>/<action>.env when that file exists. That file is
// where the script's own production credentials live; it must be a
// regular file that is neither group/world-writable nor world-readable.
//
// Exit codes: the script's own, or
//
//	64   usage or validation error (nothing ran)
//	65   rate limited (nothing ran)
//	70   the launcher could not do its job (broken catalogue, state, audit log, env file)
//	124  the script exceeded its timeout and was killed
//	128+N the script died from signal N
//
// Every invocation appends one JSON line to the audit log, runs and
// refusals alike. A refused invocation's arguments are not recorded.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/actions"
	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const (
	exitUsage       = 64
	exitRateLimited = 65
	exitInternal    = 70
	exitTimeout     = 124

	maxOutput = 64 << 10 // per stream

	defaultStateDir = "/var/lib/dutydesk-act"
	defaultEnvDir   = "/etc/dutydesk/actions.env.d"
	defaultPath     = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// passedEnv is what a script inherits from the launcher's environment.
var passedEnv = []string{"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ"}

// now is replaced in tests.
var now = time.Now

// dirs are the directories of an installation.
type dirs struct{ catalogue, state, envDir string }

// defaults apply when the environment does not, or may not, say otherwise.
// Replaced in tests, like confPath and confOwnerUID.
var defaults = dirs{catalogue: actions.DefaultCatalogueDir, state: defaultStateDir, envDir: defaultEnvDir}

var (
	// confPath is the administrator's file that may allow the environment
	// overrides over SSH.
	confPath = "/etc/dutydesk/act.conf"
	// confOwnerUID must own confPath.
	confOwnerUID = 0
)

// overrideVars are the variables that move the launcher's directories.
var overrideVars = []string{
	"DUTYDESK_ACTIONS_DIR", "DUTYDESK_ACTIONS_STATE_DIR", "DUTYDESK_ACTIONS_AUDIT_LOG", "DUTYDESK_ACTIONS_ENV_DIR",
}

// envOverridesAllowed reads act.conf: "key = value" lines, "#" comments.
// The only key is allow_env_overrides (true | false). A missing file
// allows nothing. The file must be a regular file (never a link) owned by
// confOwnerUID and neither group- nor world-writable, else it is an error.
func envOverridesAllowed(path string) (bool, error) {
	// O_NOFOLLOW: a link is an error; the checks are made on the file that
	// was opened, not on a name that could change in between.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return false, errors.New("is a symbolic link")
		}
		return false, errors.New("cannot be opened")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, errors.New("cannot be read")
	}
	if !st.Mode().IsRegular() {
		return false, errors.New("not a regular file")
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != confOwnerUID {
		return false, fmt.Errorf("not owned by uid %d", confOwnerUID)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return false, fmt.Errorf("mode %04o is group- or world-writable", st.Mode().Perm())
	}
	allowed := false
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch {
		case !ok || key != "allow_env_overrides":
			return false, fmt.Errorf("line %d: want \"allow_env_overrides = true|false\"", n)
		case val == "true":
			allowed = true
		case val == "false":
			allowed = false
		default:
			return false, fmt.Errorf("line %d: allow_env_overrides: want true or false", n)
		}
	}
	return allowed, sc.Err()
}

// realDir reports, with Lstat, whether path is a directory that is not a
// symbolic link. A missing path is (false, nil).
func realDir(path string) (bool, error) {
	st, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, errors.New("cannot be read")
	case st.Mode()&os.ModeSymlink != 0:
		return false, errors.New("is a symbolic link")
	case !st.IsDir():
		return false, errors.New("is not a directory")
	}
	return true, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

type auditRecord struct {
	Time       string            `json:"time"`
	Action     string            `json:"action"`
	Args       map[string]string `json:"args,omitempty"`
	User       string            `json:"user"`
	Outcome    string            `json:"outcome"` // ok | failed | timeout | rate_limited | rejected | error
	ExitCode   int               `json:"exit_code"`
	DurationMS int64             `json:"duration_ms"`
	Error      string            `json:"error,omitempty"`
}

func run(argv []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fail := func(code int, format string, args ...any) int {
		fmt.Fprintf(stderr, "dutydesk-act: "+format+"\n", args...)
		return code
	}
	if len(argv) == 0 || argv[0] == "-h" || argv[0] == "--help" {
		return fail(exitUsage, "usage: dutydesk-act <action> [--param value ...]")
	}

	// Through SSH (lockssh), the environment does not move the catalogue,
	// the state or the audit log unless the administrator's act.conf says so.
	honourEnv := true
	if getenv("SSH_CONNECTION") != "" || getenv("SSH_CLIENT") != "" {
		overridden := false
		for _, key := range overrideVars {
			overridden = overridden || getenv(key) != ""
		}
		if overridden {
			allowed, err := envOverridesAllowed(confPath)
			if err != nil {
				return fail(exitInternal, "%s: %v; nothing ran", confPath, err)
			}
			if !allowed {
				honourEnv = false
				fmt.Fprintf(stderr, "dutydesk-act: the DUTYDESK_ACTIONS_* variables are ignored over SSH (allow_env_overrides in %s)\n", confPath)
			}
		}
	}
	env := func(key, def string) string {
		if v := getenv(key); v != "" && honourEnv {
			return v
		}
		return def
	}
	catalogue := env("DUTYDESK_ACTIONS_DIR", defaults.catalogue)
	stateDir := env("DUTYDESK_ACTIONS_STATE_DIR", defaults.state)
	auditPath := env("DUTYDESK_ACTIONS_AUDIT_LOG", filepath.Join(stateDir, "audit.log"))
	envDir := env("DUTYDESK_ACTIONS_ENV_DIR", defaults.envDir)

	// Fail closed: nothing runs without a place to record it.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fail(exitInternal, "state directory: %v", err)
	}
	audit, err := os.OpenFile(auditPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fail(exitInternal, "audit log: %v", err)
	}
	defer audit.Close()

	start := now()
	rec := auditRecord{Time: start.UTC().Format(time.RFC3339Nano), Action: "(invalid)", User: currentUser()}
	finish := func(code int, outcome, format string, args ...any) int {
		rec.Outcome, rec.ExitCode = outcome, code
		rec.DurationMS = now().Sub(start).Milliseconds()
		if format != "" {
			rec.Error = fmt.Sprintf(format, args...)
			fmt.Fprintf(stderr, "dutydesk-act: %s\n", rec.Error)
		}
		line, _ := json.Marshal(rec)
		if _, err := audit.Write(append(line, '\n')); err != nil {
			fmt.Fprintf(stderr, "dutydesk-act: audit log: %v\n", err)
			if code == 0 {
				return exitInternal
			}
		}
		return code
	}

	name := argv[0]
	if !actions.ValidName(name) {
		return finish(exitUsage, "rejected", "invalid action name")
	}
	rec.Action = name
	// Absolute: the script runs with its own directory as working directory.
	catalogue, err = filepath.Abs(catalogue)
	if err != nil {
		return finish(exitInternal, "error", "catalogue: %v", err)
	}
	actionDir := filepath.Join(catalogue, name)
	// Lstat, never Stat: the catalogue, the action directory, the manifest
	// and the script (LoadAction) are what was installed, not a link to
	// something else.
	for _, d := range []struct{ what, path string }{{"the catalogue", catalogue}, {"the directory of action " + name, actionDir}} {
		ok, err := realDir(d.path)
		if err != nil {
			return finish(exitInternal, "error", "%s %v; nothing ran", d.what, err)
		}
		if !ok {
			return finish(exitUsage, "rejected", "unknown action %s", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(actionDir, actions.ManifestName)); errors.Is(err, os.ErrNotExist) {
		return finish(exitUsage, "rejected", "unknown action %s", name)
	}
	action, err := actions.LoadAction(actionDir)
	if err != nil {
		return finish(exitInternal, "error", "action %s: installed manifest refused: %v", name, err)
	}
	args, err := parseArgs(argv[1:])
	if err != nil {
		return finish(exitUsage, "rejected", "%v", err)
	}
	if err := actions.ValidateArgs(action, args); err != nil {
		return finish(exitUsage, "rejected", "%v", err)
	}
	rec.Args = args

	scriptEnv := []string{"DUTYDESK_ACTION=" + name}
	for _, key := range passedEnv {
		v := getenv(key)
		if key == "PATH" && v == "" {
			v = defaultPath
		}
		if v != "" {
			scriptEnv = append(scriptEnv, key+"="+v)
		}
	}
	fileEnv, err := readEnvFile(filepath.Join(envDir, name+".env"))
	if err != nil {
		return finish(exitInternal, "error", "env file of action %s: %v", name, err)
	}
	scriptEnv = append(scriptEnv, fileEnv...)

	allowed, err := takeRateToken(filepath.Join(stateDir, name+".rate"), action.RateLimit, start)
	if err != nil {
		return finish(exitInternal, "error", "rate limit state: %v", err)
	}
	if !allowed {
		return finish(exitRateLimited, "rate_limited", "action %s is rate limited (%d per %s); nothing ran",
			name, action.RateLimit.Count, action.RateLimit.Window)
	}

	code, outcome, runErr := execute(action, actionDir, args, scriptEnv, stdout, stderr)
	if runErr != "" {
		return finish(code, outcome, "%s", runErr)
	}
	return finish(code, outcome, "")
}

// parseArgs reads strict "--name value" pairs. Errors never quote a value.
func parseArgs(argv []string) (map[string]string, error) {
	args := map[string]string{}
	for i := 0; i < len(argv); i += 2 {
		flag := argv[i]
		name := strings.TrimPrefix(flag, "--")
		if !strings.HasPrefix(flag, "--") || !actions.ValidName(name) {
			return nil, fmt.Errorf("argument %d: want --param value pairs", i+1)
		}
		if i+1 >= len(argv) {
			return nil, fmt.Errorf("parameter --%s: missing value", name)
		}
		if _, dup := args[name]; dup {
			return nil, fmt.Errorf("parameter --%s: given twice", name)
		}
		args[name] = argv[i+1]
	}
	return args, nil
}

// takeRateToken records one run at time t in the action's state file and
// reports whether the limit allows it (a sliding window: at most Count
// runs in any Window). The file is locked for the read-modify-write, so
// concurrent launchers cannot both take the last slot. A refused attempt
// is not recorded.
func takeRateToken(path string, limit model.RateLimit, t time.Time) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return false, err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	var state struct {
		Runs []int64 `json:"runs"` // Unix nanoseconds
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return false, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &state); err != nil {
			return false, fmt.Errorf("%s is corrupt (remove it to reset the limit): %v", filepath.Base(path), err)
		}
	}
	cutoff := t.Add(-limit.Window).UnixNano()
	kept := state.Runs[:0]
	for _, r := range state.Runs {
		// A timestamp from the future (clock moved back) still counts.
		if r > cutoff {
			kept = append(kept, r)
		}
	}
	if len(kept) >= limit.Count {
		return false, nil
	}
	state.Runs = append(kept, t.UnixNano())
	out, _ := json.Marshal(state)
	if err := f.Truncate(0); err != nil {
		return false, err
	}
	if _, err := f.WriteAt(out, 0); err != nil {
		return false, err
	}
	return true, f.Sync()
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// readEnvFile reads KEY=VALUE lines ("#" comments, blank lines, optional
// "export ", optional matching quotes around the value; no expansion).
// A missing file is no variables. Errors never quote a value.
func readEnvFile(path string) ([]string, error) {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Mode().Perm()&0o026 != 0 {
		return nil, fmt.Errorf("mode %04o is too open: it holds credentials (want 0600 or 0640)", st.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !envKeyRe.MatchString(key) {
			return nil, fmt.Errorf("line %d: want KEY=VALUE", n)
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		out = append(out, key+"="+val)
	}
	return out, sc.Err()
}

// capWriter passes at most max bytes on and swallows the rest.
type capWriter struct {
	mu        sync.Mutex
	w         io.Writer
	left      int
	truncated bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if len(p) > c.left {
		p = p[:c.left]
		c.truncated = true
	}
	c.left -= len(p)
	if len(p) > 0 {
		if _, err := c.w.Write(p); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// execute runs the script and returns the exit code, the audit outcome
// and, when the launcher has something to say, a message.
func execute(a model.Action, dir string, args map[string]string, env []string, stdout, stderr io.Writer) (int, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	// argv[1:] of the launcher's own command line, re-built from the
	// validated values: "--param value" in manifest order.
	scriptArgs := actions.CommandLine(a, "", args)[2:]
	cmd := exec.CommandContext(ctx, filepath.Join(dir, a.Script), scriptArgs...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = nil
	out := &capWriter{w: stdout, left: maxOutput}
	errw := &capWriter{w: stderr, left: maxOutput}
	cmd.Stdout, cmd.Stderr = out, errw
	// The script gets its own process group so that a timeout kills its
	// children too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second

	err := cmd.Run()
	if out.truncated {
		fmt.Fprintf(stderr, "dutydesk-act: stdout truncated at %d bytes\n", maxOutput)
	}
	if errw.truncated {
		fmt.Fprintf(stderr, "dutydesk-act: stderr truncated at %d bytes\n", maxOutput)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return exitTimeout, "timeout", fmt.Sprintf("action %s exceeded its timeout of %s and was killed", a.Name, a.Timeout)
	}
	if err == nil {
		return 0, "ok", ""
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), "failed", fmt.Sprintf("action %s died from signal %d", a.Name, int(ws.Signal()))
		}
		return ee.ExitCode(), "failed", ""
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return 0, "ok", ""
	}
	return exitInternal, "error", fmt.Sprintf("action %s could not be started: %v", a.Name, err)
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return fmt.Sprintf("uid:%d", os.Getuid())
}
