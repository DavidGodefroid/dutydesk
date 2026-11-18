package forge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// pushDisabledURL is the push URL left in clones handed to the agent.
const pushDisabledURL = "file:///dev/null/dutydesk-push-disabled"

// credentialHelper answers "get" with the values of two environment variables,
// so the token is never part of an argument, a URL or a config file.
const credentialHelper = `!f() { test "$1" = get && printf 'username=%s\npassword=%s\n' "$DUTYDESK_GIT_USERNAME" "$DUTYDESK_GIT_PASSWORD"; }; f`

// passEnv lists the only variables inherited from the daemon's environment.
var passEnv = []string{
	"PATH", "TMPDIR", "GIT_EXEC_PATH",
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
}

// gitCmd describes one git invocation. Every invocation ignores the system and
// user configuration, disables hooks and never prompts.
type gitCmd struct {
	dir      string // working directory
	gitDir   string // GIT_DIR, "" = discovered from dir
	workTree string // GIT_WORK_TREE
	auth     *gitAuth
	env      []string // extra variables
	maxOut   int      // stdout cap in bytes, 0 = 32 MiB
}

type gitAuth struct {
	origin   string // scheme://host[:port] the credentials are valid for
	username string
	token    string
}

type gitResult struct {
	out       []byte
	truncated bool
}

// capBuffer keeps at most max bytes and remembers whether more were written.
type capBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.truncated = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (f *Forge) gitEnv(c gitCmd) []string {
	env := []string{
		"LC_ALL=C", "LANG=C",
		"HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=",
		"GIT_LITERAL_PATHSPECS=1", "GIT_NO_REPLACE_OBJECTS=1",
	}
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if f.cfg.AllowLocal {
		env = append(env, "GIT_ALLOW_PROTOCOL=https:http:file")
	} else {
		env = append(env, "GIT_ALLOW_PROTOCOL=https")
	}
	if c.gitDir != "" {
		env = append(env, "GIT_DIR="+c.gitDir)
	}
	if c.workTree != "" {
		env = append(env, "GIT_WORK_TREE="+c.workTree)
	}
	conf := [][2]string{
		{"core.hooksPath", "/dev/null"},
		{"core.fsmonitor", "false"},
		{"core.untrackedCache", "false"},
		{"core.attributesFile", "/dev/null"},
		{"core.excludesFile", "/dev/null"},
		{"core.autocrlf", "false"},
		{"core.protectNTFS", "true"},
		{"core.protectHFS", "true"},
		{"gc.auto", "0"},
		{"maintenance.auto", "false"},
		{"commit.gpgSign", "false"},
		{"advice.detachedHead", "false"},
		{"init.defaultBranch", "main"},
		{"safe.directory", "*"},
		{"http.followRedirects", "false"},
		{"credential.helper", ""},
	}
	if c.auth != nil && c.auth.origin != "" {
		conf = append(conf, [2]string{"credential." + c.auth.origin + ".helper", credentialHelper})
		env = append(env,
			"DUTYDESK_GIT_USERNAME="+c.auth.username,
			"DUTYDESK_GIT_PASSWORD="+c.auth.token)
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(conf)))
	for i, kv := range conf {
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return append(env, c.env...)
}

// git runs one git command. The error carries the first lines of stderr with
// the token removed, never the environment.
func (f *Forge) git(ctx context.Context, c gitCmd, args ...string) (gitResult, error) {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.GitTimeout)
	defer cancel()
	full := append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = c.dir
	cmd.Env = f.gitEnv(c)
	cmd.WaitDelay = 5 * time.Second
	max := c.maxOut
	if max == 0 {
		max = 32 << 20
	}
	stdout := &capBuffer{max: max}
	stderr := &capBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	res := gitResult{out: stdout.buf.Bytes(), truncated: stdout.truncated}
	if err != nil {
		token := ""
		if c.auth != nil {
			token = c.auth.token
		}
		name := ""
		if len(args) > 0 {
			name = args[0]
		}
		msg := strings.TrimSpace(stderr.buf.String())
		if ctxErr := ctx.Err(); ctxErr != nil {
			msg = ctxErr.Error()
		}
		return res, errors.New(redact(fmt.Sprintf("forge: git %s: %s", name, msg), token))
	}
	return res, nil
}

// redact removes every secret from s.
func redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "[redacted]")
		}
	}
	return s
}

// checkRepoURL validates the clone URL: https only (http and file when
// AllowLocal), no embedded credentials. It returns the origin used to scope
// the credential helper ("" for file URLs).
func (f *Forge) checkRepoURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil, "", errors.New("forge: repo URL is not a valid absolute URL")
	}
	if u.User != nil {
		return nil, "", errors.New("forge: repo URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
	case "http", "file":
		if !f.cfg.AllowLocal {
			return nil, "", fmt.Errorf("forge: repo URL scheme %q is not allowed (https only)", u.Scheme)
		}
	default:
		return nil, "", fmt.Errorf("forge: repo URL scheme %q is not allowed (https only)", u.Scheme)
	}
	if u.Scheme == "file" {
		return u, "", nil
	}
	if u.Host == "" {
		return nil, "", errors.New("forge: repo URL has no host")
	}
	return u, u.Scheme + "://" + u.Host, nil
}

func gitUsername(kind string) string {
	if kind == "github" {
		return "x-access-token"
	}
	return "oauth2"
}

// validRefName is a conservative check for branch names coming from configuration.
func validRefName(name string) bool {
	if name == "" || len(name) > 200 || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "/") ||
		strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, ".lock") ||
		strings.Contains(name, "..") || strings.Contains(name, "//") || strings.Contains(name, "@{") {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	return true
}

func isHexID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
