package core

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/forge"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/seat"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

var storeOpenFilter = store.IncidentFilter{OpenOnly: true}

// loadRepo loads a config repository and checks it against the daemon file.
func (s *Service) loadRepo(dir string) (*config.Repo, error) {
	repo, err := s.o.LoadRepo(dir)
	if err != nil {
		return nil, err
	}
	if err := s.d.CheckRepo(repo); err != nil {
		return nil, err
	}
	return repo, nil
}

// ConfigSyncer makes the local checkout of the config repository follow its
// protected branch. The configuration is never read from an agent
// workspace: only from this checkout.
type ConfigSyncer interface {
	// Fetch fetches the branch and returns its revision and whether it
	// differs from the checkout.
	Fetch(ctx context.Context) (rev string, changed bool, err error)
	// Export writes the tree of rev into dir (a new directory), so that it
	// can be validated before the checkout moves.
	Export(ctx context.Context, rev, dir string) error
	// FastForward moves the checkout to rev (fast-forward only).
	FastForward(ctx context.Context, rev string) error
}

// syncConfig fetches the protected branch; a valid new revision replaces the
// running configuration at once, an invalid one is rejected (the old
// configuration keeps running) and alerts, once per revision.
func (s *Service) syncConfig(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rev, changed, err := s.syncer.Fetch(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("config repository not fetched", "error", s.scrub(err.Error()))
			s.alertOnce("config-fetch", 6*time.Hour, model.Alert{Kind: model.AlertSystem,
				Title: "The configuration repository cannot be fetched",
				Body:  "DutyDesk keeps running with its current configuration.\n" + s.scrub(err.Error())})
		}
		return
	}
	s.mu.Lock()
	rejected := s.badConfig == rev
	s.mu.Unlock()
	if !changed || rejected {
		return
	}
	reject := func(why error) {
		s.mu.Lock()
		s.badConfig = rev
		s.mu.Unlock()
		s.log.Error("new configuration rejected; keeping the current one", "revision", rev, "error", why)
		s.systemAlert(model.Alert{Kind: model.AlertSystem,
			Title: "New configuration rejected (revision " + short(rev, 12) + ")",
			Body:  "DutyDesk keeps running with the previous configuration. Fix the config repository:\n" + s.scrub(why.Error())})
	}
	tmp, err := os.MkdirTemp(s.d.DataDir, "config-check-")
	if err != nil {
		s.log.Error("config check directory", "error", err)
		return
	}
	defer os.RemoveAll(tmp)
	tree := filepath.Join(tmp, "tree")
	if err := s.syncer.Export(ctx, rev, tree); err != nil {
		s.log.Warn("config revision not exported", "error", s.scrub(err.Error()))
		return
	}
	if _, err := s.loadRepo(tree); err != nil {
		reject(err)
		return
	}
	if err := s.syncer.FastForward(ctx, rev); err != nil {
		reject(fmt.Errorf("the checkout cannot be fast-forwarded: %w", err))
		return
	}
	repo, err := s.loadRepo(s.d.ConfigRepo)
	if err != nil {
		reject(err)
		return
	}
	s.cfg.Store(repo)
	if err := s.sched.Reload(repo.Projects); err != nil {
		s.log.Error("some checks were not scheduled", "error", err)
	}
	s.log.Info("configuration reloaded", "revision", rev, "projects", len(repo.Projects))
}

// ---------- configuration repository as a forge repository ----------

const configRepoPrefix = "dutydesk-config:"

// configRepo describes the config repository for proposals that concern one
// project. The project is carried in the name so that the path policy can
// tell which directory the proposal may touch.
func (s *Service) configRepo(project string) (model.Repo, bool) {
	r := s.d.ConfigRemote
	if r == nil {
		return model.Repo{}, false
	}
	return model.Repo{Name: configRepoPrefix + project, Forge: r.Forge, URL: r.URL, Project: r.Project,
		DefaultBranch: r.Branch, TokenFile: r.TokenFile}, true
}

// DefaultDenyPaths are the paths a DutyDesk merge request on a project
// repository may not touch unless project.yaml says otherwise
// (repos[].deny_paths): CI definitions run on the pushed branch BEFORE any
// human reviews the merge request, with whatever secrets the runners hold,
// and git plumbing files change what a checkout does.
var DefaultDenyPaths = []string{
	".gitlab-ci.yml", ".gitlab/**", ".github/**", ".circleci/**", ".woodpecker/**", ".woodpecker.yml", ".drone.yml",
	".buildkite/**", ".travis.yml", "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml",
	".gitmodules", ".gitattributes", "**/.gitmodules", "**/.gitattributes", "**/.git/**",
}

// proposalPolicy is the path policy of proposals.
//
// On the configuration repository an agent may only propose checks,
// runbooks and actions of its own project: project.yaml (seats, repos,
// locks, limits), standard/ and every other project are out of reach. A
// path must lie at least one segment below checks/, runbooks/ or actions/
// (the directories themselves cannot be replaced by a file or a link), and
// no symbolic link is accepted at all.
//
// On a project repository the built-in deny-list DefaultDenyPaths applies,
// replaced by the repository's deny_paths when project.yaml sets it and
// narrowed by its allow_paths.
func proposalPolicy(repo model.Repo) forge.PathPolicy {
	project, ok := strings.CutPrefix(repo.Name, configRepoPrefix)
	if !ok {
		deny := DefaultDenyPaths
		if repo.DenyPaths != nil {
			deny = repo.DenyPaths
		}
		return forge.PathPolicy{Allow: repo.AllowPaths, Deny: deny}
	}
	if project == "" || strings.ContainsAny(project, "*?[/\\") {
		return forge.PathPolicy{Deny: []string{"**"}, NoSymlinks: true}
	}
	base := "projects/" + project + "/"
	return forge.PathPolicy{
		Allow:      []string{base + "checks/*", base + "runbooks/*", base + "actions/*"},
		Deny:       []string{base + "project.yaml", "standard/**"},
		NoSymlinks: true,
	}
}

// ---------- secrets ----------

// Secrets lists the literal secrets that must never leave: every seat
// token, the agent token of every open incident and every forge token. It
// feeds the forge's secret scan and the scrubbing of journals and alerts.
func (s *Service) Secrets() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v = strings.TrimSpace(v); len(v) >= 8 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, st := range s.d.Seats {
		if tok, err := seat.ReadTokenFile(st.TokenFile); err == nil {
			add(tok)
		}
	}
	file := func(path string) {
		if path == "" {
			return
		}
		if b, err := os.ReadFile(path); err == nil {
			add(string(b))
		}
	}
	if r := s.d.ConfigRemote; r != nil {
		file(r.TokenFile)
	}
	if repo := s.cfg.Load(); repo != nil {
		for _, p := range repo.Projects {
			for _, r := range p.Repos {
				file(r.TokenFile)
			}
			file(p.Alerts.WebhookURLFile)
			for _, w := range p.Webhooks {
				file(w.SecretFile)
			}
		}
	}
	// An incident whose pass just resolved it is no longer open while its
	// merge request is being checked: its token still counts.
	s.mu.Lock()
	for _, tok := range s.passTokens {
		add(tok)
	}
	s.mu.Unlock()
	if s.st != nil {
		if open, err := s.st.ListIncidents(storeOpenFilter); err == nil {
			for _, inc := range open {
				add(inc.AgentToken)
			}
		}
		// The effects of a pass run after it: the token of an incident the
		// pass resolved still counts while its proposal is owed.
		if owed, err := s.st.OwedAgentTokens(); err == nil {
			for _, tok := range owed {
				add(tok)
			}
		}
	}
	return out
}

// scrub removes every known secret from a text bound for a journal, an
// alert or a log.
func (s *Service) scrub(text string) string {
	if text == "" {
		return text
	}
	for _, sec := range s.Secrets() {
		text = strings.ReplaceAll(text, sec, "[redacted]")
	}
	return text
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------- git implementation of ConfigSyncer ----------

// GitSyncer follows config_remote with git: fetch, validate elsewhere, then
// fast-forward. The token reaches git through the environment only (a
// credential helper scoped to the remote's origin), never through an
// argument, a URL or a file of the checkout.
type GitSyncer struct {
	Dir        string // the checkout (config_repo)
	Remote     config.Remote
	AllowLocal bool // accept file:// remotes (tests)
	Timeout    time.Duration
}

const gitCredentialHelper = `!f() { test "$1" = get && printf 'username=%s\npassword=%s\n' "$DUTYDESK_GIT_USERNAME" "$DUTYDESK_GIT_PASSWORD"; }; f`

func (g *GitSyncer) git(ctx context.Context, auth bool, extraEnv []string, args ...string) (string, error) {
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u, err := url.Parse(g.Remote.URL)
	if err != nil || u.User != nil {
		return "", errors.New("config remote: invalid URL")
	}
	protocols := "https"
	if g.AllowLocal {
		protocols = "https:http:file"
	} else if u.Scheme != "https" {
		return "", errors.New("config remote: https only")
	}
	env := []string{
		"LC_ALL=C", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=" + protocols,
	}
	for _, k := range []string{"PATH", "TMPDIR", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	conf := [][2]string{
		{"core.hooksPath", "/dev/null"}, {"safe.directory", "*"}, {"gc.auto", "0"},
		{"http.followRedirects", "false"}, {"credential.helper", ""}, {"advice.detachedHead", "false"},
	}
	token := ""
	if auth && g.Remote.TokenFile != "" && u.Host != "" {
		raw, err := os.ReadFile(g.Remote.TokenFile)
		if err != nil {
			return "", fmt.Errorf("config remote: token file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
		user := "oauth2"
		if g.Remote.Forge == "github" {
			user = "x-access-token"
		}
		conf = append(conf, [2]string{"credential." + u.Scheme + "://" + u.Host + ".helper", gitCredentialHelper})
		env = append(env, "DUTYDESK_GIT_USERNAME="+user, "DUTYDESK_GIT_PASSWORD="+token)
	}
	env = append(env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(conf)))
	for i, kv := range conf {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = g.Dir
	cmd.Env = append(env, extraEnv...)
	cmd.WaitDelay = 5 * time.Second
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.Join(strings.Fields(stderr.String()), " ")
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "[redacted]")
		}
		return "", fmt.Errorf("git %s: %s", args[0], short(msg, 300))
	}
	return strings.TrimSpace(string(out)), nil
}

// Fetch implements ConfigSyncer.
func (g *GitSyncer) Fetch(ctx context.Context) (string, bool, error) {
	if _, err := g.git(ctx, true, nil, "fetch", "-q", "--no-tags", "--no-recurse-submodules", "--", g.Remote.URL,
		"refs/heads/"+g.Remote.Branch); err != nil {
		return "", false, err
	}
	rev, err := g.git(ctx, false, nil, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", false, err
	}
	head, err := g.git(ctx, false, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", false, err
	}
	return rev, rev != head, nil
}

// Export implements ConfigSyncer: the tree of rev is checked out in dir
// through a private index, without touching the checkout.
func (g *GitSyncer) Export(ctx context.Context, rev, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	index := dir + ".index"
	defer os.Remove(index)
	env := []string{"GIT_INDEX_FILE=" + index}
	if _, err := g.git(ctx, false, env, "read-tree", rev); err != nil {
		return err
	}
	_, err := g.git(ctx, false, env, "--work-tree="+dir, "checkout-index", "-a", "-f")
	return err
}

// FastForward implements ConfigSyncer.
func (g *GitSyncer) FastForward(ctx context.Context, rev string) error {
	_, err := g.git(ctx, false, nil, "merge", "-q", "--ff-only", rev)
	return err
}
