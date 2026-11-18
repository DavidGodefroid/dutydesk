// Package forge clones repositories, pushes one proposal branch and opens a
// merge request (GitLab) or pull request (GitHub) with the service account.
//
// The agent edits a clone it fully controls, so nothing inside that clone is
// trusted: Propose never reads the clone's .git directory to run anything. It
// builds the commit in a private repository created for the call, fetches the
// base from the URL of model.Repo and pushes to that URL only.
//
// There is deliberately no merge function anywhere in this package.
package forge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Refusal reasons. Propose returns them wrapped in a *Refusal, before any push.
var (
	ErrNoChange      = errors.New("forge: nothing changed")
	ErrForbiddenPath = errors.New("forge: forbidden path")
	ErrSecretFound   = errors.New("forge: secret found")
	ErrTooLarge      = errors.New("forge: change too large")
	ErrSymlinkEscape = errors.New("forge: symlink points outside the repository")
	ErrBadBranch     = errors.New("forge: invalid branch name")
	ErrBranchExists  = errors.New("forge: branch already exists on the remote")
	ErrUnknownBase   = errors.New("forge: base commit of the clone is unknown")
	ErrTokenFile     = errors.New("forge: unusable token file")
)

// Refusal explains why a proposal was refused. Details name paths, lines and
// rules; they never contain a secret.
type Refusal struct {
	Reason  error
	Details []string
}

func (r *Refusal) Error() string {
	if len(r.Details) == 0 {
		return r.Reason.Error()
	}
	return r.Reason.Error() + ": " + strings.Join(r.Details, ", ")
}

func (r *Refusal) Unwrap() error { return r.Reason }

func refuse(reason error, details ...string) error {
	return &Refusal{Reason: reason, Details: details}
}

// Limits caps the size of a proposal. Zero values use the defaults.
type Limits struct {
	MaxFiles       int // changed files, default 100
	MaxDiffBytes   int // total size of the diff, default 512 KiB
	MaxBinaryBytes int // size of one added or modified binary file, default 64 KiB
}

// Config configures a Forge. The zero value is usable.
type Config struct {
	AuthorName  string // commit author and committer, default "DutyDesk"
	AuthorEmail string // default "dutydesk@localhost"

	// PolicyFor returns the path policy of a repository; nil means no restriction.
	PolicyFor func(model.Repo) PathPolicy
	// Secrets returns the literal secrets that must never leave (seat tokens,
	// tokens of other forges...). The token of the repository is always added.
	Secrets func() []string
	Limits  Limits

	// APIBase overrides the REST base URL per forge kind ("gitlab", "github"),
	// e.g. "https://gitlab.example.com/api/v4". Otherwise it is derived from Repo.URL.
	APIBase    map[string]string
	HTTPClient *http.Client  // default: 30 s timeout, redirects not followed
	GitTimeout time.Duration // per git command, default 2 min
	TempDir    string        // where private repositories are created, default os.TempDir()
	// AllowLocal accepts http:// and file:// repositories. For tests only.
	AllowLocal bool
	Logf       func(format string, args ...any)
}

// Forge implements model.Forge for GitLab and GitHub, selected by Repo.Forge.
type Forge struct {
	cfg  Config
	http *http.Client

	mu    sync.Mutex
	bases map[string]string // clone directory -> commit it was cloned at
}

var _ model.Forge = (*Forge)(nil)

// New returns a Forge.
func New(cfg Config) *Forge {
	if cfg.AuthorName == "" {
		cfg.AuthorName = "DutyDesk"
	}
	if cfg.AuthorEmail == "" {
		cfg.AuthorEmail = "dutydesk@localhost"
	}
	if cfg.Limits.MaxFiles <= 0 {
		cfg.Limits.MaxFiles = 100
	}
	if cfg.Limits.MaxDiffBytes <= 0 {
		cfg.Limits.MaxDiffBytes = 512 << 10
	}
	if cfg.Limits.MaxBinaryBytes <= 0 {
		cfg.Limits.MaxBinaryBytes = 64 << 10
	}
	if cfg.GitTimeout <= 0 {
		cfg.GitTimeout = 2 * time.Minute
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			// Never carry the token to another location.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Forge{cfg: cfg, http: client, bases: map[string]string{}}
}

func (f *Forge) logf(format string, args ...any) {
	if f.cfg.Logf != nil {
		f.cfg.Logf(format, args...)
	}
}

// readToken reads a service account token. The file must be a regular file
// that group and others cannot read.
func readToken(file string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("%w: no token file configured", ErrTokenFile)
	}
	fh, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenFile, err)
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenFile, err)
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%w: %s is not a regular file", ErrTokenFile, file)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%w: %s is accessible by group or others (mode %04o, want 0600)", ErrTokenFile, file, st.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(fh, 8192))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTokenFile, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrTokenFile, file)
	}
	for _, r := range token {
		if r <= ' ' || r == 0x7f {
			return "", fmt.Errorf("%w: %s holds more than one token", ErrTokenFile, file)
		}
	}
	return token, nil
}

func (f *Forge) checkRepo(repo model.Repo) (auth *gitAuth, err error) {
	if repo.Forge != "gitlab" && repo.Forge != "github" {
		return nil, fmt.Errorf("forge: unknown forge %q", repo.Forge)
	}
	_, origin, err := f.checkRepoURL(repo.URL)
	if err != nil {
		return nil, err
	}
	if repo.DefaultBranch != "" && !validRefName(repo.DefaultBranch) {
		return nil, errors.New("forge: invalid default branch name")
	}
	token, err := readToken(repo.TokenFile)
	if err != nil {
		return nil, err
	}
	return &gitAuth{origin: origin, username: gitUsername(repo.Forge), token: token}, nil
}

func cloneKey(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// Clone makes a shallow clone of the default branch in dir. The token is
// handed to git through the environment only: the clone holds no credential
// and its origin push URL is disabled.
func (f *Forge) Clone(ctx context.Context, repo model.Repo, dir string) error {
	auth, err := f.checkRepo(repo)
	if err != nil {
		return err
	}
	key, err := cloneKey(dir)
	if err != nil {
		return err
	}
	if entries, err := os.ReadDir(key); err == nil && len(entries) > 0 {
		return fmt.Errorf("forge: clone directory %s is not empty", key)
	}
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		return err
	}
	args := []string{"clone", "-q", "--depth=1", "--single-branch", "--no-tags", "--template="}
	if repo.DefaultBranch != "" {
		args = append(args, "--branch", repo.DefaultBranch)
	}
	args = append(args, "--", repo.URL, key)
	if _, err := f.git(ctx, gitCmd{dir: filepath.Dir(key), auth: auth}, args...); err != nil {
		return err
	}
	if _, err := f.git(ctx, gitCmd{dir: key}, "config", "remote.origin.pushurl", pushDisabledURL); err != nil {
		return err
	}
	res, err := f.git(ctx, gitCmd{dir: key}, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return err
	}
	base := strings.TrimSpace(string(res.out))
	if !isHexID(base) {
		return errors.New("forge: clone has no commit")
	}
	f.mu.Lock()
	for k := range f.bases { // forget clones that were removed
		if _, err := os.Lstat(k); err != nil {
			delete(f.bases, k)
		}
	}
	f.bases[key] = base
	f.mu.Unlock()
	return nil
}

// change is one entry of the staged diff against the base.
type change struct {
	oldMode, newMode string
	oldID, newID     string
	status           string
	path             string
}

// Propose commits the working tree of dir on a new branch, pushes that single
// branch and opens a merge request. Every refusal happens before the push.
func (f *Forge) Propose(ctx context.Context, repo model.Repo, dir, branch, title, description string, draft bool, labels []string) (model.MRInfo, error) {
	var none model.MRInfo
	if !validBranch(branch) {
		return none, refuse(ErrBadBranch, "want "+branchRE.String())
	}
	title = strings.Join(strings.Fields(title), " ")
	if title == "" {
		return none, errors.New("forge: empty title")
	}
	if r := []rune(title); len(r) > 200 {
		title = string(r[:200])
	}
	for _, l := range labels {
		if l == "" || len(l) > 64 || strings.ContainsAny(l, ",\n\r") {
			return none, errors.New("forge: invalid label")
		}
	}
	auth, err := f.checkRepo(repo)
	if err != nil {
		return none, err
	}
	if _, err := f.apiBase(repo); err != nil {
		return none, err
	}
	policy := PathPolicy{}
	if f.cfg.PolicyFor != nil {
		policy = f.cfg.PolicyFor(repo)
	}
	if err := policy.validate(); err != nil {
		return none, err
	}
	key, err := cloneKey(dir)
	if err != nil {
		return none, err
	}
	if st, err := os.Lstat(key); err != nil || !st.IsDir() {
		return none, fmt.Errorf("forge: %s is not a directory", key)
	}

	// A private repository: the clone's own .git (config, hooks, remotes,
	// index, refs) is never used.
	tmp, err := os.MkdirTemp(f.cfg.TempDir, "dutydesk-forge-")
	if err != nil {
		return none, err
	}
	defer os.RemoveAll(tmp)
	if _, err := f.git(ctx, gitCmd{dir: tmp}, "init", "-q", "--template=", "repo"); err != nil {
		return none, err
	}
	bare := gitCmd{dir: tmp, gitDir: filepath.Join(tmp, "repo", ".git")}
	remote := bare
	remote.auth = auth
	tree := bare
	tree.dir, tree.workTree = key, key

	target := repo.DefaultBranch
	if target == "" {
		if target, err = f.remoteDefault(ctx, remote, repo.URL); err != nil {
			return none, err
		}
	}
	if branch == target {
		return none, refuse(ErrBadBranch, "the default branch")
	}
	base, err := f.fetchBase(ctx, remote, repo.URL, target, key)
	if err != nil {
		return none, err
	}

	if _, err := f.git(ctx, bare, "read-tree", base); err != nil {
		return none, err
	}
	if _, err := f.git(ctx, tree, "add", "-A"); err != nil {
		return none, err
	}
	changes, err := f.changes(ctx, bare, base)
	if err != nil {
		return none, err
	}
	if len(changes) == 0 {
		return none, refuse(ErrNoChange)
	}

	// Paths: nothing under a .git directory, no nested repository, no symlink out of the tree.
	var paths, underGit, escapes []string
	for _, c := range changes {
		paths = append(paths, c.path)
		for _, seg := range strings.Split(c.path, "/") {
			if strings.EqualFold(seg, ".git") {
				underGit = append(underGit, c.path)
				break
			}
		}
		if c.newMode == "160000" {
			underGit = append(underGit, c.path+" (nested repository)")
		}
		if c.newMode == "120000" {
			res, err := f.git(ctx, bare, "cat-file", "blob", c.newID)
			if err != nil {
				return none, err
			}
			if symlinkEscapes(c.path, string(res.out)) {
				escapes = append(escapes, c.path)
			}
		}
	}
	if len(underGit) > 0 {
		return none, refuse(ErrForbiddenPath, underGit...)
	}
	if len(escapes) > 0 {
		return none, refuse(ErrSymlinkEscape, escapes...)
	}
	if bad := policy.violations(paths); len(bad) > 0 {
		return none, refuse(ErrForbiddenPath, bad...)
	}

	// Size caps, then the secret scan over the added lines.
	lim := f.cfg.Limits
	if len(changes) > lim.MaxFiles {
		return none, refuse(ErrTooLarge, fmt.Sprintf("%d files changed, limit %d", len(changes), lim.MaxFiles))
	}
	if err := f.checkBinaries(ctx, bare, base, changes); err != nil {
		return none, err
	}
	secrets := []string{auth.token}
	if f.cfg.Secrets != nil {
		secrets = append(secrets, f.cfg.Secrets()...)
	}
	scan := newScanner(secrets)
	scan.text("branch", branch)
	scan.text("title", title)
	scan.text("description", description)
	scan.text("labels", strings.Join(labels, "\n"))
	total := 0
	for _, c := range changes {
		scan.text(c.path+" (file name)", c.path)
		one := bare
		one.maxOut = lim.MaxDiffBytes - total + 1
		res, err := f.git(ctx, one, "diff", "--cached", "--no-renames", "--no-color", "--no-ext-diff",
			"--no-textconv", "--text", "--unified=0", base, "--", c.path)
		if err != nil {
			return none, err
		}
		total += len(res.out)
		if res.truncated || total > lim.MaxDiffBytes {
			return none, refuse(ErrTooLarge, fmt.Sprintf("diff larger than %d bytes", lim.MaxDiffBytes))
		}
		scan.diff(c.path, res.out)
	}
	if len(scan.findings) > 0 {
		return none, refuse(ErrSecretFound, scan.findings...)
	}

	// Commit as the service account, without touching the clone.
	res, err := f.git(ctx, bare, "write-tree")
	if err != nil {
		return none, err
	}
	commitCmd := bare
	commitCmd.env = []string{
		"GIT_AUTHOR_NAME=" + f.cfg.AuthorName, "GIT_AUTHOR_EMAIL=" + f.cfg.AuthorEmail,
		"GIT_COMMITTER_NAME=" + f.cfg.AuthorName, "GIT_COMMITTER_EMAIL=" + f.cfg.AuthorEmail,
	}
	res, err = f.git(ctx, commitCmd, "commit-tree", strings.TrimSpace(string(res.out)), "-p", base, "-m", title)
	if err != nil {
		return none, err
	}
	commit := strings.TrimSpace(string(res.out))
	if !isHexID(commit) {
		return none, errors.New("forge: commit failed")
	}

	// Push that single new branch: never forced, never onto an existing branch.
	ref := "refs/heads/" + branch
	if id, err := f.remoteRef(ctx, remote, repo.URL, ref); err != nil {
		return none, err
	} else if id != "" {
		return none, refuse(ErrBranchExists, branch)
	}
	if _, err := f.git(ctx, remote, "push", "-q", "--no-verify", repo.URL, commit+":"+ref); err != nil {
		return none, err
	}

	info, err := f.openMR(ctx, repo, auth.token, branch, target, title, description, draft, labels)
	if err != nil {
		// Do not leave an orphan branch that would block the next attempt:
		// remove it if it still is exactly the commit pushed above.
		if id, lerr := f.remoteRef(ctx, remote, repo.URL, ref); lerr == nil && id == commit {
			if _, derr := f.git(ctx, remote, "push", "-q", "--no-verify", repo.URL, ":"+ref); derr != nil {
				f.logf("forge: branch %s was pushed, the merge request failed and the branch could not be removed: %v", branch, derr)
			}
		}
		return none, err
	}
	if info.Branch == "" {
		info.Branch = branch
	}
	return info, nil
}

// remoteDefault asks the remote for the branch its HEAD points to.
func (f *Forge) remoteDefault(ctx context.Context, c gitCmd, repoURL string) (string, error) {
	res, err := f.git(ctx, c, "ls-remote", "--symref", repoURL, "HEAD")
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(res.out), "\n") {
		if rest, ok := strings.CutPrefix(l, "ref: refs/heads/"); ok {
			name, _, _ := strings.Cut(rest, "\t")
			if validRefName(name) {
				return name, nil
			}
		}
	}
	return "", errors.New("forge: the remote does not tell its default branch; set Repo.DefaultBranch")
}

// remoteRef returns the commit of a remote ref, "" when it does not exist.
func (f *Forge) remoteRef(ctx context.Context, c gitCmd, repoURL, ref string) (string, error) {
	res, err := f.git(ctx, c, "ls-remote", repoURL, ref)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(res.out), "\n") {
		id, name, ok := strings.Cut(l, "\t")
		if ok && name == ref {
			return id, nil
		}
	}
	return "", nil
}

// fetchBase fetches the commit the clone was made at and returns it. The
// commit comes from the record made by Clone; for a clone this Forge did not
// make, from the clone's own files, read as plain data and accepted only if
// the remote serves that commit.
func (f *Forge) fetchBase(ctx context.Context, c gitCmd, repoURL, target, key string) (string, error) {
	f.mu.Lock()
	want := f.bases[key]
	f.mu.Unlock()
	if want == "" {
		want = baseHint(key)
	}
	if want == "" {
		return "", refuse(ErrUnknownBase, "not cloned by this forge and no readable HEAD")
	}
	fetch := []string{"fetch", "-q", "--depth=1", "--no-tags", "--no-recurse-submodules", repoURL}
	tip := ""
	if _, err := f.git(ctx, c, append(fetch, "refs/heads/"+target)...); err != nil {
		return "", err
	}
	if res, err := f.git(ctx, c, "rev-parse", "--verify", "FETCH_HEAD^{commit}"); err == nil {
		tip = strings.TrimSpace(string(res.out))
	}
	if tip != want {
		// The default branch moved since the clone: fetch the exact commit.
		if _, err := f.git(ctx, c, append(fetch, want)...); err != nil {
			return "", refuse(ErrUnknownBase, "the remote does not serve the commit the clone was made at")
		}
	}
	if _, err := f.git(ctx, c, "cat-file", "-e", want+"^{commit}"); err != nil {
		return "", refuse(ErrUnknownBase, "the remote does not serve the commit the clone was made at")
	}
	return want, nil
}

// baseHint reads the commit a clone was made at from its files, without
// running git in it: the graft point of a shallow clone, else HEAD.
func baseHint(dir string) string {
	gitDir := filepath.Join(dir, ".git")
	if lines := strings.Fields(readSmall(filepath.Join(gitDir, "shallow"))); len(lines) == 1 && isHexID(lines[0]) {
		return lines[0]
	}
	head := strings.TrimSpace(readSmall(filepath.Join(gitDir, "HEAD")))
	if isHexID(head) {
		return head
	}
	ref, ok := strings.CutPrefix(head, "ref: ")
	if !ok || !strings.HasPrefix(ref, "refs/heads/") || !validRefName(ref) {
		return ""
	}
	if id := strings.TrimSpace(readSmall(filepath.Join(gitDir, filepath.FromSlash(ref)))); isHexID(id) {
		return id
	}
	for _, l := range strings.Split(readSmall(filepath.Join(gitDir, "packed-refs")), "\n") {
		if id, name, ok := strings.Cut(l, " "); ok && name == ref && isHexID(id) {
			return id
		}
	}
	return ""
}

// readSmall returns the content of a regular file of at most 4 MiB, "" otherwise.
func readSmall(file string) string {
	st, err := os.Lstat(file)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return ""
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	return string(data)
}

// changes lists the staged differences against base.
func (f *Forge) changes(ctx context.Context, c gitCmd, base string) ([]change, error) {
	res, err := f.git(ctx, c, "diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", base)
	if err != nil {
		return nil, err
	}
	if res.truncated {
		return nil, refuse(ErrTooLarge, "too many files changed")
	}
	fields := bytes.Split(bytes.TrimSuffix(res.out, []byte{0}), []byte{0})
	var out []change
	for i := 0; i+1 < len(fields); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(string(fields[i]), ":"))
		if len(meta) != 5 {
			return nil, errors.New("forge: unreadable diff")
		}
		out = append(out, change{oldMode: meta[0], newMode: meta[1], oldID: meta[2], newID: meta[3], status: meta[4], path: string(fields[i+1])})
	}
	return out, nil
}

// checkBinaries refuses added or modified binary files above the limit.
func (f *Forge) checkBinaries(ctx context.Context, c gitCmd, base string, changes []change) error {
	res, err := f.git(ctx, c, "diff", "--cached", "--numstat", "-z", "--no-renames", base)
	if err != nil {
		return err
	}
	binary := map[string]bool{}
	for _, rec := range bytes.Split(res.out, []byte{0}) {
		if name, ok := bytes.CutPrefix(rec, []byte("-\t-\t")); ok {
			binary[string(name)] = true
		}
	}
	var big []string
	for _, ch := range changes {
		if !binary[ch.path] || ch.status == "D" || ch.newMode == "160000" {
			continue
		}
		res, err := f.git(ctx, c, "cat-file", "-s", ch.newID)
		if err != nil {
			return err
		}
		size, _ := strconv.Atoi(strings.TrimSpace(string(res.out)))
		if size > f.cfg.Limits.MaxBinaryBytes {
			big = append(big, fmt.Sprintf("%s (binary, %d bytes, limit %d)", ch.path, size, f.cfg.Limits.MaxBinaryBytes))
		}
	}
	if len(big) > 0 {
		return refuse(ErrTooLarge, big...)
	}
	return nil
}

// symlinkEscapes reports whether a link at name with that target leaves the tree.
func symlinkEscapes(name, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0) {
		return true
	}
	resolved := path.Join(path.Dir(name), target)
	return resolved == ".." || strings.HasPrefix(resolved, "../")
}
