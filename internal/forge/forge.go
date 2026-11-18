// Package forge clones repositories, pushes one proposal branch and opens a
// merge request (GitLab) or pull request (GitHub) with the service account.
//
// The agent edits a clone it fully controls, so nothing inside that clone is
// trusted: Propose never reads the clone's .git directory, neither to run
// anything nor to learn anything. It builds the commit in a private repository
// created for the call, on the base commit recorded by Clone (BaseOf,
// RestoreBase), fetched from the URL of model.Repo, and pushes to that URL only.
//
// Propose is idempotent for a branch: called again with the same working tree
// it neither pushes nor opens a second merge request.
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
	"sort"
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

	// Caps on the whole working tree, measured with lstat before git reads a
	// single file. The clone's own .git directory is not counted.
	MaxTreeFiles int   // files, links and directories, default 200000
	MaxTreeBytes int64 // total size of the regular files, default 2 GiB
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
	if cfg.Limits.MaxTreeFiles <= 0 {
		cfg.Limits.MaxTreeFiles = 200000
	}
	if cfg.Limits.MaxTreeBytes <= 0 {
		cfg.Limits.MaxTreeBytes = 2 << 30
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

// BaseOf returns the commit the clone in dir was made at, as recorded by Clone
// or RestoreBase. The core stores it to call RestoreBase after a restart.
func (f *Forge) BaseOf(dir string) (rev string, ok bool) {
	key, err := cloneKey(dir)
	if err != nil {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	rev, ok = f.bases[key]
	return rev, ok
}

// RestoreBase records rev as the commit the clone in dir was made at, for a
// clone made before the daemon restarted. rev must be a full lower-case
// hexadecimal commit id that the caller got from BaseOf and kept in its own
// storage: never a value read from the clone, which the agent controls.
func (f *Forge) RestoreBase(dir, rev string) error {
	if dir == "" {
		return errors.New("forge: no clone directory")
	}
	if !isHexID(rev) {
		return errors.New("forge: the base must be a full hexadecimal commit id")
	}
	key, err := cloneKey(dir)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.bases[key] = rev
	f.mu.Unlock()
	return nil
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
//
// The base commit is the one recorded by Clone (or RestoreBase) for dir;
// without a record Propose refuses with ErrUnknownBase.
//
// Calling it again for the same branch is safe: when the remote branch already
// holds exactly this tree on this base, nothing is pushed, and an open merge
// request of that branch is returned instead of opening a second one. A remote
// branch with any other content is refused with ErrBranchExists.
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
	f.mu.Lock()
	base, known := f.bases[key]
	f.mu.Unlock()
	if !known {
		return none, refuse(ErrUnknownBase, "no base recorded for this clone directory")
	}
	// Measured before git hashes anything.
	if err := measureTree(ctx, key, f.cfg.Limits.MaxTreeFiles, f.cfg.Limits.MaxTreeBytes); err != nil {
		return none, err
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
	if err := f.fetchBase(ctx, remote, repo.URL, target, base); err != nil {
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
	var paths, underGit, links []string
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
			links = append(links, c.path)
		}
	}
	if len(underGit) > 0 {
		return none, refuse(ErrForbiddenPath, underGit...)
	}
	if len(links) > 0 {
		if policy.NoSymlinks {
			for i, l := range links {
				links[i] = l + " (symbolic link)"
			}
			return none, refuse(ErrForbiddenPath, links...)
		}
		escapes, err := f.escapingLinks(ctx, bare, links)
		if err != nil {
			return none, err
		}
		if len(escapes) > 0 {
			return none, refuse(ErrSymlinkEscape, escapes...)
		}
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
	treeID := strings.TrimSpace(string(res.out))
	if !isHexID(treeID) {
		return none, errors.New("forge: write-tree failed")
	}

	// Push that single new branch: never forced, never onto an existing
	// branch. A branch that already holds this very proposal (an earlier call
	// that was interrupted, or whose merge request failed) is left as it is.
	ref := "refs/heads/" + branch
	existing, err := f.remoteRef(ctx, remote, repo.URL, ref)
	if err != nil {
		return none, err
	}
	if existing != "" {
		same, err := f.sameProposal(ctx, remote, repo.URL, ref, existing, treeID, base)
		if err != nil {
			return none, err
		}
		if !same {
			return none, refuse(ErrBranchExists, branch)
		}
		info, found, err := f.findOpenMR(ctx, repo, auth.token, branch)
		if err != nil {
			return none, err
		}
		if found {
			if info.Branch == "" {
				info.Branch = branch
			}
			return info, nil
		}
	} else {
		res, err = f.git(ctx, commitCmd, "commit-tree", treeID, "-p", base, "-m", title)
		if err != nil {
			return none, err
		}
		commit := strings.TrimSpace(string(res.out))
		if !isHexID(commit) {
			return none, errors.New("forge: commit failed")
		}
		if _, err := f.git(ctx, remote, "push", "-q", "--no-verify", repo.URL, commit+":"+ref); err != nil {
			return none, err
		}
	}

	info, err := f.openMR(ctx, repo, auth.token, branch, target, title, description, draft, labels)
	if err != nil {
		// The branch stays: the next call for this branch finds it, sees the
		// same tree and only opens the merge request.
		f.logf("forge: branch %s is pushed but its merge request was not opened: %v", branch, err)
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

// sameProposal reports whether the remote branch ref, whose tip is tip, is
// the proposal about to be pushed: one commit holding tree on top of base.
func (f *Forge) sameProposal(ctx context.Context, c gitCmd, repoURL, ref, tip, tree, base string) (bool, error) {
	if !isHexID(tip) {
		return false, errors.New("forge: unreadable remote branch")
	}
	if _, err := f.git(ctx, c, "fetch", "-q", "--depth=1", "--no-tags", "--no-recurse-submodules", repoURL, ref); err != nil {
		return false, err
	}
	one := c
	one.auth = nil
	one.maxOut = 64 << 10
	res, err := f.git(ctx, one, "cat-file", "commit", tip)
	if err != nil {
		return false, nil // the branch moved between the two calls: not ours
	}
	var trees, parents []string
	header, _, _ := strings.Cut(string(res.out), "\n\n")
	for _, l := range strings.Split(header, "\n") {
		if v, ok := strings.CutPrefix(l, "tree "); ok {
			trees = append(trees, v)
		} else if v, ok := strings.CutPrefix(l, "parent "); ok {
			parents = append(parents, v)
		}
	}
	return len(trees) == 1 && trees[0] == tree && len(parents) == 1 && parents[0] == base, nil
}

// fetchBase fetches want, the commit the clone was made at according to the
// record of Clone or RestoreBase. Nothing of the clone is read.
func (f *Forge) fetchBase(ctx context.Context, c gitCmd, repoURL, target, want string) error {
	fetch := []string{"fetch", "-q", "--depth=1", "--no-tags", "--no-recurse-submodules", repoURL}
	tip := ""
	if _, err := f.git(ctx, c, append(fetch, "refs/heads/"+target)...); err != nil {
		return err
	}
	if res, err := f.git(ctx, c, "rev-parse", "--verify", "FETCH_HEAD^{commit}"); err == nil {
		tip = strings.TrimSpace(string(res.out))
	}
	if tip != want {
		// The default branch moved since the clone: fetch the exact commit.
		if _, err := f.git(ctx, c, append(fetch, want)...); err != nil {
			return refuse(ErrUnknownBase, "the remote does not serve the commit the clone was made at")
		}
	}
	if _, err := f.git(ctx, c, "cat-file", "-e", want+"^{commit}"); err != nil {
		return refuse(ErrUnknownBase, "the remote does not serve the commit the clone was made at")
	}
	return nil
}

// measureTree refuses a working tree with more than maxFiles entries or more
// than maxBytes of regular files. It only lists directories and calls lstat:
// no file is opened, no link is followed, and it stops at the first cap
// exceeded. The .git directory at the root is skipped, git never adds it.
func measureTree(ctx context.Context, root string, maxFiles int, maxBytes int64) error {
	files, size := 0, int64(0)
	stack := []string{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if err := ctx.Err(); err != nil {
			return err
		}
		if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
			continue // replaced meanwhile; never follow a link
		}
		fh, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("forge: unreadable directory in the working tree: %v", err)
		}
		for {
			entries, err := fh.ReadDir(256)
			for _, e := range entries {
				if dir == root && e.Name() == ".git" {
					continue
				}
				if files++; files > maxFiles {
					fh.Close()
					return refuse(ErrTooLarge, fmt.Sprintf("more than %d files in the working tree (limit MaxTreeFiles)", maxFiles))
				}
				full := filepath.Join(dir, e.Name())
				switch {
				case e.IsDir():
					stack = append(stack, full)
				case e.Type().IsRegular():
					st, err := os.Lstat(full)
					if err != nil || !st.Mode().IsRegular() {
						continue
					}
					if size += st.Size(); size > maxBytes {
						fh.Close()
						return refuse(ErrTooLarge, fmt.Sprintf("more than %d bytes in the working tree (limit MaxTreeBytes)", maxBytes))
					}
				}
			}
			if err != nil { // io.EOF, or a directory that cannot be listed further
				fh.Close()
				if err != io.EOF {
					return fmt.Errorf("forge: unreadable directory in the working tree: %v", err)
				}
				break
			}
		}
	}
	return nil
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

// maxLinkHops is how many links one resolution may follow.
const maxLinkHops = 40

// maxLinkTarget is the longest link target accepted, as PATH_MAX.
const maxLinkTarget = 4096

// treeLinks returns the target of every symbolic link of the staged tree.
func (f *Forge) treeLinks(ctx context.Context, c gitCmd) (map[string]string, error) {
	res, err := f.git(ctx, c, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	if res.truncated {
		return nil, refuse(ErrTooLarge, "too many files to check the symbolic links")
	}
	ids := map[string][]string{} // blob -> paths
	var stdin bytes.Buffer
	for _, rec := range strings.Split(string(res.out), "\x00") {
		meta, name, ok := strings.Cut(rec, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 || fields[0] != "120000" || !isHexID(fields[1]) {
			continue
		}
		if ids[fields[1]] == nil {
			stdin.WriteString(fields[1] + "\n")
		}
		ids[fields[1]] = append(ids[fields[1]], name)
	}
	links := map[string]string{}
	if len(ids) == 0 {
		return links, nil
	}
	batch := c
	batch.stdin = stdin.Bytes()
	res, err = f.git(ctx, batch, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	if res.truncated {
		return nil, refuse(ErrTooLarge, "symbolic links too large to be checked")
	}
	out := res.out
	for len(out) > 0 {
		head, rest, ok := bytes.Cut(out, []byte{'\n'})
		fields := strings.Fields(string(head))
		if !ok || len(fields) != 3 || fields[1] != "blob" {
			return nil, errors.New("forge: unreadable symbolic link")
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size < 0 || size >= len(rest) || rest[size] != '\n' {
			return nil, errors.New("forge: unreadable symbolic link")
		}
		target := string(rest[:size])
		if size > maxLinkTarget {
			target = "" // refused by symlinkEscapes
		}
		for _, name := range ids[fields[0]] {
			links[name] = target
		}
		delete(ids, fields[0])
		out = rest[size+1:]
	}
	if len(ids) != 0 {
		return nil, errors.New("forge: unreadable symbolic link")
	}
	return links, nil
}

// escapingLinks returns the links of the staged tree that leave the
// repository once every link of that tree is followed, limited to those whose
// resolution involves a link of changed: a changed link itself, or an older
// link that one of the changed links now leads outside.
func (f *Forge) escapingLinks(ctx context.Context, c gitCmd, changed []string) ([]string, error) {
	links, err := f.treeLinks(ctx, c)
	if err != nil {
		return nil, err
	}
	isChanged := map[string]bool{}
	for _, name := range changed {
		isChanged[name] = true
		if _, ok := links[name]; !ok {
			return nil, errors.New("forge: unreadable symbolic link")
		}
	}
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	var bad []string
	for _, name := range names {
		escapes, followed := symlinkEscapes(links, name)
		if !escapes {
			continue
		}
		for _, l := range followed {
			if isChanged[l] {
				bad = append(bad, name)
				break
			}
		}
	}
	return bad, nil
}

// unsafeTarget reports a link target that can never be accepted.
func unsafeTarget(target string) bool {
	return target == "" || strings.HasPrefix(target, "/") || strings.ContainsRune(target, 0)
}

// symlinkEscapes resolves the link at name inside the tree described by
// links (path -> target of every link of the tree), one component at a time,
// following the other links it meets. It reports true when the resolution
// reaches or passes above the repository root, meets an absolute or empty
// target, or needs more than maxLinkHops links (a loop). followed lists the
// links that were read, name first.
func symlinkEscapes(links map[string]string, name string) (escapes bool, followed []string) {
	followed = []string{name}
	target := links[name]
	if unsafeTarget(target) {
		return true, followed
	}
	var cur []string // resolved directory, from the root
	if d := path.Dir(name); d != "." {
		cur = strings.Split(d, "/")
	}
	pending := strings.Split(target, "/")
	for len(pending) > 0 {
		comp := pending[0]
		pending = pending[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(cur) == 0 {
				return true, followed
			}
			cur = cur[:len(cur)-1]
			continue
		}
		next := strings.Join(append(cur[:len(cur):len(cur)], comp), "/")
		if t, ok := links[next]; ok {
			followed = append(followed, next)
			if len(followed) > maxLinkHops || unsafeTarget(t) {
				return true, followed
			}
			pending = append(strings.Split(t, "/"), pending...)
			continue
		}
		cur = append(cur, comp)
	}
	return false, followed
}
