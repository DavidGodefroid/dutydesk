package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// ---------- S5: the base never comes from the clone ----------

func TestBaseIsNeverReadFromTheClone(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	base := run(t, e.bare, "rev-parse", "main")
	if got, ok := e.forge.BaseOf(e.dir); !ok || got != base {
		t.Fatalf("BaseOf = %q, %v; want %q", got, ok, base)
	}
	if got, ok := e.forge.BaseOf(filepath.Join(e.dir, "..", "clone", ".")); !ok || got != base {
		t.Fatalf("BaseOf with an unclean path = %q, %v", got, ok)
	}
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")

	// A Forge without a record (daemon restarted) refuses: the clone's .git,
	// which holds a perfectly valid HEAD and shallow file, is not consulted.
	other := New(e.forge.cfg)
	if _, ok := other.BaseOf(e.dir); ok {
		t.Fatal("BaseOf knows a clone it did not make")
	}
	_, err := other.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-1", "t", "d", false, nil)
	e.mustRefuse(err, ErrUnknownBase)
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("error %T is not a *Refusal", err)
	}

	// A full clone made by someone else, or a plain directory: same refusal.
	full := filepath.Join(t.TempDir(), "full")
	run(t, filepath.Dir(full), "clone", "-q", e.bare, full)
	write(t, filepath.Join(full, "b.txt"), "b\n")
	_, err = e.forge.Propose(context.Background(), e.repo, full, "dutydesk/inc-2", "t", "d", false, nil)
	e.mustRefuse(err, ErrUnknownBase)

	// The core restores the base it stored itself.
	for _, bad := range []string{"", "HEAD", "main", base[:39], base + "0", strings.ToUpper(base), "refs/heads/main", "-" + base[1:]} {
		if err := other.RestoreBase(e.dir, bad); err == nil {
			t.Errorf("RestoreBase accepted %q", bad)
		}
	}
	if err := other.RestoreBase("", base); err == nil {
		t.Error("RestoreBase accepted an empty directory")
	}
	if _, ok := other.BaseOf(e.dir); ok {
		t.Fatal("a refused RestoreBase left a record")
	}
	if err := other.RestoreBase(e.dir, base); err != nil {
		t.Fatalf("RestoreBase: %v", err)
	}
	if got, ok := other.BaseOf(e.dir); !ok || got != base {
		t.Fatalf("BaseOf after RestoreBase = %q, %v", got, ok)
	}
	if _, err := other.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-1", "t", "d", false, nil); err != nil {
		t.Fatalf("Propose after RestoreBase: %v", err)
	}
	if got := run(t, e.bare, "rev-parse", "dutydesk/inc-1^"); got != base {
		t.Fatalf("parent %s, want %s", got, base)
	}
}

// The agent rewrites what its .git says about the base: the record wins.
func TestCloneGitFilesCannotMoveTheBase(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	base := run(t, e.bare, "rev-parse", "main")
	pushUpstream(t, e.bare, "colleague.txt", "work\n")
	newer := run(t, e.bare, "rev-parse", "main")
	write(t, filepath.Join(e.dir, ".git", "shallow"), newer+"\n")
	write(t, filepath.Join(e.dir, ".git", "HEAD"), newer+"\n")
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if got := run(t, e.bare, "rev-parse", "dutydesk/inc-1^"); got != base {
		t.Fatalf("parent %s, want the recorded base %s", got, base)
	}
}

// A restored base the remote does not serve is refused, nothing is pushed.
func TestRestoredBaseMustExistOnTheRemote(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	other := New(e.forge.cfg)
	if err := other.RestoreBase(e.dir, strings.Repeat("ab", 20)); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	_, err := other.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-1", "t", "d", false, nil)
	e.mustRefuse(err, ErrUnknownBase)
}

// ---------- Fix 6: the working tree is measured before any hashing ----------

func TestWorkingTreeCaps(t *testing.T) {
	// The clone holds README.md, src and src/app.txt: 3 entries, 24 bytes.
	e := newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxTreeFiles: 8} })
	for i := 0; i < 6; i++ {
		write(t, filepath.Join(e.dir, "junk", fmt.Sprintf("f%d", i)), "x\n")
	}
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTooLarge)
	if !strings.Contains(err.Error(), "MaxTreeFiles") || !strings.Contains(err.Error(), "8") {
		t.Errorf("error %q does not name the cap", err)
	}
	// Nothing was hashed: no private repository was even created.
	if left, _ := os.ReadDir(e.forge.cfg.TempDir); len(left) != 0 {
		t.Fatalf("temporary files: %v", left)
	}

	e = newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxTreeBytes: 4000} })
	write(t, filepath.Join(e.dir, "big.bin"), strings.Repeat("x", 5000))
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTooLarge)
	if !strings.Contains(err.Error(), "MaxTreeBytes") || !strings.Contains(err.Error(), "4000") {
		t.Errorf("error %q does not name the cap", err)
	}

	// Within the caps, and a link to something big outside is not followed.
	e = newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxTreeFiles: 8, MaxTreeBytes: 4000} })
	outside := t.TempDir()
	write(t, filepath.Join(outside, "big"), strings.Repeat("x", 50000))
	if err := os.Symlink("src", filepath.Join(e.dir, "inside")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(e.dir, "ok.txt"), "ok\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("a small tree was refused: %v", err)
	}

	d := New(Config{}).cfg.Limits
	if d.MaxTreeFiles != 200000 || d.MaxTreeBytes != 2<<30 {
		t.Fatalf("defaults %+v", d)
	}
}

// ---------- Fix 11: symbolic links ----------

func TestNoSymlinksPolicy(t *testing.T) {
	policy := PathPolicy{NoSymlinks: true}
	e := newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	write(t, filepath.Join(e.dir, "ok.txt"), "ok\n")
	if err := os.Symlink("../README.md", filepath.Join(e.dir, "src", "link")); err != nil {
		t.Fatal(err)
	}
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrForbiddenPath)
	if !strings.Contains(err.Error(), "src/link") || strings.Contains(err.Error(), "ok.txt") {
		t.Errorf("error %q", err)
	}
	// A regular file replaced by a link is refused too.
	e = newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	os.Remove(filepath.Join(e.dir, "README.md"))
	if err := os.Symlink("src/app.txt", filepath.Join(e.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrForbiddenPath)
	// Without links the policy changes nothing.
	e = newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	write(t, filepath.Join(e.dir, "ok.txt"), "ok\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
}

func TestSymlinkChains(t *testing.T) {
	link := func(e *env, target, name string) {
		t.Helper()
		full := filepath.Join(e.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	// a -> b, b -> ../../etc
	e := newEnv(t, "gitlab", nil)
	link(e, "b", "a")
	link(e, "../../etc", "b")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSymlinkEscape)
	if d := err.(*Refusal).Details; len(d) != 2 || d[0] != "a" || d[1] != "b" {
		t.Errorf("details %v, want a and b", d)
	}
	// Each link is lexically inside; together they leave the tree.
	e = newEnv(t, "gitlab", nil)
	link(e, "..", "p/r")
	link(e, "../r/../../x", "p/q/l")
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSymlinkEscape)
	if d := err.(*Refusal).Details; len(d) != 1 || d[0] != "p/q/l" {
		t.Errorf("details %v, want p/q/l", d)
	}
	// A loop.
	e = newEnv(t, "gitlab", nil)
	link(e, "y", "x")
	link(e, "x", "y")
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSymlinkEscape)
	// Chains that stay inside are allowed.
	e = newEnv(t, "gitlab", nil)
	write(t, filepath.Join(e.dir, "other", "file"), "f\n")
	link(e, "../other/file", "dir/link")
	link(e, "dir/link", "again")
	link(e, "src", "s")
	link(e, "s/../README.md", "viadir")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("links inside the tree were refused: %v", err)
	}
	if got := run(t, e.bare, "ls-tree", "-r", "--format=%(objectmode) %(path)", "dutydesk/inc-1"); !strings.Contains(got, "120000 dir/link") {
		t.Fatalf("tree:\n%s", got)
	}
}

// A link that was already in the repository starts leaving the tree because
// of a link added by the proposal.
func TestExistingSymlinkTurnedIntoAnEscape(t *testing.T) {
	bare := newRemote(t)
	w := filepath.Join(t.TempDir(), "w")
	run(t, filepath.Dir(w), "clone", "-q", bare, w)
	if err := os.MkdirAll(filepath.Join(w, "p", "q"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../r/../../x", filepath.Join(w, "p", "q", "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(w, "legacy")); err != nil { // an old escape nobody touches
		t.Fatal(err)
	}
	run(t, w, "add", "-A")
	run(t, w, "commit", "-q", "-m", "links")
	run(t, w, "push", "-q", "origin", "main")

	e := &env{t: t, bare: bare, api: newFakeAPI(t)}
	e.api.bare = e.bare
	e.forge = New(Config{AllowLocal: true, TempDir: t.TempDir(), APIBase: map[string]string{"gitlab": e.api.URL + "/api/v4"}})
	e.repo = model.Repo{Forge: "gitlab", URL: "file://" + bare, Project: "group/app", DefaultBranch: "main", TokenFile: tokenFile(t, testToken)}
	e.dir = filepath.Join(t.TempDir(), "clone")
	if err := e.forge.Clone(context.Background(), e.repo, e.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(e.dir, "p", "r")); err != nil {
		t.Fatal(err)
	}
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSymlinkEscape)
	if d := err.(*Refusal).Details; len(d) != 1 || d[0] != "p/q/l" {
		t.Errorf("details %v, want p/q/l only", d)
	}
	// The old escape alone does not block a proposal that adds a harmless link.
	os.Remove(filepath.Join(e.dir, "p", "r"))
	if err := os.Symlink("README.md", filepath.Join(e.dir, "readme")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
}

// ---------- Fix 4: idempotent proposals ----------

func posts(calls []apiCall, suffix string) int {
	n := 0
	for _, c := range calls {
		if c.Method == http.MethodPost && strings.HasSuffix(c.URI, suffix) {
			n++
		}
	}
	return n
}

func TestProposeTwiceIsIdempotent(t *testing.T) {
	for _, kind := range []string{"gitlab", "github"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t, kind, nil)
			write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
			first, err := e.propose("dutydesk/inc-1", "Fix", "d")
			if err != nil {
				t.Fatalf("Propose: %v", err)
			}
			tip := run(t, e.bare, "rev-parse", "dutydesk/inc-1")
			calls := len(e.api.recorded())
			second, err := e.propose("dutydesk/inc-1", "Fix", "d")
			if err != nil {
				t.Fatalf("second Propose: %v", err)
			}
			if first != second || first.ID == "" || first.Branch != "dutydesk/inc-1" || first.State != "open" {
				t.Fatalf("first %+v, second %+v", first, second)
			}
			if got := run(t, e.bare, "rev-parse", "dutydesk/inc-1"); got != tip {
				t.Fatalf("the branch was pushed again: %s -> %s", tip, got)
			}
			if got := e.branches(); len(got) != 2 {
				t.Fatalf("branches %v", got)
			}
			all := e.api.recorded()
			suffix, lookup := "/merge_requests", "/api/v4/projects/group%2Fapp/merge_requests?source_branch=dutydesk%2Finc-1&state=opened"
			if kind == "github" {
				suffix, lookup = "/pulls", "/repos/owner/app/pulls?head=owner%3Adutydesk%2Finc-1&state=open"
			}
			if n := posts(all, suffix); n != 1 {
				t.Fatalf("%d merge requests opened", n)
			}
			if len(all) != calls+1 || all[calls].Method != http.MethodGet || all[calls].URI != lookup {
				t.Fatalf("calls of the second Propose: %+v", all[calls:])
			}
		})
	}
}

func TestProposeAfterFailedMergeRequest(t *testing.T) {
	for _, kind := range []string{"gitlab", "github"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t, kind, nil)
			e.api.failPosts = 1
			write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
			_, err := e.propose("dutydesk/inc-1", "Fix", "d")
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadGateway {
				t.Fatalf("error %v", err)
			}
			if got := e.branches(); len(got) != 2 {
				t.Fatalf("branches after the failure: %v", got)
			}
			tip := run(t, e.bare, "rev-parse", "dutydesk/inc-1")
			info, err := e.propose("dutydesk/inc-1", "Fix", "d")
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			if info.ID == "" || info.State != "open" || info.Branch != "dutydesk/inc-1" {
				t.Fatalf("info %+v", info)
			}
			if got := run(t, e.bare, "rev-parse", "dutydesk/inc-1"); got != tip {
				t.Fatal("the branch was pushed again")
			}
			suffix := "/merge_requests"
			if kind == "github" {
				suffix = "/pulls"
			}
			if n := posts(e.api.recorded(), suffix); n != 2 { // the failed one, then the one that opened it
				t.Fatalf("%d POST", n)
			}
			// A third call finds the open merge request.
			again, err := e.propose("dutydesk/inc-1", "Fix", "d")
			if err != nil || again != info {
				t.Fatalf("third call: %+v, %v", again, err)
			}
			if n := posts(e.api.recorded(), suffix); n != 2 {
				t.Fatalf("%d POST after the third call", n)
			}
		})
	}
}

func TestSameBranchDifferentContent(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := e.propose("dutydesk/inc-1", "Fix", "d"); err != nil {
		t.Fatal(err)
	}
	tip := run(t, e.bare, "rev-parse", "dutydesk/inc-1")
	calls := len(e.api.recorded())
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed differently\n")
	_, err := e.propose("dutydesk/inc-1", "Fix", "d")
	if !errors.Is(err, ErrBranchExists) {
		t.Fatalf("error %v, want ErrBranchExists", err)
	}
	if run(t, e.bare, "rev-parse", "dutydesk/inc-1") != tip || len(e.api.recorded()) != calls {
		t.Fatal("the existing branch was touched or the API called")
	}

	// Same tree on another base is not the same proposal either.
	pushUpstream(t, e.bare, "colleague.txt", "work\n")
	dir := filepath.Join(t.TempDir(), "clone")
	if err := e.forge.Clone(context.Background(), e.repo, dir); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "colleague.txt"))
	write(t, filepath.Join(dir, "src", "app.txt"), "changed\n")
	_, err = e.forge.Propose(context.Background(), e.repo, dir, "dutydesk/inc-1", "Fix", "d", false, nil)
	if !errors.Is(err, ErrBranchExists) {
		t.Fatalf("same tree, other base: %v, want ErrBranchExists", err)
	}
}

// A merge request on our branch name that is not ours (opened from a fork, or
// pointing at another commit) is never taken for the one DutyDesk opened.
func TestForeignMergeRequestIsNotAdopted(t *testing.T) {
	for _, kind := range []string{"gitlab", "github"} {
		for _, how := range []string{"fork", "other commit"} {
			t.Run(kind+"/"+how, func(t *testing.T) {
				e := newEnv(t, kind, nil)
				write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
				if _, err := e.propose("dutydesk/inc-1", "Fix", "d"); err != nil {
					t.Fatalf("Propose: %v", err)
				}
				e.api.mu.Lock()
				e.api.foreign, e.api.staleHead = how == "fork", how == "other commit"
				e.api.mu.Unlock()
				before := len(e.api.recorded())
				if _, err := e.propose("dutydesk/inc-1", "Fix", "d"); err != nil {
					t.Fatalf("second Propose: %v", err)
				}
				opened := 0
				for _, c := range e.api.recorded()[before:] {
					p, _, _ := strings.Cut(c.URI, "?")
					if c.Method == http.MethodPost && (strings.HasSuffix(p, "/merge_requests") || strings.HasSuffix(p, "/pulls")) {
						opened++
					}
				}
				if opened != 1 {
					t.Fatalf("the foreign request was adopted: %d request(s) opened by the second call, want 1", opened)
				}
			})
		}
	}
}
