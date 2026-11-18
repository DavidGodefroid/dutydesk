package forge

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

func errorsIs(err, target error) bool { return errors.Is(err, target) }

func TestCloneIsShallowWithoutCredentialsAndCannotPush(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	if got, err := os.ReadFile(filepath.Join(e.dir, "src", "app.txt")); err != nil || string(got) != "line one\nline two\n" {
		t.Fatalf("working tree: %q, %v", got, err)
	}
	if n := run(t, e.dir, "rev-list", "--count", "HEAD"); n != "1" {
		t.Fatalf("clone depth %s, want 1", n)
	}
	if b := run(t, e.dir, "rev-parse", "--abbrev-ref", "HEAD"); b != "main" {
		t.Fatalf("branch %s", b)
	}
	filepath.WalkDir(filepath.Join(e.dir, ".git"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if data, _ := os.ReadFile(p); bytes.Contains(data, []byte(testToken)) {
				t.Errorf("token found in %s", p)
			}
		}
		return nil
	})
	if got := run(t, e.dir, "config", "--get", "remote.origin.pushurl"); got != pushDisabledURL {
		t.Fatalf("pushurl %q", got)
	}
	write(t, filepath.Join(e.dir, "x.txt"), "x\n")
	run(t, e.dir, "add", "-A")
	run(t, e.dir, "commit", "-q", "-m", "agent commit")
	cmd := exec.Command("git", "push", "origin", "HEAD:refs/heads/agent")
	cmd.Dir = e.dir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("push from the clone succeeded: %s", out)
	}
	if got := e.branches(); len(got) != 1 {
		t.Fatalf("remote branches: %v", got)
	}
}

func TestCloneRefusesNonEmptyDirectory(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	if err := e.forge.Clone(context.Background(), e.repo, e.dir); err == nil {
		t.Fatal("clone into a non-empty directory succeeded")
	}
}

func TestTokenFileMustBePrivate(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	if err := os.Chmod(e.repo.TokenFile, 0o640); err != nil {
		t.Fatal(err)
	}
	err := e.forge.Clone(context.Background(), e.repo, filepath.Join(t.TempDir(), "c"))
	if !errors.Is(err, ErrTokenFile) {
		t.Fatalf("Clone: %v, want ErrTokenFile", err)
	}
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTokenFile)
	if _, err := e.forge.Status(context.Background(), e.repo, "7"); !errors.Is(err, ErrTokenFile) {
		t.Fatalf("Status: %v, want ErrTokenFile", err)
	}
}

func TestOnlyHTTPSOutsideTests(t *testing.T) {
	f := New(Config{})
	for _, u := range []string{"file:///tmp/x.git", "http://gitlab.example.com/g/a.git", "ssh://git@host/g/a.git",
		"https://user:pw@gitlab.example.com/g/a.git", "--upload-pack=x", "ext::sh -c x"} {
		if _, _, err := f.checkRepoURL(u); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
	if _, origin, err := f.checkRepoURL("https://gitlab.example.com:8443/g/a.git"); err != nil || origin != "https://gitlab.example.com:8443" {
		t.Errorf("origin %q, %v", origin, err)
	}
}

func TestProposeGitLab(t *testing.T) {
	e := newEnv(t, "gitlab", func(c *Config) { c.AuthorName, c.AuthorEmail = "DutyDesk Bot", "bot@example.com" })
	base := run(t, e.bare, "rev-parse", "main")
	write(t, filepath.Join(e.dir, "src", "app.txt"), "line one\nline two fixed\n")
	write(t, filepath.Join(e.dir, "src", "new.txt"), "new\n")
	if err := os.Remove(filepath.Join(e.dir, "README.md")); err != nil {
		t.Fatal(err)
	}
	info, err := e.forge.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-000123-fix", "Fix the  stuck\njob", "Incident INC-000123", true, []string{"dutydesk", "bug"})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	want := model.MRInfo{ID: "7", URL: "https://gitlab.example.com/group/app/-/merge_requests/7", State: "open", Branch: "dutydesk/inc-000123-fix"}
	if info != want {
		t.Fatalf("info %+v", info)
	}
	if got := run(t, e.bare, "rev-parse", "main"); got != base {
		t.Fatal("the default branch moved")
	}
	if got := run(t, e.bare, "rev-parse", "dutydesk/inc-000123-fix^"); got != base {
		t.Fatalf("parent %s, want %s", got, base)
	}
	if got := run(t, e.bare, "log", "-1", "--format=%an <%ae>|%cn <%ce>|%s", "dutydesk/inc-000123-fix"); got != "DutyDesk Bot <bot@example.com>|DutyDesk Bot <bot@example.com>|Fix the stuck job" {
		t.Fatalf("commit %q", got)
	}
	if got := run(t, e.bare, "diff", "--name-status", "main", "dutydesk/inc-000123-fix"); got != "D\tREADME.md\nM\tsrc/app.txt\nA\tsrc/new.txt" {
		t.Fatalf("diff %q", got)
	}
	calls := e.api.recorded()
	if len(calls) != 1 {
		t.Fatalf("%d API calls", len(calls))
	}
	c := calls[0]
	if c.Method != "POST" || c.URI != "/api/v4/projects/group%2Fapp/merge_requests" {
		t.Fatalf("call %s %s", c.Method, c.URI)
	}
	if c.Header.Get("PRIVATE-TOKEN") != testToken {
		t.Fatal("token header missing")
	}
	for k, v := range map[string]any{"source_branch": "dutydesk/inc-000123-fix", "target_branch": "main", "title": "Draft: Fix the stuck job",
		"description": "Incident INC-000123", "labels": "dutydesk,bug", "remove_source_branch": true} {
		if c.Body[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, c.Body[k], v)
		}
	}
	// The private repository is gone.
	if left, _ := os.ReadDir(e.forge.cfg.TempDir); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestProposeGitHub(t *testing.T) {
	e := newEnv(t, "github", nil)
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	info, err := e.forge.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-9", "Fix", "Body", true, []string{"dutydesk"})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if info != (model.MRInfo{ID: "12", URL: "https://github.com/owner/app/pull/12", State: "open", Branch: "dutydesk/inc-9"}) {
		t.Fatalf("info %+v", info)
	}
	calls := e.api.recorded()
	if len(calls) != 2 {
		t.Fatalf("%d API calls", len(calls))
	}
	if calls[0].URI != "/repos/owner/app/pulls" || calls[0].Header.Get("Authorization") != "Bearer "+testToken {
		t.Fatalf("call %+v", calls[0])
	}
	for k, v := range map[string]any{"title": "Fix", "head": "dutydesk/inc-9", "base": "main", "body": "Body", "draft": true} {
		if calls[0].Body[k] != v {
			t.Errorf("body[%s] = %v, want %v", k, calls[0].Body[k], v)
		}
	}
	if calls[1].URI != "/repos/owner/app/issues/12/labels" || fmt.Sprint(calls[1].Body["labels"]) != "[dutydesk]" {
		t.Fatalf("labels call %+v", calls[1])
	}
	if got := e.branches(); len(got) != 2 {
		t.Fatalf("branches %v", got)
	}
}

func TestStatus(t *testing.T) {
	for _, tc := range []struct {
		kind, state string
		merged      bool
		want        string
	}{
		{"gitlab", "opened", false, "open"},
		{"gitlab", "locked", false, "open"},
		{"gitlab", "merged", false, "merged"},
		{"gitlab", "closed", false, "closed"},
		{"github", "open", false, "open"},
		{"github", "closed", false, "closed"},
		{"github", "closed", true, "merged"},
	} {
		api := newFakeAPI(t)
		api.state, api.merged = tc.state, tc.merged
		f := New(Config{APIBase: map[string]string{tc.kind: api.URL + map[string]string{"gitlab": "/api/v4", "github": ""}[tc.kind]}})
		repo := model.Repo{Forge: tc.kind, URL: "https://example.com/group/app.git", Project: "group/app", TokenFile: tokenFile(t, testToken)}
		info, err := f.Status(context.Background(), repo, "7")
		if err != nil || info.State != tc.want || info.Branch != "dutydesk/inc-1" || info.URL == "" {
			t.Errorf("%s %s merged=%v: %+v, %v", tc.kind, tc.state, tc.merged, info, err)
		}
	}
	f := New(Config{})
	if _, err := f.Status(context.Background(), model.Repo{Forge: "gitlab"}, "7/../../x"); err == nil {
		t.Error("non numeric id accepted")
	}
}

func TestNoChange(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrNoChange)
}

// An agent that committed in its clone changes nothing: the working tree is what counts.
func TestAgentCommitsAreNotTrusted(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	base := run(t, e.bare, "rev-parse", "main")
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	run(t, e.dir, "add", "-A")
	run(t, e.dir, "commit", "-q", "-m", "by the agent")
	if _, err := e.propose("dutydesk/inc-1", "Add a", "d"); err != nil {
		t.Fatal(err)
	}
	if got := run(t, e.bare, "log", "--format=%p|%an|%s", "dutydesk/inc-1", "-1"); got != base[:len(strings.Split(got, "|")[0])]+"|DutyDesk|Add a" {
		t.Fatalf("commit %q", got)
	}
}

func TestPlantedHooksAndConfigAreNotExecuted(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	script := "#!/bin/sh\ntouch " + e.marker + "\n"
	hooks := filepath.Join(e.dir, ".git", "hooks")
	for _, h := range []string{"pre-commit", "commit-msg", "post-commit", "pre-push", "post-index-change", "prepare-commit-msg", "reference-transaction"} {
		write(t, filepath.Join(hooks, h), script)
		if err := os.Chmod(filepath.Join(hooks, h), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	planted := filepath.Join(e.dir, "run.sh")
	write(t, planted, script)
	if err := os.Chmod(planted, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, e.dir, "config", "core.fsmonitor", planted)
	run(t, e.dir, "config", "core.hooksPath", hooks)
	run(t, e.dir, "config", "filter.evil.clean", "touch "+e.marker+"; cat")
	run(t, e.dir, "config", "diff.evil.textconv", planted)
	run(t, e.dir, "config", "core.sshCommand", planted)
	run(t, e.dir, "config", "credential.helper", "!"+planted)
	write(t, filepath.Join(e.dir, ".gitattributes"), "* filter=evil diff=evil\n")
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if _, err := os.Stat(e.marker); err == nil {
		t.Fatal("code planted in the clone was executed")
	}
	if got := run(t, e.bare, "show", "dutydesk/inc-1:src/app.txt"); got != "changed" {
		t.Fatalf("pushed content %q", got)
	}
}

func TestRedirectedRemoteIsIgnored(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	evil := filepath.Join(t.TempDir(), "evil.git")
	run(t, t.TempDir(), "init", "-q", "--bare", evil)
	run(t, e.dir, "config", "remote.origin.url", evil)
	run(t, e.dir, "config", "remote.origin.pushurl", evil)
	run(t, e.dir, "config", "url."+evil+".insteadOf", "file://"+e.bare)
	run(t, e.dir, "config", "url."+evil+".pushInsteadOf", "file://"+e.bare)
	run(t, e.dir, "config", "remote.pushDefault", "origin")
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if out := run(t, evil, "for-each-ref"); out != "" {
		t.Fatalf("the redirected remote received: %s", out)
	}
	if got := e.branches(); len(got) != 2 || got[0] != "dutydesk/inc-1" {
		t.Fatalf("branches %v", got)
	}
}

func TestSymlinkEscape(t *testing.T) {
	for _, target := range []string{"/etc/passwd", "../../outside", "sub/../../../x"} {
		e := newEnv(t, "gitlab", nil)
		if err := os.Symlink(target, filepath.Join(e.dir, "src", "link")); err != nil {
			t.Fatal(err)
		}
		_, err := e.propose("dutydesk/inc-1", "t", "d")
		e.mustRefuse(err, ErrSymlinkEscape)
		if !strings.Contains(err.Error(), "src/link") {
			t.Errorf("error %q does not name the link", err)
		}
	}
	e := newEnv(t, "gitlab", nil)
	if err := os.Symlink("../README.md", filepath.Join(e.dir, "src", "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("a link inside the tree was refused: %v", err)
	}
}

func TestNestedRepositoryIsRefused(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	sub := filepath.Join(e.dir, "vendor", "lib")
	write(t, filepath.Join(sub, "f.txt"), "f\n")
	run(t, sub, "init", "-q")
	run(t, sub, "add", "-A")
	run(t, sub, "commit", "-q", "-m", "nested")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrForbiddenPath)
}

func TestSecretInDiff(t *testing.T) {
	seat := "seat-token-abcdefghijklmnop"
	cases := map[string]string{
		"seat token":        "key = " + seat + "\n",
		"seat token base64": "auth: " + base64.StdEncoding.EncodeToString([]byte("user:"+seat+":x")) + "\n",
		"forge token":       "x " + testToken + " y\n",
		"gitlab pattern":    "t=glpat-" + strings.Repeat("a1B2", 6) + "\n",
		"github pattern":    "t=ghp_" + strings.Repeat("a1B2", 9) + "\n",
		"anthropic pattern": "t=sk-ant-" + strings.Repeat("a1B2", 9) + "\n",
		"aws key id":        "id: AKIAIOSFODNN7EXAMPLE\n",
		"private key":       "-----BEGIN OPENSSH PRIVATE KEY-----\n",
		"password":          "db_password = \"S3cretS3cretS3cret\"\n",
	}
	for name, added := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "gitlab", nil)
			write(t, filepath.Join(e.dir, "src", "app.txt"), "line one\nline two\nline three\n"+added)
			_, err := e.propose("dutydesk/inc-1", "t", "d")
			e.mustRefuse(err, ErrSecretFound)
			if !strings.Contains(err.Error(), "src/app.txt:4 ") {
				t.Errorf("error %q does not name file and line", err)
			}
			if strings.Contains(err.Error(), strings.TrimSpace(added)) || strings.Contains(err.Error(), seat) || strings.Contains(err.Error(), testToken) {
				t.Errorf("error echoes the secret: %q", err)
			}
		})
	}
}

func TestSecretAlreadyInTheRepositoryIsNotReported(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	pushUpstream(t, e.bare, "legacy.txt", "old seat-token-abcdefghijklmnop\nsecond\n")
	dir := filepath.Join(t.TempDir(), "clone")
	if err := e.forge.Clone(context.Background(), e.repo, dir); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "legacy.txt"), "old seat-token-abcdefghijklmnop\nsecond changed\n")
	if _, err := e.forge.Propose(context.Background(), e.repo, dir, "dutydesk/inc-1", "t", "d", false, nil); err != nil {
		t.Fatalf("only added lines are scanned: %v", err)
	}
}

func TestSecretInDescriptionTitleOrFileName(t *testing.T) {
	seat := "seat-token-abcdefghijklmnop"
	e := newEnv(t, "gitlab", nil)
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	_, err := e.propose("dutydesk/inc-1", "t", "first line\nsee "+seat+"\n")
	e.mustRefuse(err, ErrSecretFound)
	if !strings.Contains(err.Error(), "description:2 ") || strings.Contains(err.Error(), seat) {
		t.Errorf("error %q", err)
	}
	_, err = e.propose("dutydesk/inc-1", "token "+testToken, "d")
	e.mustRefuse(err, ErrSecretFound)
	if !strings.Contains(err.Error(), "title:1 ") || strings.Contains(err.Error(), testToken) {
		t.Errorf("error %q", err)
	}
	write(t, filepath.Join(e.dir, seat+".txt"), "a\n")
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSecretFound)
	if strings.Count(err.Error(), seat) != 1 { // the file name itself is the only place it may appear
		t.Errorf("error %q", err)
	}
}

func TestForbiddenPath(t *testing.T) {
	policy := PathPolicy{Deny: []string{"projects/*/project.yaml", "standard/security", "**/seats.yaml"}}
	e := newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	write(t, filepath.Join(e.dir, "projects", "shop", "project.yaml"), "x: 1\n")
	write(t, filepath.Join(e.dir, "standard", "security", "deep", "rule.md"), "x\n")
	write(t, filepath.Join(e.dir, "projects", "shop", "runbooks", "ok.md"), "ok\n")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrForbiddenPath)
	for _, p := range []string{"projects/shop/project.yaml", "standard/security/deep/rule.md"} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %q does not list %s", err, p)
		}
	}
	if strings.Contains(err.Error(), "ok.md") {
		t.Errorf("error %q lists an allowed path", err)
	}

	policy = PathPolicy{Allow: []string{"projects/*/actions/**", "projects/*/runbooks/*.md"}}
	e = newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	write(t, filepath.Join(e.dir, "projects", "shop", "actions", "restart", "run.sh"), "#!/bin/sh\n")
	write(t, filepath.Join(e.dir, "projects", "shop", "runbooks", "ok.md"), "ok\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("allowed paths refused: %v", err)
	}
	// Deleting a file outside the allowed paths is a change there too.
	e = newEnv(t, "gitlab", func(c *Config) { c.PolicyFor = func(model.Repo) PathPolicy { return policy } })
	os.Remove(filepath.Join(e.dir, "README.md"))
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrForbiddenPath)
}

func TestExistingBranch(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	run(t, e.bare, "branch", "dutydesk/inc-1", "main")
	before := run(t, e.bare, "rev-parse", "dutydesk/inc-1")
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	if !errors.Is(err, ErrBranchExists) {
		t.Fatalf("error %v, want ErrBranchExists", err)
	}
	if run(t, e.bare, "rev-parse", "dutydesk/inc-1") != before || len(e.api.recorded()) != 0 {
		t.Fatal("the existing branch was touched or the API called")
	}
}

func TestBadBranch(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	for _, b := range []string{"main", "feature/x", "dutydesk/", "dutydesk/-x", "dutydesk/UPPER", "dutydesk/a b", "dutydesk/a/b",
		"dutydesk/a..b", "dutydesk/a.lock", "dutydesk/a.", "refs/heads/dutydesk/a", "dutydesk/" + strings.Repeat("a", 82), "+dutydesk/a", "dutydesk/a:main"} {
		_, err := e.propose(b, "t", "d")
		e.mustRefuse(err, ErrBadBranch)
	}
}

func TestTooLarge(t *testing.T) {
	e := newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxFiles: 3, MaxDiffBytes: 2000, MaxBinaryBytes: 100} })
	for i := 0; i < 4; i++ {
		write(t, filepath.Join(e.dir, fmt.Sprintf("f%d.txt", i)), "x\n")
	}
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTooLarge)

	e = newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxFiles: 3, MaxDiffBytes: 2000, MaxBinaryBytes: 100} })
	write(t, filepath.Join(e.dir, "big.txt"), strings.Repeat("0123456789\n", 300))
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTooLarge)

	e = newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxFiles: 3, MaxDiffBytes: 2000, MaxBinaryBytes: 100} })
	write(t, filepath.Join(e.dir, "blob.bin"), "\x00\x01\x02"+strings.Repeat("\xff\x00", 100))
	_, err = e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrTooLarge)
	if !strings.Contains(err.Error(), "blob.bin") {
		t.Errorf("error %q", err)
	}

	e = newEnv(t, "gitlab", func(c *Config) { c.Limits = Limits{MaxFiles: 3, MaxDiffBytes: 2000, MaxBinaryBytes: 100} })
	write(t, filepath.Join(e.dir, "small.bin"), "\x00\x01\x02 small")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("a small binary file was refused: %v", err)
	}
}

func TestSecretInsideBinaryFile(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	write(t, filepath.Join(e.dir, "blob.bin"), "\x00\x01 seat-token-abcdefghijklmnop \x00")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	e.mustRefuse(err, ErrSecretFound)
}

// The default branch moved after the clone: the proposal keeps the base it was made on.
func TestBaseMovedAfterClone(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	base := run(t, e.bare, "rev-parse", "main")
	pushUpstream(t, e.bare, "colleague.txt", "work\n")
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if got := run(t, e.bare, "rev-parse", "dutydesk/inc-1^"); got != base {
		t.Fatalf("parent %s, want the clone base %s", got, base)
	}
	if got := run(t, e.bare, "diff", "--name-status", base, "dutydesk/inc-1"); got != "M\tsrc/app.txt" {
		t.Fatalf("diff %q", got)
	}
}

// A clone made elsewhere (another Forge instance, another package) still works.
func TestProposeOnForeignClone(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	base := run(t, e.bare, "rev-parse", "main")
	pushUpstream(t, e.bare, "colleague.txt", "work\n")
	other := New(e.forge.cfg)
	write(t, filepath.Join(e.dir, "src", "app.txt"), "changed\n")
	if _, err := other.Propose(context.Background(), e.repo, e.dir, "dutydesk/inc-1", "t", "d", false, nil); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if got := run(t, e.bare, "diff", "--name-status", base, "dutydesk/inc-1"); got != "M\tsrc/app.txt" {
		t.Fatalf("diff %q", got)
	}

	full := filepath.Join(t.TempDir(), "full")
	run(t, filepath.Dir(full), "clone", "-q", e.bare, full)
	write(t, filepath.Join(full, "b.txt"), "b\n")
	if _, err := other.Propose(context.Background(), e.repo, full, "dutydesk/inc-2", "t", "d", false, nil); err != nil {
		t.Fatalf("Propose on a full clone: %v", err)
	}

	plain := filepath.Join(t.TempDir(), "plain")
	write(t, filepath.Join(plain, "b.txt"), "b\n")
	if _, err := other.Propose(context.Background(), e.repo, plain, "dutydesk/inc-3", "t", "d", false, nil); !errors.Is(err, ErrUnknownBase) {
		t.Fatalf("directory without a base: %v", err)
	}
}

func TestAPIFailureRemovesTheBranchAndHidesTheToken(t *testing.T) {
	e := newEnv(t, "gitlab", nil)
	e.api.fail = http.StatusInternalServerError
	write(t, filepath.Join(e.dir, "a.txt"), "a\n")
	_, err := e.propose("dutydesk/inc-1", "t", "d")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("error holds the token: %v", err)
	}
	if got := e.branches(); len(got) != 1 {
		t.Fatalf("orphan branch left: %v", got)
	}
	e.api.fail = 0
	if _, err := e.propose("dutydesk/inc-1", "t", "d"); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestGitErrorsHideTheToken(t *testing.T) {
	f := New(Config{AllowLocal: true})
	_, err := f.git(context.Background(), gitCmd{dir: t.TempDir(), auth: &gitAuth{token: testToken}}, "ls-remote", "file:///nonexistent/"+testToken)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("error %v", err)
	}
}

// The token reaches the server through the credential helper only, and only
// the server named by Repo.URL.
func TestCredentialsOverHTTP(t *testing.T) {
	out, err := exec.Command("git", "--exec-path").Output()
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, serr := os.Stat(backend); err != nil || serr != nil {
		t.Skip("git-http-backend not available")
	}
	bare := newRemote(t)
	run(t, bare, "config", "http.receivepack", "true")
	api := newFakeAPI(t)
	var authed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "oauth2" || pass != testToken {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + filepath.Dir(bare), "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=bot"}}).ServeHTTP(w, r)
	}))
	defer srv.Close()
	f := New(Config{AllowLocal: true, TempDir: t.TempDir(), APIBase: map[string]string{"gitlab": api.URL + "/api/v4"}})
	repo := model.Repo{Forge: "gitlab", URL: srv.URL + "/remote.git", Project: "group/app", DefaultBranch: "main", TokenFile: tokenFile(t, testToken)}
	dir := filepath.Join(t.TempDir(), "clone")
	if err := f.Clone(context.Background(), repo, dir); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if bytes.Contains(cfg, []byte(testToken)) || bytes.Contains(cfg, []byte("oauth2")) {
		t.Fatalf("credentials in the clone config:\n%s", cfg)
	}
	// Without the core, the clone cannot even read the remote again.
	cmd := exec.Command("git", "fetch", "origin")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ASKPASS=")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("the clone fetched without credentials: %s", out)
	}
	write(t, filepath.Join(dir, "a.txt"), "a\n")
	if _, err := f.Propose(context.Background(), repo, dir, "dutydesk/inc-1", "t", "d", false, nil); err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if got := run(t, bare, "show", "dutydesk/inc-1:a.txt"); got != "a" || authed.Load() == 0 {
		t.Fatalf("pushed %q, %d authenticated requests", got, authed.Load())
	}

	// A wrong token fails without leaking it.
	repo.TokenFile = tokenFile(t, "wrong-token-000000000000")
	err = f.Clone(context.Background(), repo, filepath.Join(t.TempDir(), "c2"))
	if err == nil || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("Clone with a wrong token: %v", err)
	}
}

func TestAPIBaseDerivation(t *testing.T) {
	f := New(Config{})
	for _, tc := range []struct{ kind, url, project, want string }{
		{"gitlab", "https://gitlab.com/group/sub/app.git", "group/sub/app", "https://gitlab.com/api/v4"},
		{"gitlab", "https://git.example.com:8443/gitlab/group/app.git", "group/app", "https://git.example.com:8443/gitlab/api/v4"},
		{"gitlab", "https://git.example.com/group/app", "group/app", "https://git.example.com/api/v4"},
		{"github", "https://github.com/owner/app.git", "owner/app", "https://api.github.com"},
		{"github", "https://ghe.example.com/owner/app.git", "owner/app", "https://ghe.example.com/api/v3"},
	} {
		got, err := f.apiBase(model.Repo{Forge: tc.kind, URL: tc.url, Project: tc.project})
		if err != nil || got != tc.want {
			t.Errorf("%s %s: %q, %v; want %q", tc.kind, tc.url, got, err, tc.want)
		}
	}
	f = New(Config{APIBase: map[string]string{"gitlab": "https://override.example.com/api/v4/"}})
	if got, _ := f.apiBase(model.Repo{Forge: "gitlab", URL: "https://gitlab.com/g/a.git", Project: "g/a"}); got != "https://override.example.com/api/v4" {
		t.Errorf("override: %q", got)
	}
	if _, err := New(Config{}).apiBase(model.Repo{Forge: "bitbucket", URL: "https://x.example.com/g/a.git"}); err == nil {
		t.Error("unknown forge accepted")
	}
}
