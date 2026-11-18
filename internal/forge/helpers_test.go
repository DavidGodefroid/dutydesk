package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

const testToken = "tok-forge-service-account-0123456789"

// run executes git for test setup, isolated from the host configuration.
func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Dev", "GIT_AUTHOR_EMAIL=dev@example.com",
		"GIT_COMMITTER_NAME=Dev", "GIT_COMMITTER_EMAIL=dev@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// newRemote creates a bare repository with one commit on main and returns its path.
func newRemote(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")
	run(t, root, "init", "-q", "--bare", "--initial-branch=main", bare)
	seed := filepath.Join(root, "seed")
	run(t, root, "init", "-q", "--initial-branch=main", seed)
	write(t, filepath.Join(seed, "README.md"), "hello\n")
	write(t, filepath.Join(seed, "src", "app.txt"), "line one\nline two\n")
	run(t, seed, "add", "-A")
	run(t, seed, "commit", "-q", "-m", "initial")
	run(t, seed, "push", "-q", bare, "main")
	return bare
}

// pushUpstream adds a commit to main on the remote, as a colleague would.
func pushUpstream(t *testing.T, bare, file, content string) {
	t.Helper()
	w := filepath.Join(t.TempDir(), "w")
	run(t, filepath.Dir(w), "clone", "-q", bare, w)
	write(t, filepath.Join(w, file), content)
	run(t, w, "add", "-A")
	run(t, w, "commit", "-q", "-m", "upstream change")
	run(t, w, "push", "-q", "origin", "main")
}

func tokenFile(t *testing.T, token string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

type apiCall struct {
	Method string
	URI    string
	Header http.Header
	Body   map[string]any
}

// fakeAPI imitates the few GitLab and GitHub endpoints the package uses.
type fakeAPI struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []apiCall
	fail   int    // status returned by every call when non-zero
	state  string // state returned by the GET endpoints
	merged bool
	// failPosts makes the next n requests that open a merge request fail.
	failPosts int
	opened    map[string]bool // source branches with an open merge request
	// bare is the remote repository: listed requests carry the branch's commit.
	bare string
	// foreign makes listed requests come from another project (a fork).
	foreign bool
	// staleHead makes listed requests point at another commit.
	staleHead bool
}

// head is the commit a listed merge request reports for branch.
func (a *fakeAPI) head(branch string, stale bool) string {
	if a.bare == "" {
		return ""
	}
	if stale {
		return strings.Repeat("0", 40)
	}
	out, err := exec.Command("git", "--git-dir", a.bare, "rev-parse", "refs/heads/"+branch).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	a := &fakeAPI{}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Close)
	return a
}

func (a *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	call := apiCall{Method: r.Method, URI: r.RequestURI, Header: r.Header.Clone()}
	_ = json.Unmarshal(raw, &call.Body)
	a.mu.Lock()
	a.calls = append(a.calls, call)
	fail, state, merged := a.fail, a.state, a.merged
	foreign, stale := a.foreign, a.staleHead
	gitlab := strings.HasPrefix(r.RequestURI, "/api/v4/")
	path, _, _ := strings.Cut(r.RequestURI, "?")
	opening := r.Method == http.MethodPost && (strings.HasSuffix(path, "/merge_requests") || strings.HasSuffix(path, "/pulls"))
	if opening && fail == 0 {
		if a.failPosts > 0 {
			a.failPosts--
			fail = http.StatusBadGateway
		} else {
			if a.opened == nil {
				a.opened = map[string]bool{}
			}
			key := "source_branch"
			if !gitlab {
				key = "head"
			}
			a.opened[fmt.Sprint(call.Body[key])] = true
		}
	}
	listed := false
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		if gitlab {
			listed = a.opened[q.Get("source_branch")]
		} else {
			_, b, _ := strings.Cut(q.Get("head"), ":")
			listed = a.opened[b]
		}
	}
	a.mu.Unlock()
	if fail != 0 {
		// A careless server echoing the credential back.
		http.Error(w, `{"message":"boom `+r.Header.Get("PRIVATE-TOKEN")+`"}`, fail)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case gitlab && r.Method == http.MethodGet && strings.HasSuffix(path, "/merge_requests"):
		q := r.URL.Query()
		list := []map[string]any{}
		if listed && q.Get("state") == "opened" {
			list = append(list, map[string]any{"iid": 7, "web_url": "https://gitlab.example.com/group/app/-/merge_requests/7",
				"state": "opened", "source_branch": q.Get("source_branch"), "sha": a.head(q.Get("source_branch"), stale),
				"source_project_id": map[bool]int{false: 42, true: 99}[foreign], "target_project_id": 42})
		}
		json.NewEncoder(w).Encode(list)
	case !gitlab && r.Method == http.MethodGet && strings.HasSuffix(path, "/pulls"):
		q := r.URL.Query()
		list := []map[string]any{}
		if owner, b, _ := strings.Cut(q.Get("head"), ":"); listed && owner == "owner" && q.Get("state") == "open" {
			list = append(list, map[string]any{"number": 12, "html_url": "https://github.com/owner/app/pull/12",
				"state": "open", "head": map[string]any{"ref": b, "sha": a.head(b, stale),
					"repo": map[string]any{"full_name": map[bool]string{false: "owner/app", true: "mallory/app"}[foreign]}},
				"base": map[string]any{"repo": map[string]any{"full_name": "owner/app"}}})
		}
		json.NewEncoder(w).Encode(list)
	case gitlab && r.Method == http.MethodPost && strings.HasSuffix(r.RequestURI, "/merge_requests"):
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"iid": 7, "web_url": "https://gitlab.example.com/group/app/-/merge_requests/7",
			"state": "opened", "source_branch": call.Body["source_branch"]})
	case gitlab && r.Method == http.MethodGet && strings.Contains(r.RequestURI, "/merge_requests/"):
		json.NewEncoder(w).Encode(map[string]any{"iid": 7, "web_url": "https://gitlab.example.com/group/app/-/merge_requests/7",
			"state": state, "source_branch": "dutydesk/inc-1"})
	case r.Method == http.MethodPost && strings.HasSuffix(r.RequestURI, "/pulls"):
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"number": 12, "html_url": "https://github.com/owner/app/pull/12",
			"state": "open", "head": map[string]any{"ref": call.Body["head"]}})
	case r.Method == http.MethodPost && strings.HasSuffix(r.RequestURI, "/labels"):
		w.Write([]byte(`[]`))
	case r.Method == http.MethodGet && strings.Contains(r.RequestURI, "/pulls/"):
		json.NewEncoder(w).Encode(map[string]any{"number": 12, "html_url": "https://github.com/owner/app/pull/12",
			"state": state, "merged": merged, "head": map[string]any{"ref": "dutydesk/inc-1"}})
	default:
		http.NotFound(w, r)
	}
}

func (a *fakeAPI) recorded() []apiCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]apiCall(nil), a.calls...)
}

// env is one remote, one fake API, one Forge and one clone ready to be edited.
type env struct {
	t      *testing.T
	bare   string
	api    *fakeAPI
	forge  *Forge
	repo   model.Repo
	dir    string
	marker string // must never be created: proof that planted code ran
}

func newEnv(t *testing.T, kind string, tune func(*Config)) *env {
	t.Helper()
	e := &env{t: t, bare: newRemote(t), api: newFakeAPI(t)}
	e.api.bare = e.bare
	cfg := Config{
		AllowLocal: true,
		TempDir:    t.TempDir(),
		APIBase:    map[string]string{"gitlab": e.api.URL + "/api/v4", "github": e.api.URL},
		Secrets:    func() []string { return []string{"seat-token-abcdefghijklmnop"} },
	}
	if tune != nil {
		tune(&cfg)
	}
	e.forge = New(cfg)
	project := "group/app"
	if kind == "github" {
		project = "owner/app"
	}
	e.repo = model.Repo{Name: "app", Forge: kind, URL: "file://" + e.bare, Project: project,
		DefaultBranch: "main", TokenFile: tokenFile(t, testToken)}
	e.dir = filepath.Join(t.TempDir(), "clone")
	e.marker = filepath.Join(t.TempDir(), "executed")
	if err := e.forge.Clone(context.Background(), e.repo, e.dir); err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return e
}

func (e *env) propose(branch, title, description string) (model.MRInfo, error) {
	return e.forge.Propose(context.Background(), e.repo, e.dir, branch, title, description, false, []string{"dutydesk"})
}

// branches lists the branches of the remote.
func (e *env) branches() []string {
	return strings.Fields(run(e.t, e.bare, "for-each-ref", "--format=%(refname:short)", "refs/heads"))
}

// mustRefuse checks the error and that nothing reached the remote or the API.
func (e *env) mustRefuse(err, want error) {
	e.t.Helper()
	if err == nil {
		e.t.Fatalf("no error, want %v", want)
	}
	if !errorsIs(err, want) {
		e.t.Fatalf("error %q, want %v", err, want)
	}
	if got := e.branches(); len(got) != 1 || got[0] != "main" {
		e.t.Fatalf("remote branches after a refusal: %v", got)
	}
	if n := len(e.api.recorded()); n != 0 {
		e.t.Fatalf("%d API calls after a refusal", n)
	}
}
