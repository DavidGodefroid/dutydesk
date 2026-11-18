package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// APIError is a non-2xx answer of the forge REST API. It never holds the token.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string // start of the response body, token removed
}

func (e *APIError) Error() string {
	return fmt.Sprintf("forge: %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Message)
}

// apiBase returns the REST base URL of the forge hosting repo: the configured
// override for the forge kind, else a URL derived from the clone URL.
func (f *Forge) apiBase(repo model.Repo) (string, error) {
	if b := f.cfg.APIBase[repo.Forge]; b != "" {
		return strings.TrimRight(b, "/"), nil
	}
	u, _, err := f.checkRepoURL(repo.URL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "file" {
		return "", errors.New("forge: no API base URL for a file repository; set Config.APIBase")
	}
	root := u.Scheme + "://" + u.Host
	switch repo.Forge {
	case "gitlab":
		// A GitLab served under a sub-path keeps that prefix: strip "<project>.git".
		p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
		prefix := strings.TrimSuffix(p, "/"+strings.Trim(repo.Project, "/"))
		if prefix == p {
			prefix = ""
		}
		return root + strings.TrimRight(prefix, "/") + "/api/v4", nil
	case "github":
		if strings.EqualFold(u.Host, "github.com") {
			return "https://api.github.com", nil
		}
		return root + "/api/v3", nil
	}
	return "", fmt.Errorf("forge: unknown forge %q", repo.Forge)
}

// call sends one JSON request with the service account token and decodes a 2xx answer into out.
func (f *Forge) call(ctx context.Context, repo model.Repo, token, method, path string, in, out any) error {
	base, err := f.apiBase(repo)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return errors.New("forge: invalid API URL")
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "dutydesk")
	if repo.Forge == "github" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	} else {
		req.Header.Set("PRIVATE-TOKEN", token)
		req.Header.Set("Accept", "application/json")
	}
	resp, err := f.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return errors.New(redact(fmt.Sprintf("forge: %s %s: %v", method, path, err), token))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.Join(strings.Fields(string(data)), " ")
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: redact(msg, token)}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("forge: %s %s: unreadable answer", method, path)
		}
	}
	return nil
}

type glMR struct {
	IID          int64  `json:"iid"`
	WebURL       string `json:"web_url"`
	State        string `json:"state"`
	SourceBranch string `json:"source_branch"`
}

func (m glMR) info() (model.MRInfo, error) {
	info := model.MRInfo{ID: strconv.FormatInt(m.IID, 10), URL: m.WebURL, Branch: m.SourceBranch}
	switch m.State {
	case "opened", "locked": // locked: a merge is in progress
		info.State = "open"
	case "merged", "closed":
		info.State = m.State
	default:
		return info, fmt.Errorf("forge: unknown merge request state %q", m.State)
	}
	if m.IID == 0 {
		return info, errors.New("forge: answer without a merge request id")
	}
	return info, nil
}

type ghPR struct {
	Number  int64  `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
	Merged  bool   `json:"merged"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

func (p ghPR) info() (model.MRInfo, error) {
	info := model.MRInfo{ID: strconv.FormatInt(p.Number, 10), URL: p.HTMLURL, Branch: p.Head.Ref}
	switch {
	case p.Merged:
		info.State = "merged"
	case p.State == "open" || p.State == "closed":
		info.State = p.State
	default:
		return info, fmt.Errorf("forge: unknown pull request state %q", p.State)
	}
	if p.Number == 0 {
		return info, errors.New("forge: answer without a pull request number")
	}
	return info, nil
}

func gitlabProject(repo model.Repo) (string, error) {
	p := strings.Trim(repo.Project, "/")
	if p == "" {
		return "", errors.New("forge: repo has no project path")
	}
	return "/projects/" + url.PathEscape(p), nil
}

func githubRepo(repo model.Repo) (string, error) {
	parts := strings.Split(strings.Trim(repo.Project, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New(`forge: a GitHub project must be "owner/repo"`)
	}
	return "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]), nil
}

// openMR opens the merge request (GitLab) or pull request (GitHub). There is
// no merge call in this package, on purpose.
func (f *Forge) openMR(ctx context.Context, repo model.Repo, token, branch, target, title, description string, draft bool, labels []string) (model.MRInfo, error) {
	switch repo.Forge {
	case "gitlab":
		base, err := gitlabProject(repo)
		if err != nil {
			return model.MRInfo{}, err
		}
		if draft {
			title = "Draft: " + title
		}
		in := map[string]any{
			"source_branch":        branch,
			"target_branch":        target,
			"title":                title,
			"description":          description,
			"remove_source_branch": true,
		}
		if len(labels) > 0 {
			in["labels"] = strings.Join(labels, ",")
		}
		var mr glMR
		if err := f.call(ctx, repo, token, http.MethodPost, base+"/merge_requests", in, &mr); err != nil {
			return model.MRInfo{}, err
		}
		return mr.info()
	case "github":
		base, err := githubRepo(repo)
		if err != nil {
			return model.MRInfo{}, err
		}
		in := map[string]any{"title": title, "head": branch, "base": target, "body": description, "draft": draft}
		var pr ghPR
		if err := f.call(ctx, repo, token, http.MethodPost, base+"/pulls", in, &pr); err != nil {
			return model.MRInfo{}, err
		}
		info, err := pr.info()
		if err != nil {
			return info, err
		}
		if len(labels) > 0 {
			// The pull request exists: a label failure must not make the caller retry.
			path := base + "/issues/" + info.ID + "/labels"
			if err := f.call(ctx, repo, token, http.MethodPost, path, map[string]any{"labels": labels}, nil); err != nil {
				f.logf("forge: pull request %s opened but labels were not set: %v", info.ID, err)
			}
		}
		return info, nil
	}
	return model.MRInfo{}, fmt.Errorf("forge: unknown forge %q", repo.Forge)
}

// Status returns the state of a merge request or pull request: open, merged or closed.
func (f *Forge) Status(ctx context.Context, repo model.Repo, id string) (model.MRInfo, error) {
	if id == "" || len(id) > 18 || strings.Trim(id, "0123456789") != "" {
		return model.MRInfo{}, errors.New("forge: merge request id must be a number")
	}
	token, err := readToken(repo.TokenFile)
	if err != nil {
		return model.MRInfo{}, err
	}
	switch repo.Forge {
	case "gitlab":
		base, err := gitlabProject(repo)
		if err != nil {
			return model.MRInfo{}, err
		}
		var mr glMR
		if err := f.call(ctx, repo, token, http.MethodGet, base+"/merge_requests/"+id, nil, &mr); err != nil {
			return model.MRInfo{}, err
		}
		return mr.info()
	case "github":
		base, err := githubRepo(repo)
		if err != nil {
			return model.MRInfo{}, err
		}
		var pr ghPR
		if err := f.call(ctx, repo, token, http.MethodGet, base+"/pulls/"+id, nil, &pr); err != nil {
			return model.MRInfo{}, err
		}
		return pr.info()
	}
	return model.MRInfo{}, fmt.Errorf("forge: unknown forge %q", repo.Forge)
}
