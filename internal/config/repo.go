// Package config loads and validates DutyDesk's configuration: the config
// repository (standard texts and projects) and the daemon's own file.
//
// Layout of a config repository:
//
//	standard/method.md              investigation method given to every agent
//	standard/mr-rules.md            merge request rules (a project may override)
//	standard/runbooks/*.md          standard runbooks; generic.md (applies_to ["*"]) is required
//	projects/<slug>/project.yaml    repos, locks, limits, alerts, seats, webhooks
//	projects/<slug>/checks/*.yaml   scheduled checks
//	projects/<slug>/runbooks/*.md   runbooks; one with a standard id overrides it
//	projects/<slug>/actions/<name>/ action.yaml + script
//	projects/<slug>/mr-rules.md     optional override of the standard rules
//
// Every YAML file is strict: an unknown key is an error. Checks, runbooks
// and actions are named after their file or directory; an "id"/"name" key,
// when present, must agree.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

// Repo is a loaded config repository.
type Repo struct {
	Dir      string
	Method   string          // standard/method.md
	MRRules  string          // standard/mr-rules.md
	Runbooks []model.Runbook // standard/runbooks/*.md (Project == "")
	Projects []*model.Project
}

// Project returns the project with that slug, or nil.
func (r *Repo) Project(slug string) *model.Project {
	for _, p := range r.Projects {
		if p.Slug == slug {
			return p
		}
	}
	return nil
}

// GenericRunbookID is the id of the required fallback runbook.
const GenericRunbookID = "generic"

// LoadRepo loads and validates the config repository in dir. It reports
// every problem it finds (errors.Join), each as "<file>: <field>: <why>"
// with the file relative to dir. Each project's Runbooks hold its own
// runbooks first, then the standard ones it does not override; its Limits
// have their defaults filled in.
func LoadRepo(dir string) (*Repo, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, errors.New(dir + ": not a directory")
	}
	var el errlist
	repo := &Repo{Dir: dir}

	repo.Method = readText(dir, "standard/method.md", &el)
	repo.MRRules = readText(dir, "standard/mr-rules.md", &el)
	repo.Runbooks = loadRunbooks(dir, "standard/runbooks", "", &el)
	generic := false
	for _, rb := range repo.Runbooks {
		if len(rb.Actions) > 0 || rb.ActionInstance != "" || rb.AskInstance != "" {
			el.addf(runbookPath("standard/runbooks", rb.ID), "actions: a standard runbook runs no action (actions belong to a project)")
		}
		if rb.RecheckCheck != "" {
			el.addf(runbookPath("standard/runbooks", rb.ID), "recheck_check: a standard runbook cannot name a project check")
		}
		if rb.ID == GenericRunbookID {
			generic = true
			if len(rb.AppliesTo) != 1 || rb.AppliesTo[0] != "*" {
				el.addf(runbookPath("standard/runbooks", rb.ID), "applies_to: the generic runbook wants exactly [\"*\"]")
			}
		}
	}
	if !generic && fileExists(filepath.Join(dir, "standard/runbooks")) {
		el.addf("standard/runbooks/generic.md", "missing (the generic fallback runbook is required)")
	}
	checkSources("standard/runbooks", repo.Runbooks, &el)

	entries, err := os.ReadDir(filepath.Join(dir, "projects"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		el.addf("projects", "%v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rel := "projects/" + e.Name()
		if !e.IsDir() {
			el.addf(rel, "unexpected file (want one directory per project)")
			continue
		}
		if !idRe.MatchString(e.Name()) {
			el.addf(rel, "invalid project slug: %s", idRule)
			continue
		}
		repo.Projects = append(repo.Projects, loadProject(dir, e.Name(), repo, &el))
	}
	if err := el.err(); err != nil {
		return nil, err
	}
	return repo, nil
}

// RunbookFor returns the runbook for a signal source (a check id or a
// webhook source id): the one a webhook names, else the one whose
// AppliesTo lists the source, else the generic one ("*").
func RunbookFor(p *model.Project, source string) model.Runbook {
	if wh, ok := p.Webhooks[source]; ok && wh.Runbook != "" {
		for _, rb := range p.Runbooks {
			if rb.ID == wh.Runbook {
				return rb
			}
		}
	}
	for _, want := range []string{source, "*"} {
		for _, rb := range p.Runbooks {
			for _, s := range rb.AppliesTo {
				if s == want {
					return rb
				}
			}
		}
	}
	return model.Runbook{
		ID:             GenericRunbookID,
		AppliesTo:      []string{"*"},
		RecheckDefault: DefaultRecheck,
		Body:           "Investigate read-only through the locks. Run no action. Conclude with outcome \"escalate\" and your diagnosis.",
	}
}

func readText(dir, rel string, el *errlist) string {
	data, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		el.addf(rel, "missing or unreadable")
		return ""
	}
	if strings.TrimSpace(string(data)) == "" {
		el.addf(rel, "empty")
	}
	return string(data)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// listFiles lists dir's files with the extension ext, sorted. Any other
// entry is reported: a ".yml" or a stray file would be silently ignored.
func listFiles(root, rel, ext string, el *errlist) []string {
	entries, err := os.ReadDir(filepath.Join(root, rel))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			el.addf(rel, "%v", err)
		}
		return nil
	}
	var out []string
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "."):
		case e.IsDir() || filepath.Ext(e.Name()) != ext:
			el.addf(rel+"/"+e.Name(), "unexpected entry (only %s files are read here)", ext)
		case !idRe.MatchString(strings.TrimSuffix(e.Name(), ext)):
			el.addf(rel+"/"+e.Name(), "invalid file name: %s", idRule)
		default:
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
