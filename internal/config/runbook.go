package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/model"
)

type runbookFront struct {
	ID             string   `yaml:"id"`
	AppliesTo      []string `yaml:"applies_to"`
	Actions        []string `yaml:"actions"`
	ActionInstance string   `yaml:"action_instance"`
	AskInstance    string   `yaml:"ask_instance"`
	RecheckDefault duration `yaml:"recheck_default"`
	RecheckCheck   string   `yaml:"recheck_check"`
	MaxRuns        int      `yaml:"max_runs"`
}

func runbookPath(rel, id string) string { return rel + "/" + id + ".md" }

// ParseRunbook parses a runbook file: a YAML front matter between two
// "---" lines, then the Markdown body. The front matter is strict.
func ParseRunbook(data []byte) (model.Runbook, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return model.Runbook{}, errors.New("front matter: the file must start with a \"---\" line")
	}
	rest := text[4:]
	var front, body string
	if strings.HasPrefix(rest, "---\n") {
		front, body = "", rest[4:]
	} else if i := strings.Index(rest, "\n---\n"); i >= 0 {
		front, body = rest[:i+1], rest[i+5:]
	} else if strings.HasSuffix(rest, "\n---") {
		front, body = rest[:len(rest)-3], ""
	} else {
		return model.Runbook{}, errors.New("front matter: no closing \"---\" line")
	}
	var f runbookFront
	if err := decodeStrict([]byte(front), &f); err != nil {
		return model.Runbook{}, errors.New("front matter: " + err.Error())
	}
	return model.Runbook{
		ID:             f.ID,
		AppliesTo:      f.AppliesTo,
		Actions:        f.Actions,
		ActionInstance: f.ActionInstance,
		AskInstance:    f.AskInstance,
		RecheckDefault: time.Duration(f.RecheckDefault),
		RecheckCheck:   f.RecheckCheck,
		MaxRuns:        f.MaxRuns,
		Body:           strings.TrimLeft(body, "\n"),
	}, nil
}

// loadRunbooks loads rel/*.md and checks what does not depend on the
// project: ids, shape of the front matter, bounds.
func loadRunbooks(root, rel, project string, el *errlist) []model.Runbook {
	var out []model.Runbook
	for _, name := range listFiles(root, rel, ".md", el) {
		file := rel + "/" + name
		stem := strings.TrimSuffix(name, ".md")
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			el.addf(file, "%v", err)
			continue
		}
		rb, err := ParseRunbook(data)
		if err != nil {
			el.addf(file, "%v", err)
			continue
		}
		if rb.ID == "" {
			rb.ID = stem
		}
		if rb.ID != stem {
			el.addf(file, "id: %q does not match the file name %q", rb.ID, stem)
			continue
		}
		rb.Project = project
		if len(rb.AppliesTo) == 0 {
			el.addf(file, "applies_to: required (check ids, webhook source ids, or \"*\" for the fallback)")
		}
		seen := map[string]bool{}
		for _, s := range rb.AppliesTo {
			if s != "*" && !idRe.MatchString(s) {
				el.addf(file, "applies_to: %q is not a source id", s)
			}
			if seen[s] {
				el.addf(file, "applies_to: %q is listed twice", s)
			}
			seen[s] = true
		}
		if rb.RecheckDefault < 0 || rb.RecheckDefault > 24*time.Hour {
			el.addf(file, "recheck_default: want a duration in [1m, 24h]")
		} else if rb.RecheckDefault == 0 {
			rb.RecheckDefault = DefaultRecheck
		} else if rb.RecheckDefault < time.Minute {
			el.addf(file, "recheck_default: want a duration in [1m, 24h]")
		}
		if rb.MaxRuns < 0 || rb.MaxRuns > 50 {
			el.addf(file, "max_runs: %d is outside [0, 50]", rb.MaxRuns)
		}
		if strings.TrimSpace(rb.Body) == "" {
			el.addf(file, "body: the runbook has no text")
		}
		out = append(out, rb)
	}
	return out
}

// checkSources reports a source claimed by two runbooks of one directory.
func checkSources(rel string, rbs []model.Runbook, el *errlist) {
	owner := map[string]string{}
	for _, rb := range rbs {
		for _, s := range rb.AppliesTo {
			if prev, ok := owner[s]; ok && prev != rb.ID {
				el.addf(runbookPath(rel, rb.ID), "applies_to: %q is already claimed by runbook %q", s, prev)
				continue
			}
			owner[s] = rb.ID
		}
	}
}
