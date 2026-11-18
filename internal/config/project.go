package config

import (
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/DavidGodefroid/dutydesk/internal/actions"
	"github.com/DavidGodefroid/dutydesk/internal/model"
)

type projectFile struct {
	Name  string `yaml:"name"`
	Repos []struct {
		Name          string `yaml:"name"`
		Forge         string `yaml:"forge"`
		URL           string `yaml:"url"`
		Project       string `yaml:"project"`
		DefaultBranch string `yaml:"default_branch"`
		TokenFile     string `yaml:"token_file"`
		// Pointers: an absent (or null) key and an empty list differ.
		DenyPaths  *[]string `yaml:"deny_paths"`
		AllowPaths *[]string `yaml:"allow_paths"`
	} `yaml:"repos"`
	Locks struct {
		Workspace string `yaml:"workspace"`
		SQL       string `yaml:"sql"`
		Log       string `yaml:"log"`
		MQ        string `yaml:"mq"`
		File      string `yaml:"file"`
	} `yaml:"locks"`
	Limits struct {
		MaxOpenPerCheck    int      `yaml:"max_open_per_check"`
		MaxRunsPerIncident int      `yaml:"max_runs_per_incident"`
		MaxIncidentAge     duration `yaml:"max_incident_age"`
		RunTimeout         duration `yaml:"run_timeout"`
		MaxTurns           int      `yaml:"max_turns"`
		MaxParallelRuns    int      `yaml:"max_parallel_runs"`
		GreenLightTimeout  duration `yaml:"green_light_timeout"`
		QueueAlertAfter    duration `yaml:"queue_alert_after"`
		RecurrenceCount    int      `yaml:"recurrence_count"`
		RecurrenceWindow   duration `yaml:"recurrence_window"`
		ReminderEvery      duration `yaml:"reminder_every"`
		MaxGreenLights     int      `yaml:"max_green_lights"`
		MaxQuotaRuns       int      `yaml:"max_quota_runs"`
	} `yaml:"limits"`
	Alerts struct {
		WebhookURLFile string `yaml:"webhook_url_file"`
		HeartbeatURL   string `yaml:"heartbeat_url"`
	} `yaml:"alerts"`
	Seats    []string `yaml:"seats"`
	Webhooks map[string]struct {
		Kind        string            `yaml:"kind"`
		SecretFile  string            `yaml:"secret_file"`
		Severity    string            `yaml:"severity"`
		Fingerprint string            `yaml:"fingerprint"`
		Fields      map[string]string `yaml:"fields"`
		Runbook     string            `yaml:"runbook"`
	} `yaml:"webhooks"`
}

type checkFile struct {
	ID          string   `yaml:"id"`
	Kind        string   `yaml:"kind"`
	Schedule    string   `yaml:"schedule"`
	Severity    string   `yaml:"severity"`
	Fingerprint string   `yaml:"fingerprint"`
	Summary     string   `yaml:"summary"`
	Query       string   `yaml:"query"`
	LogQuery    string   `yaml:"log_query"`
	LogWindow   duration `yaml:"log_window"`
	Threshold   int      `yaml:"threshold"`
	Source      string   `yaml:"source"`
}

// ValidatePathGlob checks one deny_paths / allow_paths pattern: a path glob
// anchored at the repository root, with "/" separators, "*" and "?" inside
// a segment (path.Match syntax) and "**" as a whole segment for any number
// of segments. The error never needs the file: it says what is wrong.
func ValidatePathGlob(g string) error {
	switch {
	case g == "":
		return errors.New("empty pattern")
	case len(g) > 512:
		return errors.New("longer than 512 bytes")
	case strings.Contains(g, `\`):
		return errors.New("a backslash is not allowed (use \"/\" separators, no escaping)")
	case strings.HasPrefix(g, "/"):
		return errors.New("want a path relative to the repository root, not an absolute path")
	}
	for _, r := range g {
		if r < 0x20 || r == 0x7F {
			return errors.New("a control character is not allowed")
		}
	}
	for _, seg := range strings.Split(g, "/") {
		switch {
		case seg == "":
			return errors.New("empty path segment (no \"//\", no trailing \"/\")")
		case seg == "." || seg == "..":
			return errors.New("\".\" and \"..\" segments are not allowed")
		case seg == "**":
		case strings.Contains(seg, "**"):
			return errors.New("\"**\" must be a whole path segment")
		default:
			if _, err := path.Match(seg, ""); err != nil {
				return errors.New("a segment is not a valid glob")
			}
		}
	}
	return nil
}

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func loadProject(root, slug string, repo *Repo, el *errlist) *model.Project {
	rel := "projects/" + slug
	p := &model.Project{Slug: slug, Actions: map[string]model.Action{}, Webhooks: map[string]model.Webhook{}}

	// project.yaml
	file := rel + "/project.yaml"
	var pf projectFile
	if data, err := os.ReadFile(filepath.Join(root, file)); err != nil {
		el.addf(file, "missing or unreadable")
	} else if err := decodeStrict(data, &pf); err != nil {
		el.addf(file, "%v", err)
	}
	p.Name = pf.Name
	if p.Name == "" {
		el.addf(file, "name: required")
	}
	repoNames := map[string]bool{}
	for i, r := range pf.Repos {
		f := "repos[" + itoa(i) + "]"
		if !idRe.MatchString(r.Name) {
			el.addf(file, "%s.name: required; %s", f, idRule)
		} else {
			f = "repos." + r.Name
			if repoNames[r.Name] {
				el.addf(file, "%s: declared twice", f)
			}
			repoNames[r.Name] = true
		}
		if r.Forge != "gitlab" && r.Forge != "github" {
			el.addf(file, "%s.forge: want \"gitlab\" or \"github\"", f)
		}
		if u, err := url.Parse(r.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			el.addf(file, "%s.url: want an https clone URL without credentials", f)
		}
		if r.Project == "" || strings.ContainsAny(r.Project, " \t") || strings.HasPrefix(r.Project, "/") {
			el.addf(file, "%s.project: want the forge project path, e.g. \"group/app\"", f)
		}
		if r.DefaultBranch == "" {
			r.DefaultBranch = "main"
		}
		if !filepath.IsAbs(r.TokenFile) {
			el.addf(file, "%s.token_file: want an absolute path", f)
		}
		mr := model.Repo{Name: r.Name, Forge: r.Forge, URL: r.URL, Project: r.Project,
			DefaultBranch: r.DefaultBranch, TokenFile: r.TokenFile}
		// Key absent (or null): nil, the core applies its built-in deny-list.
		// "deny_paths: []": a non-nil empty list, the restriction is lifted.
		for _, pl := range []struct {
			key string
			in  *[]string
			out *[]string
		}{{"deny_paths", r.DenyPaths, &mr.DenyPaths}, {"allow_paths", r.AllowPaths, &mr.AllowPaths}} {
			if pl.in == nil {
				continue
			}
			*pl.out = append([]string{}, *pl.in...)
			for j, g := range *pl.in {
				if err := ValidatePathGlob(g); err != nil {
					el.addf(file, "%s.%s[%d]: %v", f, pl.key, j, err)
				}
			}
		}
		p.Repos = append(p.Repos, mr)
	}
	p.Locks = model.Locks{Workspace: pf.Locks.Workspace, SQL: pf.Locks.SQL, Log: pf.Locks.Log, MQ: pf.Locks.MQ, File: pf.Locks.File}
	if !filepath.IsAbs(p.Locks.Workspace) {
		el.addf(file, "locks.workspace: want the absolute path of the directory holding .lockfamily/")
	}
	for key, v := range map[string]string{"sql": p.Locks.SQL, "log": p.Locks.Log, "mq": p.Locks.MQ, "file": p.Locks.File} {
		if v != "" && !idRe.MatchString(v) {
			el.addf(file, "locks.%s: %q is not a lock instance name", key, v)
		}
	}
	p.Limits = WithDefaults(model.Limits{
		MaxOpenPerCheck:    pf.Limits.MaxOpenPerCheck,
		MaxRunsPerIncident: pf.Limits.MaxRunsPerIncident,
		MaxIncidentAge:     time.Duration(pf.Limits.MaxIncidentAge),
		RunTimeout:         time.Duration(pf.Limits.RunTimeout),
		MaxTurns:           pf.Limits.MaxTurns,
		MaxParallelRuns:    pf.Limits.MaxParallelRuns,
		GreenLightTimeout:  time.Duration(pf.Limits.GreenLightTimeout),
		QueueAlertAfter:    time.Duration(pf.Limits.QueueAlertAfter),
		RecurrenceCount:    pf.Limits.RecurrenceCount,
		RecurrenceWindow:   time.Duration(pf.Limits.RecurrenceWindow),
		ReminderEvery:      time.Duration(pf.Limits.ReminderEvery),
		MaxGreenLights:     pf.Limits.MaxGreenLights,
		MaxQuotaRuns:       pf.Limits.MaxQuotaRuns,
	})
	if err := ValidateLimits(p.Limits); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			el.addf(file, "%s", line)
		}
	}
	p.Alerts = model.AlertConfig{WebhookURLFile: pf.Alerts.WebhookURLFile, HeartbeatURL: pf.Alerts.HeartbeatURL}
	if !filepath.IsAbs(p.Alerts.WebhookURLFile) {
		el.addf(file, "alerts.webhook_url_file: required, an absolute path")
	}
	if p.Alerts.HeartbeatURL != "" && !httpURL(p.Alerts.HeartbeatURL) {
		el.addf(file, "alerts.heartbeat_url: want an http(s) URL")
	}
	seats := map[string]bool{}
	for _, s := range pf.Seats {
		if !idRe.MatchString(s) || seats[s] {
			el.addf(file, "seats: %q is not a seat name or is listed twice", s)
		}
		seats[s] = true
	}
	p.Seats = pf.Seats

	// actions
	if cat, err := actions.LoadCatalogue(filepath.Join(root, rel, "actions")); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			el.errs = append(el.errs, errors.New(rel+"/actions/"+line))
		}
	} else {
		p.Actions = cat
	}

	// checks
	checkIDs := map[string]bool{}
	for _, name := range listFiles(root, rel+"/checks", ".yaml", el) {
		cfile := rel + "/checks/" + name
		if c, ok := loadCheck(root, cfile, strings.TrimSuffix(name, ".yaml"), p, el); ok {
			checkIDs[c.ID] = true
			p.Checks = append(p.Checks, c)
		}
	}

	// runbooks: the project's own first, then the standard ones it does not override
	own := loadRunbooks(root, rel+"/runbooks", slug, el)
	checkSources(rel+"/runbooks", own, el)
	ownIDs := map[string]bool{}
	for _, rb := range own {
		ownIDs[rb.ID] = true
	}
	p.Runbooks = own
	for _, rb := range repo.Runbooks {
		if !ownIDs[rb.ID] {
			p.Runbooks = append(p.Runbooks, rb)
		}
	}
	runbookIDs := map[string]bool{}
	for _, rb := range p.Runbooks {
		runbookIDs[rb.ID] = true
	}

	// webhooks
	names := make([]string, 0, len(pf.Webhooks))
	for n := range pf.Webhooks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w := pf.Webhooks[n]
		f := "webhooks." + n
		if !idRe.MatchString(n) {
			el.addf(file, "%s: invalid source id: %s", f, idRule)
		}
		if checkIDs[n] {
			el.addf(file, "%s: a check has the same id; source ids are unique in a project", f)
		}
		if w.Kind != "sentry" && w.Kind != "generic" {
			el.addf(file, "%s.kind: want \"sentry\" or \"generic\"", f)
		}
		if !filepath.IsAbs(w.SecretFile) {
			el.addf(file, "%s.secret_file: required, an absolute path", f)
		}
		sev, err := ParseSeverity(w.Severity)
		if err != nil {
			el.addf(file, "%s.severity: %v", f, err)
		}
		if w.Fingerprint == "" && w.Kind == "sentry" {
			w.Fingerprint = "sentry:{issue_id}"
		}
		ph, err := Placeholders(w.Fingerprint)
		switch {
		case err != nil:
			el.addf(file, "%s.fingerprint: %v", f, err)
		case Family(w.Fingerprint) == "":
			el.addf(file, "%s.fingerprint: required, with a literal part (e.g. \"%s:{id}\")", f, n)
		case w.Kind == "generic":
			for _, name := range ph {
				if _, ok := w.Fields[name]; !ok {
					el.addf(file, "%s.fingerprint: {%s} is not one of the allow-listed fields", f, name)
				}
			}
		}
		if w.Kind == "generic" && len(w.Fields) == 0 {
			el.addf(file, "%s.fields: required for a generic webhook (output field: payload path)", f)
		}
		for k, v := range w.Fields {
			if !placeholderRe.MatchString("{"+k+"}") || v == "" {
				el.addf(file, "%s.fields.%s: want a field name (letters, digits, \"_\") and a payload path", f, k)
			}
		}
		if w.Runbook != "" && !runbookIDs[w.Runbook] {
			el.addf(file, "%s.runbook: no runbook %q", f, w.Runbook)
		}
		p.Webhooks[n] = model.Webhook{Kind: w.Kind, SecretFile: w.SecretFile, Severity: sev,
			FingerprintTemplate: w.Fingerprint, Fields: w.Fields, Runbook: w.Runbook}
	}

	// runbooks against the rest of the project
	// A lockssh instance (profile) is "auto" or "ask" as a whole and carries
	// exactly the actions of one level of the runbook(s) that name it.
	type instanceUse struct {
		runbook string
		level   model.ActionLevel
		actions []string
	}
	instances := map[string]instanceUse{}
	for _, rb := range own {
		rfile := runbookPath(rel+"/runbooks", rb.ID)
		for _, s := range rb.AppliesTo {
			if _, isHook := p.Webhooks[s]; s != "*" && !checkIDs[s] && !isHook {
				el.addf(rfile, "applies_to: %q is neither a check nor a webhook source of project %s", s, slug)
			}
		}
		seen := map[string]bool{}
		byLevel := map[model.ActionLevel][]string{}
		for _, a := range rb.Actions {
			act, ok := p.Actions[a]
			if !ok {
				el.addf(rfile, "actions: %q is not an action of project %s (no actions/%s/)", a, slug, a)
			} else if !seen[a] {
				byLevel[act.Level] = append(byLevel[act.Level], a)
			}
			if seen[a] {
				el.addf(rfile, "actions: %q is listed twice", a)
			}
			seen[a] = true
		}
		for _, in := range []struct {
			key, name, what string
			level           model.ActionLevel
		}{
			{"action_instance", rb.ActionInstance, "auto", model.ActionAuto},
			{"ask_instance", rb.AskInstance, "green-light", model.ActionGreenLight},
		} {
			acts := byLevel[in.level]
			switch {
			case len(acts) > 0 && in.name == "":
				el.addf(rfile, "%s: required when the runbook has %s actions (the lockssh instance carrying exactly these actions)", in.key, in.what)
			case len(acts) == 0 && in.name != "":
				el.addf(rfile, "%s: set, but the runbook has no %s action", in.key, in.what)
			case in.name != "" && !idRe.MatchString(in.name):
				el.addf(rfile, "%s: %q is not a lock instance name", in.key, in.name)
			case in.name != "":
				prev, ok := instances[in.name]
				switch {
				case ok && prev.level != in.level:
					el.addf(rfile, "%s: %q is already the %s instance of runbook %q (a lockssh profile is auto or ask as a whole)", in.key, in.name, prev.level, prev.runbook)
				case ok && !sameSet(prev.actions, acts):
					el.addf(rfile, "%s: %q is shared with runbook %q but the actions differ", in.key, in.name, prev.runbook)
				case !ok:
					instances[in.name] = instanceUse{runbook: rb.ID, level: in.level, actions: acts}
				}
			}
		}
		if rb.ActionInstance != "" && rb.ActionInstance == rb.AskInstance {
			el.addf(rfile, "ask_instance: must differ from action_instance (lockssh decides auto or ask per profile)")
		}
		if rb.RecheckCheck != "" && !checkIDs[rb.RecheckCheck] {
			el.addf(rfile, "recheck_check: no check %q in project %s", rb.RecheckCheck, slug)
		}
	}

	// mr-rules.md
	p.MRRules = repo.MRRules
	if fileExists(filepath.Join(root, rel, "mr-rules.md")) {
		p.MRRules = readText(root, rel+"/mr-rules.md", el)
	}
	return p
}

func loadCheck(root, file, stem string, p *model.Project, el *errlist) (model.Check, bool) {
	var cf checkFile
	data, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		el.addf(file, "%v", err)
		return model.Check{}, false
	}
	if err := decodeStrict(data, &cf); err != nil {
		el.addf(file, "%v", err)
		return model.Check{}, false
	}
	if cf.ID == "" {
		cf.ID = stem
	}
	if cf.ID != stem {
		el.addf(file, "id: %q does not match the file name %q", cf.ID, stem)
		return model.Check{}, false
	}
	c := model.Check{
		ID: cf.ID, Project: p.Slug, Kind: model.CheckKind(cf.Kind), Schedule: cf.Schedule,
		Fingerprint: cf.Fingerprint, Summary: cf.Summary, Query: strings.TrimSpace(cf.Query),
		LogQuery: strings.TrimSpace(cf.LogQuery), LogWindow: time.Duration(cf.LogWindow),
		Threshold: cf.Threshold, Source: cf.Source,
	}
	if len(strings.Fields(c.Schedule)) != 5 {
		el.addf(file, "schedule: want a 5-field cron expression (minute hour day month weekday)")
	} else if _, err := cron.ParseStandard(c.Schedule); err != nil {
		el.addf(file, "schedule: %v", err)
	}
	if c.Severity, err = ParseSeverity(cf.Severity); err != nil {
		el.addf(file, "severity: %v", err)
	}
	if _, err := Placeholders(c.Fingerprint); err != nil {
		el.addf(file, "fingerprint: %v", err)
	} else if Family(c.Fingerprint) == "" {
		el.addf(file, "fingerprint: required, with a literal part (e.g. \"%s:{id}\")", c.ID)
	}
	if _, err := Placeholders(c.Summary); err != nil {
		el.addf(file, "summary: %v", err)
	} else if strings.TrimSpace(c.Summary) == "" {
		el.addf(file, "summary: required")
	}

	needSQL := func() {
		if c.Query == "" {
			el.addf(file, "query: required")
		}
		if p.Locks.SQL == "" {
			el.addf(file, "kind: reads SQL but project %s has no locks.sql", p.Slug)
		}
		if c.LogQuery != "" || c.LogWindow != 0 {
			el.addf(file, "log_query, log_window: not used by a SQL source")
		}
	}
	needLog := func() {
		if c.LogQuery == "" {
			el.addf(file, "log_query: required")
		}
		if c.LogWindow < time.Minute || c.LogWindow > 7*24*time.Hour {
			el.addf(file, "log_window: required, a duration in [1m, 168h]")
		}
		if p.Locks.Log == "" {
			el.addf(file, "kind: reads logs but project %s has no locks.log", p.Slug)
		}
		if c.Query != "" {
			el.addf(file, "query: not used by a log source")
		}
	}
	switch c.Kind {
	case model.CheckSQL:
		needSQL()
		if c.Threshold != 0 || c.Source != "" {
			el.addf(file, "threshold, source: not used by kind sql (each returned row is a signal)")
		}
	case model.CheckLog:
		needLog()
		if c.Threshold < 1 {
			el.addf(file, "threshold: required, at least 1 (signal when count >= threshold)")
		}
		if c.Source != "" {
			el.addf(file, "source: not used by kind log")
		}
	case model.CheckExpect:
		switch c.Source {
		case "sql":
			needSQL()
		case "log":
			needLog()
		default:
			el.addf(file, "source: want \"sql\" or \"log\" for kind expect")
		}
		if c.Threshold == 0 {
			c.Threshold = 1
		}
		if c.Threshold < 1 {
			el.addf(file, "threshold: at least 1 (signal when count < threshold)")
		}
	default:
		el.addf(file, "kind: want \"sql\", \"log\" or \"expect\"")
	}
	return c, true
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\n") == strings.Join(y, "\n")
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}
