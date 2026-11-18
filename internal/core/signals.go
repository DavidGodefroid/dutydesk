package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// Ingest turns one signal into incident state with the rules of its project:
// family from the fingerprint template of its source, runbook from the
// configuration. It is shared by the daemon and by `dutydesk check run`.
func Ingest(mgr *incident.Manager, p *model.Project, sig model.Signal) (incident.IngestResult, error) {
	if p == nil {
		return incident.IngestResult{}, errors.New("core: signal for an unknown project")
	}
	sig.Project = p.Slug
	// Signal text comes from production data or from a webhook: no control
	// character is stored, journaled or printed.
	sig.Summary, sig.Fingerprint = model.CleanLine(sig.Summary), model.CleanLine(sig.Fingerprint)
	if sig.Fingerprint == "" {
		return incident.IngestResult{}, errors.New("core: signal without a fingerprint")
	}
	if len(sig.Fields) > 0 {
		fields := make(map[string]string, len(sig.Fields))
		for k, v := range sig.Fields {
			fields[model.CleanLine(k)] = model.CleanText(v)
		}
		sig.Fields = fields
	}
	return mgr.Ingest(sig, p.Limits, familyOf(p, sig), config.RunbookFor(p, sig.Source).ID)
}

// familyOf is the fingerprint without its variable part.
func familyOf(p *model.Project, sig model.Signal) string {
	for _, c := range p.Checks {
		if c.ID == sig.Source {
			if f := config.Family(c.Fingerprint); f != "" {
				return f
			}
		}
	}
	if w, ok := p.Webhooks[sig.Source]; ok {
		if f := config.Family(w.FingerprintTemplate); f != "" {
			return f
		}
	}
	return sig.Source
}

// ingest is the sink of both triggers.
func (s *Service) ingest(sig model.Signal) {
	p := s.Project(sig.Project)
	if p == nil {
		s.log.Warn("signal for an unknown project dropped", "project", sig.Project, "source", sig.Source)
		return
	}
	res, err := Ingest(s.mgr, p, sig)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		s.log.Error("signal not ingested", "project", sig.Project, "source", sig.Source, "error", err)
		return
	}
	if err != nil {
		s.log.Error("dossier not written", "incident", res.Incident.ID, "error", err)
	}
	switch res.Kind {
	case incident.IngestCreated:
		s.log.Info("incident opened", "incident", res.Incident.ID, "project", sig.Project, "source", sig.Source,
			"fingerprint", sig.Fingerprint, "recurrent", res.Incident.Recurrent)
		s.Kick()
	case incident.IngestMassCreated:
		s.log.Warn("storm guard tripped: mass incident opened", "incident", res.Incident.ID, "project", sig.Project, "source", sig.Source)
	case incident.IngestRecurrent:
		s.log.Warn("pass budget of the family used up: incident opened escalated, no agent pass", "incident", res.Incident.ID,
			"project", sig.Project, "source", sig.Source, "family", res.Incident.Family)
	}
	if res.Alert != "" {
		// The alert is owed in the outbox, written with the incident (also
		// when `dutydesk check run` ingested the signal).
		s.kickOutbox(store.EffectTransition)
	}
}

// checkSink receives every evaluation of the scheduler.
func (s *Service) checkSink(c model.Check, signals []model.Signal, err error) {
	if err != nil {
		if errors.Is(err, errLocksDown) {
			return // skipped, not a failure of the check
		}
		var failing *check.FailingError
		if errors.As(err, &failing) {
			s.log.Error("check keeps failing", "project", c.Project, "check", c.ID, "consecutive", failing.Consecutive,
				"error", s.scrub(err.Error()))
			s.alertOnce("check-failing:"+c.Project+"/"+c.ID, time.Hour, model.Alert{
				Kind: model.AlertSystem, Project: c.Project,
				Title: fmt.Sprintf("Check %s failed %d times in a row", c.ID, failing.Consecutive),
				Body:  "This check no longer watches production. Last error:\n" + s.scrub(failing.Err.Error()),
			})
			return
		}
		s.log.Warn("check failed", "project", c.Project, "check", c.ID, "error", s.scrub(err.Error()))
		return
	}
	for _, sig := range signals {
		s.ingest(sig)
	}
}

// sourceResolved closes the open incident a webhook source declares over.
// Only an incident of that very source: two sources can produce the same
// fingerprint, and one must not close the incidents of the other.
func (s *Service) sourceResolved(project, source, fingerprint string) {
	inc, err := s.st.FindOpenIncident(project, model.CleanLine(fingerprint))
	if err != nil || inc == nil {
		return
	}
	if inc.Source != source || inc.Mass {
		s.log.Warn("resolved webhook ignored: the open incident with this fingerprint belongs to another source",
			"incident", inc.ID, "incident_source", inc.Source, "webhook_source", source)
		return
	}
	if _, err := s.mgr.Close(inc.ID, "resolved at the source ("+source+")"); err != nil && !errors.Is(err, incident.ErrDossier) {
		s.log.Warn("incident not closed on a resolved webhook", "incident", inc.ID, "error", err)
		return
	}
	s.cancelPass(inc.ID)
	s.kickOutbox(store.EffectTransition) // a held ticket is withdrawn by the outbox
	s.log.Info("incident closed by its source", "incident", inc.ID, "source", source)
}

// ---------- lock gate ----------

var errLocksDown = errors.New("core: the locks of this project do not serve")

type gateState struct {
	serving bool
	alerted bool
}

// workspaces lists the lock workspaces of the configuration and their projects.
func (s *Service) workspaces() map[string][]*model.Project {
	out := map[string][]*model.Project{}
	for _, p := range s.cfg.Load().Projects {
		out[p.Locks.Workspace] = append(out[p.Locks.Workspace], p)
	}
	return out
}

// locksServing reports whether the last poll saw the locks of the project
// serving. Unknown is closed: no agent starts before a first good poll.
func (s *Service) locksServing(p *model.Project) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.gate[p.Locks.Workspace]
	return g != nil && g.serving
}

// pollLocks reads lox live's health per workspace, outside the main loop.
// While a workspace does not serve, nothing starts for its projects; a
// human is alerted once (through the outbox: retried until delivered), with
// what needs enrolment or a secret.
func (s *Service) pollLocks(ctx context.Context) {
	for ws, projects := range s.workspaces() {
		s.background(ctx, s.ioSem, "health:"+ws, func(ctx context.Context) { s.pollWorkspace(ctx, ws, projects) })
	}
}

func (s *Service) pollWorkspace(ctx context.Context, ws string, projects []*model.Project) {
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	h, err := s.o.Status.Health(hctx, ws)
	cancel()
	if ctx.Err() != nil {
		return
	}
	serving := err == nil && h.Serving
	s.mu.Lock()
	g := s.gate[ws]
	if g == nil {
		g = &gateState{}
		s.gate[ws] = g
	}
	was, alerted := g.serving, g.alerted
	g.serving = serving
	g.alerted = !serving
	s.mu.Unlock()

	switch {
	case serving && !was:
		s.log.Info("locks serve", "workspace", ws)
		s.Kick()
	case !serving && !alerted:
		detail := "the status socket of lox live does not answer"
		if err == nil {
			detail = lockDetail(h)
		}
		s.log.Warn("locks do not serve: no agent starts, scheduled checks are skipped", "workspace", ws, "detail", detail)
		for _, p := range projects {
			s.sendAlert(p, model.Alert{Kind: model.AlertLocksDown, Project: p.Slug,
				Title: "The locks do not serve: DutyDesk is blind and starts no agent",
				Body: detail + "\nChecks are skipped and incidents wait in the queue until the locks serve again. " +
					"On the lock host: check `lox live status`; a lock that needs enrolment or a secret needs a human at a terminal."})
		}
	}
}

func lockDetail(h model.LockHealth) string {
	var bad []string
	for name, state := range h.Locks {
		if state != "serving" {
			bad = append(bad, name+": "+strings.ReplaceAll(state, "_", " "))
		}
	}
	sort.Strings(bad)
	out := "lox live reports that the locks do not serve"
	if len(bad) > 0 {
		out += " (" + strings.Join(bad, "; ") + ")"
	}
	if d := strings.TrimSpace(h.Detail); d != "" {
		out += ". " + d
	}
	return out
}

// gatedReader is the scheduler's reader: checks of a project whose locks do
// not serve are skipped instead of failing.
type gatedReader struct{ s *Service }

func (g gatedReader) SQL(ctx context.Context, p *model.Project, query string) ([]model.Row, error) {
	if !g.s.locksServing(p) {
		return nil, errLocksDown
	}
	return g.s.o.Reader.SQL(ctx, p, query)
}

func (g gatedReader) LogCount(ctx context.Context, p *model.Project, query string, window time.Duration) (int, error) {
	if !g.s.locksServing(p) {
		return 0, errLocksDown
	}
	return g.s.o.Reader.LogCount(ctx, p, query, window)
}

// ---------- alerts ----------

// sendAlert owes one alert: it is scrubbed, stripped of control characters
// and stored in the outbox, from where it is delivered and retried until it
// went out. Nothing is recorded as sent before it is.
func (s *Service) sendAlert(p *model.Project, a model.Alert) {
	a = s.cleanAlert(p, a)
	if _, err := s.st.EnqueueAlert(a); err != nil {
		s.log.Error("alert not stored", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident, "error", err)
		return
	}
	s.kickOutbox(store.EffectAlert)
}

func (s *Service) cleanAlert(p *model.Project, a model.Alert) model.Alert {
	a.Title, a.Body = model.CleanLine(s.scrub(a.Title)), model.CleanText(s.scrub(a.Body))
	if a.At.IsZero() {
		a.At = s.now()
	}
	if p != nil && a.Project == "" {
		a.Project = p.Slug
	}
	return a
}

// systemAlert owes an alert that concerns DutyDesk itself: to the project
// it names, else to every project (one per distinct alert channel).
func (s *Service) systemAlert(a model.Alert) {
	if p := s.Project(a.Project); p != nil {
		s.sendAlert(p, a)
		return
	}
	seen := map[string]bool{}
	for _, p := range s.cfg.Load().Projects {
		if seen[p.Alerts.WebhookURLFile] {
			continue
		}
		seen[p.Alerts.WebhookURLFile] = true
		one := a
		s.sendAlert(p, one)
	}
}

// alertOnce owes a system alert at most once per period for a key.
func (s *Service) alertOnce(key string, every time.Duration, a model.Alert) {
	now := s.now()
	s.mu.Lock()
	last, ok := s.onceAlerts[key]
	if ok && now.Sub(last) < every {
		s.mu.Unlock()
		return
	}
	s.onceAlerts[key] = now
	s.mu.Unlock()
	s.systemAlert(a)
}

// subject is how an alert title names an incident. The summary of a webhook
// incident is built from what a third party sent: its alert titles only
// carry the source and the fingerprint (source + issue id for Sentry).
func subject(p *model.Project, inc model.Incident) string {
	if p != nil {
		if _, ok := p.Webhooks[inc.Source]; ok && !inc.Mass {
			return short(model.CleanLine(inc.Source+" "+inc.Fingerprint), 100)
		}
	}
	return short(model.CleanLine(inc.Summary), 160)
}

// withdraw withdraws a pending ticket at the hub, best effort.
func (s *Service) withdraw(ctx context.Context, p *model.Project, ticket string) {
	if ticket == "" || p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.o.Status.Withdraw(ctx, p.Locks.Workspace, ticket); err != nil {
		s.log.Warn("ticket not withdrawn", "project", p.Slug, "ticket", ticket, "error", err)
	}
}
