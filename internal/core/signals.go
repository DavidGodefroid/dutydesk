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
)

// Ingest turns one signal into incident state with the rules of its project:
// family from the fingerprint template of its source, runbook from the
// configuration. It is shared by the daemon and by `dutydesk check run`.
func Ingest(mgr *incident.Manager, p *model.Project, sig model.Signal) (incident.IngestResult, error) {
	if p == nil {
		return incident.IngestResult{}, errors.New("core: signal for an unknown project")
	}
	sig.Project = p.Slug
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
	}
	if res.Alert == model.AlertStorm {
		s.alertIncident(s.effectCtx(), p, res.Incident, model.AlertStorm,
			"Storm on "+sig.Source+": new signals are grouped",
			res.Incident.Summary+"\nDutyDesk stopped opening one incident per signal for this source and runs no agent on the grouped ones. "+
				"Look for the common cause; close the mass incident when it is over (dutydesk incident close "+res.Incident.ID+").", "")
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
			s.alertOnce(s.effectCtx(), "check-failing:"+c.Project+"/"+c.ID, time.Hour, model.Alert{
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
func (s *Service) sourceResolved(project, source, fingerprint string) {
	inc, err := s.st.FindOpenIncident(project, fingerprint)
	if err != nil || inc == nil {
		return
	}
	tr, err := s.mgr.Close(inc.ID, "resolved at the source ("+source+")")
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		s.log.Warn("incident not closed on a resolved webhook", "incident", inc.ID, "error", err)
		return
	}
	s.cancelPass(inc.ID)
	s.withdraw(s.effectCtx(), s.Project(project), tr.WithdrawTicket)
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

// pollLocks reads lox live's health per workspace. While a workspace does
// not serve, nothing starts for its projects; a human is alerted once, with
// what needs enrolment or a secret.
func (s *Service) pollLocks(ctx context.Context) {
	for ws, projects := range s.workspaces() {
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
		if serving {
			g.alerted = false
		} else {
			g.alerted = true
		}
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
				s.sendAlert(ctx, p, model.Alert{Kind: model.AlertLocksDown, Project: p.Slug,
					Title: "The locks do not serve: DutyDesk is blind and starts no agent",
					Body: detail + "\nChecks are skipped and incidents wait in the queue until the locks serve again. " +
						"On the lock host: check `lox live status`; a lock that needs enrolment or a secret needs a human at a terminal."})
			}
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

// effectCtx is the context of side effects that must not be cut by a
// shutdown in the middle (an alert, a push); callers bound it.
func (s *Service) effectCtx() context.Context {
	s.mu.Lock()
	ctx := s.runCtx
	s.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

// sendAlert scrubs, sends and records one alert. A send failure is logged:
// the alert is recorded all the same, so the report shows it.
func (s *Service) sendAlert(ctx context.Context, p *model.Project, a model.Alert) {
	a.Title, a.Body = s.scrub(a.Title), s.scrub(a.Body)
	if a.At.IsZero() {
		a.At = s.now()
	}
	if p != nil && a.Project == "" {
		a.Project = p.Slug
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := s.o.Notifier.Send(ctx, p, a); err != nil {
		s.log.Error("alert not delivered", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident, "error", err)
	}
	if _, err := s.st.RecordAlert(a); err != nil {
		s.log.Error("alert not recorded", "kind", string(a.Kind), "error", err)
	}
	s.log.Info("alert", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident, "title", a.Title)
}

func (s *Service) alertIncident(ctx context.Context, p *model.Project, inc model.Incident, kind model.AlertKind, title, body, url string) {
	s.sendAlert(ctx, p, model.Alert{Kind: kind, Project: inc.Project, Incident: inc.ID, Title: title, Body: body, URL: url})
}

// systemAlert sends an alert that concerns DutyDesk itself: to the project
// it names, else to every project (one per distinct alert channel).
func (s *Service) systemAlert(ctx context.Context, a model.Alert) {
	if p := s.Project(a.Project); p != nil {
		s.sendAlert(ctx, p, a)
		return
	}
	seen := map[string]bool{}
	for _, p := range s.cfg.Load().Projects {
		if seen[p.Alerts.WebhookURLFile] {
			continue
		}
		seen[p.Alerts.WebhookURLFile] = true
		one := a
		s.sendAlert(ctx, p, one)
	}
}

// alertOnce sends a system alert at most once per period for a key.
func (s *Service) alertOnce(ctx context.Context, key string, every time.Duration, a model.Alert) {
	now := s.now()
	s.mu.Lock()
	last, ok := s.onceAlerts[key]
	if ok && now.Sub(last) < every {
		s.mu.Unlock()
		return
	}
	s.onceAlerts[key] = now
	s.mu.Unlock()
	s.systemAlert(ctx, a)
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
