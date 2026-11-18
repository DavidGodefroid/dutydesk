package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/forge"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/notify"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// MRLabel is set on every merge request DutyDesk opens.
const MRLabel = "dutydesk"

var (
	errSecretInText error = permanent{errors.New("a secret was found in the text of the proposal; nothing was pushed")}
	errNoConfigRepo error = permanent{errors.New("no configuration repository is connected (config_remote): the proposal is only described in the verdict")}
)

// ---------- outbox ----------

// kickOutbox wakes the drain of one kind of effect.
func (s *Service) kickOutbox(kind string) {
	select {
	case s.outKick[kind] <- struct{}{}:
	default:
	}
}

// drain delivers the owed effects of one kind, oldest first, until ctx is
// cancelled. It starts with what a previous run of the daemon left: the
// outbox is the only memory of what is owed.
func (s *Service) drain(ctx context.Context, kind string, handle func(context.Context, store.Effect)) {
	ticker := time.NewTicker(s.o.Tick)
	defer ticker.Stop()
	for ctx.Err() == nil {
		due, err := s.st.DueEffects(kind, 50)
		if err != nil && ctx.Err() == nil {
			s.log.Error("outbox not read", "kind", kind, "error", err)
		}
		for _, e := range due {
			if ctx.Err() != nil {
				return
			}
			// An effect that started is not cut by a shutdown in the
			// middle (a push, an alert); each step has its own timeout.
			handle(context.WithoutCancel(ctx), e)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		case <-s.outKick[kind]:
		}
	}
}

func (s *Service) backoff(attempts int) time.Duration {
	b := s.o.OutboxBackoff
	if attempts >= len(b) {
		attempts = len(b) - 1
	}
	return b[attempts]
}

func (s *Service) retryEffect(e store.Effect, why string) {
	why = short(s.scrub(why), 300)
	if err := s.st.RetryEffect(e.ID, s.now().Add(s.backoff(e.Attempts)), why); err != nil {
		s.log.Error("effect retry not saved", "effect", e.ID, "error", err)
	}
}

func (s *Service) finishEffect(e store.Effect, state, note string, fn func(*store.EffectTx) error) bool {
	if err := s.st.FinishEffect(e.ID, state, note, fn); err != nil {
		s.log.Error("effect not finished", "effect", e.ID, "kind", e.Kind, "error", err)
		return false
	}
	return true
}

// deliverAlert sends one owed alert, with its own timeout. It is marked
// done, recorded, and the incident's last-alert time moved, only when the
// notifier accepted it; otherwise it stays owed and is retried with a
// backoff, for as long as it takes.
func (s *Service) deliverAlert(ctx context.Context, e store.Effect) {
	var a model.Alert
	if err := json.Unmarshal([]byte(e.Payload), &a); err != nil {
		s.finishEffect(e, "dropped", "unreadable alert", nil)
		return
	}
	p := s.Project(e.Project)
	if p == nil {
		s.log.Warn("alert dropped: its project left the configuration", "kind", string(a.Kind), "project", e.Project, "incident", a.Incident)
		s.finishEffect(e, "dropped", "project not configured", nil)
		return
	}
	sctx, cancel := context.WithTimeout(ctx, s.o.AlertTimeout)
	err := s.o.Notifier.Send(sctx, p, a)
	cancel()
	if errors.Is(err, notify.ErrNoWebhook) {
		s.log.Warn("alert not sent: the project has no alert webhook", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident, "title", a.Title)
		s.finishEffect(e, "dropped", "no alert webhook configured", nil)
		return
	}
	if err != nil {
		s.log.Error("alert not delivered; it will be retried", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident,
			"attempt", e.Attempts+1, "error", s.scrub(err.Error()))
		s.retryEffect(e, err.Error())
		return
	}
	a.At = s.now() // recorded at the time it reached a human
	if err := s.st.AlertDelivered(e.ID, a); err != nil {
		s.log.Error("alert not recorded", "kind", string(a.Kind), "error", err)
		return
	}
	s.log.Info("alert", "kind", string(a.Kind), "project", a.Project, "incident", a.Incident, "title", a.Title)
}

func (s *Service) alertIncident(p *model.Project, inc model.Incident, kind model.AlertKind, title, body, url string) {
	s.sendAlert(p, s.incidentAlert(inc, kind, title, body, url))
}

func (s *Service) incidentAlert(inc model.Incident, kind model.AlertKind, title, body, url string) model.Alert {
	return model.Alert{Kind: kind, Project: inc.Project, Incident: inc.ID, Title: title, Body: body, URL: url}
}

// progress is what an owed transition already did; it is saved after each
// step so that a retry or a restart does not do it twice.
type progress struct {
	Withdrawn bool      `json:"withdrawn,omitempty"`
	MR        *stepDone `json:"mr,omitempty"`
	Config    *stepDone `json:"config,omitempty"`
}

// stepDone is the outcome of a merge-request step.
type stepDone struct {
	URL     string `json:"url,omitempty"`
	Title   string `json:"title,omitempty"`
	Draft   bool   `json:"draft,omitempty"`
	Opened  bool   `json:"opened,omitempty"`  // a merge request was opened by this effect
	Refused string `json:"refused,omitempty"` // why nothing was proposed
}

func decodeOwed(e store.Effect) (incident.Owed, passContext, error) {
	var o incident.Owed
	var pc passContext
	if err := json.Unmarshal([]byte(e.Payload), &o); err != nil {
		return o, pc, err
	}
	if len(o.Context) > 0 {
		if err := json.Unmarshal(o.Context, &pc); err != nil {
			return o, pc, err
		}
	}
	return o, pc, nil
}

// permanent marks a proposal error that no retry can fix.
type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// maxProposalAttempts is how often a merge request that fails for a reason
// that may pass (forge unreachable, API error) is tried before it is given
// up and reported like a refusal.
const maxProposalAttempts = 5

// runEffect executes what a lifecycle transition owes: the withdrawal of a
// ticket, merge requests, the known problem, alerts and notices. Every step
// is idempotent and recorded: a crash or a failure resumes where it stopped.
// DutyDesk never merges anything.
func (s *Service) runEffect(ctx context.Context, e store.Effect) {
	o, pc, err := decodeOwed(e)
	if err != nil {
		s.finishEffect(e, "dropped", "unreadable payload", nil)
		return
	}
	var pr progress
	if e.Progress != "" {
		_ = json.Unmarshal([]byte(e.Progress), &pr)
	}
	save := func(fn func(*store.EffectTx) error) bool {
		b, _ := json.Marshal(pr)
		if err := s.st.SaveProgress(e.ID, string(b), fn); err != nil {
			s.log.Error("effect progress not saved", "effect", e.ID, "error", err)
			return false
		}
		return true
	}
	done := func(state, note string, alerts []model.Alert) {
		ok := s.finishEffect(e, state, note, func(tx *store.EffectTx) error {
			for _, a := range alerts {
				ae, err := store.AlertEffect(a)
				if err != nil {
					return err
				}
				if err := tx.Enqueue(ae); err != nil {
					return err
				}
			}
			return nil
		})
		if ok {
			s.removeWork(pc.WorkDir)
			if len(alerts) > 0 {
				s.kickOutbox(store.EffectAlert)
			}
		}
	}
	inc, err := s.st.GetIncident(e.Incident)
	if errors.Is(err, store.ErrNotFound) {
		done("dropped", "incident not found", nil)
		return
	}
	if err != nil {
		s.retryEffect(e, err.Error())
		return
	}
	p := s.Project(inc.Project)
	if p == nil {
		s.log.Warn("owed effects dropped: the project left the configuration", "incident", inc.ID, "project", inc.Project)
		done("dropped", "project not configured", nil)
		return
	}

	// 0. A ticket the incident no longer follows: withdrawn at the hub,
	// best effort, once.
	if o.WithdrawTicket != "" && !pr.Withdrawn {
		s.withdraw(ctx, p, o.WithdrawTicket)
		pr.Withdrawn = true
		if !save(nil) {
			return
		}
	}
	if o.Event != incident.EventVerdict || o.Verdict == nil {
		var alerts []model.Alert
		if a, ok := s.eventAlert(p, inc, o); ok {
			alerts = append(alerts, s.cleanAlert(p, a))
		}
		done("done", "", alerts)
		return
	}
	v := *o.Verdict
	ectx, cancel := context.WithTimeout(ctx, s.o.EffectTimeout)
	defer cancel()
	s.restoreBases(pc)

	// 1. Fix proposed on a project repository.
	if v.MR != nil && pr.MR == nil {
		step, kp, err := s.projectMR(ectx, p, inc, v, pc)
		if err != nil {
			if e.Attempts+1 < maxProposalAttempts {
				s.log.Warn("merge request not opened yet; it will be retried", "incident", inc.ID, "attempt", e.Attempts+1, "error", s.scrub(err.Error()))
				s.retryEffect(e, err.Error())
				return
			}
			step = &stepDone{Refused: "the forge could not be used after several attempts: " + refusalText(err)}
		}
		pr.MR = step
		if !save(func(tx *store.EffectTx) error {
			if kp == nil {
				return nil
			}
			return tx.OpenKnownProblem(*kp)
		}) {
			return
		}
		switch {
		case step.Opened:
			s.journal(inc.ID, "merge request opened", "A "+mrKind(step.Draft)+" was opened: "+step.URL+". DutyDesk never merges: a human reviews it.")
		case step.Refused != "":
			s.log.Warn("merge request not opened", "incident", inc.ID, "reason", s.scrub(step.Refused))
			s.journal(inc.ID, "merge request not opened", step.Refused)
		default:
			s.journal(inc.ID, "merge request", "A fix is already proposed for this incident family ("+step.URL+"): no second merge request is opened.")
		}
	}
	refusedMR := pr.MR != nil && pr.MR.Refused != ""
	if refusedMR && (o.To == model.StateResolved || o.To == model.StateMROpen) {
		// The verdict counted on a fix that did not go out: a human takes
		// over, with the reason.
		s.escalateRefused(inc.ID, "the fix could not be proposed: "+pr.MR.Refused)
	}

	// 2. Proposal on the configuration repository.
	if (v.MissingAction != nil || v.Improvement != nil) && pr.Config == nil {
		step, prop, err := s.configMR(ectx, p, inc, v, pc)
		if err != nil {
			if e.Attempts+1 < maxProposalAttempts {
				s.log.Warn("configuration proposal not opened yet; it will be retried", "incident", inc.ID, "attempt", e.Attempts+1, "error", s.scrub(err.Error()))
				s.retryEffect(e, err.Error())
				return
			}
			step = &stepDone{Refused: "the forge could not be used after several attempts: " + refusalText(err)}
		}
		pr.Config = step
		if !save(func(tx *store.EffectTx) error {
			if prop == nil {
				return nil
			}
			return tx.RecordProposal(*prop)
		}) {
			return
		}
		switch {
		case step.Opened:
			s.journal(inc.ID, "configuration merge request opened", "A merge request on the configuration repository was opened: "+
				step.URL+". It changes nothing until a human merges it"+
				ifStr(v.MissingAction != nil, " and validates the new lockssh rule in lox")+".")
		case step.Refused != "":
			s.log.Warn("configuration proposal not opened", "incident", inc.ID, "reason", s.scrub(step.Refused))
			s.journal(inc.ID, "configuration proposal not opened", step.Refused)
		default:
			s.journal(inc.ID, "configuration proposal", "An improvement is already proposed for this incident family ("+step.URL+
				") and waits for review: no second merge request is opened.")
		}
	}

	// 3. What a human must know now.
	done("done", "", s.verdictAlerts(p, inc, o, v, pr))
}

func mrKind(draft bool) string {
	if draft {
		return "draft merge request"
	}
	return "merge request"
}

// restoreBases gives the forge back the base commits of the clones of a
// pass that ran before a restart. They come from the outbox row the core
// wrote when the verdict was applied, never from the clones.
func (s *Service) restoreBases(pc passContext) {
	bk, ok := s.forge.(baseKeeper)
	if !ok {
		return
	}
	for dir, rev := range pc.Bases {
		if _, known := bk.BaseOf(dir); !known {
			if err := bk.RestoreBase(dir, rev); err != nil {
				s.log.Warn("base of a clone not restored", "dir", dir, "error", err)
			}
		}
	}
}

// projectMR is step 1: nil error with a stepDone means the step is settled
// (opened, already known, or refused for good); an error means try again.
func (s *Service) projectMR(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, pc passContext) (*stepDone, *model.KnownProblem, error) {
	known, err := s.st.FindOpenKnownProblem(p.Slug, inc.Family)
	if err != nil {
		return nil, nil, err
	}
	if known != nil {
		return &stepDone{URL: known.MRURL}, nil, nil
	}
	info, draft, err := s.proposeFix(ctx, p, inc, v, pc)
	if err != nil {
		if final(err) {
			return &stepDone{Refused: refusalText(err)}, nil, nil
		}
		return nil, nil, err
	}
	return &stepDone{URL: info.URL, Title: v.MR.Title, Draft: draft, Opened: true},
		&model.KnownProblem{Project: p.Slug, Family: inc.Family, Repo: info.repo, MRURL: info.URL, MRID: info.ID, Incident: inc.ID}, nil
}

// configMR is step 2, with the same contract as projectMR.
func (s *Service) configMR(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, pc passContext) (*stepDone, *store.Proposal, error) {
	if v.MissingAction == nil {
		// Improvement only: one open merge request per project and family
		// is enough; an agent that proposes the same idea at every pass
		// does not flood the reviewers.
		open, err := s.st.FindOpenImprovement(p.Slug, inc.Family)
		if err != nil {
			return nil, nil, err
		}
		if open != nil {
			return &stepDone{URL: open.MRURL}, nil, nil
		}
	}
	info, title, err := s.proposeConfig(ctx, p, inc, v, pc)
	if err != nil {
		if final(err) {
			return &stepDone{Refused: refusalText(err)}, nil, nil
		}
		return nil, nil, err
	}
	kind := store.ProposalImprovement
	if v.MissingAction != nil {
		kind = store.ProposalMissingAction
	}
	return &stepDone{URL: info.URL, Title: title, Opened: true},
		&store.Proposal{Project: p.Slug, Incident: inc.ID, Kind: kind, Family: inc.Family, Title: title, MRURL: info.URL, MRID: info.ID}, nil
}

// final reports whether a proposal error is a decision (a refusal of the
// forge checks or of the core) rather than a failure that may pass.
func final(err error) bool {
	var r *forge.Refusal
	var perm permanent
	return errors.As(err, &r) || errors.As(err, &perm)
}

// escalateRefused moves an incident whose fix was refused to escalated.
// The incident may have moved since (a human closed it): then nothing.
func (s *Service) escalateRefused(id, reason string) {
	var from model.IncidentState
	_, err := s.st.UpdateIncident(id, []model.IncidentState{model.StateResolved, model.StateMROpen},
		func(i *model.Incident) error {
			if i.State == model.StateResolved && i.CloseReason != incident.ReasonResolvedByAgent {
				return store.ErrStateConflict // closed by a human or its source meanwhile
			}
			from = i.State
			i.State, i.CloseReason, i.RecheckAt = model.StateEscalated, "", time.Time{}
			return nil
		})
	if err != nil {
		if !errors.Is(err, store.ErrStateConflict) {
			s.log.Error("incident not escalated", "incident", id, "error", err)
		}
		return
	}
	s.journal(id, "escalated", fmt.Sprintf("State: %s → escalated (%s).", from, reason))
}

// eventAlert is the alert of a transition that is not a verdict.
func (s *Service) eventAlert(p *model.Project, inc model.Incident, o incident.Owed) (model.Alert, bool) {
	what := subject(p, inc)
	switch {
	case o.Alert == model.AlertStorm:
		return s.incidentAlert(inc, model.AlertStorm, "Storm on "+inc.Source+": new signals are grouped",
			inc.Summary+"\nDutyDesk stopped opening one incident per signal for this source and runs no agent on the grouped ones. "+
				"Look for the common cause; close the mass incident when it is over (dutydesk incident close "+inc.ID+").", ""), true
	case o.Alert != model.AlertEscalated:
		return model.Alert{}, false
	case o.Event == incident.EventRunFailed:
		return s.incidentAlert(inc, model.AlertEscalated, "Escalated without a diagnosis: "+what,
			"The agent passes failed ("+o.Reason+"). Last error: "+orDash(o.Detail)+
				"\nA human must take over; `dutydesk incident show "+inc.ID+"` has the journal.", ""), true
	case o.Event == incident.EventGreenLight:
		return s.incidentAlert(inc, model.AlertEscalated, "Escalated: "+what,
			"The sensitive action the agent asked for did not get a green light ("+o.Reason+
				"). Nothing was run. A human must take over; `dutydesk incident show "+inc.ID+"` has the diagnosis.", ""), true
	case o.Event == incident.EventRecurrence:
		return s.incidentAlert(inc, model.AlertEscalated, "Escalated, keeps coming back: "+what,
			inc.Summary+"\n"+o.Reason+".\nNo agent was started for this one. `dutydesk incident resume "+inc.ID+
				"` starts a pass anyway; `dutydesk incident close "+inc.ID+"` closes it.", ""), true
	default:
		return s.incidentAlert(inc, model.AlertEscalated, "Escalated: "+what,
			inc.Summary+"\nWhy escalated: "+o.Reason+".\nA human must take over; `dutydesk incident show "+inc.ID+"` has the journal.", ""), true
	}
}

// verdictAlerts builds the notices and the alert a verdict owes, once its
// merge requests are settled.
func (s *Service) verdictAlerts(p *model.Project, inc model.Incident, o incident.Owed, v model.Verdict, pr progress) []model.Alert {
	var out []model.Alert
	add := func(kind model.AlertKind, title, body, url string) {
		out = append(out, s.cleanAlert(p, s.incidentAlert(inc, kind, title, body, url)))
	}
	what := subject(p, inc)
	var mrURL, cfgURL, note string
	refusedFix := false
	if st := pr.MR; st != nil {
		mrURL = st.URL
		switch {
		case st.Opened:
			add(model.NoticeMROpened, "Fix proposed: "+v.MR.Title,
				"A "+mrKind(st.Draft)+" was opened for "+inc.ID+" ("+what+"). Root cause: "+orDash(v.RootCause)+
					"\nNothing is merged by DutyDesk: review it.", st.URL)
		case st.Refused != "" && (o.To == model.StateResolved || o.To == model.StateMROpen):
			refusedFix = true
		case st.Refused != "":
			note = "The fix the agent prepared could not be proposed: " + st.Refused
		}
	}
	if st := pr.Config; st != nil {
		switch {
		case st.Opened:
			cfgURL = st.URL
			add(model.NoticeConfigMR, "Configuration change proposed: "+st.Title,
				"From "+inc.ID+". Review the merge request on the configuration repository.", st.URL)
		case st.Refused != "":
			note = strings.TrimSpace(note + "\nThe configuration change the agent prepared could not be proposed: " + st.Refused)
		}
	}
	diag := diagnosis(v)
	if note != "" {
		diag += "\n" + note
	}
	switch {
	case refusedFix:
		add(model.AlertEscalated, "Escalated: "+what,
			diag+"\nWhy escalated: the fix could not be proposed: "+pr.MR.Refused+".\nA human must take over.", "")
	case o.To == model.StateMROpen:
		// Production is still affected: a notice is not enough.
		add(model.AlertEscalated, "Production still affected, fix proposed: "+what,
			diag+"\nDutyDesk could not unblock production; the fix waits for review in the merge request. A human must take over.", mrURL)
	case o.Alert == model.AlertEscalated:
		add(model.AlertEscalated, "Escalated: "+what, diag+"\nWhy escalated: "+o.Reason+".\nA human must take over.", mrURL)
	case o.Alert == model.AlertBlocked:
		name, why := "", ""
		if m := v.MissingAction; m != nil {
			name, why = m.Name, m.Why
		}
		body := diag + "\nMissing action: " + orDash(name) + ". " + why + "\nUnblock production by hand."
		if cfgURL != "" {
			body += " Then review the configuration merge request and validate the new lockssh rule in lox: the action exists only after both."
		}
		add(model.AlertBlocked, "Blocked, an action is missing: "+what, body, cfgURL)
	case o.Alert == model.AlertGreenLight:
		add(model.AlertGreenLight, "Green light needed: "+what,
			diag+"\nTicket "+inc.Ticket+" waits for a decision. Without one within "+p.Limits.GreenLightTimeout.String()+
				", DutyDesk withdraws the ticket and escalates.", "")
	}
	return out
}

type proposed struct {
	model.MRInfo
	repo string
}

// proposeFix pushes the agent's edits of a project clone on a dutydesk/
// branch and opens the merge request: draft unless the confidence is high.
func (s *Service) proposeFix(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, pc passContext) (proposed, bool, error) {
	if pc.TaintMR {
		return proposed{}, false, errSecretInText
	}
	mr := v.MR
	var repo *model.Repo
	for i := range p.Repos {
		if p.Repos[i].Name == mr.Repo {
			repo = &p.Repos[i]
		}
	}
	if repo == nil && len(p.Repos) == 1 && strings.TrimSpace(mr.Repo) == "" {
		repo = &p.Repos[0]
	}
	if repo == nil {
		return proposed{}, false, permanent{fmt.Errorf("the verdict names repository %q, which is not a repository of project %s", short(model.CleanLine(mr.Repo), 60), p.Slug)}
	}
	dir, ok := pc.RepoDirs[repo.Name]
	if !ok {
		return proposed{}, false, permanent{fmt.Errorf("repository %s was not mounted for this pass", repo.Name)}
	}
	draft := v.Confidence != "high"
	desc := strings.TrimSpace(mr.Description) + "\n\n---\n" +
		"Opened by DutyDesk for incident " + inc.ID + " (project " + p.Slug + ", source `" + inc.Source + "`).\n\n" +
		"**Root cause:** " + orDash(v.RootCause) + "\n\n" +
		"**Confidence:** " + orDash(v.Confidence) + ifStr(draft, " (draft: the confidence is not high)") + "\n\n" +
		"DutyDesk never merges: review, then merge or close.\n"
	info, err := s.propose(ctx, *repo, dir, inc.ID, mr.Title, desc, draft, pc.Run)
	return proposed{MRInfo: info, repo: repo.Name}, draft, err
}

// proposeConfig opens a merge request on the configuration repository from
// the throwaway clone the agent edited. The path policy only lets through
// checks, runbooks and actions of the incident's project.
func (s *Service) proposeConfig(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, pc passContext) (model.MRInfo, string, error) {
	repo, ok := s.configRepo(p.Slug)
	if !ok || pc.ConfigDir == "" {
		return model.MRInfo{}, "", errNoConfigRepo
	}
	if pc.TaintConfig {
		return model.MRInfo{}, "", errSecretInText
	}
	var title string
	var b strings.Builder
	if m := v.MissingAction; m != nil {
		if title = strings.TrimSpace(m.Title); title == "" {
			title = "Add action " + m.Name
		}
		fmt.Fprintf(&b, "## Missing action: `%s`\n\n**Why it is needed:** %s\n\n%s\n\n", m.Name, orDash(m.Why), strings.TrimSpace(m.Detail))
		b.WriteString("Merging this adds the script to the catalogue; the action can run only after a human also validates the proposed lockssh rule in lox (`dutydesk config lockssh-rules`).\n\n")
	}
	if m := v.Improvement; m != nil {
		if title == "" {
			if title = strings.TrimSpace(m.Title); title == "" {
				title = "Improve the configuration of " + p.Slug
			}
		}
		fmt.Fprintf(&b, "## Improvement: %s\n\n**Observed:** %s\n\n**Change:** %s\n\n**Expected effect:** %s\n\n**Risk:** %s\n\n",
			orDash(m.Title), orDash(m.Observation), orDash(m.Change), orDash(m.Effect), orDash(m.Risk))
	}
	b.WriteString("---\nProposed by DutyDesk from incident " + inc.ID + " (project " + p.Slug + ", source `" + inc.Source + "`). " +
		"DutyDesk never merges and never changes a lock policy.\n")
	info, err := s.propose(ctx, repo, pc.ConfigDir, inc.ID, title, b.String(), v.Confidence != "high", pc.Run)
	return info, title, err
}

// propose pushes and opens a merge request under a branch name that is a
// function of the incident, the title and, when that name is taken by an
// earlier pass, the pass number. The name is the identity of the effect:
// the forge recognises a branch it already pushed with the same tree (a
// previous attempt of this very effect) and an open merge request for it,
// instead of making a second one.
func (s *Service) propose(ctx context.Context, repo model.Repo, dir, incidentID, title, desc string, draft bool, run int) (model.MRInfo, error) {
	title = model.CleanLine(title)
	info, err := s.forge.Propose(ctx, repo, dir, forge.BranchName(incidentID, title), title, desc, draft, []string{MRLabel})
	if errors.Is(err, forge.ErrBranchExists) {
		// An earlier pass of this incident already used the name, with
		// other content.
		info, err = s.forge.Propose(ctx, repo, dir, forge.BranchName(incidentID, fmt.Sprintf("p%d %s", run, title)), title, desc, draft, []string{MRLabel})
	}
	return info, err
}

// refusalText explains why a proposal did not go out, for the journal and
// the alert. It never quotes a secret: forge refusals name paths and rules.
func refusalText(err error) string {
	var r *forge.Refusal
	if !errors.As(err, &r) {
		return short(strings.Join(strings.Fields(err.Error()), " "), 400)
	}
	details := short(strings.Join(r.Details, ", "), 300)
	var text string
	switch {
	case errors.Is(err, forge.ErrNoChange):
		return "the agent described a change but modified no file"
	case errors.Is(err, forge.ErrSecretFound):
		text = "a secret was found in the change; nothing was pushed"
	case errors.Is(err, forge.ErrForbiddenPath):
		text = "the change touches a forbidden path; nothing was pushed"
	case errors.Is(err, forge.ErrTooLarge):
		text = "the change is too large; nothing was pushed"
	case errors.Is(err, forge.ErrUnknownBase):
		text = "the commit the clone was made from is not known to the core; nothing was pushed"
	case errors.Is(err, forge.ErrBranchExists):
		text = "a branch of that name already exists with other content; nothing was pushed"
	default:
		text = strings.TrimPrefix(r.Reason.Error(), "forge: ") + "; nothing was pushed"
	}
	if details != "" {
		text += " (" + details + ")"
	}
	return text
}

func diagnosis(v model.Verdict) string {
	out := strings.TrimSpace(v.Summary)
	if rc := strings.TrimSpace(v.RootCause); rc != "" {
		out += "\nRoot cause: " + rc
	}
	if len(v.ActionsRun) > 0 {
		out += "\nActions run: " + strings.Join(v.ActionsRun, "; ")
	}
	return out
}

func orDash(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return "not established"
	}
	return s
}

func ifStr(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}
