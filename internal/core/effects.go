package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/forge"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// MRLabel is set on every merge request DutyDesk opens.
const MRLabel = "dutydesk"

var (
	errSecretInText = errors.New("a secret was found in the text of the proposal; nothing was pushed")
	errNoConfigRepo = errors.New("no configuration repository is connected (config_remote): the proposal is only described in the verdict")
)

// effects executes what a verdict's transition owes: merge requests, known
// problems, proposals on the configuration repository, alerts and notices.
// DutyDesk never merges anything.
func (s *Service) effects(ctx context.Context, p *model.Project, tr incident.Transition, v model.Verdict, req model.RunRequest, t taint) {
	inc := tr.Incident
	var mrURL, note string

	// 1. Fix proposed on a project repository.
	if tr.OpenMR != nil {
		known, _ := s.st.FindOpenKnownProblem(p.Slug, inc.Family)
		switch {
		case known != nil:
			mrURL = known.MRURL
			s.journal(inc.ID, "merge request", "A fix is already proposed for this incident family ("+known.MRURL+
				", from "+known.Incident+"): no second merge request is opened.")
		default:
			info, draft, err := s.proposeFix(ctx, p, inc, v, req, t.mr)
			if err != nil {
				reason := refusalText(err)
				s.log.Warn("merge request not opened", "incident", inc.ID, "reason", s.scrub(reason))
				s.journal(inc.ID, "merge request not opened", reason)
				if inc.State == model.StateResolved || inc.State == model.StateMROpen {
					s.escalate(ctx, p, &inc, "the fix could not be proposed: "+reason, v)
					tr.Alert = "" // the escalation above is the alert
				} else {
					note = "The fix the agent prepared could not be proposed: " + reason
				}
				break
			}
			mrURL = info.URL
			kind := "merge request"
			if draft {
				kind = "draft merge request"
			}
			s.journal(inc.ID, "merge request opened", "A "+kind+" was opened: "+info.URL+". DutyDesk never merges: a human reviews it.")
			if _, err := s.st.OpenKnownProblem(model.KnownProblem{Project: p.Slug, Family: inc.Family, Repo: info.repo,
				MRURL: info.URL, MRID: info.ID, Incident: inc.ID}); err != nil {
				s.log.Error("known problem not recorded", "incident", inc.ID, "error", err)
			}
			s.alertIncident(ctx, p, inc, model.NoticeMROpened, "Fix proposed: "+v.MR.Title,
				"A "+kind+" was opened for "+inc.ID+" ("+inc.Summary+"). Root cause: "+orDash(v.RootCause)+
					"\nNothing is merged by DutyDesk: review it.", info.URL)
		}
	}

	// 2. Proposal on the configuration repository.
	cfgURL := ""
	if tr.MissingAction != nil || tr.Improvement != nil {
		info, title, err := s.proposeConfig(ctx, p, inc, v, req, t.config)
		if err != nil {
			reason := refusalText(err)
			s.log.Warn("configuration proposal not opened", "incident", inc.ID, "reason", s.scrub(reason))
			s.journal(inc.ID, "configuration proposal not opened", reason)
			note = strings.TrimSpace(note + "\nThe configuration change the agent prepared could not be proposed: " + reason)
		} else {
			cfgURL = info.URL
			kind := store.ProposalImprovement
			if tr.MissingAction != nil {
				kind = store.ProposalMissingAction
			}
			if _, err := s.st.RecordProposal(store.Proposal{Project: p.Slug, Incident: inc.ID, Kind: kind, Title: title,
				MRURL: info.URL, MRID: info.ID}); err != nil {
				s.log.Error("proposal not recorded", "incident", inc.ID, "error", err)
			}
			s.journal(inc.ID, "configuration merge request opened", "A merge request on the configuration repository was opened: "+
				info.URL+". It changes nothing until a human merges it"+
				ifStr(tr.MissingAction != nil, " and validates the new lockssh rule in lox")+".")
			s.alertIncident(ctx, p, inc, model.NoticeConfigMR, "Configuration change proposed: "+title,
				"From "+inc.ID+". Review the merge request on the configuration repository.", info.URL)
		}
	}

	// 3. What a human must know now.
	diag := diagnosis(v)
	if note != "" {
		diag += "\n" + note
	}
	switch {
	case tr.Alert == model.AlertEscalated:
		s.alertIncident(ctx, p, inc, model.AlertEscalated, "Escalated: "+inc.Summary,
			diag+"\nWhy escalated: "+tr.Reason+".\nA human must take over.", mrURL)
	case inc.State == model.StateMROpen:
		// Production is still affected: a notice is not enough.
		s.alertIncident(ctx, p, inc, model.AlertEscalated, "Production still affected, fix proposed: "+inc.Summary,
			diag+"\nDutyDesk could not unblock production; the fix waits for review in the merge request. A human must take over.", mrURL)
	case tr.Alert == model.AlertBlocked:
		name, why := "", ""
		if m := tr.MissingAction; m != nil {
			name, why = m.Name, m.Why
		}
		body := diag + "\nMissing action: " + orDash(name) + ". " + why + "\nUnblock production by hand."
		if cfgURL != "" {
			body += " Then review the configuration merge request and validate the new lockssh rule in lox: the action exists only after both."
		}
		s.alertIncident(ctx, p, inc, model.AlertBlocked, "Blocked, an action is missing: "+inc.Summary, body, cfgURL)
	case tr.Alert == model.AlertGreenLight:
		s.alertIncident(ctx, p, inc, model.AlertGreenLight, "Green light needed: "+inc.Summary,
			diag+"\nTicket "+inc.Ticket+" waits for a decision. Without one within "+p.Limits.GreenLightTimeout.String()+
				", DutyDesk withdraws the ticket and escalates.", "")
	}
}

// escalate moves an incident whose proposal was refused to escalated and
// alerts with the reason (never with the secret that caused a refusal).
func (s *Service) escalate(ctx context.Context, p *model.Project, inc *model.Incident, reason string, v model.Verdict) {
	from := inc.State
	updated, err := s.st.UpdateIncident(inc.ID, []model.IncidentState{model.StateResolved, model.StateMROpen, model.StateWaiting},
		func(i *model.Incident) error {
			i.State, i.CloseReason = model.StateEscalated, ""
			i.RecheckAt = time.Time{}
			return nil
		})
	if err != nil {
		s.log.Error("incident not escalated", "incident", inc.ID, "error", err)
		return
	}
	*inc = updated
	s.journal(inc.ID, "escalated", fmt.Sprintf("State: %s → escalated (%s).", from, reason))
	s.alertIncident(ctx, p, *inc, model.AlertEscalated, "Escalated: "+inc.Summary,
		diagnosis(v)+"\nWhy escalated: "+reason+".\nA human must take over.", "")
}

type proposed struct {
	model.MRInfo
	repo string
}

// proposeFix pushes the agent's edits of a project clone on a dutydesk/
// branch and opens the merge request: draft unless the confidence is high.
func (s *Service) proposeFix(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, req model.RunRequest, tainted bool) (proposed, bool, error) {
	if tainted {
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
		return proposed{}, false, fmt.Errorf("the verdict names repository %q, which is not a repository of project %s", short(mr.Repo, 60), p.Slug)
	}
	dir, ok := req.RepoDirs[repo.Name]
	if !ok {
		return proposed{}, false, fmt.Errorf("repository %s was not mounted for this pass", repo.Name)
	}
	draft := v.Confidence != "high"
	desc := strings.TrimSpace(mr.Description) + "\n\n---\n" +
		"Opened by DutyDesk for incident " + inc.ID + " (project " + p.Slug + ", source `" + inc.Source + "`).\n\n" +
		"**Root cause:** " + orDash(v.RootCause) + "\n\n" +
		"**Confidence:** " + orDash(v.Confidence) + ifStr(draft, " (draft: the confidence is not high)") + "\n\n" +
		"DutyDesk never merges: review, then merge or close.\n"
	info, err := s.propose(ctx, *repo, dir, inc.ID, mr.Title, desc, draft, req.Run)
	return proposed{MRInfo: info, repo: repo.Name}, draft, err
}

// proposeConfig opens a merge request on the configuration repository from
// the throwaway clone the agent edited. The path policy only lets through
// checks, runbooks and actions of the incident's project.
func (s *Service) proposeConfig(ctx context.Context, p *model.Project, inc model.Incident, v model.Verdict, req model.RunRequest, tainted bool) (model.MRInfo, string, error) {
	repo, ok := s.configRepo(p.Slug)
	if !ok || req.ConfigDir == "" {
		return model.MRInfo{}, "", errNoConfigRepo
	}
	if tainted {
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
	info, err := s.propose(ctx, repo, req.ConfigDir, inc.ID, title, b.String(), v.Confidence != "high", req.Run)
	return info, title, err
}

func (s *Service) propose(ctx context.Context, repo model.Repo, dir, incidentID, title, desc string, draft bool, run int) (model.MRInfo, error) {
	info, err := s.forge.Propose(ctx, repo, dir, forge.BranchName(incidentID, title), title, desc, draft, []string{MRLabel})
	if errors.Is(err, forge.ErrBranchExists) {
		// An earlier pass of this incident already used the name.
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
