package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/check"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// replayCheck picks the deterministic check that tells whether the condition
// of an incident is still there: the runbook's recheck_check, else the check
// the incident came from. Webhook incidents without one have none.
func replayCheck(p *model.Project, inc model.Incident) (model.Check, string, bool) {
	find := func(id string) (model.Check, bool) {
		for _, c := range p.Checks {
			if c.ID == id {
				return c, true
			}
		}
		return model.Check{}, false
	}
	if rb := runbookOf(p, inc); rb.RecheckCheck != "" && rb.RecheckCheck != inc.Source {
		if c, ok := find(rb.RecheckCheck); ok {
			// Another check has other fingerprints: any signal counts.
			return c, check.AnyFingerprint, true
		}
	}
	if c, ok := find(inc.Source); ok {
		if inc.Mass {
			return c, check.AnyFingerprint, true
		}
		return c, inc.Fingerprint, true
	}
	return model.Check{}, "", false
}

// stillFiring replays the check of an incident through the locks.
// ok is false when no answer could be had now (locks down, lock error).
func (s *Service) stillFiring(ctx context.Context, p *model.Project, inc model.Incident, c model.Check, fp string) (firing, ok bool) {
	if !s.locksServing(p) {
		return false, false
	}
	now := s.now()
	s.mu.Lock()
	wait := now.Before(s.retryAt[inc.ID])
	s.mu.Unlock()
	if wait {
		return false, false
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	firing, err := check.StillFiring(cctx, c, p, s.o.Reader, fp)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.retryAt[inc.ID] = now.Add(s.periods.RecheckRetry)
		if ctx.Err() == nil {
			s.log.Warn("check not replayed", "incident", inc.ID, "check", c.ID, "error", s.scrub(err.Error()))
		}
		return false, false
	}
	delete(s.retryAt, inc.ID)
	return firing, true
}

// rechecks handles the waiting incidents whose wake-up time has come: the
// deterministic check is replayed first; the agent runs again only when the
// condition persists.
func (s *Service) rechecks(ctx context.Context) {
	due, err := s.st.DueRechecks()
	if err != nil {
		s.log.Error("due rechecks not read", "error", err)
		return
	}
	for _, inc := range due {
		if ctx.Err() != nil {
			return
		}
		p := s.Project(inc.Project)
		if p == nil {
			continue
		}
		firing := true
		if c, fp, ok := replayCheck(p, inc); ok {
			var answered bool
			if firing, answered = s.stillFiring(ctx, p, inc, c, fp); !answered {
				continue // try again later; the incident stays waiting
			}
		}
		tr, err := s.mgr.Recheck(inc, firing)
		if err != nil && !errors.Is(err, incident.ErrDossier) {
			if !errors.Is(err, store.ErrStateConflict) {
				s.log.Error("recheck not applied", "incident", inc.ID, "error", err)
			}
			continue
		}
		s.log.Info("recheck", "incident", inc.ID, "still_firing", firing, "to", string(tr.To))
	}
}

// clearedConditions closes escalated, blocked and mr_open incidents whose
// deterministic check no longer sees the condition. No alert: it is over.
func (s *Service) clearedConditions(ctx context.Context) {
	open, err := s.st.ListIncidents(store.IncidentFilter{States: []model.IncidentState{
		model.StateEscalated, model.StateBlocked, model.StateMROpen}})
	if err != nil {
		s.log.Error("open incidents not read", "error", err)
		return
	}
	for _, inc := range open {
		if ctx.Err() != nil {
			return
		}
		p := s.Project(inc.Project)
		if p == nil {
			continue
		}
		c, fp, ok := replayCheck(p, inc)
		if !ok {
			continue
		}
		firing, answered := s.stillFiring(ctx, p, inc, c, fp)
		if !answered || firing {
			continue
		}
		if _, err := s.mgr.Recheck(inc, false); err != nil && !errors.Is(err, incident.ErrDossier) {
			if !errors.Is(err, store.ErrStateConflict) {
				s.log.Error("cleared incident not closed", "incident", inc.ID, "error", err)
			}
			continue
		}
		s.log.Info("incident closed: condition cleared", "incident", inc.ID, "was", string(inc.State))
	}
}

// greenLights follows the tickets of incidents waiting for a human decision
// and enforces the runbook's patience: past GreenLightTimeout the ticket is
// withdrawn and the incident escalated.
func (s *Service) greenLights(ctx context.Context) {
	waiting, err := s.st.ListIncidents(store.IncidentFilter{States: []model.IncidentState{model.StateGreenLight}})
	if err != nil {
		s.log.Error("green-light incidents not read", "error", err)
		return
	}
	for _, inc := range waiting {
		if ctx.Err() != nil {
			return
		}
		p := s.Project(inc.Project)
		if p == nil {
			continue
		}
		state := model.TicketUnknown
		if inc.Ticket != "" {
			tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			st, err := s.o.Status.Ticket(tctx, p.Locks.Workspace, inc.Ticket)
			cancel()
			if err != nil {
				s.log.Warn("ticket state not read", "incident", inc.ID, "error", err)
			} else {
				state = st
			}
		}
		var tr incident.Transition
		switch state {
		case model.TicketPending, model.TicketUnknown:
			since, err := s.st.StateSince(inc.ID)
			if err != nil || p.Limits.GreenLightTimeout <= 0 || s.now().Sub(since) < p.Limits.GreenLightTimeout {
				continue
			}
			tr, err = s.mgr.GreenLightTimedOut(inc)
			if err != nil && !errors.Is(err, incident.ErrDossier) {
				s.log.Error("green-light timeout not applied", "incident", inc.ID, "error", err)
				continue
			}
			s.withdraw(ctx, p, tr.WithdrawTicket)
		default:
			tr, err = s.mgr.GreenLightDecided(inc, state)
			if err != nil && !errors.Is(err, incident.ErrDossier) {
				s.log.Error("ticket decision not applied", "incident", inc.ID, "error", err)
				continue
			}
		}
		s.log.Info("green light", "incident", inc.ID, "ticket_state", string(state), "to", string(tr.To))
		if tr.Alert == model.AlertEscalated {
			s.alertIncident(ctx, p, tr.Incident, model.AlertEscalated, "Escalated: "+tr.Incident.Summary,
				"The sensitive action the agent asked for did not get a green light ("+tr.Reason+
					"). Nothing was run. A human must take over; `dutydesk incident show "+inc.ID+"` has the diagnosis.", "")
		}
		if tr.To == model.StateQueued {
			s.Kick()
		}
	}
}

// knownProblems asks the forge about every open merge request DutyDesk
// follows: merged or closed ends the known problem (or the proposal).
func (s *Service) knownProblems(ctx context.Context) {
	known, err := s.st.ListOpenKnownProblems("")
	if err != nil {
		s.log.Error("known problems not read", "error", err)
		return
	}
	for _, k := range known {
		if ctx.Err() != nil {
			return
		}
		p := s.Project(k.Project)
		if p == nil {
			continue
		}
		var repo *model.Repo
		for i := range p.Repos {
			if p.Repos[i].Name == k.Repo {
				repo = &p.Repos[i]
			}
		}
		if repo == nil {
			continue
		}
		fctx, cancel := context.WithTimeout(ctx, time.Minute)
		info, err := s.forge.Status(fctx, *repo, k.MRID)
		cancel()
		if err != nil {
			s.log.Warn("merge request state not read", "project", k.Project, "mr", k.MRID, "error", s.scrub(err.Error()))
			continue
		}
		if info.State == "merged" || info.State == "closed" {
			if err := s.st.CloseKnownProblem(k.ID); err != nil {
				s.log.Error("known problem not closed", "error", err)
				continue
			}
			s.log.Info("known problem closed", "project", k.Project, "family", k.Family, "mr", k.MRURL, "state", info.State)
		}
	}
	proposals, err := s.st.ListProposals("", true)
	if err != nil {
		return
	}
	for _, pr := range proposals {
		repo, ok := s.configRepo(pr.Project)
		if !ok || ctx.Err() != nil {
			return
		}
		fctx, cancel := context.WithTimeout(ctx, time.Minute)
		info, err := s.forge.Status(fctx, repo, pr.MRID)
		cancel()
		if err != nil {
			continue
		}
		if info.State == "merged" || info.State == "closed" {
			if err := s.st.SetProposalState(pr.ID, info.State); err != nil {
				s.log.Error("proposal state not saved", "error", err)
			}
		}
	}
}

// reminders re-alerts for incidents that still wait for a human.
func (s *Service) reminders(ctx context.Context) {
	due, err := s.mgr.DueReminders()
	if err != nil {
		s.log.Error("reminders not read", "error", err)
		return
	}
	for _, inc := range due {
		p := s.Project(inc.Project)
		if p == nil {
			continue
		}
		what := map[model.IncidentState]string{
			model.StateEscalated:  "is escalated and waits for a human",
			model.StateBlocked:    "is blocked: an action is missing from the catalogue",
			model.StateGreenLight: "waits for a green light on ticket " + inc.Ticket,
		}[inc.State]
		s.alertIncident(ctx, p, inc, model.AlertReminder, "Still open: "+inc.Summary,
			fmt.Sprintf("%s %s since %s.\nTake it over, or close it once handled: dutydesk incident close %s",
				inc.ID, what, inc.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"), inc.ID), "")
	}
}

// seatExpiry alerts 30 days before a seat token expires, once per day.
func (s *Service) seatExpiry(ctx context.Context) {
	today := s.now().UTC().Format("2006-01-02")
	for _, st := range s.pool.Expiring(30 * 24 * time.Hour) {
		key := "seat_expiry_alert:" + st.Name
		if last, ok, err := s.st.GetKV(key); err != nil || (ok && last == today) {
			continue
		}
		if err := s.st.SetKV(key, today); err != nil {
			continue
		}
		days := int(st.ExpiresOn.Sub(s.now()).Hours() / 24)
		title := fmt.Sprintf("The token of seat %s expires in %d days (%s)", st.Name, days, st.ExpiresOn.Format("2006-01-02"))
		if days < 0 || !st.ExpiresOn.After(s.now()) {
			title = fmt.Sprintf("The token of seat %s expired on %s", st.Name, st.ExpiresOn.Format("2006-01-02"))
		}
		s.systemAlert(ctx, model.Alert{Kind: model.AlertSeatExpiry, Title: title,
			Body: "Renew it with `claude setup-token` under the seat's account, replace the token file (mode 0600) and update expires_on in dutydesk.yaml."})
	}
}

var leftoverName = regexp.MustCompile(`^` + regexp.QuoteMeta(agent.ContainerPrefix) + `inc-[0-9]+-[0-9]+$`)

// removeLeftoverContainers removes the agent containers a crash left
// behind (their runs were just marked cancelled). Best effort: an
// unreachable runtime is only logged. Only names of the form
// dutydesk-inc-<n>-<pass> are touched, never another dutydesk-* container
// such as the egress proxy.
func (s *Service) removeLeftoverContainers(ctx context.Context) {
	if s.o.Containers == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out, errOut strings.Builder
	code, err := s.o.Containers.Run(ctx, agent.Command{Name: s.d.Runtime,
		Args:   []string{"ps", "-a", "--filter", "name=" + agent.ContainerPrefix + "inc-", "--format", "{{.Names}}"},
		Stdout: &out, Stderr: &errOut})
	if err != nil || code != 0 {
		s.log.Warn("container runtime not reachable: leftover agent containers were not looked for", "runtime", s.d.Runtime)
		return
	}
	var names []string
	for _, n := range strings.Fields(out.String()) {
		if leftoverName.MatchString(n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return
	}
	var sink strings.Builder
	code, err = s.o.Containers.Run(ctx, agent.Command{Name: s.d.Runtime, Args: append([]string{"rm", "-f"}, names...),
		Stdout: &sink, Stderr: &sink})
	s.log.Warn("removed agent containers left by an interrupted run", "containers", strings.Join(names, " "), "ok", err == nil && code == 0)
}
