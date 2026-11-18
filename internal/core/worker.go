package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/agent"
	"github.com/DavidGodefroid/dutydesk/internal/config"
	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

// dispatch starts passes while there is room: global and per-project
// parallel limits, locks serving, a free seat among the project's seats.
func (s *Service) dispatch(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	skip := map[string]bool{}
	for {
		s.mu.Lock()
		running := len(s.passes)
		var exclude []string
		for slug := range skip {
			exclude = append(exclude, slug)
		}
		for slug, n := range s.perProject {
			if p := s.Project(slug); p != nil && p.Limits.MaxParallelRuns > 0 && n >= p.Limits.MaxParallelRuns && !skip[slug] {
				exclude = append(exclude, slug)
			}
		}
		s.mu.Unlock()
		if running >= s.d.MaxParallelRuns {
			return
		}
		next, err := s.st.NextQueued(exclude...)
		if err != nil {
			s.log.Error("queue not read", "error", err)
			return
		}
		if next == nil {
			return
		}
		p := s.Project(next.Project)
		if p == nil {
			s.orphan(*next)
			continue
		}
		if !s.locksServing(p) {
			skip[p.Slug] = true
			continue
		}
		st, release, ok := s.pool.Acquire(p.Seats)
		if !ok {
			// No seat for this project now: its incidents wait in the queue.
			skip[p.Slug] = true
			s.capacity(ctx, p)
			continue
		}
		inc, err := s.st.ClaimIncident(next.ID)
		if err != nil {
			release()
			if !errors.Is(err, store.ErrStateConflict) {
				s.log.Error("incident not claimed", "incident", next.ID, "error", err)
				return
			}
			continue
		}
		passCtx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.passes[inc.ID] = cancel
		s.passTokens[inc.ID] = inc.AgentToken
		s.perProject[p.Slug]++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				cancel()
				release()
				s.mu.Lock()
				delete(s.passes, inc.ID)
				delete(s.passTokens, inc.ID)
				if s.perProject[p.Slug]--; s.perProject[p.Slug] <= 0 {
					delete(s.perProject, p.Slug)
				}
				s.mu.Unlock()
				s.Kick()
			}()
			s.runPass(passCtx, p, inc, st)
		}()
	}
}

func (s *Service) cancelPass(id string) {
	s.mu.Lock()
	cancel := s.passes[id]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// orphan escalates a queued incident whose project left the configuration:
// nothing can run for it.
func (s *Service) orphan(inc model.Incident) {
	_, err := s.st.UpdateIncident(inc.ID, []model.IncidentState{model.StateQueued}, func(i *model.Incident) error {
		i.State = model.StateEscalated
		return nil
	})
	if err != nil {
		s.log.Error("orphan incident not escalated", "incident", inc.ID, "error", err)
		return
	}
	s.journal(inc.ID, "escalated", "Project "+inc.Project+" is no longer in the configuration: no pass can run. State: queued → escalated.")
	s.log.Warn("incident of an unknown project escalated", "incident", inc.ID, "project", inc.Project)
}

// capacity alerts when a high or critical incident of the project has been
// waiting for a seat longer than QueueAlertAfter.
func (s *Service) capacity(ctx context.Context, p *model.Project) {
	after := p.Limits.QueueAlertAfter
	if after <= 0 {
		return
	}
	queued, err := s.st.ListIncidents(store.IncidentFilter{Project: p.Slug, States: []model.IncidentState{model.StateQueued}})
	if err != nil {
		return
	}
	now := s.now()
	for _, inc := range queued {
		if inc.Severity < model.SevHigh {
			continue
		}
		since, err := s.st.StateSince(inc.ID)
		if err != nil || now.Sub(since) < after {
			continue
		}
		every := after
		if every < time.Hour {
			every = time.Hour
		}
		var lines []string
		for _, st := range s.pool.Stats() {
			switch {
			case st.Exhausted:
				lines = append(lines, fmt.Sprintf("%s: quota exhausted until %s", st.Name, st.ExhaustedUntil.UTC().Format("15:04 UTC")))
			default:
				lines = append(lines, fmt.Sprintf("%s: %d/%d passes running", st.Name, st.InUse, st.MaxParallel))
			}
		}
		s.alertOnce(ctx, "capacity:"+p.Slug, every, model.Alert{Kind: model.AlertCapacity, Project: p.Slug,
			Title: fmt.Sprintf("No seat free: %s (%s) has been waiting since %s", inc.ID, severityName(inc.Severity), since.UTC().Format("15:04 UTC")),
			Body: "Every seat allowed for this project is busy or out of quota, so no agent investigates.\n" +
				strings.Join(lines, "\n") + "\nAdd a seat, or handle the incident by hand."})
		return
	}
}

func severityName(sev model.Severity) string {
	switch sev {
	case model.SevLow:
		return "low"
	case model.SevMedium:
		return "medium"
	case model.SevHigh:
		return "high"
	case model.SevCritical:
		return "critical"
	}
	return "unknown"
}

func runbookOf(p *model.Project, inc model.Incident) model.Runbook {
	for _, rb := range p.Runbooks {
		if rb.ID == inc.Runbook {
			return rb
		}
	}
	return config.RunbookFor(p, inc.Source)
}

func maxRunsOf(p *model.Project, rb model.Runbook) int {
	if rb.MaxRuns > 0 {
		return rb.MaxRuns
	}
	return p.Limits.MaxRunsPerIncident
}

// runPass is one agent pass on a claimed incident (state investigating).
func (s *Service) runPass(ctx context.Context, p *model.Project, inc model.Incident, st model.Seat) {
	rb := runbookOf(p, inc)
	log := s.log.With("incident", inc.ID, "project", p.Slug, "seat", st.Name)

	run, err := s.st.StartRun(inc.ID, st.Name)
	if err != nil {
		log.Error("run not recorded", "error", err)
		s.failed(ctx, p, inc, model.RunResult{Status: model.RunCancelled, Error: "the pass could not be recorded"})
		return
	}
	// The pass number is unique per incident, quota retries included: it
	// names the container and the run directory of the dossier.
	n := 1
	if runs, err := s.st.ListRuns(inc.ID); err == nil && len(runs) > 0 {
		n = len(runs)
	}
	finish := func(res model.RunResult) {
		if err := s.st.FinishRun(run.ID, res); err != nil {
			log.Error("run result not recorded", "error", err)
		}
	}

	workDir := filepath.Join(s.d.DataDir, "work", fmt.Sprintf("%s-%d", strings.ToLower(inc.ID), n))
	_ = os.RemoveAll(workDir)
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			log.Warn("work directory not removed", "error", err)
		}
	}()

	req, err := s.prepare(ctx, p, rb, inc, st, n, workDir)
	if err != nil {
		res := model.RunResult{Status: model.RunFailed, Error: s.scrub("pass not prepared: " + err.Error())}
		if ctx.Err() != nil {
			res.Status = model.RunCancelled
		}
		log.Warn("pass not prepared", "error", res.Error)
		finish(res)
		s.failed(ctx, p, inc, res)
		return
	}

	log.Info("pass started", "run", n, "runbook", rb.ID)
	started := time.Now()
	res := s.o.Launcher.Run(ctx, req)
	res.Error = s.scrub(res.Error)
	var tainted taint
	if res.Verdict != nil {
		res.Verdict, tainted = s.scrubVerdict(res.Verdict)
	}
	if res.Status == model.RunOK && res.Verdict == nil {
		res.Status, res.Error = model.RunFailed, "the launcher returned no verdict"
	}
	finish(res)
	log.Info("pass ended", "run", n, "status", string(res.Status), "turns", res.Turns, "cost_usd", res.CostUSD,
		"duration", time.Since(started).Round(time.Millisecond).String())

	if res.Status != model.RunOK {
		if res.Status == model.RunQuota {
			if err := s.pool.MarkExhausted(st.Name, res.QuotaReset); err != nil {
				log.Warn("seat exhaustion not saved", "error", err)
			}
			log.Warn("seat exhausted; the incident goes to another seat")
		}
		s.failed(ctx, p, inc, res)
		return
	}

	v := *res.Verdict
	for _, a := range v.ActionsRun {
		if err := s.st.RecordAction(inc.ID, run.ID, a); err != nil {
			log.Warn("action not recorded", "error", err)
		}
	}
	tr, err := s.mgr.ApplyVerdict(inc, v, rb, p.Limits)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		// Typically closed by a human or by its source while the pass ran.
		log.Warn("verdict not applied", "outcome", string(v.Outcome), "error", err)
		return
	}
	log.Info("verdict applied", "outcome", string(v.Outcome), "from", string(tr.From), "to", string(tr.To))
	ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.o.EffectTimeout)
	defer cancel()
	s.effects(ectx, p, tr, v, req, tainted)
}

// failed applies a pass that ended without a valid verdict.
func (s *Service) failed(ctx context.Context, p *model.Project, inc model.Incident, res model.RunResult) {
	tr, err := s.mgr.RunFailed(inc, res.Status, p.Limits)
	if err != nil && !errors.Is(err, incident.ErrDossier) {
		s.log.Warn("failed pass not applied", "incident", inc.ID, "status", string(res.Status), "error", err)
		return
	}
	if res.Error != "" && res.Status != model.RunCancelled {
		s.journal(inc.ID, "pass error", res.Error)
	}
	if tr.Alert == model.AlertEscalated {
		ectx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.o.EffectTimeout)
		defer cancel()
		s.alertIncident(ectx, p, tr.Incident, model.AlertEscalated,
			"Escalated without a diagnosis: "+tr.Incident.Summary,
			"The agent passes failed ("+tr.Reason+"). Last error: "+res.Error+
				"\nA human must take over; `dutydesk incident show "+inc.ID+"` has the journal.", "")
	}
}

// prepare builds everything one pass needs: fresh clones, the dossier
// directories and the prompt.
func (s *Service) prepare(ctx context.Context, p *model.Project, rb model.Runbook, inc model.Incident, st model.Seat, n int, workDir string) (model.RunRequest, error) {
	var req model.RunRequest
	if err := os.MkdirAll(workDir, 0o750); err != nil {
		return req, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	repoDirs := map[string]string{}
	var repoNames []string
	for _, r := range p.Repos {
		dir := filepath.Join(workDir, "repos", r.Name)
		if err := s.forge.Clone(cctx, r, dir); err != nil {
			return req, fmt.Errorf("clone of %s: %w", r.Name, err)
		}
		repoDirs[r.Name] = dir
		repoNames = append(repoNames, r.Name)
	}
	configDir := ""
	if cr, ok := s.configRepo(p.Slug); ok {
		// A throwaway clone of the protected branch: the agent may write a
		// proposal there, the running configuration never comes from it.
		configDir = filepath.Join(workDir, "config")
		if err := s.forge.Clone(cctx, cr, configDir); err != nil {
			return req, fmt.Errorf("clone of the config repository: %w", err)
		}
	}
	dossierDir, err := s.dossier.Dir(inc.ID)
	if err != nil {
		return req, err
	}
	outDir, err := s.dossier.RunDir(inc.ID, n)
	if err != nil {
		return req, err
	}

	in := agent.PromptInput{
		Method: s.cfg.Load().Method, Project: p, Runbook: rb, Incident: inc,
		Run: inc.Runs + 1, MaxRuns: maxRunsOf(p, rb),
		ActionInstallDir: s.d.ActionInstallDir, Repos: repoNames, ConfigMounted: configDir != "",
	}
	if sigs, err := s.st.ListSignals(inc.ID); err == nil && len(sigs) > 0 {
		in.Signal = sigs[0].Signal
	}
	if text, err := s.dossier.Journal(inc.ID); err == nil {
		in.Journal = parseJournal(text)
	}
	if known, err := s.st.ListOpenKnownProblems(p.Slug); err == nil {
		for _, k := range known {
			if k.Family == inc.Family {
				in.KnownProblems = append(in.KnownProblems, k)
			}
		}
	}
	for _, name := range rb.Actions {
		if a, ok := p.Actions[name]; ok {
			in.Actions = append(in.Actions, agent.PromptAction{Action: a,
				CommandLine: agent.ActionCommandLine(a, s.d.ActionInstallDir)})
		}
	}
	if inc.Ticket != "" {
		tctx, tcancel := context.WithTimeout(ctx, 15*time.Second)
		state, err := s.o.Status.Ticket(tctx, p.Locks.Workspace, inc.Ticket)
		tcancel()
		if err == nil && state == model.TicketApproved {
			in.ApprovedTicket = inc.Ticket
		}
	}
	return model.RunRequest{
		Incident: inc, Run: n, Project: p, Runbook: rb, Seat: st, Prompt: agent.BuildPrompt(in),
		DossierDir: dossierDir, RepoDirs: repoDirs, ConfigDir: configDir, OutDir: outDir,
	}, nil
}

var journalHead = regexp.MustCompile(`^## (\S+) — (.*)$`)

// parseJournal turns journal.md into the entries shown in the prompt: one
// per "## <time> — <title>" heading, with its body.
func parseJournal(text string) []agent.JournalEntry {
	var out []agent.JournalEntry
	var cur *agent.JournalEntry
	for _, line := range strings.Split(text, "\n") {
		if m := journalHead.FindStringSubmatch(line); m != nil {
			if at, err := time.Parse(time.RFC3339, m[1]); err == nil {
				out = append(out, agent.JournalEntry{At: at, Text: m[2] + ":"})
				cur = &out[len(out)-1]
				continue
			}
		}
		if cur != nil && strings.TrimSpace(line) != "" {
			cur.Text += " " + strings.TrimSpace(line)
		}
	}
	return out
}

// taint says which proposals of a verdict held a secret in their text: such
// a proposal is refused as a whole, like a secret in its diff.
type taint struct{ mr, config bool }

// scrubVerdict removes known secrets from every text of a verdict before it
// is stored, journaled or shown to a human: the agent holds its seat token
// and its lock identity token, and its output is not trusted.
func (s *Service) scrubVerdict(v *model.Verdict) (*model.Verdict, taint) {
	secrets := s.Secrets()
	var t taint
	dirty := false
	c := func(text string) string {
		for _, sec := range secrets {
			if strings.Contains(text, sec) {
				text, dirty = strings.ReplaceAll(text, sec, "[redacted]"), true
			}
		}
		return text
	}
	out := *v
	out.Summary, out.RootCause, out.Ticket = c(v.Summary), c(v.RootCause), c(v.Ticket)
	out.Evidence = nil
	for _, e := range v.Evidence {
		out.Evidence = append(out.Evidence, c(e))
	}
	out.ActionsRun = nil
	for _, a := range v.ActionsRun {
		out.ActionsRun = append(out.ActionsRun, c(a))
	}
	dirty = false
	if v.MR != nil {
		out.MR = &model.MRProposal{Repo: c(v.MR.Repo), Title: c(v.MR.Title), Description: c(v.MR.Description)}
		t.mr = dirty
	}
	dirty = false
	if m := v.MissingAction; m != nil {
		out.MissingAction = &model.MissingAction{Name: c(m.Name), Why: c(m.Why), Title: c(m.Title), Detail: c(m.Detail)}
	}
	if m := v.Improvement; m != nil {
		out.Improvement = &model.Improvement{Title: c(m.Title), Observation: c(m.Observation), Change: c(m.Change),
			Effect: c(m.Effect), Risk: c(m.Risk)}
	}
	t.config = dirty
	return &out, t
}
