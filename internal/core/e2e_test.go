package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/dutydesk/internal/incident"
	"github.com/DavidGodefroid/dutydesk/internal/model"
	"github.com/DavidGodefroid/dutydesk/internal/store"
)

const first = "INC-000001"

// detect fires the scheduled stuck-job check and waits for n incidents.
func (w *world) detect(n int) {
	w.t.Helper()
	if w.crons.fire(stuckSpec) == 0 {
		w.t.Fatal("the stuck-job check is not scheduled")
	}
	w.waitIncidents(n)
}

// Scenario 1: a stuck job is detected, the agent asks for a recheck, and at
// wake-up the deterministic check sees nothing: resolved with no second
// pass and no alert.
func TestE2ERecheckThenCleared(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Job 4812 still progresses.", RecheckMinutes: 20}))
	w.start()
	w.detect(1)

	inc := w.waitState(first, model.StateWaiting)
	if inc.Runs != 1 || inc.Runbook != "stuck-job" || inc.Family != "stuck-job:" || inc.Fingerprint != "stuck-job:4812" ||
		!inc.RecheckAt.Equal(t0.Add(20*time.Minute)) {
		t.Fatalf("incident after pass 1 = %+v", inc)
	}
	// A second firing of the same row attaches: no new incident, no new pass.
	w.crons.fire(stuckSpec)
	w.settle()
	if got := w.incidents(); len(got) != 1 || got[0].SignalCount != 2 {
		t.Fatalf("incidents after a second signal = %+v", got)
	}

	// Before the wake-up time nothing happens, even with the condition gone.
	w.reader.set()
	w.clock.Advance(19 * time.Minute)
	w.settle()
	if st := w.incident(first).State; st != model.StateWaiting {
		t.Fatalf("state before the wake-up = %s", st)
	}
	w.clock.Advance(2 * time.Minute)
	inc = w.waitState(first, model.StateResolved)
	w.settle()

	if inc.CloseReason != incident.ReasonConditionCleared || inc.ClosedAt.IsZero() {
		t.Errorf("close = %q at %v", inc.CloseReason, inc.ClosedAt)
	}
	if n := w.agent.passes(); n != 1 {
		t.Errorf("agent passes = %d, want 1 (the check is replayed, not the agent)", n)
	}
	w.wantKinds()
	w.wantJournal(first, "— signal", "Job 4812 (export) has been running since", "pass 1: verdict recheck", "Job 4812 still progresses.",
		"recheck: condition cleared", "State: waiting → resolved")
	req := w.agent.requests()[0]
	if req.Run != 1 || req.Seat.Name == "" || req.RepoDirs["app"] == "" || req.ConfigDir == "" || !strings.HasSuffix(req.OutDir, "runs/1") {
		t.Errorf("run request = %+v", req)
	}
	for _, want := range []string{"Incident: INC-000001", "Pass: 1 of 5", "fingerprint: stuck-job:4812", "## Runbook: stuck-job",
		"/opt/dutydesk/bin/dutydesk-act requeue-job --job-id <job-id>",
		"/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id <job-id> --status <status>",
		`through the lockssh instance "docflow-stuck-job". It runs at once`,
		`through the lockssh instance "docflow-stuck-job-ask". It does not run`,
		"/work/repos/app", "A throwaway clone of the DutyDesk configuration repository"} {
		if !strings.Contains(req.Prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(w.daemon.DataDir, "work", "inc-000001-1")); !os.IsNotExist(err) {
		t.Errorf("work directory left behind: %v", err)
	}
	runs, _ := w.store().ListRuns(first)
	if len(runs) != 1 || runs[0].Status != model.RunOK || runs[0].Verdict == nil || runs[0].Turns != 7 {
		t.Errorf("runs = %+v", runs)
	}
	w.noSecrets()
}

// Scenario 2: the condition persists, a second pass escalates with a
// diagnosis; a reminder follows after the delay; the incident closes by
// itself when the condition clears.
func TestE2EPersistsThenEscalates(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(
		verdict(model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Job 4812 still progresses.", RecheckMinutes: 20}),
		verdict(model.Verdict{Outcome: model.OutcomeEscalate, Summary: "Job 4812 no longer progresses and its worker is alive.",
			RootCause: "Deadlock between the export worker and the archiver.", Evidence: []string{"processed_count unchanged for 40 minutes"}}),
	)
	w.start()
	w.detect(1)
	w.waitState(first, model.StateWaiting)
	w.wantKinds()

	w.clock.Advance(21 * time.Minute)
	inc := w.waitState(first, model.StateEscalated)
	w.waitAlerts(1)
	w.settle()
	w.wantKinds(model.AlertEscalated)
	a := w.rec.Sent()[0].Alert
	if a.Incident != first || a.Project != "docflow" || !strings.Contains(a.Body, "no longer progresses") ||
		!strings.Contains(a.Body, "Root cause: Deadlock between the export worker and the archiver.") {
		t.Errorf("escalation alert = %+v", a)
	}
	if inc.Runs != 2 || w.agent.passes() != 2 {
		t.Errorf("runs = %d, passes = %d", inc.Runs, w.agent.passes())
	}
	second := w.agent.requests()[1]
	if second.Run != 2 || !strings.Contains(second.Prompt, "Pass: 2 of 5") || !strings.Contains(second.Prompt, "pass 1: verdict recheck") ||
		!strings.Contains(second.Prompt, "recheck: still firing") {
		t.Errorf("second pass does not start from the dossier:\n%s", second.Prompt)
	}

	// Nobody acts: one reminder after the delay, not before.
	w.clock.Advance(23 * time.Hour)
	w.settle()
	w.wantKinds(model.AlertEscalated)
	w.clock.Advance(2 * time.Hour)
	w.waitAlerts(2)
	w.settle()
	w.wantKinds(model.AlertEscalated, model.AlertReminder)

	// The condition clears later: closed without a human and without an alert.
	w.reader.set()
	inc = w.waitState(first, model.StateResolved)
	w.settle()
	if inc.CloseReason != incident.ReasonConditionCleared {
		t.Errorf("close reason = %q", inc.CloseReason)
	}
	w.wantKinds(model.AlertEscalated, model.AlertReminder)
	if w.agent.passes() != 2 {
		t.Errorf("passes = %d", w.agent.passes())
	}
	w.wantJournal(first, "recheck: still firing", "pass 2: verdict escalate", "**Root cause:** Deadlock", "State: escalated → resolved")
	w.noSecrets()
}

// Scenario 3: 50 identical signals give one incident and one pass; a flood
// of distinct fingerprints gives one mass incident and one storm alert.
func TestE2EDedupAndStorm(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	same := make([]model.Row, 50)
	for i := range same {
		same[i] = job("4812")
	}
	w.reader.set(same...)
	w.agent.fallback = verdict(model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Still progressing.", RecheckMinutes: 60})
	w.start()
	w.detect(1)
	w.waitState(first, model.StateWaiting)
	w.settle()
	if got := w.incidents(); len(got) != 1 || got[0].SignalCount != 50 || w.agent.passes() != 1 {
		t.Fatalf("50 identical signals: %d incidents, %d signals, %d passes", len(got), got[0].SignalCount, w.agent.passes())
	}
	w.wantKinds()

	// 40 distinct stuck jobs at once: max_open_per_check is 10.
	var flood []model.Row
	for i := 0; i < 40; i++ {
		flood = append(flood, job(fmt.Sprintf("%d", 9000+i)))
	}
	w.reader.set(flood...)
	w.crons.fire(stuckSpec)
	w.eventually("every regular incident waits", func() bool {
		n, _ := w.store().CountIncidentsInState("docflow", model.StateWaiting)
		return n == 10
	})
	w.settle()
	var mass []model.Incident
	regular := 0
	for _, inc := range w.incidents() {
		if inc.Mass {
			mass = append(mass, inc)
		} else {
			regular++
		}
	}
	if regular != 10 || len(mass) != 1 {
		t.Fatalf("regular = %d, mass = %d", regular, len(mass))
	}
	m := mass[0]
	if m.State != model.StateEscalated || m.Fingerprint != "stuck-job:mass" || m.SignalCount != 31 || m.Runs != 0 {
		t.Errorf("mass incident = %+v", m)
	}
	w.wantKinds(model.AlertStorm)
	if a := w.rec.Sent()[0].Alert; a.Incident != m.ID || !strings.Contains(a.Title, "Storm on stuck-job") {
		t.Errorf("storm alert = %+v", a)
	}
	if n := w.agent.passes(); n != 10 {
		t.Errorf("passes = %d, want 10 (one per regular incident, none for the mass incident)", n)
	}
	for _, req := range w.agent.requests() {
		if req.Incident.ID == m.ID {
			t.Errorf("an agent ran on the mass incident")
		}
	}
	w.wantJournal(m.ID, "storm guard")
	w.noSecrets()
}

// Scenario 4: the agent resolves by running an allowed action.
func TestE2EResolvedByAction(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	cmd := "/opt/dutydesk/bin/dutydesk-act requeue-job --job-id 4812"
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Worker gone; job requeued and progressing again.",
		ActionsRun: []string{cmd}, Confidence: "high"}))
	w.start()
	w.detect(1)
	inc := w.waitState(first, model.StateResolved)
	w.settle()
	if inc.CloseReason != incident.ReasonResolvedByAgent || inc.Runs != 1 {
		t.Errorf("incident = %+v", inc)
	}
	acts, err := w.store().ListActions(first)
	if err != nil || len(acts) != 1 || acts[0].Name != cmd || acts[0].RunID == 0 {
		t.Errorf("actions = %+v, %v", acts, err)
	}
	w.wantKinds()
	w.wantJournal(first, "pass 1: verdict resolved", "**Actions run:** "+cmd, "State: investigating → resolved")
	if len(w.gitlab.calls()) != 0 {
		t.Errorf("a merge request was opened")
	}
	w.noSecrets()
}

const ticket = "docflow-stuck-job-ask/T-77"

func greenLightWorld(t *testing.T) *world {
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.status.setTicket(ticket, model.TicketPending)
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeGreenLight, Ticket: ticket,
		Summary: "The job is finished according to the logs but its status is still running; reset-job-status needs a green light."}))
	w.start()
	w.detect(1)
	inc := w.waitState(first, model.StateGreenLight)
	w.waitAlerts(1)
	w.settle()
	w.wantKinds(model.AlertGreenLight)
	if a := w.rec.Sent()[0].Alert; inc.Ticket != ticket || !strings.Contains(a.Body, ticket) || a.Incident != first {
		t.Fatalf("ticket = %q, alert = %+v", inc.Ticket, a)
	}
	if w.agent.passes() != 1 {
		t.Fatalf("passes while waiting for the green light = %d", w.agent.passes())
	}
	return w
}

// Scenario 5: green light approved: a new pass gets the approved ticket and
// the same agent identity.
func TestE2EGreenLightApproved(t *testing.T) {
	t.Parallel()
	w := greenLightWorld(t)
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Status reset with the approved ticket; verified.",
		ActionsRun: []string{"/opt/dutydesk/bin/dutydesk-act reset-job-status --job-id 4812 --status done"}}))
	w.status.setTicket(ticket, model.TicketApproved)
	inc := w.waitState(first, model.StateResolved)
	w.settle()
	reqs := w.agent.requests()
	if len(reqs) != 2 {
		t.Fatalf("passes = %d", len(reqs))
	}
	if strings.Contains(reqs[0].Prompt, "APPROVED TICKET") || !strings.Contains(reqs[1].Prompt, "APPROVED TICKET: a human approved ticket "+ticket) {
		t.Errorf("approved ticket in prompts: first=%v", strings.Contains(reqs[0].Prompt, "APPROVED TICKET"))
	}
	if reqs[0].Incident.AgentToken == "" || reqs[0].Incident.AgentToken != reqs[1].Incident.AgentToken || reqs[1].Incident.ID != first {
		t.Errorf("the second pass does not run under the incident's agent identity")
	}
	if inc.Runs != 2 || len(w.status.withdrawnTickets()) != 0 {
		t.Errorf("runs = %d, withdrawn = %v", inc.Runs, w.status.withdrawnTickets())
	}
	w.wantKinds(model.AlertGreenLight)
	w.wantJournal(first, "pass 1: verdict green_light", "green light: approved", "pass 2: verdict resolved")
	w.noSecrets()
}

func TestE2EGreenLightTimeout(t *testing.T) {
	t.Parallel()
	w := greenLightWorld(t)
	w.clock.Advance(119 * time.Minute)
	w.settle()
	if st := w.incident(first).State; st != model.StateGreenLight {
		t.Fatalf("state before the timeout = %s", st)
	}
	w.clock.Advance(2 * time.Minute)
	inc := w.waitState(first, model.StateEscalated)
	w.waitAlerts(2)
	w.settle()
	if got := w.status.withdrawnTickets(); len(got) != 1 || got[0] != ticket {
		t.Errorf("withdrawn = %v", got)
	}
	if inc.Ticket != "" || w.agent.passes() != 1 {
		t.Errorf("ticket = %q, passes = %d", inc.Ticket, w.agent.passes())
	}
	w.wantKinds(model.AlertGreenLight, model.AlertEscalated)
	w.wantJournal(first, "green light: timed out")
	w.noSecrets()
}

func TestE2EGreenLightDenied(t *testing.T) {
	t.Parallel()
	w := greenLightWorld(t)
	w.status.setTicket(ticket, model.TicketDenied)
	w.waitState(first, model.StateEscalated)
	w.waitAlerts(2)
	w.settle()
	w.wantKinds(model.AlertGreenLight, model.AlertEscalated)
	if a := w.rec.Sent()[1].Alert; !strings.Contains(a.Body, "denied") {
		t.Errorf("alert = %+v", a)
	}
	if len(w.status.withdrawnTickets()) != 0 || w.agent.passes() != 1 {
		t.Errorf("withdrawn = %v, passes = %d", w.status.withdrawnTickets(), w.agent.passes())
	}
	w.wantJournal(first, "green light: denied")
	w.noSecrets()
}

// fix is an agent that edits the project clone and describes a merge request.
func fix(v model.Verdict, content string) step {
	return func(req model.RunRequest) model.RunResult {
		if err := os.WriteFile(filepath.Join(req.RepoDirs["app"], "src", "worker.txt"), []byte(content), 0o644); err != nil {
			return model.RunResult{Status: model.RunFailed, Error: err.Error()}
		}
		v.MR = &model.MRProposal{Repo: "app", Title: "Retry the archiver lock", Description: "## Symptoms\nJobs hang.\n\n## Fix\nRetry three times."}
		return verdict(v)(req)
	}
}

// Scenario 6: a code fix becomes a pushed branch and a merge request, a
// known problem, and a notice only. A second incident of the family opens
// no second merge request. A merged request ends the known problem.
func TestE2ECodeFix(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(fix(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Document skipped; the job runs again.",
		RootCause: "The worker never retries the archiver lock.", Confidence: "medium"}, "retry = 3\n"))
	w.start()
	w.detect(1)
	w.waitState(first, model.StateResolved)
	w.waitAlerts(1)
	w.settle()

	if got := branches(t, w.appBare); len(got) != 2 || got[0] != "dutydesk/inc-000001-retry-the-archiver-lock" {
		t.Fatalf("branches = %v", got)
	}
	if diff := git(t, w.appBare, "show", "--format=%an|%s", got0(branches(t, w.appBare))); !strings.Contains(diff, "DutyDesk|Retry the archiver lock") ||
		!strings.Contains(diff, "+retry = 3") {
		t.Errorf("pushed commit:\n%s", diff)
	}
	calls := w.gitlab.calls()
	if len(calls) != 1 || calls[0].Project != "acme/docflow" {
		t.Fatalf("merge requests = %+v", calls)
	}
	body := calls[0].Body
	desc, _ := body["description"].(string)
	if body["title"] != "Draft: Retry the archiver lock" || body["labels"] != "dutydesk" || body["target_branch"] != "main" ||
		!strings.Contains(desc, "## Symptoms") || !strings.Contains(desc, "incident INC-000001") ||
		!strings.Contains(desc, "**Root cause:** The worker never retries the archiver lock.") {
		t.Errorf("merge request = %+v", body)
	}
	known, _ := w.store().ListOpenKnownProblems("docflow")
	if len(known) != 1 || known[0].Family != "stuck-job:" || known[0].MRID != "1" || known[0].Incident != first || known[0].Repo != "app" {
		t.Fatalf("known problems = %+v", known)
	}
	w.wantKinds(model.NoticeMROpened)
	if a := w.rec.Sent()[0].Alert; a.URL != known[0].MRURL {
		t.Errorf("notice = %+v", a)
	}
	w.wantJournal(first, "**Merge request proposed** on app", "A draft merge request was opened: "+known[0].MRURL)

	// Same family, another job, while the merge request is open.
	w.agent.queue(fix(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Same defect; document skipped.",
		RootCause: "Same as INC-000001."}, "retry = 5\n"))
	w.reader.set(job("5000"))
	w.detect(2)
	w.waitState("INC-000002", model.StateResolved)
	w.settle()
	if p := w.agent.requests()[1].Prompt; !strings.Contains(p, known[0].MRURL) || !strings.Contains(p, "do NOT open a second merge request") {
		t.Errorf("the second agent is not told about the known problem")
	}
	if len(w.gitlab.calls()) != 1 || len(branches(t, w.appBare)) != 2 {
		t.Errorf("a second merge request was opened: %d calls, branches %v", len(w.gitlab.calls()), branches(t, w.appBare))
	}
	w.wantKinds(model.NoticeMROpened)
	w.wantJournal("INC-000002", "no second merge request is opened")

	// Merged by a human: the known problem ends.
	w.gitlab.setState("acme/docflow", 1, "merged")
	w.eventually("known problem closed", func() bool {
		k, err := w.store().ListOpenKnownProblems("docflow")
		return err == nil && len(k) == 0
	})
	w.wantKinds(model.NoticeMROpened)
	w.noSecrets()
}

func got0(s []string) string { return s[0] }

// A high confidence opens a real merge request, not a draft; production
// still affected (mr_open) alerts a human with the merge request URL.
func TestE2EFixWhileProductionAffected(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(fix(model.Verdict{Outcome: model.OutcomeEscalate, Summary: "No allowed action unblocks the job.",
		RootCause: "The worker never retries the archiver lock.", Confidence: "high"}, "retry = 3\n"))
	w.start()
	w.detect(1)
	w.waitState(first, model.StateMROpen)
	w.waitAlerts(2)
	w.settle()
	w.wantKinds(model.NoticeMROpened, model.AlertEscalated)
	calls := w.gitlab.calls()
	if len(calls) != 1 || calls[0].Body["title"] != "Retry the archiver lock" {
		t.Fatalf("merge requests = %+v", calls)
	}
	a := w.rec.Sent()[1].Alert
	if a.URL != "https://gitlab.example.com/acme/docflow/-/merge_requests/1" || !strings.Contains(a.Title, "Production still affected") ||
		!strings.Contains(a.Body, "No allowed action unblocks the job.") {
		t.Errorf("alert = %+v", a)
	}
	if k, _ := w.store().ListOpenKnownProblems("docflow"); len(k) != 1 {
		t.Errorf("known problems = %+v", k)
	}
	// The condition clears (a human fixed production): closed, no more alert.
	w.reader.set()
	w.waitState(first, model.StateResolved)
	w.settle()
	w.wantKinds(model.NoticeMROpened, model.AlertEscalated)
	w.noSecrets()
}

// Scenario 6, variant: the agent plants a secret it holds in the diff (and
// in its verdict). Nothing is pushed, the incident is escalated, and the
// secret appears nowhere.
func TestE2ESecretInFix(t *testing.T) {
	t.Parallel()
	for name, pick := range map[string]func(req model.RunRequest) string{
		"seat token": func(req model.RunRequest) string {
			if req.Seat.Name == "seat-b" {
				return seatTokenB
			}
			return seatTokenA
		},
		"agent token": func(req model.RunRequest) string { return req.Incident.AgentToken },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.reader.set(job("4812"))
			w.agent.queue(func(req model.RunRequest) model.RunResult {
				// What a hijacked agent would try with what its container holds.
				secret := pick(req)
				return fix(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Fixed. token=" + secret + " agent=" + req.Incident.AgentToken,
					RootCause: "Missing retry.", Evidence: []string{"env: " + secret}}, "retry = 3\napi_key = "+secret+"\n")(req)
			})
			w.start()
			w.detect(1)
			inc := w.waitState(first, model.StateEscalated)
			w.waitAlerts(1)
			w.settle()
			if got := branches(t, w.appBare); len(got) != 1 || got[0] != "main" {
				t.Errorf("something was pushed: %v", got)
			}
			if len(w.gitlab.calls()) != 0 {
				t.Errorf("a merge request was opened")
			}
			if k, _ := w.store().ListOpenKnownProblems("docflow"); len(k) != 0 {
				t.Errorf("known problems = %+v", k)
			}
			w.wantKinds(model.AlertEscalated)
			if a := w.rec.Sent()[0].Alert; !strings.Contains(a.Body, "a secret was found in the change; nothing was pushed") ||
				!strings.Contains(a.Body, "[redacted]") {
				t.Errorf("alert = %+v", a)
			}
			if inc.CloseReason != "" || !inc.ClosedAt.IsZero() {
				t.Errorf("incident still looks closed: %+v", inc)
			}
			w.wantJournal(first, "merge request not opened", "a secret was found in the change", "src/worker.txt", "State: resolved → escalated",
				"token=[redacted] agent=[redacted]")
			w.noSecrets()
		})
	}
}

// A secret in the text of the merge request (not in the diff) is refused too.
func TestE2ESecretInMRText(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(func(req model.RunRequest) model.RunResult {
		res := fix(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Fixed."}, "retry = 3\n")(req)
		res.Verdict.MR.Description += "\n\nDebug: " + seatTokenA
		return res
	})
	w.start()
	w.detect(1)
	w.waitState(first, model.StateEscalated)
	w.waitAlerts(1)
	if len(branches(t, w.appBare)) != 1 || len(w.gitlab.calls()) != 0 {
		t.Errorf("something left: %v, %d merge requests", branches(t, w.appBare), len(w.gitlab.calls()))
	}
	w.wantKinds(model.AlertEscalated)
	w.wantJournal(first, "a secret was found in the text of the proposal")
	w.noSecrets()
}

// newAction is an agent that writes a new action in the config clone.
func newAction(extra func(configDir string)) step {
	return func(req model.RunRequest) model.RunResult {
		dir := filepath.Join(req.ConfigDir, "projects", "docflow", "actions", "purge-cache")
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "action.yaml"), []byte("name: purge-cache\ndescription: Purge the render cache of one job.\nlevel: auto\nscript: purge-cache.sh\nparams:\n  - name: job-id\n    type: int\n    min: 1\ntimeout: 60s\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "purge-cache.sh"), []byte("#!/bin/sh\nset -eu\nexec /opt/docflow/bin/purge-cache \"$2\"\n"), 0o755)
		if extra != nil {
			extra(req.ConfigDir)
		}
		return verdict(model.Verdict{Outcome: model.OutcomeBlocked, Summary: "The render cache of job 4812 is corrupt; nothing in the catalogue purges it.",
			MissingAction: &model.MissingAction{Name: "purge-cache", Why: "A corrupt render cache blocks the job.",
				Title: "Add action purge-cache", Detail: "Purges the render cache of one job."}})(req)
	}
}

// Scenario 7: a missing action becomes a merge request on the configuration
// repository and a "blocked" alert.
func TestE2EMissingAction(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(newAction(nil))
	w.start()
	w.detect(1)
	w.waitState(first, model.StateBlocked)
	w.waitAlerts(2)
	w.settle()

	got := branches(t, w.confBare)
	if len(got) != 2 || got[0] != "dutydesk/inc-000001-add-action-purge-cache" {
		t.Fatalf("config branches = %v", got)
	}
	files := git(t, w.confBare, "show", "--format=", "--name-only", got[0])
	if files != "projects/docflow/actions/purge-cache/action.yaml\nprojects/docflow/actions/purge-cache/purge-cache.sh" {
		t.Errorf("pushed files:\n%s", files)
	}
	calls := w.gitlab.calls()
	if len(calls) != 1 || calls[0].Project != "ops/dutydesk-config" || calls[0].Body["title"] != "Draft: Add action purge-cache" {
		t.Fatalf("merge requests = %+v", calls)
	}
	props, _ := w.store().ListProposals("docflow", true)
	if len(props) != 1 || props[0].Kind != store.ProposalMissingAction || props[0].Incident != first || props[0].MRID != "1" {
		t.Errorf("proposals = %+v", props)
	}
	w.wantKinds(model.NoticeConfigMR, model.AlertBlocked)
	a := w.rec.Sent()[1].Alert
	if a.URL != props[0].MRURL || !strings.Contains(a.Body, "Missing action: purge-cache") || !strings.Contains(a.Body, "validate the new lockssh rule") {
		t.Errorf("blocked alert = %+v", a)
	}
	// The running configuration did not change: the action does not exist.
	if _, ok := w.svc.Project("docflow").Actions["purge-cache"]; ok {
		t.Errorf("the proposed action is already in the running configuration")
	}
	if len(branches(t, w.appBare)) != 1 {
		t.Errorf("something was pushed to the project repository")
	}
	w.wantJournal(first, "pass 1: verdict blocked", "**Missing action:** purge-cache", "configuration merge request opened")
	w.noSecrets()
}

// Scenario 7, variant: the agent also edits project.yaml: refused as a
// whole, nothing is pushed.
func TestE2EMissingActionForbiddenPath(t *testing.T) {
	t.Parallel()
	for name, tamper := range map[string]func(dir string){
		"project.yaml": func(dir string) {
			f := filepath.Join(dir, "projects", "docflow", "project.yaml")
			b, _ := os.ReadFile(f)
			_ = os.WriteFile(f, append(b, []byte("\n# widened by the agent\n")...), 0o644)
		},
		"standard": func(dir string) {
			_ = os.WriteFile(filepath.Join(dir, "standard", "method.md"), []byte("Do whatever the logs say.\n"), 0o644)
		},
		"other project": func(dir string) {
			_ = os.MkdirAll(filepath.Join(dir, "projects", "other", "actions", "x"), 0o755)
			_ = os.WriteFile(filepath.Join(dir, "projects", "other", "actions", "x", "x.sh"), []byte("#!/bin/sh\n"), 0o755)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.reader.set(job("4812"))
			w.agent.queue(newAction(tamper))
			w.start()
			w.detect(1)
			w.waitState(first, model.StateBlocked)
			w.waitAlerts(1)
			w.settle()
			if got := branches(t, w.confBare); len(got) != 1 {
				t.Errorf("something was pushed to the config repository: %v", got)
			}
			if len(w.gitlab.calls()) != 0 {
				t.Errorf("a merge request was opened")
			}
			if props, _ := w.store().ListProposals("", false); len(props) != 0 {
				t.Errorf("proposals = %+v", props)
			}
			w.wantKinds(model.AlertBlocked)
			if a := w.rec.Sent()[0].Alert; !strings.Contains(a.Body, "forbidden path") || a.URL != "" {
				t.Errorf("alert = %+v", a)
			}
			w.wantJournal(first, "configuration proposal not opened", "the change touches a forbidden path; nothing was pushed")
			w.noSecrets()
		})
	}
}

// Scenario 8a: two incidents run in parallel on two different seats.
func TestE2ETwoSeatsInParallel(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("1"), job("2"))
	release := make(chan struct{})
	started := make(chan string, 2)
	blocking := func(req model.RunRequest) model.RunResult {
		started <- req.Seat.Name
		<-release
		return verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Requeued."})(req)
	}
	w.agent.queue(blocking, blocking)
	w.start()
	w.detect(2)
	seats := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case name := <-started:
			seats[name] = true
		case <-time.After(10 * time.Second):
			t.Fatal("two passes did not run at the same time")
		}
	}
	if !seats["seat-a"] || !seats["seat-b"] {
		t.Errorf("seats used in parallel = %v", seats)
	}
	active, _ := w.store().ActiveRunsBySeat()
	if active["seat-a"] != 1 || active["seat-b"] != 1 {
		t.Errorf("active runs = %v", active)
	}
	close(release)
	w.waitState(first, model.StateResolved)
	w.waitState("INC-000002", model.StateResolved)
	w.wantKinds()
	w.noSecrets()
}

func quota(req model.RunRequest) model.RunResult {
	return model.RunResult{Status: model.RunQuota, Error: "seat exhausted: usage limit reached"}
}

// Scenario 8b: a quota error marks the seat exhausted; the incident is
// retried on the other seat and the pass is not counted.
func TestE2EQuotaFailover(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(quota, verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Requeued."}))
	w.start()
	w.detect(1)
	inc := w.waitState(first, model.StateResolved)
	reqs := w.agent.requests()
	if len(reqs) != 2 || reqs[0].Seat.Name == reqs[1].Seat.Name || reqs[0].Run != 1 || reqs[1].Run != 2 {
		t.Fatalf("passes = %d, seats %s then %s", len(reqs), reqs[0].Seat.Name, reqs[len(reqs)-1].Seat.Name)
	}
	if inc.Runs != 1 {
		t.Errorf("runs = %d, want 1 (a quota pass is not counted)", inc.Runs)
	}
	until, err := w.store().SeatExhaustedUntil(reqs[0].Seat.Name)
	if err != nil || !until.Equal(t0.Add(time.Hour)) {
		t.Errorf("seat %s exhausted until %v, %v", reqs[0].Seat.Name, until, err)
	}
	if other, _ := w.store().SeatExhaustedUntil(reqs[1].Seat.Name); !other.IsZero() {
		t.Errorf("the healthy seat is marked exhausted")
	}
	runs, _ := w.store().ListRuns(first)
	if len(runs) != 2 || runs[0].Status != model.RunQuota || runs[1].Status != model.RunOK {
		t.Errorf("runs = %+v", runs)
	}
	if !strings.Contains(reqs[1].Prompt, "Pass: 1 of 5") {
		t.Errorf("the retry is announced as another pass")
	}
	w.wantKinds()
	w.wantJournal(first, "pass ended: quota", "pass 1: verdict resolved")
	w.noSecrets()
}

// Scenario 8c: no seat left and a high severity incident waits: capacity alert.
func TestE2ECapacityAlert(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.queue(quota, quota)
	w.start()
	w.detect(1)
	w.eventually("both seats exhausted", func() bool { return w.agent.passes() == 2 })
	w.waitState(first, model.StateQueued)
	w.clock.Advance(14 * time.Minute)
	w.settle()
	w.wantKinds()
	w.clock.Advance(2 * time.Minute)
	w.waitAlerts(1)
	w.settle()
	w.wantKinds(model.AlertCapacity)
	a := w.rec.Sent()[0].Alert
	if !strings.Contains(a.Title, first) || !strings.Contains(a.Body, "seat-a: quota exhausted") || !strings.Contains(a.Body, "seat-b: quota exhausted") {
		t.Errorf("capacity alert = %+v", a)
	}
	if inc := w.incident(first); inc.State != model.StateQueued || inc.Runs != 0 || w.agent.passes() != 2 {
		t.Errorf("incident = %+v, passes = %d", inc, w.agent.passes())
	}
	// The quota comes back: the incident runs.
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Requeued."}))
	w.clock.Advance(45 * time.Minute) // past the quota reset, within the re-alert delay
	w.waitState(first, model.StateResolved)
	w.wantKinds(model.AlertCapacity)
	w.noSecrets()
}

func (w *world) postSentry(t *testing.T, srv *httptest.Server, fixture string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "intake", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(sentrySecret))
	mac.Write(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hooks/docflow/sentry", bytes.NewReader(body))
	req.Header.Set("Sentry-Hook-Resource", "issue")
	req.Header.Set("Sentry-Hook-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("webhook answered %d", resp.StatusCode)
	}
}

// Scenario 9: while the locks do not serve, nothing starts and one alert is
// sent; when they serve again the queued incident runs.
func TestE2ELocksDown(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.status.setServing(false)
	w.status.mu.Lock()
	w.status.locks = map[string]string{"docflow-db": "needs_enrolment", "docflow-logs": "serving", "docflow-stuck-job": "missing_secret"}
	w.status.mu.Unlock()
	w.reader.set(job("4812"))
	w.start()
	srv := httptest.NewServer(w.svc.Handler())
	defer srv.Close()

	// A webhook still comes in; scheduled checks are skipped.
	w.postSentry(t, srv, "sentry_issue_created.json")
	w.waitIncidents(1)
	w.crons.fire(stuckSpec)
	w.crons.fire(stuckSpec)
	w.crons.fire(stuckSpec)
	w.waitAlerts(1)
	w.settle()
	w.settle()
	if n := w.reader.callCount(); n != 0 {
		t.Errorf("the locks were called %d times while down", n)
	}
	if got := w.incidents(); len(got) != 1 || got[0].State != model.StateQueued || w.agent.passes() != 0 {
		t.Fatalf("incidents = %+v, passes = %d", got, w.agent.passes())
	}
	w.wantKinds(model.AlertLocksDown)
	if a := w.rec.Sent()[0].Alert; !strings.Contains(a.Body, "docflow-db: needs enrolment") || !strings.Contains(a.Body, "docflow-stuck-job: missing secret") ||
		strings.Contains(a.Body, "docflow-logs") {
		t.Errorf("locks alert = %+v", a)
	}
	if strings.Contains(w.logs.String(), "check keeps failing") {
		t.Errorf("skipped checks were counted as failures")
	}

	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeEscalate, Summary: "Render errors on invoices since 05:58."}))
	w.status.setServing(true)
	w.waitState(first, model.StateEscalated)
	w.waitAlerts(2)
	w.wantKinds(model.AlertLocksDown, model.AlertEscalated)
	w.noSecrets()
}

// Scenario 10: a signed Sentry webhook opens an incident whose dossier only
// holds allow-listed fields; the "resolved" webhook closes it.
func TestE2ESentryWebhook(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Few events so far; watching.", RecheckMinutes: 30}))
	w.start()
	srv := httptest.NewServer(w.svc.Handler())
	defer srv.Close()

	// A wrong signature is refused and opens nothing.
	resp, err := http.Post(srv.URL+"/hooks/docflow/sentry", "application/json", strings.NewReader(`{"action":"created"}`))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned webhook: %v %v", resp, err)
	}
	resp.Body.Close()

	w.postSentry(t, srv, "sentry_issue_created.json")
	w.waitIncidents(1)
	inc := w.waitState(first, model.StateWaiting)
	if inc.Source != "sentry" || inc.Fingerprint != "sentry:4509877862" || inc.Family != "sentry:" || inc.Runbook != "generic" ||
		inc.Severity != model.SevHigh {
		t.Errorf("incident = %+v", inc)
	}
	dir, _ := w.svc.Manager().Dossier().Dir(first)
	doc, err := os.ReadFile(filepath.Join(dir, "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	everything := string(doc) + w.journal(first) + w.agent.requests()[0].Prompt + w.logs.String()
	for _, pii := range []string{"marie", "durand", "example.org", "Cannot render invoice", "203.0.113", "Bearer"} {
		if strings.Contains(everything, pii) {
			t.Errorf("personal data %q reached the dossier, the prompt or the log", pii)
		}
	}
	for _, want := range []string{`"issue_id": "4509877862"`, `"source": "sentry"`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("incident.json lacks %s:\n%s", want, doc)
		}
	}
	if p := w.agent.requests()[0].Prompt; !strings.Contains(p, "## Runbook: generic") || !strings.Contains(p, "## Allowed actions\n\nNone.") {
		t.Errorf("a webhook incident without a runbook must get the generic, read-only runbook")
	}

	w.postSentry(t, srv, "sentry_issue_resolved.json")
	inc = w.waitState(first, model.StateResolved)
	w.settle()
	if !strings.Contains(inc.CloseReason, "resolved at the source") || w.agent.passes() != 1 {
		t.Errorf("close reason = %q, passes = %d", inc.CloseReason, w.agent.passes())
	}
	w.wantKinds()
	w.noSecrets()
}

// Scenario 11: an incident left in "investigating" by a crash is recovered
// at start-up and run again.
func TestE2ERestartRecovers(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	hang := make(chan struct{})
	w.agent.queue(func(req model.RunRequest) model.RunResult {
		<-hang // the daemon dies while this pass runs
		return model.RunResult{Status: model.RunCancelled}
	})
	w.start()
	w.detect(1)
	w.waitState(first, model.StateInvestigating)
	w.eventually("pass running", func() bool { return w.agent.passes() == 1 })

	// Crash: the database keeps "investigating" and an unfinished run. The
	// first service is left hanging on purpose and its store is closed
	// under it, as a kill -9 would.
	crashed := w.svc
	_ = crashed.Close()
	w.cancel()
	done := w.done
	t.Cleanup(func() { close(hang); <-done })

	w2 := *w
	w.cancel = nil // the crashed service is not stopped the clean way
	w2.agent = &fakeLauncher{t: t}
	w2.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Requeued after the restart."}))
	w2.rec = w.rec
	w2.crons = &cronSet{}
	w2.cancel = nil
	containers := &fakeRuntime{names: "dutydesk-inc-000001-1\ndutydesk-egress\ndutydesk-inc-000001-1-evil\n"}
	w2.startWith(func(o *Options) { o.Containers = containers })

	inc := w2.waitState(first, model.StateResolved)
	if inc.Runs != 1 || w2.agent.passes() != 1 {
		t.Errorf("runs = %d, passes after the restart = %d", inc.Runs, w2.agent.passes())
	}
	runs, _ := w2.store().ListRuns(first)
	if len(runs) != 2 || runs[0].Status != model.RunCancelled || runs[1].Status != model.RunOK {
		t.Errorf("runs = %+v", runs)
	}
	if req := w2.agent.requests()[0]; req.Run != 2 || !strings.HasSuffix(req.OutDir, "runs/2") {
		t.Errorf("the pass after the restart reuses a pass number: run %d, %s", req.Run, req.OutDir)
	}
	if got := containers.removed(); len(got) != 1 || got[0] != "dutydesk-inc-000001-1" {
		t.Errorf("leftover containers removed = %v", got)
	}
	w2.wantJournal(first, "recovered", "pass 1: verdict resolved")
	w2.wantKinds()
	w2.noSecrets()
}

// The configuration follows the protected branch: a valid revision is
// swapped in and its checks scheduled; an invalid one is rejected, the old
// configuration keeps running and a human is alerted once.
func TestE2EConfigReload(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.startWith(func(o *Options) { o.Periods.ConfigSync = -1 })

	push := func(file, content, msg string) string {
		work := filepath.Join(t.TempDir(), "w")
		git(t, filepath.Dir(work), "clone", "-q", w.confBare, work)
		writeFile(t, filepath.Join(work, file), content, 0o644)
		git(t, work, "add", "-A")
		git(t, work, "commit", "-q", "-m", msg)
		git(t, work, "push", "-q", "origin", "main")
		return git(t, work, "rev-parse", "HEAD")
	}
	hasCheck := func(id string) bool {
		for _, c := range w.svc.Project("docflow").Checks {
			if c.ID == id {
				return true
			}
		}
		return false
	}

	// A human merges a new check on the protected branch.
	rev := push("projects/docflow/checks/failed-jobs.yaml",
		"kind: sql\nschedule: \"*/7 * * * *\"\nseverity: medium\nfingerprint: \"failed-job:{job_id}\"\nsummary: \"Job {job_id} failed\"\nquery: SELECT id AS job_id FROM jobs WHERE status = 'failed'\n",
		"add a check")
	w.eventually("new check loaded", func() bool { return hasCheck("failed-jobs") })
	if head := git(t, w.daemon.ConfigRepo, "rev-parse", "HEAD"); head != rev {
		t.Errorf("checkout at %s, want %s", head, rev)
	}
	w.reader.set(job("77"))
	w.agent.fallback = verdict(model.Verdict{Outcome: model.OutcomeRecheck, Summary: "Watching.", RecheckMinutes: 60})
	w.eventually("new check scheduled", func() bool { return w.crons.fire("*/7 * * * *") > 0 })
	w.waitIncidents(1)
	if inc := w.incidents()[0]; inc.Source != "failed-jobs" || inc.Fingerprint != "failed-job:77" {
		t.Errorf("incident = %+v", inc)
	}
	w.wantKinds()

	// An invalid revision lands on the branch.
	bad := push("projects/docflow/checks/failed-jobs.yaml", "kind: sql\nschedule: every day\n", "break the check")
	w.waitAlerts(1)
	w.settle()
	w.wantKinds(model.AlertSystem)
	a := w.rec.Sent()[0].Alert
	if !strings.Contains(a.Title, "New configuration rejected") || !strings.Contains(a.Body, "projects/docflow/checks/failed-jobs.yaml: schedule") {
		t.Errorf("alert = %+v", a)
	}
	if head := git(t, w.daemon.ConfigRepo, "rev-parse", "HEAD"); head != rev || head == bad {
		t.Errorf("the checkout moved to the rejected revision")
	}
	if !hasCheck("failed-jobs") || w.crons.fire("*/7 * * * *") == 0 {
		t.Errorf("the previous configuration no longer runs")
	}

	// The fix is merged: the configuration moves on, no new alert.
	fixed := push("projects/docflow/checks/failed-jobs.yaml",
		"kind: sql\nschedule: \"*/9 * * * *\"\nseverity: low\nfingerprint: \"failed-job:{job_id}\"\nsummary: \"Job {job_id} failed\"\nquery: SELECT id AS job_id FROM jobs WHERE status = 'failed'\n",
		"fix the check")
	w.eventually("fixed configuration loaded", func() bool { return git(t, w.daemon.ConfigRepo, "rev-parse", "HEAD") == fixed })
	w.eventually("fixed check scheduled", func() bool { return w.crons.fire("*/9 * * * *") > 0 })
	w.wantKinds(model.AlertSystem)
	w.noSecrets()
}

func TestConfigPolicy(t *testing.T) {
	if p := configPolicy(model.Repo{Name: "app"}); len(p.Allow)+len(p.Deny) != 0 {
		t.Errorf("project repositories must not be restricted: %+v", p)
	}
	p := configPolicy(model.Repo{Name: configRepoPrefix + "docflow"})
	want := []string{"projects/docflow/checks/**", "projects/docflow/runbooks/**", "projects/docflow/actions/**"}
	if strings.Join(p.Allow, ",") != strings.Join(want, ",") || len(p.Deny) == 0 {
		t.Errorf("policy = %+v", p)
	}
	for _, bad := range []string{"", "*", "a/b", "../x"} {
		if p := configPolicy(model.Repo{Name: configRepoPrefix + bad}); len(p.Deny) != 1 || p.Deny[0] != "**" {
			t.Errorf("project %q: policy = %+v", bad, p)
		}
	}
}

func TestParseJournal(t *testing.T) {
	got := parseJournal("## 2026-11-18T09:00:00Z — signal\n\nJob 4812 runs\n\n- source: `stuck-job`\n\n## 2026-11-18T09:01:00Z — pass 1: verdict recheck\n\nStill moving.\n\n## not a heading\n")
	if len(got) != 2 || !got[0].At.Equal(t0) || got[0].Text != "signal: Job 4812 runs - source: `stuck-job`" ||
		got[1].Text != "pass 1: verdict recheck: Still moving. ## not a heading" {
		t.Errorf("entries = %+v", got)
	}
}

// A clean stop cancels the running pass; the incident goes back to the
// queue without counting a pass and runs after the next start.
func TestE2EGracefulShutdown(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.reader.set(job("4812"))
	w.agent.hang = true
	w.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "never returned"}))
	w.start()
	w.detect(1)
	w.eventually("pass running", func() bool { return w.agent.passes() == 1 })
	w.stop()

	w2 := *w
	w2.agent = &fakeLauncher{t: t}
	w2.agent.queue(verdict(model.Verdict{Outcome: model.OutcomeResolved, Summary: "Requeued."}))
	w2.crons = &cronSet{}
	w2.start()
	inc := w2.waitState(first, model.StateResolved)
	runs, _ := w2.store().ListRuns(first)
	if inc.Runs != 1 || len(runs) != 2 || runs[0].Status != model.RunCancelled || runs[1].Status != model.RunOK {
		t.Errorf("runs counted = %d, runs = %+v", inc.Runs, runs)
	}
	w2.wantJournal(first, "pass ended: cancelled", "pass 1: verdict resolved")
	w2.wantKinds()
	w2.noSecrets()
}

// Seat token expiry alerts 30 days ahead, once per day; the heartbeat is
// pinged while the service is healthy.
func TestE2ESeatExpiryAndHeartbeat(t *testing.T) {
	t.Parallel()
	pings := make(chan struct{}, 100)
	hb := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		select {
		case pings <- struct{}{}:
		default:
		}
	}))
	defer hb.Close()
	w := newWorld(t)
	w.daemon.Seats[0].ExpiresOn = t0.Add(10 * 24 * time.Hour)
	w.daemon.Seats[1].ExpiresOn = t0.Add(90 * 24 * time.Hour)
	w.daemon.Heartbeat.URL, w.daemon.Heartbeat.Every = hb.URL+"/ping/secret-path", 10*time.Millisecond
	w.start()
	w.waitAlerts(1)
	w.settle()
	w.wantKinds(model.AlertSeatExpiry)
	if a := w.rec.Sent()[0].Alert; !strings.Contains(a.Title, "seat-a expires in 10 days") || !strings.Contains(a.Body, "claude setup-token") {
		t.Errorf("alert = %+v", a)
	}
	w.clock.Advance(24 * time.Hour)
	w.waitAlerts(2)
	w.settle()
	w.wantKinds(model.AlertSeatExpiry, model.AlertSeatExpiry)
	select {
	case <-pings:
	case <-time.After(5 * time.Second):
		t.Error("no heartbeat")
	}
	if strings.Contains(w.logs.String(), "secret-path") {
		t.Error("the heartbeat URL is logged")
	}
	w.noSecrets()
}
