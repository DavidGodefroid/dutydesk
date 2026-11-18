# Changelog

## [0.1.0] - 2026-11-18

First release. **Experimental**: the whole service is covered by tests with
a scripted agent, fake locks and a fake forge, but it has not yet run on a
real host against real locks. Read `docs/deployment.md` §9 (what is still to
verify) before trying it.

DutyDesk needs the Lock Family served unattended by `lox live`
(lockhub#226, not released yet).

### Added

- `dutydesk serve`: the deterministic core.
  - Scheduled checks through the locks (`sql`, `log`, `expect`), with no
    model call; inbound webhooks (Sentry, generic) with signature, replay
    and rate checks, keeping an allow-list of fields only.
  - Incidents: one per fingerprint, storm guard, "check again later" that
    replays the check before waking an agent, recurrence budget per family,
    bounded passes and age.
  - One short-lived Claude Code agent per pass, in an isolated container,
    on a subscription seat; a pool of seats with failover on quota.
  - Validated actions only, through lockssh: an `auto` profile and a
    `green-light` profile per runbook; a green light is a ticket a human
    decides.
  - Merge requests on GitLab and GitHub, opened by the core, never merged;
    default deny-list (CI files, submodules), secret scan, size caps.
  - Missing actions and improvements proposed as merge requests on the
    configuration repository, restricted to checks, runbooks and actions.
  - Alerts only for what needs a human (outgoing webhook, Teams
    compatible), a persisted outbox so nothing owed is lost on a crash, a
    dead-man heartbeat, and a report in SQLite.
- `dutydesk` CLI: `status`, `incidents`, `incident show|close|resume`,
  `seats`, `check run`, `config validate`, `config lockssh-rules`.
- `dutydesk-act`: the launcher of the action catalogue on the action host
  (argument validation, rate limit, timeout, audit log).
- `example/config`: a generic project, `docflow`.
- `agent/Containerfile`: the agent image.
- Documentation: `docs/deployment.md`, `docs/configuration.md`, systemd
  unit, GitLab CI template for a configuration repository.

### Known limits

- The requester of a green-light ticket is not yet verified with lox live.
- The agent's egress is filtered by host, not by credential.
- The secret scan of proposals is a best-effort pattern and substring check.
- `dutydesk/*` branches must run on CI runners without secrets.
- locklog on a production profile needs its client run in its own
  container (see `docs/deployment.md` §5).
