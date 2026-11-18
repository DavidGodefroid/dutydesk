# Configuration

Two things configure DutyDesk:

- `dutydesk.yaml`, the daemon's own file, on the host (no secret inside,
  only paths to files the `dutydesk` user alone can read);
- the **config repository**, a git repository with a protected branch,
  reviewed by humans. The daemon loads it only from its local checkout of
  that branch, never from an agent workspace.

Every YAML file is strict: an unknown key is an error. `dutydesk config
validate [DIR]` reports every problem as `<file>: <field>: <why>`.

## dutydesk.yaml

See `example/dutydesk.yaml` for a commented file. Relative paths are taken
from the file's directory.

| Key | Meaning | Default |
|---|---|---|
| `data_dir` | database (`dutydesk.db`), incident dossiers, work directories | required |
| `config_repo` | local checkout of the config repository | required |
| `config_remote.url`, `.branch`, `.token_file` | when set, the daemon fetches and fast-forwards the checkout itself and agents get a throwaway clone for proposals | off; branch `main` |
| `config_remote.forge`, `.project` | where configuration merge requests are opened | `gitlab`; URL path without `.git` |
| `listen` | `host:port` of the webhook endpoint (`POST /hooks/{project}/{source}`, `GET /healthz`) | off |
| `runtime` | `podman` or `docker` | `podman` |
| `agent_image` | image of the agent container | required |
| `lox_status_socket` | read-only status socket of lox live | required |
| `action_install_dir` | where `dutydesk-act` lives on the action hosts | `/opt/dutydesk/bin` |
| `seats[].name`, `.token_file`, `.max_parallel`, `.expires_on` | Claude subscription seats | at least one; 1 pass per seat |
| `max_parallel_runs` | agent passes at once, all projects | sum of the seats |
| `claude_model` | `claude --model` | CLI default |
| `heartbeat.url`, `.every` | dead-man switch ping while healthy | off; `1m` |
| `agent.network` | pre-created **internal** container network | required |
| `agent.https_proxy`, `agent.no_proxy` | egress proxy as seen from that network | none |
| `agent.mcp_config` | host path of the MCP config mounted at `/etc/dutydesk/mcp.json` | required |
| `agent.extra_mounts[]` | `host:container[:ro\|rw]`: lock client binaries and sockets | none; read-only |
| `agent.user` | numeric `uid[:gid]` in the container, never root | `10001:10001` |
| `agent.run_args[]` | extra `run` flags (`--userns=…`); isolation flags are refused | none |
| `agent.memory`, `agent.cpus`, `agent.pids_limit` | container limits | `4g`, `2`, `512` |
| `lock_clients.sql_plan`, `.sql_run`, `.log_mcp` | argv templates of the lock clients used by checks; `{instance}`, `{plan_id}` | the launchers lox installs |
| `lock_clients.env`, `.timeout` | extra environment; bound of one lock call | none; `30s` |

`agent.mcp_config` and `agent.extra_mounts` accept `{project}`, `{runbook}`,
`{action_instance}`, `{ask_instance}` and `{incident}`: give each runbook its
own MCP file so that a pass only sees the lockssh profiles of its runbook.

## Config repository

```
standard/method.md              investigation method given to every agent
standard/mr-rules.md            merge request rules (a project may override)
standard/runbooks/*.md          standard runbooks; generic.md (applies_to ["*"]) is required
projects/<slug>/project.yaml    repos, locks, limits, alerts, seats, webhooks
projects/<slug>/checks/*.yaml   scheduled checks
projects/<slug>/runbooks/*.md   one runbook per incident family
projects/<slug>/actions/<name>/ action.yaml + script
projects/<slug>/mr-rules.md     optional override
```

### project.yaml

```yaml
name: Docflow
repos:                       # code repositories agents may read and patch
  - name: app
    forge: gitlab            # gitlab | github
    url: https://gitlab.example.com/acme/docflow.git
    project: acme/docflow
    default_branch: main
    token_file: /etc/dutydesk/secrets/gitlab-docflow.token
locks:
  workspace: /srv/locks/docflow   # directory holding .lockfamily/
  sql: docflow-db                 # locksql instance (optional: log, mq, file)
limits: { max_open_per_check: 10, max_runs_per_incident: 6, max_incident_age: 24h,
          run_timeout: 20m, max_turns: 60, max_parallel_runs: 2, green_light_timeout: 2h,
          queue_alert_after: 15m, recurrence_count: 3, recurrence_window: 168h, reminder_every: 24h }
alerts:
  webhook_url_file: /etc/dutydesk/secrets/docflow-alerts.url   # Teams-compatible webhook
seats: [seat-a, seat-b]      # empty = every seat
webhooks:
  sentry:                    # POST /hooks/docflow/sentry
    kind: sentry             # sentry | generic
    secret_file: /etc/dutydesk/secrets/sentry-docflow.secret
    severity: high
    # generic only: fingerprint: "queue:{queue}", fields: {queue: alert.labels.queue}
    # runbook: some-runbook  (default: match by applies_to, else generic)
```

`green_light_timeout` is capped at 4 hours (a production ticket expires at
the hub then).

### Checks

```yaml
kind: sql                    # sql | log | expect
schedule: "*/5 * * * *"      # 5-field cron
severity: high               # low | medium | high | critical
fingerprint: "stuck-job:{job_id}"   # dedup key; {name} = a column of the row
summary: "Job {job_id} has been running since {started_at}"
query: SELECT id AS job_id, started_at FROM jobs WHERE …
```

- `sql`: each returned row is a signal (at most 500).
- `log`: `log_query`, `log_window`, `threshold`: one signal when the count
  reaches the threshold (fields `count`, `window`, `threshold`).
- `expect`: `source: sql|log`; one signal when the expected thing is
  **absent** (no row, or a count under `threshold`).

Templates only know `{name}` placeholders; the literal part of the
fingerprint is the incident **family** (recurrence, known problems).

### Runbooks

Markdown with a YAML front matter:

```yaml
---
applies_to: [stuck-job]            # check ids or webhook source ids; "*" = fallback
actions: [requeue-job, skip-document, reset-job-status]
action_instance: docflow-stuck-job       # lockssh profile, run = "auto": the auto actions
ask_instance: docflow-stuck-job-ask      # lockssh profile, run = "ask": the green-light actions
recheck_default: 20m
recheck_check: stuck-job           # check replayed at wake-up (webhook incidents)
max_runs: 5
---
```

lockssh decides "runs at once" or "ticket" per profile, so a runbook has one
instance per level: `action_instance` is required when it lists auto actions,
`ask_instance` when it lists green-light actions, and the two must differ.
Standard runbooks run no action.

### Actions

`actions/<name>/action.yaml` next to its script:

```yaml
description: Put a job that no longer progresses back in the queue.
level: auto                  # auto | green-light
script: requeue-job.sh
params:                      # rendered as --name value, in this order
  - { name: job-id, type: int, min: 1, max: 999999999999 }
  - { name: status, type: enum, enum: [queued, done] }
  - { name: document-id, type: string, pattern: "^doc-[0-9a-f]{8,32}$" }
rate_limit: { count: 6, window: 1h }
timeout: 60s
```

A value never contains `/`, whitespace or a leading `-`. The command an agent
sends is `<action_install_dir>/dutydesk-act <name> --param value …`, exactly
what the lockssh allow rule matches.

### What an agent may propose

An agent can propose changes to the config repository (missing action,
improvement) only under `projects/<its project>/checks/`, `runbooks/` and
`actions/`. A proposal touching `project.yaml`, `standard/` or another
project is refused as a whole. Nothing applies until a human merges; a new
action also needs its lockssh rule validated in lox.
