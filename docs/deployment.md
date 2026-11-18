# Deployment

One Linux host, two systemd services, two Unix users:

| User | Service | Holds |
|---|---|---|
| `lox` | `lox live` (hub and locks) | lock policies, Vault AppRole, the façade socket (decisions) |
| `dutydesk` | `dutydesk serve` | seat tokens, forge tokens, the data directory; agents in containers |

DutyDesk must **not** run as the lox user: a process of that user can decide
tickets. DutyDesk only reads lox live's status socket (health, ticket state,
withdrawal of its own tickets) and never decides anything.

## 1. Enrol the locks with lox live

1. As a human at a terminal, run `lox run` in the lock workspace of each
   project (`locks.workspace` in `project.yaml`): review the configuration,
   approve each lock policy, trust the SSH host keys, type the name of each
   production profile. Then enrol the workspace for live mode.
2. Expected rules for DutyDesk: reads `auto`; writes, DDL and queue actions
   `deny`; lockssh profiles as printed by `dutydesk config lockssh-rules`
   (section 6); unmasking, grants and policy loosening always human.
3. Start `lox live` as a service. All secrets come from Vault in live mode.
4. Make the status socket readable by the `dutydesk` user (group
   permission on the socket directory) and set `lox_status_socket`.

While the status socket does not say "serving", DutyDesk starts no agent,
skips its checks and sends one "locks do not serve" alert naming the locks
that need enrolment or a secret.

## 2. Install DutyDesk

```sh
make build && sudo install -m 0755 bin/dutydesk /usr/local/bin/
sudo useradd --system --create-home --home-dir /var/lib/dutydesk --shell /usr/sbin/nologin dutydesk
sudo install -d -o dutydesk -g dutydesk -m 0750 /etc/dutydesk /etc/dutydesk/secrets /etc/dutydesk/mcp
sudo -u dutydesk git clone https://forge.example.com/ops/dutydesk-config.git /var/lib/dutydesk/config
sudo install -m 0644 contrib/systemd/dutydesk.service /etc/systemd/system/
sudo systemctl enable --now dutydesk
```

`/etc/dutydesk/dutydesk.yaml` starts from `example/dutydesk.yaml`
([configuration.md](configuration.md)). With `config_remote` set, the daemon
fetches the protected branch every minute, validates the new revision in a
scratch directory and only then fast-forwards the checkout; an invalid
revision is rejected (the previous configuration keeps running) and alerts.
The checkout must be a clone whose history fast-forwards to that branch.

The unit starts after lox live (`After=lox-live.service`); adapt the name.
With rootless podman, enable lingering: `loginctl enable-linger dutydesk`.

## 3. Seats

A seat is one Claude subscription (a service account).

1. Signed in as that account, run `claude setup-token` and copy the
   long-lived token.
2. Store it in a file owned by `dutydesk`, mode `0600` (`0400` works too);
   anything wider is refused: `/etc/dutydesk/secrets/seat-a.token`.
3. Declare it under `seats:` with `expires_on` (the token lasts one year).
   DutyDesk alerts 30 days before, once a day.

`dutydesk seats` shows running passes and quota state. A seat that runs out
of quota is set aside until its reset time (one hour when unknown) and the
pass is retried on another seat.

Other secret files, all `0600` and owned by `dutydesk`: forge tokens
(`repos[].token_file`, `config_remote.token_file`), the alert webhook URL
(`alerts.webhook_url_file`), inbound webhook secrets (`secret_file`). Forge
service accounts must be unable to push to protected branches or to merge.

## 4. Agent containers: network and egress proxy

Each pass runs in one container: read-only root, tmpfs `/tmp` and
`/home/agent`, non-root user, no capability, `no-new-privileges`, memory,
CPU and pids limits, removed at the end. The launcher refuses to run
without `agent.network`, and refuses the default networks.

Create the network as **internal** (no route out) and attach one egress
proxy that only allows `CONNECT api.anthropic.com:443`:

```sh
podman network create --internal dutydesk-agents
podman network create dutydesk-egress-out
podman run -d --name dutydesk-egress --restart=always \
  --network dutydesk-agents --network dutydesk-egress-out \
  -v /etc/dutydesk/egress/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro \
  registry.example.com/ops/tinyproxy:1
```

```
# tinyproxy.conf (any proxy with a CONNECT allow-list works)
Port 3128
FilterDefaultDeny Yes
Filter "/etc/tinyproxy/filter"      # one line: ^api\.anthropic\.com$
ConnectPort 443
```

Set `agent.https_proxy: http://dutydesk-egress:3128`. The agent has no other
way out: no forge, no package registry, no DNS beyond the network.

At start-up the daemon removes agent containers left by a crash. It only
touches names of the form `dutydesk-inc-<n>-<pass>`: do not name other
containers that way (`dutydesk-egress` is safe).

## 5. Lock clients inside the agent container

The agent image contains no lock client. Two settings bring them in:

- `agent.mcp_config`: a host file mounted read-only at
  `/etc/dutydesk/mcp.json`. It declares one MCP server per lock the runbook
  may use; Claude runs with `--strict-mcp-config` and only the tools
  `mcp__<server>__*` of that file are allowed. Use one file per runbook
  (`/etc/dutydesk/mcp/{project}/{runbook}.json`) so that a pass only gets
  the lockssh profiles of its runbook:

  ```json
  { "mcpServers": {
      "locksql":      { "command": "/opt/lockfamily/bin/locksql",  "args": ["mcp", "--instance", "docflow-db"] },
      "locklog":      { "command": "/opt/lockfamily/bin/locklog",  "args": ["mcp", "--instance", "docflow-logs"] },
      "lockssh":      { "command": "/opt/lockfamily/bin/lockssh",  "args": ["mcp", "--instance", "docflow-stuck-job"] },
      "lockssh_ask":  { "command": "/opt/lockfamily/bin/lockssh",  "args": ["mcp", "--instance", "docflow-stuck-job-ask"] } } }
  ```

- `agent.extra_mounts`: the client binaries (static, or with what they need
  next to them) and the client socket directories / launch material of the
  project's locks, read-only by default.

The lock identity of an agent is per incident: `LEA_AGENT=dutydesk:<incident>`
and a random `LEA_AGENT_TOKEN` kept by the core, the same on every pass, so
a later pass can replay a ticket a human approved. The seat token and this
identity are the only secrets in the container; they travel in an
owner-only env-file, never on a command line.

### Lock clients of the core (checks)

Checks call the lock clients as the agent label `dutydesk:core`.
`lock_clients:` in `dutydesk.yaml` sets the argv of `locksql plan`,
`locksql run` and the locklog MCP client; commands run with the project's
`locks.workspace` as working directory. Defaults are the launchers lox
installs on the host.

**Production limitation.** locklog's host launcher refuses production
profiles (`E_PRODUCTION_HOST_AGENT`), and the host launchers do not forward
`LEA_AGENT` / `LEA_AGENT_TOKEN` for locklog. On production, `log_mcp` must
therefore run the locklog client in its own container with the socket volume
mounted, passing the identity by name:

```yaml
lock_clients:
  log_mcp: [podman, run, --rm, -i, --network, none, -e, LEA_AGENT, -e, LEA_AGENT_TOKEN,
            -v, "/run/lox-live/clients/docflow:/run/locks:ro",
            "registry.example.com/ops/locklog-client:1.0.0", mcp, --instance, "{instance}"]
```

## 6. Action host

Validated actions run on an action host, through lockssh, as scripts with
their own credentials. DutyDesk holds none of them.

1. Install the launcher: `install -m 0755 bin/dutydesk-act /opt/dutydesk/bin/`
   (`action_install_dir`). It validates arguments against the manifest,
   enforces the rate limit, runs the script without a shell and keeps an
   audit log. Environment: `DUTYDESK_ACTIONS_DIR` (default
   `/opt/dutydesk/actions`), state, audit and per-action env files (see
   `cmd/dutydesk-act`). **Over SSH** (`SSH_CONNECTION` / `SSH_CLIENT` set,
   which is how lockssh reaches it) these `DUTYDESK_ACTIONS_*` overrides are
   ignored, unless a root-owned, not group/world-writable
   `/etc/dutydesk/act.conf` holds `allow_env_overrides = true`. The
   catalogue directory, each action directory, each manifest and each script
   must be real directories / regular files: a symbolic link anywhere
   (including a `current -> release` link as catalogue root) is refused.
2. The catalogue is deployed **by the CI of the config repository, from the
   protected branch only** (`contrib/ci/config-repo.gitlab-ci.yml`): each
   project's `actions/` directory lands under `/opt/dutydesk/actions`.
   Script credentials live in `/etc/dutydesk/actions.env.d/<action>.env` on
   the host, never in the repository.
3. The same pipeline publishes `dutydesk config lockssh-rules --project P`
   as an artifact. A human reviews that TOML fragment, merges it into the
   lockssh configuration (adding host, user and key of each profile) and
   approves it in lox, then re-enrols. One profile per runbook and level:
   `action_instance` with `run = "auto"`, `ask_instance` with `run = "ask"`,
   both `exec = false`.

A new action therefore needs two human gestures: merging the merge request,
then validating the rule. Until both, the action does not exist.

Parameter values are restricted to `[A-Za-z0-9._:@=+-]` (no leading `-`),
by the manifest validation, by `dutydesk-act` at run time and, as far as
lockssh globs can express it, by the generated rules (one rule per enum
value). A lockssh glob cannot say "this class, repeated": after a trailing
`*` only `dutydesk-act` refuses a value such as `7;id`. **Verify on each
lockssh upgrade that its exec path does not hand the command line to a
shell unquoted** (the version checked single-quotes every argument for the
account's login shell).

## 7. Podman or Docker

- **Rootless podman (recommended).** The clones mounted read-write belong
  to the `dutydesk` host user; the agent is uid 10001 in the container. Map
  it: `agent.run_args: ["--userns=keep-id:uid=10001,gid=10001"]`. Socket
  directories mounted from lox live must be readable by that mapped uid.
- **Docker.** The daemon socket is root-equivalent: giving it to the
  `dutydesk` user weakens the two-user separation. If you accept that, set
  `runtime: docker` and make the clones writable for the container user:
  either `agent.user: "<uid of dutydesk>:<gid>"`, or user-namespace
  remapping on the Docker daemon.

Build the image with `make image` (`agent/Containerfile`, Claude Code CLI
pinned by `CLAUDE_CODE_VERSION`).

## 8. Webhooks, alerts, heartbeat

- `listen` should be a loopback address behind a reverse proxy with TLS.
  Sentry: an internal integration posting to `/hooks/<project>/<source>`;
  its client secret goes in the webhook's `secret_file`. Only allow-listed
  fields are kept, each cut down to a conservative character class (120
  characters, e-mail / long-number / UUID path segments become `<id>`);
  bodies are never logged or stored. Each source has a token bucket (60
  requests, then 1/s; over it: `429` with `Retry-After`), checked before the
  body is read. A Sentry delivery whose `Sentry-Hook-Timestamp` is more
  than 5 minutes off is refused, and a delivery whose signature was already
  accepted in the last 10 minutes is acknowledged without a second signal.
  The Sentry signature covers the body only, not the timestamp: a captured
  delivery can be replayed once the cache forgot it; it then attaches to the
  open incident of the same fingerprint, or opens one, like any signal.
- Alerts go to the project's outgoing webhook (Teams-compatible). A merge
  request gives a notice; an incident left in `mr_open` (production still
  affected) also alerts. Alerts are **owed** in the database (table
  `outbox`) from the transaction that changes the incident, and delivered
  from there with a backoff (15 s, 1 min, 5 min, then every 15 min) until
  the webhook accepts them, across restarts. The reminder delay runs from
  the last alert that was delivered. Delivery is at-least-once: a crash
  right after the webhook answered can repeat one alert.
- Agent or signal text in an alert is inert: control characters removed,
  Markdown links / images and HTML broken, URLs defanged (`http[:]//…`).
  Only the alert's own link (merge request) is clickable. The title of an
  alert for a webhook incident is `<source> <fingerprint>` (for Sentry:
  source and issue id), never third-party text.
- `heartbeat.url` is pinged while the main loop turns, the store answers
  and the scheduler is alive. The loop itself never waits on a lock, the
  forge, git or a webhook (bounded background pools and the outbox do), so
  a slow lock does not stop the pings. Point it at a dead-man switch that
  alerts when the pings stop.

## 9. Security: what is enforced, what is not

The agent is **untrusted**: a log line, a database row or an alert can carry
text that takes it over. Its verdict, the files it wrote and its transcript
are attacker-controlled input to the core.

### Operator duties

- **CI on `dutydesk/*` branches.** DutyDesk pushes the agent's change to a
  `dutydesk/<incident>-…` branch *before* any human reads it. By default a
  merge request may not touch `.gitlab-ci.yml`, `.gitlab/`, `.github/`,
  `.circleci/`, `.woodpecker*`, `.drone.yml`, `.buildkite/`, `.travis.yml`,
  `Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`,
  `.gitmodules` and `.gitattributes` (`repos[].deny_paths` /
  `allow_paths` in project.yaml change the list; a refused change is not
  pushed and the incident escalates with the reason). That is not enough:
  an existing pipeline runs whatever the branch contains (a test, a
  Makefile, a build script, an included CI file elsewhere in the tree).
  **Pipelines of `dutydesk/*` branches must run on runners that hold no
  secret, or be manual** (GitLab: `rules: - if: $CI_COMMIT_BRANCH =~
  /^dutydesk\// → when: manual`, protected variables only on protected
  branches; GitHub: no secrets for the service account's pushes, required
  approval for workflows).
- **Size-limit `<data_dir>/work`.** The clones of a pass are writable by
  the agent. Put `<data_dir>/work` on its own size-limited file system (a
  quota'd volume, or a dedicated partition) so that a pass cannot fill the
  disk the database lives on. The core refuses to propose a tree above
  200 000 entries or 2 GiB, caps the transcript it keeps per pass
  (`agent.max_transcript_bytes`, 20 MiB), opens modes before removing a
  work directory and raises a system alert when a removal fails; with
  rootless podman and `--userns=keep-id` the files belong to the
  `dutydesk` user and can be removed.
- **Retention.** Transcripts of resolved incidents are removed after
  `retention.transcripts` (30 days), dossiers and rows after
  `retention.incidents` (180 days).

### Enforced by the core

- Budgets on every path that leads to another pass: `max_runs` (runbook)
  and `max_incident_age` apply to rechecks, green lights and failed passes;
  green-light rounds (`max_green_lights`, 3) and passes lost to an
  exhausted seat (`max_quota_runs`, 3) are bounded; the age limit is also a
  timer for queued and waiting incidents.
- A `resolved` verdict is checked: when the incident has a deterministic
  check (its origin check or the runbook's `recheck_check`), the check is
  replayed; while it fires (or cannot be replayed) the verdict is handled
  as a recheck. Per family, once `recurrence_count` incidents were resolved
  within `recurrence_window`, the next one is opened `escalated` with an
  alert and no agent pass (`dutydesk incident resume` starts one anyway).
- Green-light tickets: only `<runbook ask_instance>/<id>`, recorded once
  for one incident; a ticket presented twice, held by another incident, or
  reported `consumed` while the incident waits, escalates. DutyDesk
  withdraws only tickets it recorded that way.
- Quota: a pass counts as "seat exhausted" only on the CLI's own final
  error result; whatever reset time it reports, a seat is out for at most
  `quota_cap` (5 h, hard maximum 24 h). All seats out: one capacity alert.
- The container of a pass is removed and its absence verified
  (`rm -f`, `inspect`) however the pass ended; if it cannot be removed, a
  system alert is raised and the seat is not reused until it is gone. An
  incident that leaves `investigating` (closed with the CLI, resolved by
  its source) has its pass cancelled and its container killed at the next
  loop turn.
- Proposals: the base commit of a clone is the one the core recorded when
  it cloned (kept in the outbox across restarts), never anything read from
  the clone; on the configuration repository no symbolic link is accepted
  and only paths *below* `checks/`, `runbooks/`, `actions/` of the project;
  the configuration loader and `dutydesk-act` refuse symbolic links.
- Journal, alerts, terminal: agent and signal text is stripped of control
  characters, block-quoted in the journal under headings only the core
  writes, and presented to later passes as quoted data.

### Residual risks (accepted, know them)

- **The secret scan is best effort.** Before a push the core looks for the
  literal secrets it knows (seat tokens, agent tokens, forge tokens,
  webhook secrets) in plain, base64, reversed and hex form, and for common
  token patterns. It is a substring / pattern check, not a guarantee: a
  secret split over lines, encrypted, compressed or otherwise transformed
  passes. The real protections are that the agent holds only its seat
  token and that a human reviews every merge request.
- **Egress is allow-listed by host, not by account.** The container may
  reach the Anthropic API host. An injected agent that was handed an
  attacker's API key (in a log line, say) could send masked data to that
  account through the allowed host. Masking by the locks bounds what can
  leave; nothing in DutyDesk prevents the channel.
- **Agent containers share one internal network.** Passes that run at the
  same time can reach each other on it. Prefer a runtime setup without
  inter-container connectivity (one network per seat or per pass, each with
  its own proxy leg; docker: `-o com.docker.network.bridge.enable_icc=false` on the network; podman:
  `--opt isolate=true`). The launcher takes one network name
  (`agent.network`); a per-pass network is not implemented.
- **The requester of a ticket is not verified.** DutyDesk checks the shape
  and the ownership of the ticket id the agent reports, not that the hub
  issued it to this incident's agent identity. That check belongs to
  lox live (expose the requester on the status socket; DutyDesk then
  refuses a ticket requested by another identity). Until then: an agent can
  point its incident at a ticket of the same ask instance that it did not
  create, if it learns the id; the human who decides still sees the real
  command at the hub.
- **The seat token is in the agent container.** An injected agent can use
  the seat's quota; it cannot keep the seat out for more than `quota_cap`
  through DutyDesk.
- **Forged final result.** A pass is `quota` when the last `result` line
  of the CLI's output says so. An agent that manages to print such a line
  after the CLI's own result is believed; the cap and `max_quota_runs`
  bound the effect.

## 10. Known limitations and items to verify on a real host

| Where | Item | What to check |
|---|---|---|
| `lox live` | The status socket protocol (`GET /v1/health`, `GET /v1/tickets/{instance}/{id}`, `POST …/withdraw`) is DutyDesk's expectation of lox live | Match it with the delivered lox live; adapt `internal/lockcli/status.go` |
| `internal/lockcli/logcount.go` | `log_query` → locklog arguments mapping is DutyDesk's own convention | Queries of your checks give the intended locklog filter |
| `internal/lockcli/logcount.go` | locklog's host launcher refuses production profiles (`E_PRODUCTION_HOST_AGENT`) | Use the own-container `log_mcp` template above on production |
| `internal/lockcli/logcount.go` | A count split over continuations: the last complete answer is assumed to hold the whole count | Compare one check with a manual count |
| `internal/lockcli/logcount.go` | "No console" is recognised from the `lox run` wording of the tool error | Stop the console and run `dutydesk check run … --dry-run` |
| `internal/lockcli/reader.go` | Host launchers do not forward `LEA_AGENT` / `LEA_AGENT_TOKEN`; locksql gets them through `LOCKSQL_DOCKER_ARGS`, locklog has no such override | The audit shows `dutydesk:core` for check reads |
| `internal/intake/sentry.go` | Sentry is assumed to send `Sentry-Hook-Resource`; otherwise the resource is inferred from the payload | Send a test alert from the integration |
| `internal/agent/launcher.go` | `--permission-mode dontAsk` with `StructuredOutput` in `--allowedTools` returns a verdict | **Confirmed on 2.1.327 by a real run** |
| `internal/agent/launcher.go` | `--max-turns` is accepted by the pinned CLI version | **Confirmed on 2.1.327 by a real run** |
| `internal/agent/launcher.go` | `structured_output` is a JSON object on the `result` event (`result` holds the same verdict as a JSON string; both are accepted) | **Confirmed on 2.1.327** (`internal/agent/testdata/real-2.1.327.jsonl`) |
| `internal/agent/verdict.go` | Claude's structured output honours `minLength`, `maxLength`, `maxItems`, `pattern`, `additionalProperties` (the core re-validates anyway) | A too-long field gives a failed pass, not a truncated verdict |
| `internal/agent/stream.go` | `resetsAt` of a `rate_limit_event` (`rate_limit_info.resetsAt`) is Unix seconds | **Confirmed on 2.1.327** (same capture; the observed status was `allowed_warning`, which is not a quota outcome) |
| `internal/agent/launcher.go` | A usage-limit end is an error `result` event with `api_error_status` 429 or the limit wording; the `rejected` status of a `rate_limit_event` only supplies the reset time (none observed live) | A real exhausted seat is reported as `quota`, not `failed` |
| lockssh | An `allow` rule in automatic execution on a **production** profile; two lockssh instances per runbook on one host | Enrol both profiles; run one auto and one green-light action |
| Agent container | Socket directories readable by the mapped agent uid; lock clients runnable from `agent.extra_mounts` | `podman run` the image with the same mounts and start each MCP server |
| Core | One lox live status socket for all workspaces (`lox_status_socket`) | Several workspaces need one daemon each, or a socket per workspace |
| Core | "Locks down" is alerted once per daemon run; a restart alerts again | — |
| Core | A refused *improvement* proposal (forbidden path) is journaled, not alerted, unless the incident already alerts | — |
| Core | A merge request that fails for a reason that may pass (forge unreachable) is retried 5 times with the outbox backoff, then reported like a refusal | — |
| `lox live` | The requester of a ticket is not exposed on the status socket (see §9, residual risks) | Add it to lox live; refuse foreign tickets in `internal/incident` |
| lockssh | The exec path quotes every argument for the login shell | Re-check on each lockssh upgrade |
| Core | Runs of the project test suite are left to the merge request's CI | — |
