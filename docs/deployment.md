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
   `cmd/dutydesk-act`).
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
  fields are kept; bodies are never logged or stored.
- Alerts go to the project's outgoing webhook (Teams-compatible). A merge
  request gives a notice; an incident left in `mr_open` (production still
  affected) also alerts.
- `heartbeat.url` is pinged while the main loop turns, the store answers
  and the scheduler is alive. Point it at a dead-man switch that alerts
  when the pings stop.

## 9. Known limitations and items to verify on a real host

| Where | Item | What to check |
|---|---|---|
| `lox live` | The status socket protocol (`GET /v1/health`, `GET /v1/tickets/{instance}/{id}`, `POST …/withdraw`) is DutyDesk's expectation of lox live | Match it with the delivered lox live; adapt `internal/lockcli/status.go` |
| `internal/lockcli/logcount.go` | `log_query` → locklog arguments mapping is DutyDesk's own convention | Queries of your checks give the intended locklog filter |
| `internal/lockcli/logcount.go` | locklog's host launcher refuses production profiles (`E_PRODUCTION_HOST_AGENT`) | Use the own-container `log_mcp` template above on production |
| `internal/lockcli/logcount.go` | A count split over continuations: the last complete answer is assumed to hold the whole count | Compare one check with a manual count |
| `internal/lockcli/logcount.go` | "No console" is recognised from the `lox run` wording of the tool error | Stop the console and run `dutydesk check run … --dry-run` |
| `internal/lockcli/reader.go` | Host launchers do not forward `LEA_AGENT` / `LEA_AGENT_TOKEN`; locksql gets them through `LOCKSQL_DOCKER_ARGS`, locklog has no such override | The audit shows `dutydesk:core` for check reads |
| `internal/intake/sentry.go` | Sentry is assumed to send `Sentry-Hook-Resource`; otherwise the resource is inferred from the payload | Send a test alert from the integration |
| `internal/agent/launcher.go` | `StructuredOutput` may need an allow rule under `--permission-mode dontAsk` (listed to be safe) | One real pass returns a verdict |
| `internal/agent/launcher.go` | `--max-turns` is accepted by the pinned CLI version | `claude -p --max-turns 1` in the image |
| `internal/agent/launcher.go` | `structured_output` is the JSON object itself (a JSON string holding it is accepted too) | Inspect one `transcript.jsonl` |
| `internal/agent/verdict.go` | Claude's structured output honours `minLength`, `maxLength`, `maxItems`, `pattern`, `additionalProperties` (the core re-validates anyway) | A too-long field gives a failed pass, not a truncated verdict |
| `internal/agent/stream.go` | `resetsAt` of a rate-limit event is Unix seconds | Seat reset time after a real quota error (`dutydesk seats`) |
| `internal/agent/stream.go` | An assistant message standing for an API error carries `error: rate_limit \| billing_error …` | Same |
| `internal/agent/stream.go` | Wording of usage-limit messages (patterns from CLI 2.1.327, none observed live) | A real exhausted seat is reported as `quota`, not `failed` |
| lockssh | An `allow` rule in automatic execution on a **production** profile; two lockssh instances per runbook on one host | Enrol both profiles; run one auto and one green-light action |
| Agent container | Socket directories readable by the mapped agent uid; lock clients runnable from `agent.extra_mounts` | `podman run` the image with the same mounts and start each MCP server |
| Core | One lox live status socket for all workspaces (`lox_status_socket`) | Several workspaces need one daemon each, or a socket per workspace |
| Core | "Locks down" is alerted once per daemon run; a restart alerts again | — |
| Core | A refused *improvement* proposal (forbidden path) is journaled, not alerted, unless the incident already alerts | — |
| Core | Runs of the project test suite are left to the merge request's CI | — |
