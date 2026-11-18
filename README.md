# DutyDesk

DutyDesk is an autonomous incident manager for projects in production. It
watches (scheduled checks, inbound alerts), investigates (one short-lived
agent per incident pass), unblocks (validated actions only) and, when the
cause is in the code, proposes the fix as a merge request it never merges.
Humans are alerted only for what it cannot solve alone.

DutyDesk is a **service**, not an agent: while everything is fine it spends
no token. Every access to production goes through the Lock Family (masking
and query control happen there, outside DutyDesk).

## Architecture

```
 cron checks ─▶ ┌───────────────────── dutydesk serve (Go) ─────────────────────┐
 webhooks    ─▶ │ signals → incidents (dedup, storm guard) → queue → dispatcher │
 (Sentry…)      │    │ reads through lock clients          │ one container/pass │
                │    ▼                                      ▼                    │
                │  internal/check, intake            agent: claude -p, dossier,  │
                │  internal/incident, store          repo clones, lock MCP only  │
                └───────────────┬────────────────────────────┬──────────────────┘
                                ▼                            ▼
                  Lock Family (served by lox live): db · logs · queues · files · action host
 core ─▶ forge (clone, push dutydesk/* branch, open MR — never merge)
 core ─▶ alerts (outgoing webhook) · report (SQLite) · heartbeat (dead-man switch)
```

- The agent thinks, the core acts: an agent holds no production or forge
  secret; its only outputs are a structured verdict and edits in throwaway
  clones, both checked by the core before anything leaves.
- The memory of an incident is its dossier on disk, never an agent session.
- Writes to production exist only as catalogue actions run through lockssh.

| Package | Role |
|---|---|
| `internal/model` | shared types and ports |
| `internal/config` | config repository and `dutydesk.yaml` loading, validation |
| `internal/check`, `internal/intake` | scheduled checks; signed webhooks (Sentry, generic) |
| `internal/incident`, `internal/store` | lifecycle, dossier; SQLite report |
| `internal/seat`, `internal/agent` | seat pool; prompt, container launcher, verdict |
| `internal/lockcli` | lock clients for checks; lox live status socket |
| `internal/actions`, `cmd/dutydesk-act` | action manifests, lockssh rules; launcher on the action host |
| `internal/forge`, `internal/notify` | merge requests (GitLab, GitHub); alerts, heartbeat |
| `internal/core`, `cmd/dutydesk` | the dispatcher wiring everything; daemon and CLI |

## Quick start (with the example)

```sh
make build                                   # bin/dutydesk, bin/dutydesk-act
bin/dutydesk config validate example/config  # validate the example config repository
bin/dutydesk config lockssh-rules --project docflow --dir example/config

cp example/dutydesk.yaml /tmp/dutydesk.yaml  # then adapt data_dir, seats, sockets
bin/dutydesk serve --config /tmp/dutydesk.yaml
```

Without a reachable lox live status socket the daemon starts, reports
"locks do not serve" and runs no agent: that is the expected closed state.
A real installation is described in [docs/deployment.md](docs/deployment.md);
the file formats in [docs/configuration.md](docs/configuration.md).

## CLI

```
dutydesk serve                                  the daemon
dutydesk status [--json]                        locks, seats, queue, open incidents by state
dutydesk incidents [--project P] [--all] [--json]
dutydesk incident show ID [--json]              state, journal, passes, signals
dutydesk incident close ID [--reason TEXT]      a human decides it is over
dutydesk incident resume ID                     queue a new agent pass
dutydesk seats                                  seats and quota state
dutydesk check run ID --project P [--dry-run]   evaluate one check through the locks
dutydesk config validate [DIR]
dutydesk config lockssh-rules --project P       TOML fragment a human reviews in lox
dutydesk version
```

`--config FILE` (or `$DUTYDESK_CONFIG`, `./dutydesk.yaml`,
`/etc/dutydesk/dutydesk.yaml`). Exit codes: 0 ok, 1 error, 2 usage. The CLI
works on the data directory directly (SQLite WAL), next to a running daemon.

## Development

```sh
make test    # go test -race ./...
make lint    # go vet + gofmt check
make image   # agent container image
```

The end-to-end suite (`internal/core/e2e_test.go`) runs the whole service
with a scripted agent, fake locks, a local bare git repository and a fake
GitLab API: no Claude, no production.
