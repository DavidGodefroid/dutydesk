# DutyDesk agent image

One container per agent pass. The image holds the Claude Code CLI (pinned by
the `CLAUDE_CODE_VERSION` build argument), Node, git and CA certificates, and
a non-root `agent` user (uid/gid 10001). It has no container client and no
curl, wget or ssh client; the build fails if one is present. The entrypoint is
`claude`; the launcher (`internal/agent`) supplies every argument and sends
the prompt on stdin.

```
podman build -t dutydesk-agent:2.1.327 --build-arg CLAUDE_CODE_VERSION=2.1.327 -f Containerfile .
```

## What the launcher provides at run time

- read-only root file system, tmpfs on `/tmp` and `/home/agent`, no
  capabilities, `no-new-privileges`, memory / CPU / pids limits;
- an internal network whose only way out is a proxy to the Anthropic API
  (created by the operator, see `Config` in `internal/agent/launcher.go`);
- mounts: `/work/dossier` (ro), `/work/repos/<name>` (rw), `/work/config`
  (rw, optional), `/etc/dutydesk/mcp.json` (ro);
- the environment through an owner-only env-file: the seat token
  (`CLAUDE_CODE_OAUTH_TOKEN`), the lock agent identity (`LEA_AGENT`,
  `LEA_AGENT_TOKEN`) and the proxy variables.

With rootless podman, the mounted clones belong to the host user: pass
`--userns=keep-id:uid=10001,gid=10001` (launcher `RunArgs`) so the `agent`
user can write them.

## Integration point: lock clients

The image deliberately contains no lock client. The clients of the Lock
Family become available through mounts configured on the host:

- `MCPConfigPath`: a host file mounted at `/etc/dutydesk/mcp.json`. It declares
  one MCP server per lock of the project (`mcpServers`), each with the command
  to start its client inside the container. Claude runs with
  `--strict-mcp-config`, so these are the only MCP servers, and the launcher
  allows exactly the tools `mcp__<server>__*` of the servers named there.
- `ExtraMounts`: the launch material those commands need, read-only: the
  client binaries (statically linked, or with what they need next to them) and
  the socket directories of the locks.

Both settings accept `{project}`, `{runbook}`, `{action_instance}`,
`{ask_instance}` and `{incident}`, so the container of a pass receives only
the lockssh sockets of its runbook's profiles (see `docs/deployment.md`). The lock clients read the agent identity from
`LEA_AGENT` / `LEA_AGENT_TOKEN`.

To be settled when wiring a real workspace: where `lox live` exposes the
client binaries and sockets on the host, and whether the socket directories
are readable by the mapped `agent` uid.
