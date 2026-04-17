---
description: Long-running command with streamed progress; FastMCP background task
---

# `ssh_exec_run_streaming`

**Tier:** dangerous | **Group:** `exec` | **Tags:** `{dangerous, group:exec}`
**Task mode:** `optional` (sync for short calls, background for long ones)

Same shape as `ssh_exec_run`, but uses `asyncssh.create_process` so the MCP
server reads stdout/stderr incrementally. Each chunk is forwarded to the
FastMCP `Progress` channel -- clients that surface task progress (Claude
Desktop, Claude Code) show the latest output line while the command runs.

`task=TaskConfig(mode="optional", poll_interval=3s)` -- the client can call
this synchronously for a short command or invoke as a background task and
poll for progress over the MCP task protocol.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `command` | str | yes | -- | Full shell command. Caller owns quoting. |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Per-call timeout in seconds. **Set this generously for long-running commands.** |

## Returns

Same `ExecResult` shape as `ssh_exec_run`.

## When to call it

- Builds, deploys, restores -- anything that runs minutes, not seconds.
- `tail`-style commands when you want to see partial output flowing.
- Bulk operations (rsync, restic, big SQL imports).

## When NOT to call it

- A short command that returns in under a second -- use `ssh_exec_run`.
- Anything where you don't want the partial output streamed to clients.
- Production deployments without a Redis docket backend -- task state lives in memory and is **lost on MCP server restart**. The lifespan emits a WARNING for this combination; set `FASTMCP_DOCKET_URL=redis://...` to fix.

## Example

```python
ssh_exec_run_streaming(
    host="web01",
    command="apt-get -y upgrade",
    timeout=600,
)
# As it runs, the client sees progress messages like "stdout: Setting up libfoo (1.2-3) ..."
```

## Backend note

In-memory tasks survive only the lifetime of the MCP server process. For long-running operations you can't afford to lose, configure Redis:

```bash
export FASTMCP_DOCKET_URL=redis://localhost:6379
```

The lifespan logs a WARNING when `ALLOW_DANGEROUS_TOOLS=true` and the docket
backend is in-memory. See [DECISIONS.md ADR-0011](../../DECISIONS.md).

## Common failures

- `CommandNotAllowed` -- first token isn't on the allowlist.
- `timed_out=true` -- terminate + pkill attempted; partial output preserved up to the cap.
- `ConnectError` -- transport failure mid-stream.

## Related

- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- synchronous, simpler, no progress.
- [`ssh_exec_script`](../ssh-exec-script/SKILL.md) -- for scripted long-runners (use streaming + script-via-stdin pattern by combining concepts; this tool takes a single command).
