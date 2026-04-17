---
description: Run a command in a persistent shell session; cwd persists
---

# `ssh_shell_exec`

**Tier:** dangerous | **Group:** `shell` | **Tags:** `{dangerous, group:shell}`

Execute `command` in the session identified by `session_id`. The session's
stored cwd is restored at the start (`cd <cwd>`), then the command runs,
then a sentinel reports the new `$PWD` -- the registry updates its stored
cwd accordingly. Exit code and stderr behave identically to `ssh_exec_run`:
non-zero exit is data, not raised.

Command allowlist applies (same as `ssh_exec_run`): first token checked
against per-host `command_allowlist` + env `SSH_COMMAND_ALLOWLIST`. Empty
allowlist rejects everything unless `ALLOW_ANY_COMMAND=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `session_id` | str | yes | -- | From `ssh_shell_open` |
| `command` | str | yes | -- | Allowlist-checked first token |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Per-call seconds |

## Returns

Extends `ExecResult` with:
- `session_id`: echoes input
- `cwd`: the session's cwd AFTER this command (reflects any `cd` the command did)

Sentinel line is stripped from `stdout` -- you see exactly what the command
printed, not our tracking marker.

## When to call it

- Second+ step of a multi-command investigation started with `ssh_shell_open`.
- `cd` to a directory, then a series of relative `ls` / `cat` / `find`.

## When NOT to call it

- One-off commands -- `ssh_exec_run` is simpler.
- Command relies on env vars set earlier -- MVP doesn't track env. Inline the
  `export VAR=... && <command>` each time, or use `ssh_exec_script`.

## Example

```python
s = ssh_shell_open(host="web01")
sid = s["session_id"]

ssh_shell_exec(session_id=sid, command="cd /var/log/nginx")
# -> {cwd: "/var/log/nginx", stdout: "", exit_code: 0}

ssh_shell_exec(session_id=sid, command="ls -la access.log")
# -> ls output for /var/log/nginx/access.log

ssh_shell_exec(session_id=sid, command="cd .. && pwd")
# -> stdout="/var/log\n", cwd="/var/log"
```

## Common failures

- `unknown session_id` -- session wasn't opened or was already closed.
- `CommandNotAllowed` -- allowlist rejects the first token.
- Sentinel not found in stdout (e.g. command killed by signal, output
  truncated past cap) -- cwd is preserved unchanged; `ExecResult` still
  returns with `stdout_truncated=true` if applicable.

## Related

- [`ssh_shell_open`](../ssh-shell-open/SKILL.md)
- [`ssh_shell_close`](../ssh-shell-close/SKILL.md)
- [`ssh_exec_run`](../ssh-exec-run/SKILL.md)
