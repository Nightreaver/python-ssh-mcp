---
description: Open a persistent shell session (cwd persists across ssh_shell_exec calls)
---

# `ssh_shell_open`

**Tier:** dangerous | **Group:** `shell` | **Tags:** `{dangerous, group:shell, persistent-session}`

Create a logical shell session on a host. Returns a `session_id` used by
subsequent `ssh_shell_exec` / `ssh_shell_close` calls. The session tracks
the current working directory across invocations -- a `cd /var/log` in one
call persists to the next.

No real remote PTY is held. Each `ssh_shell_exec` opens a fresh channel,
prefixes the command with `cd <session.cwd>`, and reads back the new `$PWD`
from a sentinel. That keeps the server stateless at the SSH layer while the
shell state lives in memory on the MCP side.

**POSIX-only.** The sentinel mechanism depends on POSIX shell semantics
(`sh`, `$PWD`, `cd ~`). Windows targets raise `PlatformNotSupported`;
there's no PowerShell branch and persistent shells on Windows hosts are
out of scope for this MVP.

## Gates (all must pass)

| Level | Knob | Default | Effect |
|---|---|---|---|
| tier | `ALLOW_DANGEROUS_TOOLS` env | `false` | closed = tool hidden from catalog |
| group | `SSH_ENABLED_GROUPS` env | all groups enabled | must include `shell` |
| feature | `ALLOW_PERSISTENT_SESSIONS` env | `true` | false = every tool tagged `persistent-session` is hidden via a Visibility transform. Hits `ssh_shell_open` + `ssh_shell_exec`; `ssh_shell_list` / `ssh_shell_close` keep their other tags and stay usable to drain pre-existing sessions |
| per-host | `persistent_session` in hosts.toml | `true` | false = `ssh_shell_open` refuses that specific host; `ssh_exec_run` on the same host still works |

Typical production shape: tier on, group on, global feature off, per-host
irrelevant. Typical dev shape: all four true.

Example of "exec allowed but no persistent shells on prod":

```toml
[defaults]
persistent_session = true

[hosts.prod-db]
persistent_session = false   # ssh_shell_open refuses; ssh_exec_run still works
```

Example of "server-wide lockout" via env:

```bash
ALLOW_PERSISTENT_SESSIONS=false
# ssh_shell_open / ssh_shell_exec disappear from the catalog on next restart.
```

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |

## Returns

```json
{"session_id": "a3f1b2c9...", "host": "web01", "cwd": "~"}
```

## When to call it

- Workflows that feel like a shell session: browse a directory tree with
  many `cd` + `ls`/`find` calls without having to thread the full path through
  every command.
- Incremental investigation where each command builds on the previous cwd.

## When NOT to call it

- Single-command invocations -- `ssh_exec_run` is cheaper and simpler.
- Workflows that need env vars / shell history -- this MVP only tracks cwd.
  Export vars as part of each `ssh_shell_exec` command.
- Workflows that need **parallel** commands in the same session.
  Concurrent `ssh_shell_exec` calls on the same `session_id` are serialized
  by a per-session async lock (INC-023; INC-047 enforces it via a runtime
  assert on `set_cwd`). They don't race -- they queue. If you need real
  parallelism, open multiple sessions or use `ssh_exec_run` per
  independent command.

## Example

```python
s = ssh_shell_open(host="web01")
ssh_shell_exec(session_id=s["session_id"], command="cd /var/log/nginx")
ssh_shell_exec(session_id=s["session_id"], command="ls -la")   # runs in /var/log/nginx
ssh_shell_close(session_id=s["session_id"])
```

## Lifecycle

- Sessions live in memory; lost on MCP restart.
- No persistent reaper yet -- close what you open (`ssh_shell_close`).
  `ssh_shell_list` shows what's outstanding.

## Related

- [`ssh_shell_exec`](../ssh-shell-exec/SKILL.md)
- [`ssh_shell_close`](../ssh-shell-close/SKILL.md)
- [`ssh_shell_list`](../ssh-shell-list/SKILL.md)
- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- stateless single-command variant
