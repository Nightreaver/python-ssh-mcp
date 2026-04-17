---
description: Run a shell command on a remote host; non-zero exit is data, not failure
---

# `ssh_exec_run`

**Tier:** dangerous | **Group:** `exec` | **Tags:** `{dangerous, group:exec}`

Execute `command` on the remote shell. The full command string is passed to
the remote `sh -c` -- **the caller owns quoting**. Returns a structured
result with stdout, stderr, exit_code, and timing. **Non-zero exit codes
are returned as data, not raised.**

Disabled unless `ALLOW_DANGEROUS_TOOLS=true`. If a per-host
`command_allowlist` (or `SSH_COMMAND_ALLOWLIST`) is set, the first token of
the command must match (after `shlex.split`).

## Last-resort tool -- prefer dedicated tools

`ssh_exec_run` is the most general, and therefore the **highest-risk**, tool
in the catalog. Every other tool in this server exists because a dedicated
wrapper is safer, faster, and better-audited than a raw shell command. When
you reach for `ssh_exec_run`, pause and ask: **is there a dedicated tool for
this job?**

| If you're about to run...     | Use this instead                                   |
|-------------------------------|----------------------------------------------------|
| `mkdir -p <dir>`              | `ssh_mkdir`                                        |
| `rm <file>`                   | `ssh_delete`                                       |
| `rm -rf <dir>`                | `ssh_delete_folder`                                |
| `cp -a <src> <dst>`           | `ssh_cp`                                           |
| `mv <src> <dst>`              | `ssh_mv`                                           |
| upload a file                 | `ssh_upload` (atomic tmp-rename, base64 payload)   |
| in-place `sed`-style edit     | `ssh_edit` (old_text/new_text, atomic)             |
| apply a unified diff          | `ssh_patch`                                        |
| `find <path> -name ...`       | `ssh_find`                                         |
| `df` / `ps` / `uname` / `uptime` | `ssh_host_disk_usage` / `_processes` / `_info`  |
| `cat <file>`                  | `ssh_sftp_download`                                |
| `ls <dir>`                    | `ssh_sftp_list`                                    |
| `stat <file>`                 | `ssh_sftp_stat`                                    |
| any `docker ...`              | `ssh_docker_*` (22 tools covering ps/logs/run/...) |
| any `docker compose ...`      | `ssh_docker_compose_*` (7 tools)                   |
| `sudo <anything>`             | `ssh_sudo_exec` / `ssh_sudo_run_script`            |

The dedicated tools are in **tiers below `dangerous`** -- they require fewer
env flags, have narrower allowlists, and produce more targeted audit lines.
Using them makes the server's safety rails actually rail.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `command` | str | yes | -- | The full shell command. You are responsible for quoting. |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` (60) | Per-call timeout in seconds |

## Returns

```json
{
  "host": "web01.example.com",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "stdout_bytes": 1234,
  "stderr_bytes": 0,
  "stdout_truncated": false,
  "stderr_truncated": false,
  "duration_ms": 142,
  "timed_out": false,
  "killed_by_signal": null
}
```

`stdout` and `stderr` are capped at `SSH_STDOUT_CAP_BYTES` / `SSH_STDERR_CAP_BYTES`
(both 1 MiB by default). Anything past the cap is dropped and `*_truncated` flips true.
The full byte counts (`stdout_bytes`, `stderr_bytes`) report what the command produced
so you can detect truncation.

## When to call it

- One-shot diagnostics not covered by the read-only tools (`netstat -tlnp`, `ss`, `journalctl --since 5min ago`).
- Service control if `command_allowlist` whitelists `systemctl`/`nginx`/etc.
- Anything you'd type at a shell -- but consider whether `ssh_exec_script` is cleaner.

## When NOT to call it

- The command may run for minutes -- use `ssh_exec_run_streaming` instead.
- The command needs sudo -- use `ssh_sudo_exec` (Phase 4).
- A multi-line script -- `ssh_exec_script` keeps the body out of argv (and audit logs).
- Anywhere a low-access tool exists (`ssh_edit`, `ssh_cp`, `ssh_find`) -- those are auditable, scoped, and don't trip allowlists.

## Quoting

You're sending a single string to the remote `sh -c`. Quote inputs containing spaces or shell metacharacters yourself:

```python
ssh_exec_run(host="web01", command="grep 'error 500' /var/log/nginx/error.log")
```

For untrusted-looking values, prefer `ssh_exec_script` and avoid shell parsing entirely.

## Example

```python
ssh_exec_run(host="web01", command="systemctl status nginx", timeout=10)
# -> {"exit_code": 0, "stdout": "* nginx.service - ..."}

ssh_exec_run(host="db01", command="ls /nonexistent")
# -> {"exit_code": 2, "stderr": "ls: cannot access ...", "stdout": ""}
# Note: exit 2 is NOT raised; it's returned as data.
```

## Timeout behavior

If the command exceeds `timeout`, the tool sends `timeout 3s pkill -f -- '<command>'` to clean up the runaway, then returns:

```json
{"timed_out": true, "exit_code": -1, "stdout": "", "stderr": ""}
```

## Common failures

- `CommandNotAllowed` -- the first token isn't on the per-host or env command allowlist.
- `ConnectError` -- TCP, auth, or transport failure.
- `HostBlocked` / `HostNotAllowed` -- see host policy.
- `timed_out=true` -- the command ran past the timeout. Pkill cleanup attempted.

## Related

- [`ssh_exec_script`](../ssh-exec-script/SKILL.md) -- multi-line script via stdin.
- [`ssh_exec_run_streaming`](../ssh-exec-run-streaming/SKILL.md) -- long-running with progress.
- [`ssh_edit`](../ssh-edit/SKILL.md) / [`ssh_patch`](../ssh-patch/SKILL.md) -- prefer for file mutation.
