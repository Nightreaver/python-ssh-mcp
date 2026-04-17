---
description: Run a multi-line shell script under sudo via `sudo -S sh -s --`
---

# `ssh_sudo_run_script`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Wraps `sudo -S -p '' -- sh -s --` and sends `password + "\n" + script` on
stdin. sudo consumes the first line as the password; `sh -s --` then reads
the remainder of stdin as the script body. With passwordless sudo, uses
`sudo -n -- sh -s --` and sends only the script.

**No command allowlist check** is applied to the script body -- the allowlist
inspects argv tokens, and the body is on stdin. Inspect what you execute.

Disabled unless **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `script` | str | yes | -- | Script body, sent verbatim to `sh -s --` after the password line |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Per-call timeout in seconds |

## Returns

Same `ExecResult` shape as `ssh_exec_run`.

## When to call it

- Multi-step privileged operations (restart a service, rotate a log, chown a tree).
- `set -euo pipefail`-style hardened scripts where every step should fail-fast.
- Anywhere chaining `ssh_sudo_exec` calls would mean sending the password
  multiple times.

## When NOT to call it

- A single command -- use `ssh_sudo_exec` (allowlist enforces).
- Anything you can do as a non-root user -- use `ssh_exec_script`. Every sudo
  invocation is a higher-risk audit event.
- Scripts that tail long-running processes -- no streaming variant for sudo.
  Launch the long runner as a detached process or use systemd.

## Password source priority

Same as `ssh_sudo_exec`:

1. `SSH_SUDO_PASSWORD_CMD`
2. OS keychain (`keyring` service `ssh-mcp-sudo`, user `default`)
3. `SSH_SUDO_PASSWORD` env var (insecure; WARNING at startup)
4. Passwordless sudoers entry

## Example

```python
script = """\
set -euo pipefail
systemctl reload nginx
journalctl -u nginx --since '1 min ago' | tail -n 20
"""
ssh_sudo_run_script(host="web01", script=script, timeout=30)
```

## Quoting note

Because the script body goes on stdin after the password line, you don't need
to escape `$`, backticks, or quotes the way you would for `ssh_sudo_exec`.
Write the script as you'd write a `.sh` file. Prepend `set -euo pipefail` for
strict failure semantics.

## Common failures

- `exit_code=1` + "incorrect password attempt" stderr -- password source is
  wrong. Rotate.
- `exit_code=1` + "a password is required" -- no passwordless entry and no
  reachable password source.
- `ConnectError` -- TCP, auth, or transport failure before sudo even ran.
- `timed_out=true` -- script exceeded the timeout. pkill cleanup attempted
  on the `sudo` parent.

## Related

- [`ssh_sudo_exec`](../ssh-sudo-exec/SKILL.md) -- single-command variant with allowlist.
- [`ssh_exec_script`](../ssh-exec-script/SKILL.md) -- non-privileged script. Prefer when possible.
