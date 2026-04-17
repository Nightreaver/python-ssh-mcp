---
description: Run a command under sudo; password piped on stdin, never in argv
---

# `ssh_sudo_exec`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Wrap `command` with `sudo -S -p '' -- sh -c <quoted>` and pipe the sudo
password on stdin. With a passwordless sudoers entry, uses `sudo -n` and no
stdin. The password never appears in argv, process listings, or audit records.

Disabled unless **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
The `command_allowlist` check from `ssh_exec_run` applies the same way -- if
neither the per-host nor env allowlist has an entry, you must also set
`ALLOW_ANY_COMMAND=true` or the call is rejected.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `command` | str | yes | -- | Full shell command. You are responsible for quoting. |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` (60) | Per-call timeout in seconds |

## Returns

Same `ExecResult` shape as `ssh_exec_run`.

## Password source priority

1. `SSH_SUDO_PASSWORD_CMD` (operator-configured shell command, stdout is the password)
2. OS keychain via `keyring`: service `ssh-mcp-sudo`, user `default`
3. `SSH_SUDO_PASSWORD` env var -- **insecure**; emits a startup WARNING
4. Passwordless sudoers entry -- `sudo -n` (no password needed)

## When to call it

- Systemctl control on hosts where the SSH user isn't root.
- Restart services, reload configs, tail privileged logs.
- Anywhere you'd type `sudo <cmd>` at a shell -- with the same allowlist scoping.

## When NOT to call it

- You can run it as the SSH user directly -- use `ssh_exec_run`. Every sudo
  call is a higher-risk audit event.
- The command is a multi-line script -- use `ssh_sudo_run_script` (body on
  stdin, out of argv).
- You need to preserve root's environment for something non-trivial -- this
  tool uses `sudo` defaults (`env_reset`). Configure sudoers instead.

## Example

```python
ssh_sudo_exec(host="web01", command="systemctl reload nginx")
# -> {"exit_code": 0, "stdout": "", "stderr": "", ...}

# Wrong password -> sudo returns non-zero, not raised:
ssh_sudo_exec(host="web01", command="systemctl status nginx")
# -> {"exit_code": 1, "stderr": "Sorry, try again.\nsudo: 1 incorrect password attempt"}
```

## Common failures

- `CommandNotAllowed` -- first token isn't in the allowlist (or no allowlist and
  `ALLOW_ANY_COMMAND=false`).
- `AuthenticationFailed: sudo password command exited ...` -- your
  `SSH_SUDO_PASSWORD_CMD` (e.g. `pass show ops/sudo`) failed. Inspect stderr
  out-of-band; the message is redacted on purpose.
- `exit_code=1` with sudo's "incorrect password" stderr -- the password source
  returned the wrong value. Rotate and retry.
- `exit_code=1` with "a password is required" -- passwordless sudoers isn't
  configured and no password source is reachable.

## Related

- [`ssh_sudo_run_script`](../ssh-sudo-run-script/SKILL.md) -- multi-line scripts under sudo.
- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- non-privileged exec. Prefer when possible.
