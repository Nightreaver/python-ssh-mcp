---
description: Start a systemd unit on a remote host
---

# `ssh_systemctl_start`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl start -- <unit>` on the remote host. Requires root: use a
sudoers-enabled SSH account, or use `ssh_sudo_exec` if you need an
interactive sudo gate. Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | -- | Systemd unit name (e.g. `nginx.service`); argv-validated |
| `timeout` | int | no | None | Per-call command timeout in seconds; defaults to `SSH_COMMAND_TIMEOUT` |

## Returns

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "action": "start",
  "exit_code": 0,
  "stdout": "",
  "stderr": "",
  "duration_ms": 142,
  "output_warnings": []
}
```

Non-zero exit codes are data (not raised). `exit_code` 5 typically means
the unit could not be loaded; check `stderr` for the reason.

## When to call it

- Bring up a unit that was previously stopped or has just been installed.
- After `ssh_systemctl_enable` you still need a separate start to bring
  the unit up in the current boot.

## When NOT to call it

- The unit is already active -- use `ssh_systemctl_is_active` first if
  you want idempotency. `start` on an already-active unit is a no-op but
  still emits an audit event.
- You need the unit to come up on next boot but not now -- use
  `ssh_systemctl_enable` (without `--now`).

## Example

```python
ssh_systemctl_start(host="web01", unit="nginx.service")
```

## Validation

`unit` is rejected if it contains shell metacharacters, slashes, or
characters outside `[A-Za-z0-9@._-]`. When a dot is present, the suffix
must be a known unit type (service, socket, target, timer, path, mount,
automount, swap, slice, scope, device).

## Common failures

- `exit_code=5`, `stderr` says "Failed to start ... Unit not found" --
  unit name is misspelled or not installed.
- `stderr` says "Interactive authentication required" -- the SSH user is
  not in sudoers without password; use `ssh_sudo_exec` instead.

## Related

- `ssh_systemctl_stop` -- the inverse
- `ssh_systemctl_restart` -- stop+start in one call
- `ssh_systemctl_is_active` -- verify the unit came up
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
