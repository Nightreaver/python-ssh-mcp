---
description: Stop a systemd unit on a remote host
---

# `ssh_systemctl_stop`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl stop -- <unit>` on the remote host. Requires root: use a
sudoers-enabled SSH account, or use `ssh_sudo_exec` if you need an
interactive sudo gate. Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

`stop` only affects the current boot; the unit will come back on next
boot unless you also `disable` it.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | -- | Systemd unit name (e.g. `nginx.service`); argv-validated |
| `timeout` | int | no | None | Per-call command timeout in seconds; defaults to `SSH_COMMAND_TIMEOUT` |

## Returns

`SystemctlUnitActionResult` with `action="stop"`. See
`ssh_systemctl_start` for the field shape.

## When to call it

- Take a service offline for maintenance without removing it.
- Roll back a botched config: stop, fix, start.

## When NOT to call it

- You want the service to stay down across reboots -- combine with
  `ssh_systemctl_disable` (or call `disable --now` via `ssh_sudo_exec`).
- The unit is a `.target` with many dependent units -- understand the
  blast radius via `ssh_systemctl_list_units --state=active` first.

## Example

```python
ssh_systemctl_stop(host="web01", unit="nginx.service")
```

## Common failures

- `Interactive authentication required` -- SSH user lacks NOPASSWD sudo.
- The unit takes longer than `SSH_COMMAND_TIMEOUT` to shut down (e.g.
  a database flushing buffers); pass an explicit `timeout=`.

## Related

- `ssh_systemctl_start` -- the inverse
- `ssh_systemctl_disable` -- prevent restart on boot
- `ssh_systemctl_mask` -- prevent ANY start until unmasked
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
