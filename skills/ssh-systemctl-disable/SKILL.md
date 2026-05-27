---
description: Disable a systemd unit so it does not start on boot
---

# `ssh_systemctl_disable`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl disable -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Removes the `*.wants/` symlinks so the unit does not start on next boot.
Does NOT stop the unit in the current boot -- call `ssh_systemctl_stop`
separately if you also want the running instance down.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="disable"`.

## When to call it

- Decommission a service: disable + stop in pair.
- Switch from a vendor-provided unit to a custom one before installing
  the replacement.

## When NOT to call it

- You only want to stop a running instance for now -- use
  `ssh_systemctl_stop` alone; `disable` is for persistence across boots.
- You want to completely prevent any start (including manual ones or
  dependency pulls) -- use `ssh_systemctl_mask`.

## Example

```python
ssh_systemctl_disable(host="web01", unit="nginx.service")
ssh_systemctl_stop(host="web01", unit="nginx.service")
```

## Common failures

- `Removed /etc/systemd/system/.../nginx.service` printed but the unit
  still starts on boot -- check for socket-activation or other unit
  files (`ssh_systemctl_list_units pattern="nginx*"`).

## Related

- `ssh_systemctl_enable` -- the inverse
- `ssh_systemctl_stop` -- disable does NOT stop; pair them
- `ssh_systemctl_mask` -- stronger: forbid any start
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
