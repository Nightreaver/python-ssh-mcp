---
description: Mask a systemd unit so nothing can start it until unmasked
---

# `ssh_systemctl_mask`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl mask -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Replaces the unit file with a symlink to `/dev/null`. Nothing can start
the unit (not manual `start`, not dependency pulls, not socket activation)
until you call `ssh_systemctl_unmask`. Stronger than `disable`.

`mask` does NOT stop a currently-running instance -- if the unit is up
right now, also call `ssh_systemctl_stop`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="mask"`. `stdout` shows the
"Created symlink ... -> /dev/null" line.

## When to call it

- Permanently prevent a problematic vendor unit from ever starting (e.g.
  disable `apport.service` on a server).
- Lock out a service during incident response so an automated dependency
  cannot accidentally restart it.

## When NOT to call it

- You just want to stop it for this boot -- use `ssh_systemctl_stop`.
- You want it off across reboots but reachable for manual debug
  `systemctl start` -- use `ssh_systemctl_disable` instead.
- You are masking a unit that other still-running units depend on --
  this will break those units' health.

## Example

```python
ssh_systemctl_mask(host="web01", unit="snapd.service")
```

## Common failures

- The unit was an alias for another unit and mask silently masks both --
  inspect with `ssh_systemctl_show` properties=["Names","Triggers"]`
  before masking.

## Related

- `ssh_systemctl_unmask` -- the inverse, mandatory before re-use
- `ssh_systemctl_disable` -- weaker: allows manual start
- `ssh_systemctl_stop` -- needed alongside if currently running
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
