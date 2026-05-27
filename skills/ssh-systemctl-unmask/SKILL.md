---
description: Unmask a systemd unit so it can be started again
---

# `ssh_systemctl_unmask`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl unmask -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Reverses `ssh_systemctl_mask` by removing the `/dev/null` symlink. After
unmask the unit becomes startable again, but is NOT automatically started
-- call `ssh_systemctl_start` to bring it up.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="unmask"`.

## When to call it

- Restore a unit that was masked during incident response.
- Undo a previous masking before a software upgrade reinstates the
  vendor unit.

## When NOT to call it

- The unit was disabled, not masked -- `unmask` is a no-op in that case;
  use `ssh_systemctl_enable` instead.

## Example

```python
ssh_systemctl_unmask(host="web01", unit="snapd.service")
ssh_systemctl_enable(host="web01", unit="snapd.service")
ssh_systemctl_start(host="web01", unit="snapd.service")
```

## Common failures

- `Unit ... is not masked` -- not actually a failure; nothing to do.

## Related

- `ssh_systemctl_mask` -- the inverse
- `ssh_systemctl_enable` -- separate step after unmask if you want
  it to start on boot again
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
