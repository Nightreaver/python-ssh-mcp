---
description: Enable a systemd unit so it starts on boot
---

# `ssh_systemctl_enable`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl enable -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Creates the symlinks under `/etc/systemd/system/<target>.wants/` so the
unit starts on next boot. Does NOT start the unit in the current boot --
call `ssh_systemctl_start` separately (or `enable --now` via
`ssh_sudo_exec` if you want both in one call).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="enable"`. `stdout` includes the
"Created symlink" lines systemd emits.

## When to call it

- New service install: enable + start as a pair.
- Promote a previously-disabled unit to autostart.
- Switch the wanted-by relationship on a custom unit file.

## When NOT to call it

- The unit is masked -- `enable` on a masked unit returns non-zero. Use
  `ssh_systemctl_unmask` first.
- You only want the unit to run NOW and not on next boot -- use
  `ssh_systemctl_start` alone.

## Example

```python
ssh_systemctl_enable(host="web01", unit="nginx.service")
ssh_systemctl_start(host="web01", unit="nginx.service")
```

## Common failures

- `Failed to enable unit: Unit ... is masked` -- unmask first.
- The unit ships with no `[Install]` section -- `enable` is a no-op
  with a warning; verify with `ssh_systemctl_is_enabled`.

## Related

- `ssh_systemctl_disable` -- the inverse
- `ssh_systemctl_start` -- enable does NOT start; pair them
- `ssh_systemctl_is_enabled` -- verify the result
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
