---
description: Clear the failed state of a single systemd unit
---

# `ssh_systemctl_reset_failed`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl reset-failed -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Clears the "failed" status on the named unit so a subsequent
`ssh_systemctl_start` (or auto-restart dependency) is no longer blocked
by the StartLimit. Operates on exactly one unit; no all-failed mode in
v1 (call once per unit if you need to clear several).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="reset-failed"`.

## When to call it

- The unit has hit `StartLimitBurst` and refuses further restarts. You
  have fixed the underlying issue and want to retry.
- A crashed one-shot timer-driven service needs its slate wiped before
  the next timer fire.

## When NOT to call it

- You have not actually fixed the issue. Resetting just lets the unit
  crash again until the next start-limit triggers.
- The unit is healthy already -- check with `ssh_systemctl_is_failed`
  first.

## Example

```python
ssh_systemctl_is_failed(host="web01", unit="nginx.service")
# {"failed": true, "state": "failed", ...}
ssh_systemctl_reset_failed(host="web01", unit="nginx.service")
ssh_systemctl_start(host="web01", unit="nginx.service")
```

## Common failures

- Reset succeeds but the unit immediately fails again -- the underlying
  cause is not fixed. Diagnose via `ssh_journalctl unit=X lines=200`.

## Related

- `ssh_systemctl_is_failed` -- check before resetting
- `ssh_systemctl_start` -- the typical follow-up
- `ssh_journalctl` -- find out why it failed
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
