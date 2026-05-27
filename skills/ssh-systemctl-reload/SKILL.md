---
description: Ask a systemd unit to reload its configuration without restarting
---

# `ssh_systemctl_reload`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl reload -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Zero-downtime config reload for units that declare `ExecReload=` in their
unit file (most web servers, sshd, postfix, etc.). Units WITHOUT
`ExecReload=` will fail with a non-zero `exit_code` and a stderr that
says "Job type reload is not applicable" -- fall back to
`ssh_systemctl_restart` in that case.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="reload"`.

## When to call it

- Pick up an nginx/apache/sshd config change without dropping in-flight
  connections.
- Re-read certificate bundles after a TLS cert rotation.

## When NOT to call it

- The unit has no `ExecReload=` -- you can check with
  `ssh_systemctl_show unit=X properties=["CanReload"]`. If
  `CanReload=no`, use `ssh_systemctl_restart`.
- The change requires a code path change (binary update, capability set,
  user/group), not just a config re-read.

## Example

```python
ssh_systemctl_reload(host="web01", unit="nginx.service")
```

## Common failures

- `exit_code != 0` with stderr "Job type reload is not applicable" --
  unit does not support reload; use `restart`.
- The reload completes but the new config is invalid; the old process
  keeps running with the old config. Always check
  `ssh_systemctl_status` afterwards.

## Related

- `ssh_systemctl_restart` -- harder option, always works
- `ssh_systemctl_show` -- check `CanReload=` before calling
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
