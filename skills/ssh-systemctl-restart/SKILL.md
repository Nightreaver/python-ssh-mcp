---
description: Restart a systemd unit on a remote host
---

# `ssh_systemctl_restart`

**Tier:** dangerous | **Group:** `systemctl` | **Tags:** `{dangerous, group:systemctl}`

Runs `systemctl restart -- <unit>` on the remote host. Requires root.
Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

`restart` is `stop` followed by `start` in a single systemctl call. Causes
a service downtime window equal to the unit's shutdown + startup time.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `unit` | str | yes | -- | Systemd unit name; argv-validated |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

`SystemctlUnitActionResult` with `action="restart"`.

## When to call it

- Pick up a configuration change that the service does not honour via
  `reload` (e.g. ports, listen addresses, capability changes).
- Recover a wedged service whose worker pool will not respond to SIGHUP.

## When NOT to call it

- The unit supports `reload` (most web servers, sshd, postfix) -- use
  `ssh_systemctl_reload` for a zero-downtime config refresh.
- You want a clean state but the unit holds long-lived client connections
  -- consider a coordinated drain instead.

## Example

```python
ssh_systemctl_restart(host="web01", unit="nginx.service", timeout=30)
```

## Common failures

- `Job for X failed because the control process exited with error code` --
  follow up with `ssh_journalctl unit=X lines=100` to read the failure.
- Timeout in the middle of a slow shutdown -- bump `timeout=`.

## Related

- `ssh_systemctl_reload` -- safer if the unit supports it
- `ssh_systemctl_status` -- verify the unit came back up
- `ssh_journalctl` -- diagnose a failed restart
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
