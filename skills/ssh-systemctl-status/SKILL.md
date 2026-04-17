---
description: Show the status of a systemd unit on a remote host
---

# `ssh_systemctl_status`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl status <unit> --no-pager` on the remote host and returns
structured output including the raw stdout, exit code, and `active_state`
parsed from the `Active:` line. Exit code 3 (unit inactive/dead) is treated
as data, not an error.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | Systemd unit name (e.g. `nginx.service`). Suffix must be a known unit type. |

## Returns

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "stdout": "* nginx.service - ...\n   Active: active (running) ...",
  "exit_code": 0,
  "active_state": "active"
}
```

`active_state` is `null` when the `Active:` line is absent (e.g. unit not found).

## When to call it

- First look at a service that may be unhealthy -- gives active state, load state, and the last few log lines in one call.
- Before deciding whether to restart or investigate further.

## When NOT to call it

- Scripted checks that only need active/inactive -- use `ssh_systemctl_is_active` instead (cheaper, structured state field).
- Bulk survey of all failed units -- use `ssh_systemctl_list_units(state="failed")`.

## Example

```python
ssh_systemctl_status(host="web01", unit="nginx.service")
```

## Common failures

- Exit code 4: unit not found (typo in unit name or unit not installed).
- Exit code 3: unit exists but is inactive/dead -- treat as data, not an error.
- `active_state=null`: the `Active:` line was absent in the output; unit may be a template or generator.

## Related

- `ssh_systemctl_is_active` - lightweight active/inactive/failed check
- `ssh_systemctl_show` - machine-readable properties
- `ssh_journalctl` - recent log lines
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
