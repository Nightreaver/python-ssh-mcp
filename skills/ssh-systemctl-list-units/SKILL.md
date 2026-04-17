---
description: List systemd units on a remote host, optionally filtered by state or type
---

# `ssh_systemctl_list_units`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl list-units --no-pager --no-legend` and returns parsed rows.
Use `state="failed"` to quickly find all broken services, or `pattern="nginx*"`
to narrow to a family of units.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `pattern` | str | no | `None` | Glob filter (e.g. `nginx*`, `*.service`) |
| `state` | str | no | `None` | Filter by state (e.g. `failed`, `running`, `inactive`) |
| `unit_type` | str | no | `service` | Unit type passed to `--type` |

## Returns

```json
{
  "host": "web01",
  "units": [
    {
      "unit": "nginx.service",
      "load": "loaded",
      "active": "active",
      "sub": "running",
      "description": "A high performance web server"
    }
  ],
  "exit_code": 0
}
```

## Examples

```python
# All failed services
ssh_systemctl_list_units(host="web01", state="failed")

# All running timers
ssh_systemctl_list_units(host="web01", state="running", unit_type="timer")

# Units matching a glob
ssh_systemctl_list_units(host="web01", pattern="nginx*")
```

## When to call it

- Initial triage: `state="failed"` to surface all broken services in one pass.
- Discovering which services a host runs when you don't know the unit names.
- Scoping a change: `pattern="nginx*"` to find all nginx-related units before touching any.

## When NOT to call it

- When you already know the unit name -- jump straight to `ssh_systemctl_status` or `ssh_systemctl_show`.
- When you need the full status text for a specific unit -- this returns a structured list only.

## Common failures

- Empty `units` list with `exit_code=0`: the filters matched nothing (e.g. `state="failed"` with no failures -- that is good news).
- Column parse error on very old systemd (pre-v209): the `--no-legend` flag was added in v209. Practically all modern distributions are well past this.

## Related

- `ssh_systemctl_status` - detailed status of a specific unit
- `ssh_systemctl_is_failed` - check a single known unit for failed state
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
