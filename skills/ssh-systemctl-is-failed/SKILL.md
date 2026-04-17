---
description: Check whether a systemd unit is in a failed state on a remote host
---

# `ssh_systemctl_is_failed`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl is-failed <unit>` on the remote host. `failed=true` when the
unit IS in a failed state (exit code 0 from the underlying command - consistent
with systemctl's own signalling convention).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | Systemd unit name (e.g. `nginx.service`) |

## Returns

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "failed": false,
  "state": "active",
  "exit_code": 1
}
```

`failed=true` when `exit_code=0` (unit IS failed). `failed=false` otherwise.

## When to call it

- Programmatic failure detection: `failed=True` gives a clean boolean to branch on.
- After a failed restart attempt to confirm the unit entered the `failed` state.
- Monitoring/alerting loop where you want a structured signal, not a text block.

## When NOT to call it

- When you want the full status output with log tail -- use `ssh_systemctl_status`.
- When you want to survey ALL failed units at once -- use `ssh_systemctl_list_units(state="failed")`.

## Example

```python
ssh_systemctl_is_failed(host="web01", unit="nginx.service")
```

## Common failures

- `failed=True` with `exit_code=0`: the unit IS in the failed state (this is the expected semantics -- consistent with `systemctl is-failed` return code convention).
- `state="not-found"` with `failed=False`: unit does not exist; verify the unit name.

## Related

- `ssh_systemctl_list_units` with `state="failed"` - find all failed services at once
- `ssh_systemctl_show` with `properties=["Result", "ExecMainStatus", "NRestarts"]`
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
