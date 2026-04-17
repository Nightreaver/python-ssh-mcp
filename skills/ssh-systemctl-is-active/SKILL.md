---
description: Check whether a systemd unit is active on a remote host
---

# `ssh_systemctl_is_active`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl is-active <unit>` on the remote host. Non-zero exit is
normal - it means the unit is not active. Returns the state string directly.

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
  "state": "active",
  "exit_code": 0
}
```

`state` is one of: `active | inactive | failed | activating | deactivating | reloading | unknown`.

## When to call it

- Scripted or automated health check where you need a clean enum field, not a text block.
- After `ssh_sudo_exec systemctl restart ...` to confirm the unit came up.
- Polling in a deploy-verify loop.

## When NOT to call it

- When you also need the log tail or exit details -- use `ssh_systemctl_status` instead.
- When you need the enablement state (survives reboot?) -- use `ssh_systemctl_is_enabled`.

## Example

```python
ssh_systemctl_is_active(host="web01", unit="nginx.service")
```

## Common failures

- Any non-zero exit is normal and expected (means unit is not `active`). Check `state`, not just `exit_code`.
- `state="unknown"`: systemctl could not determine the state; may indicate a corrupt unit or a very old systemd version.

## Related

- `ssh_systemctl_status` - full status with log tail
- `ssh_systemctl_is_failed` - check specifically for failed state
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
