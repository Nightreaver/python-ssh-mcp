---
description: Check whether a systemd unit is enabled (will start at boot) on a remote host
---

# `ssh_systemctl_is_enabled`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl is-enabled <unit>` on the remote host. Returns the enablement
state. A unit that is `active` but `disabled` will not start automatically
after a reboot.

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
  "state": "enabled",
  "exit_code": 0
}
```

`state` is one of: `enabled | enabled-runtime | linked | linked-runtime | alias |
masked | masked-runtime | static | indirect | disabled | generated | transient |
bad | not-found | unknown`.

## When to call it

- Pre-reboot audit: confirm that services which must survive a reboot are `enabled`.
- Post-provision check: verify a unit was enabled by the provisioning script.
- When `ssh_systemctl_is_active` returns `active` but you want to know if it will come back after a restart.

## When NOT to call it

- When you need to know the current running state -- use `ssh_systemctl_is_active`.
- To enable/disable a unit -- use `ssh_sudo_exec systemctl enable/disable ...`.

## Example

```python
ssh_systemctl_is_enabled(host="web01", unit="nginx.service")
```

## Common failures

- `state="not-found"`: unit does not exist on the host or the name is misspelled.
- `state="masked"`: unit is explicitly blocked from starting; `enable` will fail until it is unmasked.
- `state="static"`: unit has no `[Install]` section and cannot be enabled/disabled directly.

## Related

- `ssh_systemctl_status` - active + enabled in one call (less structured)
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
