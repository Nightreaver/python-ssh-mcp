---
description: Show the unit file content for a systemd unit on a remote host
---

# `ssh_systemctl_cat`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl cat <unit>` on the remote host. Returns the full unit file
content including drop-in overrides from `/etc/systemd/system/<unit>.d/`.
Useful for verifying the unit configuration matches what was deployed.

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
  "stdout": "# /lib/systemd/system/nginx.service\n[Unit]\nDescription=...\n",
  "exit_code": 0
}
```

## When to call it

- Verify that the deployed unit file matches what you expect after an `ssh_upload` or `ssh_edit`.
- Inspect drop-in overrides (`/etc/systemd/system/<unit>.d/`) in one call alongside the base file.
- Review `ExecStart=`, `Restart=`, `Environment=` lines before making changes.

## When NOT to call it

- When you need machine-readable properties of the *running* unit (not the file) -- use `ssh_systemctl_show`.
- To modify the unit file -- use `ssh_upload` / `ssh_edit` (low-access tier), then `ssh_sudo_exec systemctl daemon-reload`.

## Example

```python
ssh_systemctl_cat(host="web01", unit="nginx.service")
```

## Common failures

- Non-zero exit with `No files found for <unit>` in stderr: the unit name is wrong or the unit is not installed.
- Output starts with a `# /lib/systemd/...` comment line (the source path) -- this is normal; the actual unit content follows.

## Related

- `ssh_systemctl_show` - machine-readable properties parsed from the running unit
- `ssh_upload` / `ssh_edit` - modify the unit file (low-access tier)
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
