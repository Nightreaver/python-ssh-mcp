---
description: Show machine-readable systemd unit properties on a remote host
---

# `ssh_systemctl_show`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `systemctl show <unit> [--property=P1,P2,...]` and returns key-value
properties as a dict. Use `properties=` to limit output to only the fields
you need - the full output can be several hundred lines.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | -- | Systemd unit name |
| `properties` | list[str] | no | `None` | Property names (PascalCase, e.g. `["ActiveState", "NRestarts"]`) |

## Returns

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "properties": {
    "ActiveState": "active",
    "ExecMainStatus": "0",
    "Result": "success",
    "NRestarts": "0"
  },
  "exit_code": 0
}
```

Duplicate keys (e.g. multiple `ExecStartPre=`) are resolved by last-write-wins.

## Examples

```python
# Targeted failure diagnosis
ssh_systemctl_show(
    host="web01",
    unit="nginx.service",
    properties=["ActiveState", "ExecMainStatus", "Result", "NRestarts"],
)

# All properties (verbose)
ssh_systemctl_show(host="web01", unit="nginx.service")
```

## When to call it

- Programmatic failure analysis: `properties=["Result", "ExecMainStatus", "NRestarts"]` gives structured failure details that would require regex parsing from `ssh_systemctl_status`.
- Checking restart policy: `properties=["Restart", "RestartSec", "StartLimitBurst"]`.
- Pre-change audit: snapshot key properties before and after a configuration change.

## When NOT to call it

- When a human-readable summary is sufficient -- use `ssh_systemctl_status`.
- When you want to see the unit file source -- use `ssh_systemctl_cat`.

## Validation

- `unit` is rejected before the call leaves the server if it contains
  shell metacharacters, slashes, or characters outside `[A-Za-z0-9@._-]`.
  When a dot is present, the suffix must be a known unit type
  (`service | socket | target | timer | path | mount | automount |
  swap | slice | scope | device`).
- `properties[]` entries must match `^[A-Z][A-Za-z0-9]*$` (PascalCase,
  no underscores, no hyphens) -- e.g. `ActiveState`, `ExecMainStatus`,
  `NRestarts`. Lowercase / underscored / hyphenated names raise
  `ValueError`; that's distinct from systemd silently ignoring an
  unknown-but-well-formed property name (see Common failures).

## Common failures

- Property names that pass validation (`^[A-Z][A-Za-z0-9]*$`) but
  systemd does not recognise are silently absent from the returned
  `properties` dict -- systemd ignores unknown `--property=` keys and
  emits nothing for them. Names that fail validation (lowercase,
  underscores, hyphens, etc.) raise `ValueError` *before* the call --
  see the Validation section.
- Duplicate keys (e.g. multiple `ExecStartPre=`) are resolved by last-write-wins in the parser.
- `exit_code` non-zero with an empty `properties` dict: unit does not exist on the host.

## Related

- `ssh_systemctl_status` - human-readable with log tail
- `ssh_systemctl_cat` - see the unit file itself
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
