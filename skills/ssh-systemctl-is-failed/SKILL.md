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

Unit is healthy (not in failed state):

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "failed": false,
  "state": "active",
  "exit_code": 1
}
```

Unit IS in a failed state (the case you usually branch on):

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "failed": true,
  "state": "failed",
  "exit_code": 0
}
```

The exit-code semantics is inverted relative to the usual convention:
`exit_code=0` means "yes, the unit is failed" (matches what
`systemctl is-failed` itself signals at the shell). The `failed`
boolean flips that into the more intuitive direction -- branch on
`failed`, not on `exit_code`.

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

## Validation

`unit` is rejected before the call leaves the server if it contains
shell metacharacters, slashes, or characters outside `[A-Za-z0-9@._-]`.
When a dot is present, the suffix must be a known unit type
(`service | socket | target | timer | path | mount | automount |
swap | slice | scope | device`); bare names like `nginx` are accepted.

## Common failures

- `failed=True` with `exit_code=0`: the unit IS in the failed state (this is the expected semantics -- consistent with `systemctl is-failed` return code convention).
- `state="not-found"` with `failed=False`: unit does not exist; verify the unit name.

## Related

- `ssh_systemctl_list_units` with `state="failed"` - find all failed services at once
- `ssh_systemctl_show` with `properties=["Result", "ExecMainStatus", "NRestarts"]`
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
