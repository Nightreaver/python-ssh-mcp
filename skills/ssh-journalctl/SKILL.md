---
description: Fetch recent journal log entries for a systemd unit on a remote host
---

# `ssh_journalctl`

**Tier:** read-only | **Group:** `systemctl` | **Tags:** `{safe, read, group:systemctl}`

Runs `journalctl -u <unit> --no-pager -n <lines>` on the remote host and
returns the log output. Defaults to the last 200 lines. Hard cap at 1000
lines per call - use `since=` to narrow the time window instead of raising
the line count.

**Permission note:** the SSH user must be in the `systemd-journal` or `adm`
group to read journal entries. If `exit_code` is non-zero with
`Permission denied` in stderr, add the user to `systemd-journal`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `unit` | str | yes | -- | Systemd unit name |
| `since` | str | no | `None` | Time anchor: `15m`, `2h`, `2026-04-16T12:00:00Z`, `yesterday`, `today` |
| `until` | str | no | `None` | Time anchor (same formats as `since`) |
| `lines` | int | no | `200` | Max lines to return (1..1000) |
| `grep` | str | no | `None` | Filter log lines; alphanumerics + `_-.:/@ ` only |

## Returns

```json
{
  "host": "web01",
  "unit": "nginx.service",
  "stdout": "Apr 17 10:00:00 nginx: ...\n",
  "lines_returned": 42,
  "exit_code": 0
}
```

## Examples

```python
# Default: last 200 lines
ssh_journalctl(host="web01", unit="nginx.service")

# Last 15 minutes, filter for errors
ssh_journalctl(host="web01", unit="nginx.service", since="15m", grep="error")

# Time-bounded window
ssh_journalctl(
    host="web01",
    unit="nginx.service",
    since="2026-04-16T10:00:00Z",
    until="2026-04-16T10:30:00Z",
    lines=500,
)
```

## When to call it

- Diagnose a failing or recently-restarted service: `since="15m"` captures the relevant window.
- Correlate an event time with log output: use explicit `since=` / `until=` RFC3339 anchors.
- Filter for a specific error class: `grep="error"` (alphanumeric + `_-.:/@ ` only).

## When NOT to call it

- Streaming / follow mode -- this is a snapshot. For live tail use `ssh_exec_run_streaming` with `journalctl -f -u <unit>` (requires dangerous tier).
- Very high-volume services without a `since` window -- you will hit the 1000-line cap and see truncated output.
- When you only need the last few lines already included in `ssh_systemctl_status` output.

## Common failures

- Non-zero `exit_code` with `Permission denied` or `No journal files were found` in stderr: the SSH user is not in the `systemd-journal` or `adm` group. Add with `usermod -aG systemd-journal <ssh-user>` and reconnect.
- Empty `stdout` with `exit_code=0`: the unit has not logged anything in the requested window -- try a wider `since=` or remove the `grep=` filter.
- `lines_returned` less than requested `lines`: fewer entries exist in the window than the cap; not an error.

## Related

- `ssh_systemctl_status` - status with the last few journal lines built in
- `ssh_systemctl_show` - machine-readable failure details
- [ssh-systemd-diagnostics runbook](../../runbooks/ssh-systemd-diagnostics/SKILL.md)
