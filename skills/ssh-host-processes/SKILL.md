---
description: List top-N processes by CPU on a remote host
---

# `ssh_host_processes`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Runs `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu` and returns the top N rows.
Fixed argv -- no shell interpolation. The sort is `-pcpu` (CPU descending);
use `ssh_exec_run` if you need a different sort column.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `top` | int | no | 20 | Number of rows to return; clamped to `[1, 200]` |

## Returns

```json
{
  "host": "web01.example.com",
  "entries": [
    {"pid": 1823, "user": "postgres", "pcpu": 42.7, "pmem": 3.1, "command": "postgres"},
    {"pid": 42, "user": "root", "pcpu": 8.1, "pmem": 0.2, "command": "systemd"}
  ]
}
```

`pcpu` and `pmem` are floats. `command` is the short form (`comm`, not `args`)
to keep the output compact.

## When to call it

- CPU pressure triage -- something's eating the box.
- Correlate with disk/mem hints from `ssh_host_disk_usage` and load in `ssh_host_info`.
- Before a restart -- confirm the expected process is actually running.

## When NOT to call it

- Snapshot-over-time analysis -- this is a single sample.
- Full argv of a process -- use `ssh_exec_run` with `ps -eo pid,args`.
- Thread-level detail -- add `-L` via `ssh_exec_run`.

## Example

```python
ssh_host_processes(host="web01", top=5)
# -> top 5 CPU-heavy processes
```

## Common failures

- `top` outside `[1, 200]` -> `ValueError`. Pick a sensible N.
- `HostNotAllowed` / `HostBlocked` -- see host policy.

## Related

- [`ssh_host_info`](../ssh-host-info/SKILL.md) -- load average baseline.
- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- custom `ps` with args, threads, or different sort.
