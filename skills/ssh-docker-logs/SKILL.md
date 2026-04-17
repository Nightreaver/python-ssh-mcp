---
description: Read container stdout/stderr; tail or since-windowed
---

# `ssh_docker_logs`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker logs --tail=N [-- since=...] [--timestamps] -- <container>`.
Container name is argv-validated. Output is raw text in `stdout`.

## Context-protection defaults

Docker logs can easily exceed an LLM context window -- a single megabyte of
log output is ~250k tokens. This tool ships with tight defaults; raise them
only when needed.

- `tail=50` (not 10000). Use `since` when you know the time window.
- `max_bytes=65536` (~64 KiB, ~16k tokens). JSON/structured logs can hit
  this cap in 50 lines; check `stdout_truncated` in the return.
- If the cap is hit, narrow via `since`, or wrap a `grep` through
  `ssh_docker_exec` to filter before reading.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `container` | str | yes | -- | Name or ID (argv-validated) |
| `tail` | int | no | 50 | 1..10000 |
| `since` | str | no | None | `"10m"` / `"2h"` / RFC3339 |
| `timestamps` | bool | no | False | Prepend timestamps |
| `max_bytes` | int | no | 65536 | 1 KiB..10 MiB |

## Returns

`ExecResult`. Logs in `stdout` (and `stderr` for container stderr streams).
Check `stdout_truncated=true` before assuming you have the whole picture.

## When to call it

- Debug a service that reports unhealthy from `ssh_docker_ps`.
- Capture logs immediately before `ssh_docker_restart` to preserve context.

## When NOT to call it

- Multi-container project -- use `ssh_docker_compose_logs`.
- Streaming / follow -- this is snapshot-only. For live tail use `ssh_exec_run_streaming`
  with `docker logs -f` (requires exec tier).
- High-volume logs without a `since` window or a grep filter -- you'll hit
  the byte cap and read truncated output.

## Example

```python
# Narrow by time first, raise max_bytes only if truly needed
ssh_docker_logs(host="docker1", container="nginx", tail=50, since="10m")

# Searching for a specific error -- skip the logs tool, grep via exec
# ssh_docker_exec(host="docker1", container="nginx",
#                 command="sh -c 'tail -n 10000 /proc/1/fd/1 | grep ERROR'")
```

## Common failures

- `No such container` in stderr -- check `ssh_docker_ps` first.
- `tail` outside [1, 10000] -> `ValueError`.
- `max_bytes` outside [1 KiB, 10 MiB] -> `ValueError`.
- `stdout_truncated=true` in the return -- raise `max_bytes`, narrow `since`,
  or filter via `ssh_docker_exec`.

## Related

- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
- [`ssh_docker_compose_logs`](../ssh-docker-compose-logs/SKILL.md)
