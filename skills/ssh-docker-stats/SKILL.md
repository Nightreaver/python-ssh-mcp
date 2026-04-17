---
description: One-shot resource snapshot (CPU, memory, net, block I/O) per container
---

# `ssh_docker_stats`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker stats --no-stream --format '{{json .}}'` and parses the output
to a list. Snapshot only -- does not stream. For live tail, use
`ssh_exec_run_streaming` with `docker stats` (requires exec tier).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |

## Returns

`ExecResult` plus:

- `containers`: list of `{Name, CPUPerc, MemUsage, NetIO, BlockIO, ...}` dicts.

## When to call it

- Triage "which container is eating CPU?"
- Capacity planning snapshots.

## When NOT to call it

- Fine-grained live monitoring -- use Prometheus/Grafana, not an MCP.

## Example

```python
ssh_docker_stats(host="docker1")
```

## Common failures

- Slow on hosts with many containers -- docker stats enumerates all of them.

## Related

- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
- [`ssh_host_processes`](../ssh-host-processes/SKILL.md)
