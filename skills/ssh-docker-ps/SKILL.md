---
description: List docker containers on a remote host (running or all)
---

# `ssh_docker_ps`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker ps --format '{{json .}}' --no-trunc` on the remote and returns
both the raw `ExecResult` shape and a parsed `containers` list (one JSON
object per container). `all_=True` adds `-a` to include stopped containers.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from hosts.toml |
| `all_` | bool | no | `False` | Include stopped containers |

## Returns

`ExecResult` fields (exit_code, stdout, stderr, duration_ms, ...) plus:

- `containers`: list of dicts, one per container (id, image, names, status, ports, ...)

## When to call it

- First step of any container investigation.
- Before `ssh_docker_logs` / `ssh_docker_inspect` to get valid names.

## When NOT to call it

- You already know the container name/id -- use `ssh_docker_inspect` directly.

## Example

```python
ssh_docker_ps(host="docker1", all_=True)
```

## Common failures

- `exit_code != 0` + "permission denied" on docker.sock -- SSH user isn't in the
  `docker` group. Add them or use `ssh_sudo_exec` explicitly.

## Related

- [`ssh_docker_inspect`](../ssh-docker-inspect/SKILL.md)
- [`ssh_docker_logs`](../ssh-docker-logs/SKILL.md)
- [`ssh_docker_stats`](../ssh-docker-stats/SKILL.md)
