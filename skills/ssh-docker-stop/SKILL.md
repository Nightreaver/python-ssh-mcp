---
description: Stop a running container (graceful SIGTERM, then SIGKILL)
---

# `ssh_docker_stop`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `docker stop -- <container>`. Docker sends SIGTERM then SIGKILL after
the stop timeout (10s default, configured in docker, not in this call).
Argv-validated container name.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `container` | str | yes | Name or ID |

## Returns

`ExecResult`. On success, `exit_code=0` and `stdout` is the container name.

## When to call it

- Take a service down intentionally.
- Before `ssh_docker_rm` (unless using `force=True`).

## When NOT to call it

- You want the container restarted immediately -- `ssh_docker_restart` is one round-trip.
- Destructive tear-down -- `ssh_docker_rm` removes the container entirely.

## Example

```python
ssh_docker_stop(host="docker1", container="nginx")
```

## Related

- [`ssh_docker_start`](../ssh-docker-start/SKILL.md)
- [`ssh_docker_rm`](../ssh-docker-rm/SKILL.md) -- dangerous tier
- [`ssh_docker_compose_stop`](../ssh-docker-compose-stop/SKILL.md)
