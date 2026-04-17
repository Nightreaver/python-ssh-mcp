---
description: Restart a single container
---

# `ssh_docker_restart`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `docker restart -- <container>`. One round trip equivalent to stop+start.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `container` | str | yes | Name or ID |

## Returns

`ExecResult`.

## When to call it

- After changing a config file the container reads at startup.
- Unstuck a service reporting unhealthy in `ssh_docker_ps`.

## When NOT to call it

- Config change that requires a rebuild -- use `ssh_docker_compose_up` with
  `--build` (dangerous).

## Example

```python
ssh_docker_restart(host="docker1", container="nginx")
```

## Related

- [`ssh_docker_stop`](../ssh-docker-stop/SKILL.md)
- [`ssh_docker_start`](../ssh-docker-start/SKILL.md)
- [`ssh_docker_compose_restart`](../ssh-docker-compose-restart/SKILL.md)
