---
description: Start a stopped container
---

# `ssh_docker_start`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `docker start -- <container>`. Container name is argv-validated. Hidden
unless `ALLOW_LOW_ACCESS_TOOLS=true`.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `container` | str | yes | Name or ID |

## Returns

`ExecResult`. `exit_code=0` on success; `stdout` is the container name.

## When to call it

- After `ssh_docker_stop` when you want service restored.
- Part of a targeted restart workflow.

## When NOT to call it

- Create a new container -- use `ssh_docker_run` (dangerous) or `compose_up`.

## Example

```python
ssh_docker_start(host="docker1", container="nginx")
```

## Common failures

- `No such container` -- `ssh_docker_ps(all_=True)` to find it.
- `already in progress` -- the container is already starting.

## Related

- [`ssh_docker_stop`](../ssh-docker-stop/SKILL.md)
- [`ssh_docker_restart`](../ssh-docker-restart/SKILL.md)
