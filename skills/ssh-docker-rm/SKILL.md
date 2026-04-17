---
description: Remove a container (optionally force-kill if running)
---

# `ssh_docker_rm`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker rm [-f] -- <container>`. `force=True` kills running containers
first. Irreversible -- data in the container filesystem is gone.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `container` | str | yes | -- | Argv-validated |
| `force` | bool | no | False | `-f` kills before remove |

## Returns

`ExecResult`.

## When to call it

- Orphaned container from a failed `run`.
- Clear a single service before `compose_up` recreates it (though `compose_up`
  handles this itself in most cases).

## When NOT to call it

- Entire project teardown -- use `compose_down` (handles networks, volumes if asked).
- Container has unique state you care about -- back up first.

## Example

```python
ssh_docker_rm(host="docker1", container="old-nginx", force=True)
```

## Common failures

- `No such container` -- already gone.
- `container is running` -- pass `force=True` or `ssh_docker_stop` first.

## Related

- [`ssh_docker_stop`](../ssh-docker-stop/SKILL.md)
- [`ssh_docker_compose_down`](../ssh-docker-compose-down/SKILL.md)
