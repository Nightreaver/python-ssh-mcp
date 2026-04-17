---
description: Prune unused containers / images / volumes / networks / system
---

# `ssh_docker_prune`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker <scope> prune -f [--all]`. Always passes `-f` to bypass the
interactive confirm. `all_=True` is only meaningful for `image` and `system`:

- `image prune` alone removes dangling images.
- `image prune --all` removes every image not used by any container.
- `system prune --all` removes every unused container, network, image,
  and optionally volumes.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `scope` | str | no | `"container"` | `container`/`image`/`volume`/`network`/`system` |
| `all_` | bool | no | False | More aggressive (for `image` / `system` only) |

## Returns

`ExecResult`. `stdout` lists what was deleted and total reclaimed space.

## When to call it

- Scheduled cleanup on a host with bounded disk.
- After `compose_down` when you want to reclaim image layers too.

## When NOT to call it

- Production host during business hours with `all_=True` -- aggressive prune
  can remove images currently pulling or briefly unreferenced.
- Recovery scenarios where a user might need a "dead" image back.

## Example

```python
ssh_docker_prune(host="docker1", scope="image", all_=True)
ssh_docker_prune(host="docker1", scope="system")
```

## Common failures

- Nothing to reclaim -- `stdout` shows "Total reclaimed space: 0B".

## Related

- [`ssh_docker_rm`](../ssh-docker-rm/SKILL.md)
- [`ssh_docker_rmi`](../ssh-docker-rmi/SKILL.md)
