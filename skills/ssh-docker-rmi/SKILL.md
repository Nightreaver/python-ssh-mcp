---
description: Remove an image
---

# `ssh_docker_rmi`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker rmi [-f] -- <image>`. Reclaims disk space. `force=True` also
removes dependents that would otherwise block the delete.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `image` | str | yes | -- | `repo:tag` or ID |
| `force` | bool | no | False | `-f` |

## Returns

`ExecResult`.

## When to call it

- Specific image cleanup after confirming with `ssh_docker_images`.

## When NOT to call it

- Bulk cleanup -- `ssh_docker_prune` with `scope="image"` is safer.

## Example

```python
ssh_docker_rmi(host="docker1", image="nginx:1.25")
```

## Common failures

- `image is being used by container` -- stop/remove containers first or use `force=True`.

## Related

- [`ssh_docker_images`](../ssh-docker-images/SKILL.md)
- [`ssh_docker_prune`](../ssh-docker-prune/SKILL.md)
