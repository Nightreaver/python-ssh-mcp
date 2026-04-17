---
description: List local docker images on the remote
---

# `ssh_docker_images`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker images --format '{{json .}}'`, parses per-image JSON.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |

## Returns

`ExecResult` plus:

- `images`: list of `{Repository, Tag, ID, Size, CreatedSince, ...}`.

## When to call it

- Before `ssh_docker_pull` to check what's already cached.
- Before `ssh_docker_prune` (`scope="image"`) to preview what'll go.
- Capacity check -- find big/unused images.

## When NOT to call it

- To list running containers -- use `ssh_docker_ps`.

## Example

```python
ssh_docker_images(host="docker1")
```

## Related

- [`ssh_docker_pull`](../ssh-docker-pull/SKILL.md)
- [`ssh_docker_rmi`](../ssh-docker-rmi/SKILL.md)
- [`ssh_docker_prune`](../ssh-docker-prune/SKILL.md)
