---
description: Pull an image from a registry
---

# `ssh_docker_pull`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker pull -- <image>`. Network + disk impact. Bump `timeout` for
slow registries or large images.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `image` | str | yes | -- | `repo:tag` |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Raise for slow pulls |

## Returns

`ExecResult`. Success = exit_code 0.

## When to call it

- Update an image before `compose_up`.
- Prime a host's image cache.

## When NOT to call it

- Pulling as part of compose -- `compose_pull` operates on all project images in one call.

## Example

```python
ssh_docker_pull(host="docker1", image="nginx:1.29", timeout=300)
```

## Common failures

- `manifest unknown` -- tag doesn't exist.
- `denied` -- registry auth missing; docker login out-of-band.
- `timeout` -- raise the `timeout` kwarg or wait for docker's own timeout.

## Related

- [`ssh_docker_images`](../ssh-docker-images/SKILL.md)
- [`ssh_docker_compose_pull`](../ssh-docker-compose-pull/SKILL.md)
