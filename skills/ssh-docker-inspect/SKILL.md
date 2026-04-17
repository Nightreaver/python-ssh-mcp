---
description: Inspect a container, image, network, or volume (returns parsed JSON)
---

# `ssh_docker_inspect`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker inspect --type <kind> -- <target>`. Parses the JSON array and
returns it under `objects`. Most common for container config (env, mounts,
network aliases, healthcheck state).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `target` | str | yes | -- | Name or ID |
| `kind` | str | no | `"container"` | `container`/`image`/`network`/`volume` |

## Returns

`ExecResult` plus:

- `objects`: list of dicts (usually one), full JSON from docker.

## When to call it

- Check mounts / env / restart policy before changing infrastructure.
- Verify a container's network IP, state, exit code, health.
- Pre-check before `ssh_docker_rm` to confirm it's what you think.

## When NOT to call it

- You just need logs -- use `ssh_docker_logs`.
- You want all containers at once -- use `ssh_docker_ps`.

## Example

```python
ssh_docker_inspect(host="docker1", target="nginx")
ssh_docker_inspect(host="docker1", target="my-bridge", kind="network")
```

## Common failures

- `Error: No such object` with `exit_code=1` -- name is wrong.
- Invalid `kind` -> `ValueError`.

## Related

- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
- [`ssh_docker_images`](../ssh-docker-images/SKILL.md)
