---
description: Tear down a docker-compose project (optionally wipe volumes)
---

# `ssh_docker_compose_down`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `<compose> -f <file> down [-v]`. Stops and removes containers,
networks (unless external). `volumes=True` also removes named volumes --
**this is destructive** and will delete persistent data such as database
contents. Path-confined.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `compose_file` | str | yes | -- | Absolute; in `path_allowlist` |
| `volumes` | bool | no | False | Delete named volumes (DATA LOSS) |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | |
| `compose_v1` | bool | no | False | Use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult`.

## When to call it

- Permanent service teardown.
- Project rebuild from zero where you also want the volumes wiped.

## When NOT to call it

- You only need to stop -- `compose_stop` (low-access) keeps containers.
- `volumes=True` without a backup of any stateful service in the project.

## Example

```python
ssh_docker_compose_down(host="docker1", compose_file="/opt/app/docker-compose.yml")
```

## Common failures

- `PathNotAllowed` -- compose_file outside allowlist.
- Orphan containers not removed -- use `docker rm` manually or `compose_up --remove-orphans`
  before this.

## Related

- [`ssh_docker_compose_stop`](../ssh-docker-compose-stop/SKILL.md) -- preserves state
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
