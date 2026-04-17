---
description: Pull images for a docker-compose project (no service restart)
---

# `ssh_docker_compose_pull`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `<compose> -f <file> pull`. Fetches the latest images defined in the
project file. Running services are not affected until `compose_up` /
`compose_restart`. Path-confined.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `compose_file` | str | yes | -- | Absolute; in `path_allowlist` |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Raise for large images |
| `compose_v1` | bool | no | False | Use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult`.

## When to call it

- Scheduled image refresh before a maintenance window.
- Before `compose_up` when you want to avoid the "pull + start" being one
  unstopped operation.

## When NOT to call it

- Single image update -- `ssh_docker_pull` is simpler.
- You plan to `compose_up` immediately anyway -- that does its own pull.

## Example

```python
ssh_docker_compose_pull(
    host="docker1",
    compose_file="/opt/app/docker-compose.yml",
    timeout=600,
)
```

## Common failures

- Registry timeout -- raise `timeout`.
- `denied` on private registries -- docker login out-of-band.

## Related

- [`ssh_docker_pull`](../ssh-docker-pull/SKILL.md)
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
