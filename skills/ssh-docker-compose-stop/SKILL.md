---
description: Stop services in a docker-compose project (keeps containers)
---

# `ssh_docker_compose_stop`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `<compose> -f <file> stop`. Graceful stop of all project services.
Containers and volumes remain -- use `ssh_docker_compose_down` for teardown.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `compose_file` | str | yes | Absolute; in `path_allowlist` |
| `compose_v1` | bool | no | Default False; use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult`.

## When to call it

- Take the project offline for maintenance, keep the state.

## When NOT to call it

- Full teardown needed -- use `ssh_docker_compose_down` (dangerous).
- Restart use case -- `ssh_docker_compose_restart` is one round trip.

## Example

```python
ssh_docker_compose_stop(host="docker1", compose_file="/opt/app/docker-compose.yml")
```

## Related

- [`ssh_docker_compose_start`](../ssh-docker-compose-start/SKILL.md)
- [`ssh_docker_compose_down`](../ssh-docker-compose-down/SKILL.md)
