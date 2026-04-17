---
description: Restart services in a docker-compose project
---

# `ssh_docker_compose_restart`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `<compose> -f <file> restart`. Equivalent to `compose_stop` then
`compose_start` in one call.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `compose_file` | str | yes | Absolute; in `path_allowlist` |
| `compose_v1` | bool | no | Default False; use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult`.

## When to call it

- Bulk config reload across a project's services.
- After `ssh_edit` on a file mounted into the project's services.

## When NOT to call it

- Image update -- needs `compose_pull` + `compose_up` (both dangerous).
- New services added to compose file -- `compose_up` (dangerous) creates them.

## Example

```python
ssh_docker_compose_restart(host="docker1", compose_file="/opt/app/docker-compose.yml")
```

## Related

- [`ssh_docker_compose_stop`](../ssh-docker-compose-stop/SKILL.md)
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
