---
description: List services + state for a docker-compose project
---

# `ssh_docker_compose_ps`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `<compose> -f <file> ps --format json`. The compose file path is
path-confined (`canonicalize_and_check`) to whatever's in `path_allowlist`.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `compose_file` | str | yes | Absolute path; must be in `path_allowlist` |
| `include_labels` | bool | no | Default False; True emits each service's labels (noisy) |
| `compose_v1` | bool | no | Default False; use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult` plus:

- `services`: list of `{Name, Service, Image, State, Status, Ports, ...}`.

## When to call it

- Check which services of a project are up / what ports they expose.
- Before `ssh_docker_compose_restart` / `ssh_docker_compose_stop` to confirm scope.

## When NOT to call it

- Ad-hoc (non-compose) containers -- use `ssh_docker_ps`.

## Example

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml")
```

## Common failures

- `PathNotAllowed` -- `compose_file` is outside the per-host `path_allowlist`.
- `no such file` -- typo in the path.

## Related

- [`ssh_docker_compose_logs`](../ssh-docker-compose-logs/SKILL.md)
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
