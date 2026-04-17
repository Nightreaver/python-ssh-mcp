---
description: Read logs from a docker-compose project (optionally scoped to one service)
---

# `ssh_docker_compose_logs`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `<compose> -f <file> logs --tail=N --no-color [<service>]`. `--no-color`
keeps ANSI escape sequences out of the captured output. Path-confined.

## Context-protection defaults

Same guards as `ssh_docker_logs` plus a service filter:

- `tail=50`, raise to 10000 at most.
- `max_bytes=65536` (~16k tokens). Multi-service projects hit this fast;
  always prefer `service=<name>` when you can scope.
- If the cap is hit, narrow scope, use `service=`, or grep via `ssh_docker_exec`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `compose_file` | str | yes | -- | Absolute path; in `path_allowlist` |
| `tail` | int | no | 50 | 1..10000 |
| `service` | str | no | None | Limit to one service (argv-validated) |
| `max_bytes` | int | no | 65536 | 1 KiB..10 MiB |
| `compose_v1` | bool | no | False | Use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |

## Returns

`ExecResult`. Logs are in `stdout`. Check `stdout_truncated=true`.

## When to call it

- Follow a multi-service incident end-to-end.
- Capture all project logs right before `ssh_docker_compose_down`.

## When NOT to call it

- Single-container debug -- `ssh_docker_logs` is simpler.
- You know which service is affected -- always pass `service=...` to cut
  bytes roughly proportional to the number of services.

## Example

```python
# Prefer narrow scope first
ssh_docker_compose_logs(
    host="docker1",
    compose_file="/opt/app/docker-compose.yml",
    service="web",
    tail=50,
)
```

## Related

- [`ssh_docker_logs`](../ssh-docker-logs/SKILL.md)
- [`ssh_docker_compose_ps`](../ssh-docker-compose-ps/SKILL.md)
