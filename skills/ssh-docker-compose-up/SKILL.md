---
description: Bring up a docker-compose project (default detached)
---

# `ssh_docker_compose_up`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `<compose> -f <file> up [-d] [--build]`. Creates networks, volumes,
and containers as described by the compose file. Path-confined.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `compose_file` | str | yes | -- | Absolute; in `path_allowlist` |
| `detached` | bool | no | True | `-d` (don't attach to container output) |
| `build` | bool | no | False | `--build` rebuild images first |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Raise for slow builds/pulls |
| `compose_v1` | bool | no | False | Use legacy `docker-compose` standalone binary (see below) |

## Returns

`ExecResult`.

## When to call it

- First deploy of a project.
- After editing the compose file.
- After `compose_pull` on a shared image update.

## When NOT to call it

- Just restarting existing services -- `compose_restart` (low-access) is
  narrower.
- No changes have been made and services are already up -- no-op.

## Example

```python
ssh_docker_compose_up(
    host="docker1",
    compose_file="/opt/app/docker-compose.yml",
    detached=True,
    build=False,
    timeout=300,
)
```

## Common failures

- `PathNotAllowed` -- compose_file outside allowlist.
- `compose file version unsupported` -- upgrade docker compose on the host.
- Long running when pulling/building -- raise the `timeout` kwarg.

## Compose v1 vs v2 (`compose_v1` switch)

Two compose implementations coexist in the wild:

- **v2 (default):** `docker compose up` -- subcommand of the docker CLI
  plugin. Current upstream, actively maintained.
- **v1:** `docker-compose up` -- separate Python binary, upstream-removed in
  2023 but still deployed on older hosts and embedded images.

Default is v2. Pass `compose_v1=True` when you hit errors like:

- `docker: 'compose' is not a docker command.`
- `unknown shorthand flag` on flags that v2 supports (v1 is stricter on some
  v2-only options).

The switch also applies to podman operators -- `SSH_DOCKER_CMD=podman` with
`compose_v1=True` yields `podman-compose` (standalone) instead of
`podman compose` (plugin). Wrappers like `sudo docker` are preserved:
`sudo docker` + `compose_v1=True` -> `sudo docker-compose`.

`compose_v1=True` overrides `SSH_DOCKER_COMPOSE_CMD` if set globally -- the
per-call switch is the escape hatch when the configured default doesn't fit
this particular stack.

Every `ssh_docker_compose_*` tool accepts the same kwarg with the same
semantics. Set it per-call, not per-host, unless you know the host is
uniformly v1.

## Related

- [`ssh_docker_compose_down`](../ssh-docker-compose-down/SKILL.md)
- [`ssh_docker_compose_pull`](../ssh-docker-compose-pull/SKILL.md)
- [`ssh_docker_compose_restart`](../ssh-docker-compose-restart/SKILL.md)
