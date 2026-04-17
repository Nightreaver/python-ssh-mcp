---
description: Create and start a new container from an image
---

# `ssh_docker_run`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker run [--rm] [-d] [--name <n>] -- <image> [args...]`. Image
name (pre-colon) and optional container name are argv-validated. Hidden
unless `ALLOW_DANGEROUS_TOOLS=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `image` | str | yes | -- | `repo:tag` |
| `args` | list[str] | no | None | Passed after image (container CMD override) |
| `name` | str | no | None | Explicit container name |
| `remove` | bool | no | True | `--rm` (auto-delete on exit) |
| `detached` | bool | no | False | `-d` (background) |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | |

## Returns

`ExecResult`.

## Capability-escalation surface (READ THIS)

`args` accepts any `docker run` flag. Flags that grant the container root on
the host are rejected by default even under `ALLOW_DANGEROUS_TOOLS`:

- `--privileged`
- `--cap-add=...`
- Host-namespace join: `--pid=host`, `--ipc=host`, `--uts=host`,
  `--userns=host`, `--network=host` / `--net=host` (both `--pid=host`
  and two-token `--pid host` rejected)
- Another-container namespace join: `--pid=container:<id>`,
  `--network=container:<id>`, etc. for all six namespace flags
- `--security-opt=...` (seccomp/apparmor disable)
- `--device=...`
- `--group-add=...`
- Host-rooted bind mounts in BOTH flag styles:
  - `-v /:/host`, `--volume=/:...`, `--volume=/`
  - `--mount type=bind,source=/,target=/host` /
    `--mount=type=bind,source=/,...` (`source` or `src`, any attribute
    order, `//` / `/./` / trailing-slash variants all caught)

These are refused with a `ValueError`. To permit them, the operator sets
`ALLOW_DOCKER_PRIVILEGED=true`. That bypass is explicit and shows up in audit
logs. Do not ask the operator to flip it casually -- it is effectively root
on the target.

## When to call it

- One-off tool invocation (e.g., `alpine: ls /mnt`) with a bind mount.
- Ad-hoc test container.

## When NOT to call it

- Production service -- use `compose_up` with a compose file (auditable config).
- You only need to run something inside an existing container -- use `docker_exec`.

## Example

```python
ssh_docker_run(host="docker1", image="alpine:3.20", args=["echo", "hi"])
```

## Common failures

- `No such image` -- `ssh_docker_pull` first or use a local image.
- Image pulled from public registry -- `--rm` ensures no orphan.
- Invalid name -> `ValueError`.

## Related

- [`ssh_docker_pull`](../ssh-docker-pull/SKILL.md)
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
