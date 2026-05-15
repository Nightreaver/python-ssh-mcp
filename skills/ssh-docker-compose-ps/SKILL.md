---
description: List services + state for a docker-compose project, with optional service and status filters
---

# `ssh_docker_compose_ps`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `<compose> -f <file> ps --format json`. The compose file path is
path-confined (allowlist + restricted-zones check) to whatever's in `path_allowlist`.

A compose YAML is *executed* (mounts volumes, declares ports, runs init commands), so its file-path is policy-gated the same way read/write paths are.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias |
| `compose_file` | str | yes | Absolute path; must be in `path_allowlist` and outside `restricted_paths` |
| `include_labels` | bool | no | Default False; True emits each service's labels (noisy) |
| `compose_v1` | bool | no | Default False; use legacy `docker-compose` binary -- see [compose_v1 explainer](../ssh-docker-compose-up/SKILL.md#compose-v1-vs-v2-compose_v1-switch) |
| `service` | str or None | no | Narrow output to a single compose service by name. Validated against `[A-Za-z0-9][A-Za-z0-9_.-]*` |
| `status` | Literal or None | no | Filter by service state. See status values below |

## Filter details

**`service`** -- Passed as a trailing positional argument to `compose ps` (Docker
Compose positional convention). When set, only the named service's containers appear
in the output. Validated against `_validate_name` (`[A-Za-z0-9][A-Za-z0-9_.-]*`)
before any SSH connection is opened -- shell metacharacters in the service name raise
`ValueError` immediately.

**`status`** -- Accepts exactly the seven states Docker Compose recognises:
`paused`, `restarting`, `removing`, `running`, `dead`, `created`, `exited`.

Note: `removing` is **compose-only** -- it appears here but NOT in `ssh_docker_ps`'s
status set. This is the state a container is in while `docker compose rm` or
`docker compose down` is executing. If you are looking for a container in the
`removing` state, you must use `ssh_docker_compose_ps`, not `ssh_docker_ps`.

## Argv ordering (deterministic)

When filters are present, the argv is always:
```
<compose_cmd> -f <compose_file> ps --format json
  [--filter status=<status>]   # flag before positional
  [<service>]                  # trailing positional, always last
```

The `--filter status=` flag is placed **before** the `<service>` positional because
Docker Compose requires flags before positional arguments.

## Returns

`ExecResult` plus:

- `services`: list of `{Name, Service, Image, State, Status, Ports, ...}`.

## When to call it

- Check which services of a project are up / what ports they expose.
- Before `ssh_docker_compose_restart` / `ssh_docker_compose_stop` to confirm scope.
- Narrow to one service: `service="web"` to see only the web tier.
- Find all services in a specific state: `status="exited"` to surface crashed services.

## When NOT to call it

- Ad-hoc (non-compose) containers -- use `ssh_docker_ps`.
- You want to filter by container name or ancestor image -- use `ssh_docker_ps`.

## Examples

List all services in a project:

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml")
```

Narrow to a single service:

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml", service="web")
```

Find all exited (crashed) services:

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml", status="exited")
```

Find a specific service AND filter by status (e.g. confirm the web service is running):

```python
ssh_docker_compose_ps(
    host="docker1",
    compose_file="/opt/app/docker-compose.yml",
    service="web",
    status="running",
)
```

Find services currently being removed (compose-only state):

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml", status="removing")
```

## Common failures

- `PathNotAllowed` -- `compose_file` is outside the per-host `path_allowlist`.
- `PathRestricted` -- compose_file inside a restricted zone (e.g. SMB mount, NFS share).
- `no such file` -- typo in the path.
- `ValueError: service ...` -- service name contains shell metacharacters. Fix the
  value; valid names match `[A-Za-z0-9][A-Za-z0-9_.-]*`.

## Related

- [`ssh_docker_compose_logs`](../ssh-docker-compose-logs/SKILL.md)
- [`ssh_docker_compose_up`](../ssh-docker-compose-up/SKILL.md)
- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
