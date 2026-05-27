---
description: List docker containers on a remote host (running or all), with optional server-side filters
---

# `ssh_docker_ps`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker ps --format '{{json .}}' --no-trunc` on the remote and returns
both the raw `ExecResult` shape and a parsed `containers` list (one JSON
object per container). `all_=True` adds `-a` to include stopped containers.

Filter kwargs (`name`, `status`, `label`, `ancestor`) map directly to Docker's
`--filter KEY=VALUE` flags. Filters are validated before any SSH connection is
opened -- bad values raise `ValueError` immediately, before any I/O.

**POSIX-only.** Windows targets raise `PlatformNotSupported` (all docker tools
share this constraint via `_run_docker`'s `require_posix` gate).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from hosts.toml |
| `all_` | bool | no | `False` | Include stopped containers |
| `include_labels` | bool | no | `False` | Emit each container's `Labels` field (can be very large on OCI-tagged images; stripped by default) |
| `name` | str or None | no | `None` | Substring match on container name. Validated against `[A-Za-z0-9][A-Za-z0-9_.-]*` |
| `status` | Literal or None | no | `None` | One of: `created`, `running`, `paused`, `restarting`, `exited`, `dead` |
| `label` | str or None | no | `None` | Bare key (`role`) or key=value (`role=frontend`). See label format below |
| `ancestor` | str or None | no | `None` | Filter by ancestor image name/id. Same regex as `name` |

## Filter details

**`name`** -- Docker performs a substring match (not exact). `name="web"` matches
`web`, `web-1`, `nginx-web`, etc.

**`status`** -- Accepts exactly the six values Docker recognises for `ps`:
`created`, `running`, `paused`, `restarting`, `exited`, `dead`. Note that
`removing` is a compose-only status; it is not in this set.

**`label`** -- Two forms accepted:
- Bare key: `"role"` -- matches any container that has the label, regardless of value.
- Key=value: `"role=frontend"` -- exact value match.

Key regex: `[A-Za-z0-9._/-]{1,128}`. The `/` in the character class means
Kubernetes-style label keys work: `app.kubernetes.io/name=nginx`,
`app.kubernetes.io/managed-by`. Key length cap is 128 characters.

Value regex: `[A-Za-z0-9._:/=+-]{1,256}`. Shell metacharacters (`;`, `|`, `` ` ``,
`$`, `&`, `>`, newlines, quotes, spaces) are rejected in both key and value.

**`ancestor`** -- Matches containers created from the named image or any of its
descendants. Accepts an image name with or without a tag (`nginx`, `nginx:1.25`).
Same `_validate_name` regex as container names.

## Argv ordering (deterministic)

When filters are present the argv is always:
```
docker ps --format {{json .}} --no-trunc
  [--filter name=<name>]
  [--filter status=<status>]
  [--filter label=<label>]
  [--filter ancestor=<ancestor>]
  [-a]         # only when all_=True; always last
```

## Returns

`ExecResult` fields (exit_code, stdout, stderr, duration_ms, ...) plus:

- `containers`: list of dicts, one per container (id, image, names, status, ports, ...)

## When to call it

- First step of any container investigation.
- Before `ssh_docker_logs` / `ssh_docker_inspect` to get valid names.
- To narrow a large fleet to just running `web` containers: `name="web", status="running"`.

## When NOT to call it

- You already know the container name/id -- use `ssh_docker_inspect` directly.
- You want compose-project services -- use `ssh_docker_compose_ps`.

## Examples

List all running containers:

```python
ssh_docker_ps(host="docker1")
```

Find all stopped (`exited`) containers:

```python
ssh_docker_ps(host="docker1", all_=True, status="exited")
```

Find running containers whose name contains "web":

```python
ssh_docker_ps(host="docker1", name="web", status="running")
```

Find containers with a bare label key (any value):

```python
ssh_docker_ps(host="docker1", label="role")
```

Find containers with a specific label value, including Kubernetes-style keys:

```python
ssh_docker_ps(host="docker1", label="app.kubernetes.io/name=nginx")
```

Combine multiple filters (name + status) -- all filters are ANDed by Docker:

```python
ssh_docker_ps(host="docker1", name="web", status="running", label="role=frontend")
```

Filter by ancestor image:

```python
ssh_docker_ps(host="docker1", ancestor="nginx")
```

## Common failures

- `ValueError: container ...` -- `name` or `ancestor` contains characters outside
  `[A-Za-z0-9][A-Za-z0-9_.-]*`. Fix the value before retrying.
- `ValueError: label filter ...` -- shell metacharacter in label key or value.
- `exit_code != 0` + "permission denied" on docker.sock -- SSH user isn't in the
  `docker` group. Add them or use `ssh_sudo_exec` explicitly.

## Related

- [`ssh_docker_inspect`](../ssh-docker-inspect/SKILL.md)
- [`ssh_docker_logs`](../ssh-docker-logs/SKILL.md)
- [`ssh_docker_stats`](../ssh-docker-stats/SKILL.md)
- [`ssh_docker_compose_ps`](../ssh-docker-compose-ps/SKILL.md)
