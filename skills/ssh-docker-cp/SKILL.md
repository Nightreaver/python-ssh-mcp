---
description: Copy a file in or out of a container (docker cp), host-side path allowlisted
---

# `ssh_docker_cp`

**Tier:** low-access | **Group:** `docker` | **Tags:** `{low-access, group:docker}`

Runs `docker cp` in either direction. The host-side path (`host_path`) is
canonicalized on the remote via `realpath -m` (or SFTP realpath on Windows)
and checked against `path_allowlist` + `restricted_paths` -- same rules as
`ssh_cp` / `ssh_upload`. The container-side path (`container_path`) lives
inside the container's filesystem and is NOT policy-checked -- we do not
manage allowlists inside container images.

Hidden unless `ALLOW_LOW_ACCESS_TOOLS=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `container` | str | yes | -- | Container name or id; argv-validated |
| `container_path` | str | yes | -- | Path inside the container (no allowlist) |
| `host_path` | str | yes | -- | Path on the SSH host (allowlist + restricted enforced) |
| `direction` | `"from_container"` \| `"to_container"` | yes | -- | Which side is source |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Per-call timeout |

## Returns

`ExecResult`. Non-zero `exit_code` is reported as data; the body of stderr
carries the docker-level error (e.g. `No such container`, `no such file`).

## When to call it

- Pull a generated report out of a job container for inspection.
- Seed a container with a small config file at run time (prefer a bind mount
  if you control the container's lifecycle).
- Retrieve a one-off log or state dump before `docker_rm`.

## When NOT to call it

- Bulk-copy large trees -- docker cp streams through the daemon and is not
  designed for multi-GB payloads; use a bind mount or `docker exec` + tar.
- Secrets distribution -- use a proper secret store (Vault, SOPS, env from a
  sealed source), not ad-hoc file copies.
- Editing a file already baked into an image -- that's what image builds
  are for. `docker cp` to a running container is ephemeral; the next
  container from the same image won't see the change.

## Direction semantics

- **`from_container`**: copies `container:<container_path>` onto the host.
  `host_path` is treated as the destination. The parent must exist and be
  allowlisted; the file itself may or may not exist yet.
- **`to_container`**: copies `<host_path>` into the container. `host_path`
  must exist (checked via `realpath --`), must be allowlisted, and must not
  fall inside a restricted zone.

## Example

```python
# Pull a build artifact out of the runner container.
ssh_docker_cp(
    host="docker1",
    container="ci-runner",
    container_path="/workspace/artifacts/report.xml",
    host_path="/opt/app/ci/report.xml",
    direction="from_container",
)

# Push a freshly-generated config into a container before a restart.
ssh_docker_cp(
    host="docker1",
    container="nginx",
    container_path="/etc/nginx/conf.d/site.conf",
    host_path="/opt/app/nginx/site.conf",
    direction="to_container",
)
```

## Common failures

- `PathNotAllowed` -- `host_path` is outside `path_allowlist`.
- `PathRestricted` -- `host_path` is inside a `restricted_paths` zone
  (e.g. `/etc/shadow`). Use `ssh_exec_run` / `ssh_sudo_exec` if you really
  need that path (subject to dangerous-tier gating).
- `No such container` -- check `ssh_docker_ps`.
- `Could not find the file ... in container` -- the path inside the
  container doesn't exist; confirm with `ssh_docker_exec` and `ls`.
- Container name with invalid chars -> `ValueError`.

## Security notes

- A compromised container image could stage a symlink chain inside
  `container_path` that points at a surprising location when extracted. On
  `from_container`, the resulting file lands where we told docker it should
  -- but its *contents* could be anything. Treat pulled files as untrusted.
- `ssh_docker_cp` does NOT elevate. If the SSH user can't read the file
  inside the container's filesystem, the copy fails; same in reverse.

## Related

- [`ssh_cp`](../ssh-cp/SKILL.md) -- host-to-host copy (no container involvement)
- [`ssh_upload`](../ssh-upload/SKILL.md) -- base64 payload upload with atomic rename
- [`ssh_docker_exec`](../ssh-docker-exec/SKILL.md) -- run a command inside the container instead of copying
