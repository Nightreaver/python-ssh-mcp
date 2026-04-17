---
description: Run a command inside a container (arbitrary shell)
---

# `ssh_docker_exec`

**Tier:** dangerous | **Group:** `docker` | **Tags:** `{dangerous, group:docker}`

Runs `docker exec [-i] -- <container> sh -c <command>`. Container name is
argv-validated; the **command** is checked against `command_allowlist` (same
rule as `ssh_exec_run`). Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `container` | str | yes | -- | Argv-validated |
| `command` | str | yes | -- | Full shell command; subject to `command_allowlist` |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Seconds |
| `interactive` | bool | no | False | Adds `-i` (pipe stdin to container) |

## Returns

`ExecResult`. Non-zero exit is data, not raised.

## When to call it

- Diagnose inside a container when host-level tools can't see its state.
- Invoke a CLI baked into an image (`alpine` tools, db clients, etc.).

## When NOT to call it

- Run ad-hoc scripts -- use `ssh_exec_script` on the host if the script doesn't
  need the container filesystem.
- Start a long-running process -- use `compose_up` with service definition instead.

## Example

```python
ssh_docker_exec(host="docker1", container="postgres", command="psql -U postgres -c 'SELECT 1;'")
```

## Command allowlist interaction

The `command` first token is checked against per-host `command_allowlist` +
env `SSH_COMMAND_ALLOWLIST`. Empty allowlist rejects everything unless
`ALLOW_ANY_COMMAND=true`. Same semantics as `ssh_exec_run`.

## Common failures

- `CommandNotAllowed` -- first token not in allowlist.
- `No such container` -- check `ssh_docker_ps`.
- `exit_code != 0` -- command's own error; returned as data.

## Related

- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- host-level exec, not container.
- [`ssh_exec_script`](../ssh-exec-script/SKILL.md)
