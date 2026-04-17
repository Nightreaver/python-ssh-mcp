---
description: List the running processes inside a container (docker top)
---

# `ssh_docker_top`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker top <container>` and returns the raw `ps`-style output. Docker
does NOT expose a JSON format for this subcommand, so the output lands in
`stdout` unchanged for the caller to parse.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `container` | str | yes | -- | Container name or id; argv-validated |
| `ps_options` | str | no | None | Extra argv suffix for the container's `ps` (e.g. `"-eo pid,user,comm"`). Split with `shlex`; shell metacharacters are rejected. |

## Returns

`ExecResult`. Parse `stdout` yourself if you need structured data --
`docker top` output layout varies by the container's `ps` implementation
(busybox vs procps, etc.), so we do not attempt parsing here.

## When to call it

- "What is actually running inside this container right now?"
- Confirm PID 1 matches the expected entrypoint.
- Compare memory / CPU attribution with `ssh_docker_stats`.

## When NOT to call it

- You want host-level process information -- use `ssh_host_processes`.
- You need structured output -- parse `stdout` client-side, or use
  `ssh_docker_exec` with `ps -eo pid,user,pcpu,pmem,comm --no-headers` and a
  command-allowlist entry for `ps`.

## Example

```python
ssh_docker_top(host="docker1", container="nginx")
ssh_docker_top(host="docker1", container="nginx", ps_options="-eo pid,user,comm")
```

## Common failures

- `No such container` -- use `ssh_docker_ps` to find the right name.
- `ps_options contains shell metacharacters` -- any of `|&;<>\`$\n` in the
  value will be rejected before the call reaches docker.

## Related

- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md)
- [`ssh_docker_stats`](../ssh-docker-stats/SKILL.md)
- [`ssh_host_processes`](../ssh-host-processes/SKILL.md)
