---
description: List Docker volumes on a host, or inspect one by name (docker volume ls / inspect)
---

# `ssh_docker_volumes`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Two modes in one tool, discriminated by the `name` argument:

- **Without `name`** -> runs `docker volume ls --format '{{json .}}'`.
  Returns the parsed list: every volume currently on the host with its
  driver, labels, and mountpoint.
- **With `name`** -> runs `docker volume inspect -- <name>`. Returns the
  parsed inspect JSON (detailed metadata: driver, options, mountpoint,
  labels, usage-data if available).

Volume name is argv-validated against the Docker naming rule.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `name` | str | no | None | If set, inspects a single volume. Otherwise lists all. |

## Returns

`ExecResult` plus `volumes`: a list of dicts. Shape depends on mode:

- **ls**: one dict per volume, keys like `Driver`, `Labels`, `Mountpoint`,
  `Name`, `Scope`.
- **inspect**: single-element list (or more if `name` is a filter), dicts
  with the full `inspect` shape: `CreatedAt`, `Driver`, `Labels`,
  `Mountpoint`, `Name`, `Options`, `Scope`, `UsageData` (if the Docker
  daemon supports it).

## When to call it

- **Before `ssh_docker_prune(scope="volume")`.** The runbook at
  `runbooks/ssh-docker-incident-response/SKILL.md` explicitly warns against
  pruning volumes from an LLM turn without seeing what's there -- named
  volumes often carry application state (database data, uploaded files,
  Redis dumps). Use this tool to enumerate before any prune decision.
- Debugging a compose service that can't start because its volume mount
  resolves to an empty directory -- list volumes, inspect the one the
  service references, check `Mountpoint` and `CreatedAt`.
- Auditing disk-attribution: which container is responsible for the
  30GB named volume on `/var/lib/docker/volumes/...`? Inspect + then
  `ssh_docker_ps --filter volume=<name>` (via exec_run).

## When NOT to call it

- You want bind mounts (host-path mounts, not named volumes) -- those
  show up under `Mounts` in `ssh_docker_inspect` for a container, not in
  `docker volume ls`.
- You want to know which container is USING a volume -- `docker volume
  inspect` doesn't track that. Use `ssh_docker_ps --filter
  volume=<name>` via `ssh_exec_run` with a command-allowlist entry.

## Example

```python
# List
result = ssh_docker_volumes(host="docker1")
for v in result["volumes"]:
    print(v["Name"], v.get("Driver"), v.get("Labels"))

# Inspect one
result = ssh_docker_volumes(host="docker1", name="pg_data")
info = result["volumes"][0]
print(info["Mountpoint"], info["CreatedAt"], info.get("UsageData"))
```

## Common failures

- Invalid volume name -> `ValueError: invalid docker volume name ...`
  before the call reaches Docker. Only alnum + `_.-` allowed.
- `No such volume` when inspecting -> check the spelling via `ls` first.
- Empty `volumes` list in `ls` mode -> host genuinely has no volumes
  (or Docker is in a broken state; confirm with `ssh_docker_ps`).

## Related

- [`ssh_docker_inspect`](../ssh-docker-inspect/SKILL.md) -- container /
  image / network / volume in one tool. `ssh_docker_volumes(name=...)`
  is equivalent to `ssh_docker_inspect(target=..., kind="volume")`; the
  dedicated tool exists because the ls variant is the primary use case.
- [`ssh_docker_prune`](../ssh-docker-prune/SKILL.md) -- mutating;
  `scope="volume"` deletes data. Always list volumes first.
- [`runbooks/ssh-docker-incident-response/`](../../runbooks/ssh-docker-incident-response/SKILL.md)
  -- disk-pressure runbook that explicitly chains volumes + prune.
