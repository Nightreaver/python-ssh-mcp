---
description: Disk-usage summary across docker object types (docker system df)
---

# `ssh_docker_system_df`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker system df --format '{{json .}}'` and parses the four NDJSON
rows into `categories`: Images, Containers, Local Volumes, Build Cache.
One call, all four categories with `TotalCount`, `Active`, `Size`, and
`Reclaimable` -- the answer to "why is `/var/lib/docker` getting full?"
without walking every object individually.

**POSIX-only.** Windows targets raise `PlatformNotSupported`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |

## Returns

`ExecResult` plus `categories`: a list of dicts, one per docker object
type. Each entry shape (alphabetical keys, every value a string):

```json
{
  "Active": "62",
  "Reclaimable": "201.1GB (85%)",
  "Size": "235.7GB",
  "TotalCount": "190",
  "Type": "Images"
}
```

All values are Docker's own **human-readable strings** -- the tool does
not byte-convert. `Size` is the total disk consumption of that category;
`Reclaimable` is what `ssh_docker_prune` on the matching scope would
free.

The four `Type` rows in a healthy daemon: `Images`, `Containers`,
`Local Volumes`, `Build Cache`. The first three carry a `(NN%)` suffix
on `Reclaimable` (e.g. `"99.73GB (99%)"`); `Build Cache`'s
`Reclaimable` is the bare size with no percentage. A malformed line in
the middle of the stream is silently skipped -- the daemon occasionally
prints a warning before the JSON when laggy.

## When to call it

- **Before `ssh_docker_prune` of any scope.** `Reclaimable` on the
  matching category tells you what a prune would free. Pruning blind
  without seeing this is how you trigger an alert from "0.05 GB freed,
  not worth it" or a surprise from "47 GB freed, killed Redis dump".
- Fast first-pass triage on disk-pressure alerts (`/var/lib/docker > 80%`):
  one tool call shows which of the four categories is bloated, so the
  next call (`ssh_docker_volumes`, `ssh_docker_images --dangling=True`,
  etc.) is targeted.
- Capacity-planning sweeps across many hosts: chain with `ssh_broadcast`
  to compare disk consumption across a fleet.

## When NOT to call it

- You need per-image or per-container detail (which exact image is
  eating 30 GB?) -- this tool only shows category aggregates. Use
  `ssh_docker_images` / `ssh_docker_ps` / `ssh_docker_volumes` for the
  itemized view.
- You need byte-exact numbers for accounting -- `Size` is formatted
  (`"3.2GB"`, `"500MB"`); parse it yourself if you need to sum.
- The host is not running docker -- `exit_code` will be non-zero with
  `Cannot connect to the Docker daemon` in `stderr`.

## Example

```python
df = ssh_docker_system_df(host="docker1")
for cat in df["categories"]:
    print(f"{cat['Type']:<15} size={cat['Size']:>10}  reclaimable={cat['Reclaimable']}")
# Real fleet host this was built against:
#   Images          size=  235.7GB  reclaimable=201.1GB (85%)
#   Containers      size=  2.723GB  reclaimable=474.6MB (17%)
#   Local Volumes   size=  100.5GB  reclaimable=99.73GB (99%)
#   Build Cache     size=   72.6GB  reclaimable=17.54GB

# 99% of volumes reclaimable is the obvious target; confirm those volumes
# carry no live state first via ssh_docker_volumes, then:
# ssh_docker_prune(host="docker1", scope="volume")
```

## Common failures

- `exit_code=1` with `Cannot connect to the Docker daemon` in `stderr`
  -- daemon is down or the SSH user can't reach `/var/run/docker.sock`.
  Confirm with `ssh_docker_ps`.
- `categories=[]` with `exit_code=0` -- shouldn't happen on a healthy
  daemon (df always emits at least the four standard rows). If you see
  it, the JSON format flag isn't being honored (very old Docker CLI);
  fall back to `ssh_exec_run docker system df` and parse the table
  text.

## Related

- [`ssh_docker_prune`](../ssh-docker-prune/SKILL.md) -- the mutating
  counterpart. Always run `ssh_docker_system_df` first to estimate impact.
- [`ssh_docker_volumes`](../ssh-docker-volumes/SKILL.md) -- per-volume
  detail when the Volumes category looks bloated.
- [`ssh_docker_images`](../ssh-docker-images/SKILL.md) -- per-image
  detail; combine with `dangling=True` to find untagged layers.
- [`runbooks/ssh-docker-incident-response/`](../../runbooks/ssh-docker-incident-response/SKILL.md)
  -- disk-pressure runbook.
