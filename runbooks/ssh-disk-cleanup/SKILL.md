---
description: Investigate a disk-full host and recover space safely -- find before prune, never volume-prune from the LLM
---

# SSH Disk Cleanup

Disk-full is one of the most common page causes and one of the easiest
to make worse. The right order is **investigate first, prune second**;
the wrong order destroys state you can't reconstruct. Uses `read` +
`dangerous` tiers; dangerous steps are flagged.

Pair with [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) as
the trigger ("`ssh_host_alerts` flagged a disk breach") and with
[ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
Section 6 when the culprit is Docker's data-root.

## Sequence

1. Locate the breach
2. Find the actual space consumers
3. Decide: logs, app data, Docker, or user data
4. Recover -- safest lever first

## 1. Locate the breach

```python
ssh_host_disk_usage(host="web01")
ssh_host_alerts(host="web01")
```

Read `disk_entries[]` -- each row has `mount` and `use_percent`. Target
the mount(s) in breach, not the host as a whole. `/` at 95% and `/var`
at 20% is a different problem from `/` at 60% and `/var` at 95%.

Note which mount holds each of:

- `/var/log/*` -- rotated and un-rotated log files.
- `/var/lib/docker` (or `/var/lib/containers` on podman) -- container /
  image / volume data. Often a separate mount; if it's the one in breach,
  jump to the Docker branch in Section 3.
- `/home`, `/opt`, `/srv` -- app data + user data. Rarely safe to prune
  without operator review.

## 2. Find the actual consumers

```python
ssh_find(host="web01", path="/var/log",
         name_pattern="*.gz", kind="f", max_depth=4)
ssh_find(host="web01", path="/var/log",
         name_pattern="*.log", kind="f", max_depth=4)
```

`ssh_find` returns paths but no sizes; use `ssh_sftp_stat` on the top
suspects to confirm what's actually big:

```python
ssh_sftp_stat(host="web01", path="/var/log/nginx/access.log.1.gz")
```

When you need bigger-picture "what's eating the mount" and exec tier is
available, one shot of `du -x -h --max-depth=2 /var` via
`ssh_exec_run` is usually faster than iterating `ssh_find` +
`ssh_sftp_stat`. Scope `du` to the breached mount (`-x` keeps it on one
filesystem). Without exec tier, the `find`+`stat` loop is the read-only
path.

Common patterns to look for:

- Old rotated logs (`*.log.1`, `*.log.2.gz`, ...) accumulated because
  logrotate is broken. Often GBs of `*.gz` under `/var/log/`.
- An application log not under logrotate's control writing unbounded to
  `/var/log/<app>/` or `/opt/<app>/logs/`.
- Docker data-root ballooning -- stopped containers, dangling images,
  orphaned volumes. Jump to Section 3 "Docker" branch.
- Core dumps (`/var/lib/systemd/coredump/`, `/var/crash/`) from a
  crashing service.
- A runaway `tmp` directory the app never cleans up.

## 3. Decide what to recover

Pick the branch matching what Section 2 found. Stop and escalate if
Section 2 found nothing obvious -- blindly pruning anything is how you
lose data.

### Branch A: Old rotated logs

Safest recovery. Rotated `.gz` files are by definition archival and
logrotate will recreate them.

Requires `ALLOW_DANGEROUS_TOOLS` (`ssh_delete` is dangerous tier):

```python
# Example: delete nginx rotated logs older than current + .1
ssh_delete(host="web01", path="/var/log/nginx/access.log.2.gz")
ssh_delete(host="web01", path="/var/log/nginx/access.log.3.gz")
# ... iterate on the list from ssh_find
```

Do not delete the live `access.log` itself -- even if you truncate it,
nginx holds an open fd and disk doesn't free until restart. Delete
rotated siblings instead, then ask logrotate to rotate again
(`ssh_exec_run "logrotate -f /etc/logrotate.d/nginx"`).

### Branch B: Docker data-root

Hand off to
[ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
Section 6. Do not re-derive the prune logic here. Key point to carry
over: **never run `ssh_docker_prune(scope="volume")` from an LLM turn**.
Named volumes carry application state (databases, uploads). Enumerate
with `ssh_docker_volumes` first, inspect each, escalate the actual
prune to an operator.

### Branch C: Application data

Out of scope for an LLM turn. Examples: Postgres `/var/lib/postgresql`
at 95%, a user-uploaded-files mount at 95%, `/home/<user>` at 95%.
Deleting anything here requires operator judgment about what's safe to
drop (old WAL segments? retention policy?). Report the finding and
stop.

### Branch D: Core dumps / crash artifacts

Safe to delete if the incident they came from has already been
investigated. Cross-check against `ssh_host_info` uptime and recent
`journalctl` entries (exec tier) before removing evidence of a crash
that nobody has looked at yet. Rule of thumb: if you'd want someone to
have looked at it before you delete it, don't delete it.

## 4. Confirm the recovery

Re-run Section 1:

```python
ssh_host_disk_usage(host="web01")
ssh_host_alerts(host="web01")
```

`use_percent` should drop and the breach should clear. If disk usage
didn't budge, the files you deleted were held open by a live process --
restart the owning service, or accept the reclaim will happen on next
service restart.

## Boundaries

- Sections 1-2 are read-only.
- Section 3 requires `ALLOW_DANGEROUS_TOOLS` (`ssh_delete`,
  `ssh_docker_prune`, `ssh_exec_run`).
- Branch B's volume prune and Branch C (application data) **always**
  escalate, even with dangerous-tier flags set. The cost of a wrong
  deletion there is hours-to-days of work; the cost of escalating is
  minutes.
- `ssh_delete_folder` (recursive) is deliberately not the first reach;
  prefer iterating `ssh_find` results + `ssh_delete` so the operator
  can see and audit each path.

## Related runbooks

- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- usually
  the trigger for this runbook.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  -- the Docker branch.
- [ssh-incident-response](../ssh-incident-response/SKILL.md) -- if disk
  is full **because** the host is in a bad state, not the cause.
