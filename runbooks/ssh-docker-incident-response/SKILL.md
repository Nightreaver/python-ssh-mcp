---
description: Diagnose a Docker container or compose stack that's failing, looping, or unresponsive
---

# Docker Incident Response

When a container is dead, looping, OOMing, or the host is out of disk, follow
this sequence. Uses only `safe`/`read` tier tools by default; low-access +
dangerous steps are explicitly marked and guarded.

## 1. Get the full container inventory

```python
ssh_docker_ps(host="docker1", all_=True)
```

`all_=True` includes stopped containers -- a missing container is often the
whole diagnosis. Read the list:

- Container you expect is **missing** -> it died hard (see Section 3 to
  find out why) or it was never started (check `ssh_docker_images` and the
  compose file).
- Container is **restarting** / stuck in `Created` -> restart loop; go to
  Section 3.
- Container is `Up` but the service is still broken -> go to Section 4.

## 2. Triage host-level resource pressure + recent events

Container symptoms often reflect host-level problems. In parallel:

- `ssh_host_disk_usage` -- Docker blows up hard when `/var/lib/docker`
  partition is > 90% full. Look for the mount hosting Docker's data-root.
- `ssh_host_alerts` -- one call for disk / load / memory against the host's
  configured thresholds.
- `ssh_docker_stats(host=...)` -- one-shot CPU/memory/net/block I/O per
  container. The container eating 95% CPU or 100% memory is usually the
  culprit, even if it's not the one the user reported.
- `ssh_docker_events(host=..., since="30m")` -- the daemon's own log of
  what just happened. Often tells you the whole story in 30 seconds:
  OOM kills surface as `event=oom`, crashes as `event=die` with an exit
  code attribute, surprise image pulls as `type=image event=pull`.
  Narrow with `filters=["container=<name>"]` once you know the suspect.

If disk is the bottleneck, jump to Section 6.

## 3. Root-cause a failing container

For the suspect container, pull its metadata + logs in parallel:

```python
ssh_docker_inspect(host="docker1", target="nginx", kind="container")
ssh_docker_logs(host="docker1", container="nginx", tail=200)
```

Read `inspect` output first -- it tells you **why** the container is in
its current state without you having to parse logs:

- `State.Status` -- `exited` / `restarting` / `dead` / `running`.
- `State.ExitCode` -- non-zero means the process died on its own.
  - `137` -> SIGKILL, usually OOM (cross-check with `State.OOMKilled: true`).
  - `143` -> SIGTERM, clean shutdown requested (so the orchestrator killed it).
  - `1` / `2` -> application-level error; check logs.
- `State.Health.Status` -- `healthy` / `unhealthy` / `starting`. If
  unhealthy, `State.Health.Log[-1].Output` has the last healthcheck output.
- `RestartCount` -- high number + recent `State.StartedAt` = restart loop.
- `HostConfig.RestartPolicy.Name` -- `no` / `on-failure` / `always` /
  `unless-stopped`. Tells you whether Docker is trying to recover.
- `Mounts[]` -- bind mounts / volumes. A missing source directory is a
  common silent failure.

Then `ssh_docker_logs` to see what the container itself logged. Start with
`tail=200`; raise to 10000 only if the truncation is eating the error.
Prefer `since="10m"` when you know roughly when the problem started:

```python
ssh_docker_logs(host="docker1", container="nginx", since="15m", tail=5000)
```

## 4. Running-but-broken container

Container is `Up` but the service is unreachable / slow / wrong.

- `ssh_docker_top(host="docker1", container="nginx")` -- what's actually
  running inside? PID 1 should match the image's entrypoint. If PID 1 is
  a shell / init wrapper waiting on a child, the real process died and
  the restart policy didn't catch it.
- `ssh_docker_inspect ... "network"` -- check the container's network
  mode, published ports, and IP. A container on the wrong network or with
  no published port explains "reachable from host, unreachable from
  outside".
- `ssh_docker_stats` -- sustained 100% CPU or near-limit memory -> the
  workload is saturated, restart won't help; scaling or limits config is
  the fix.

## 5. Compose-stack failures

If the project is compose-managed:

```python
ssh_docker_compose_ps(host="docker1", compose_file="/opt/app/docker-compose.yml")
ssh_docker_compose_logs(host="docker1", compose_file="/opt/app/docker-compose.yml",
                        tail=200)
```

`compose_ps` shows each service's state (`running` / `exit 1` / ...). When
a service keeps failing to come up, the failure is almost always one of:

- Dependency service isn't healthy -- `depends_on` with `condition:
  service_healthy` waits but can time out.
- Volume mount references a host path that doesn't exist -- `docker
  inspect` shows the bind mount source; `ssh_sftp_stat` against that path
  confirms.
- Environment variable missing -- compose logs usually surface
  `environment variable X is not set`.
- Port conflict -- another process owns the port; `ssh_host_processes`
  + grep for the port number, or `ss -tlnp` via `ssh_exec_run` if exec
  tier is allowed.

Use `service=...` on `compose_logs` to isolate one noisy service:

```python
ssh_docker_compose_logs(host="docker1",
                        compose_file="/opt/app/docker-compose.yml",
                        service="worker", tail=500)
```

## 6. Disk pressure -> prune path

Docker data grows in three places: stopped containers, dangling images,
unused volumes. When `ssh_host_disk_usage` reports Docker's partition > 85%:

```python
ssh_docker_ps(host="docker1", all_=True)       # confirm stopped containers
ssh_docker_images(host="docker1")              # confirm dangling images
ssh_docker_volumes(host="docker1")             # ENUMERATE volumes before any volume-prune decision
```

Recovery (requires `ALLOW_DANGEROUS_TOOLS=true` -- `docker_prune` is
dangerous tier because `volume prune` destroys data):

```python
# Safe: stopped containers + dangling images + unused networks.
ssh_docker_prune(host="docker1", scope="container")
ssh_docker_prune(host="docker1", scope="image")
ssh_docker_prune(host="docker1", scope="network")
```

**Do NOT** auto-run `ssh_docker_prune(scope="volume")` from an LLM turn --
named volumes often carry application state (database data, uploaded
files). Run `ssh_docker_volumes(host=...)` first, then inspect each
suspicious entry with `ssh_docker_volumes(host=..., name=<vol>)` to check
`Mountpoint`, `CreatedAt`, and `UsageData` (if the daemon populates it).
Then escalate to an operator for the actual prune. `scope="system"` with
`all_=True` is equally destructive; same rule.

## 7. Recovery actions

Low-access tier (`ALLOW_LOW_ACCESS_TOOLS=true`):

- `ssh_docker_restart(host, container)` -- kick a specific container.
- `ssh_docker_compose_restart(host, compose_file)` -- roll the whole
  stack; tolerated for stateless services, risky for databases.
- `ssh_docker_stop` / `_start` -- more control than restart if you want
  to confirm the stop cleanly before bringing it back.

Dangerous tier:

- `ssh_docker_compose_up(host, compose_file, detached=True, build=False)`
  -- bring a stack back that was down. `build=True` for a rebuild is a
  separate judgment call; pin the image instead of rebuilding in prod.
- `ssh_docker_compose_down(host, compose_file, volumes=False)` -- tear
  down. `volumes=True` is destructive; always pass `volumes=False`
  (the default) unless you explicitly intend data loss.

## 8. When to escalate

Hand off to a human operator with the correlation ID from the audit log
if:

- `State.Health.Status == "unhealthy"` persists across a restart.
- Same container exits with the same non-zero code across more than one
  restart cycle -- it's a configuration or code problem, not a blip.
- `scope="volume"` or `scope="system"` prune looks necessary.
- The image on the host drifted from the pinned release tag (image ID in
  `ssh_docker_inspect` doesn't match your release manifest). Could be
  drift, could be a supply-chain substitution; either way, don't "fix" it
  blind. See [runbooks/ssh-verify-signature/SKILL.md](../ssh-verify-signature/SKILL.md).

## Boundaries

- Sections 1-5 use **read-only** tools -- safe to run without any `ALLOW_*`
  flag.
- Sections 6-7 require `ALLOW_LOW_ACCESS_TOOLS` (restart/stop/start) or
  `ALLOW_DANGEROUS_TOOLS` (prune, compose up/down).
- `ssh_docker_run` is deliberately not in this runbook -- spinning up an
  ad-hoc container during incident response is almost always a mistake;
  diagnose first, then let the orchestrator restart the real service.
- Docker CLI name comes from `SSH_DOCKER_CMD` / per-host `docker_cmd`.
  Podman hosts work unchanged; all commands above are API-compatible.

## Related runbooks

- [ssh-incident-response](../ssh-incident-response/SKILL.md) -- host-level
  incident response (SSH connectivity, disk, processes). Run that first
  if the host itself is unreachable or the problem isn't container-scoped.
- [ssh-verify-signature](../ssh-verify-signature/SKILL.md) -- if an image
  or artifact looks unexpected after a deploy.
