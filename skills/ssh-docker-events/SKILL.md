---
description: Fetch Docker daemon events (container/image/volume/network lifecycle) over a bounded time window
---

# `ssh_docker_events`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

Runs `docker events --since <since> --until <until> [--filter ...]
--format '{{json .}}'` and parses the output. Answers "what just happened
to this container / image / volume / network?" in one call: OOM kills,
restarts, health-status transitions, image pulls, network connects, volume
mounts. The single most useful tool when a Docker host misbehaves between
your last look and now.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `since` | str | no | `"1h"` | Relative (`10m`, `2h`, `24h30m`), Unix epoch, RFC3339, or `now`. **No `d` unit** -- use `168h` for 7 days, or pass an epoch / RFC3339 timestamp. Go `time.ParseDuration` only accepts `s`/`m`/`h`. |
| `until` | str | no | `"now"` | Same formats as `since`. Required in practice so the call is bounded. |
| `filters` | list[str] | no | None | Zero or more `KEY=VALUE` filter expressions |

## Returns

`ExecResult` plus:

- `events`: list of parsed JSON objects, one per event. Keys commonly
  present: `Type` (container/image/network/volume), `Action` (create /
  start / die / oom / restart / health_status), `Actor.ID`,
  `Actor.Attributes.name`, `Actor.Attributes.image`, `time`, `timeNano`.

## When to call it

- First action after a page / alert: `ssh_docker_events(host="...",
  since="30m")` tells you whether a container died and was restarted,
  whether an image was pulled unexpectedly, whether networks were
  reconfigured.
- After `ssh_docker_ps` reveals a restart loop: `since="5m",
  filters=["container=<name>"]` narrows to just that container's recent
  lifecycle, showing `start`, `die`, `restart` in order with exit codes.
- Post-mortem: `since="2h", filters=["event=die", "event=oom"]` collects
  all the bad-news events from the last 2 hours across the whole host.

## When NOT to call it

- You want **live tail** of events -- `docker events` streams without
  `--until`, but we force `--until` to keep the call bounded. If you
  genuinely need a live stream, that's an orchestration concern; scrape
  events on a cron via this tool instead.
- You want CONTAINER logs (what the app wrote) -- use `ssh_docker_logs`.
  Daemon events are the outside view of what Docker did; logs are the
  inside view of what the app said.

## Filter cookbook

```python
# Just one container
ssh_docker_events(host="docker1", since="30m",
                  filters=["container=api-web"])

# All OOM kills in the last 2 hours
ssh_docker_events(host="docker1", since="2h", filters=["event=oom"])

# All image pulls in the last day (unexpected updates)
ssh_docker_events(host="docker1", since="24h",
                  filters=["type=image", "event=pull"])

# Health-check state changes for one service
ssh_docker_events(host="docker1", since="1h",
                  filters=["container=nginx", "event=health_status"])
```

Multiple filters are AND-ed by Docker, matching the CLI semantics.

## Example

```python
result = ssh_docker_events(host="docker1", since="15m",
                           filters=["container=worker"])
for ev in result["events"]:
    print(ev["time"], ev["Action"], ev["Actor"]["Attributes"].get("exitCode"))
# 1713265500 start -
# 1713265645 die 137       <- OOM kill
# 1713265646 restart -
# 1713265647 start -
# 1713265712 die 137       <- looping
```

## Common failures

- `since` / `until` in an unaccepted format -> `ValueError` before the
  call hits Docker. The regex accepts relative (`10m`), epoch, RFC3339,
  and `now`; everything else is refused.
- `filters` entry failing the `KEY=VALUE` regex -> `ValueError`. Use
  `ssh_exec_run` with `"docker"` on the command allowlist for exotic
  filter values.
- Empty `events` list -> the window was too narrow, or the filter is
  too specific, or genuinely nothing happened. Widen `since` first.

## Related

- [`ssh_docker_ps`](../ssh-docker-ps/SKILL.md) -- current state (events
  show transitions; ps shows snapshots).
- [`ssh_docker_inspect`](../ssh-docker-inspect/SKILL.md) -- deep metadata
  on one container (ExitCode, RestartCount, Health.Log).
- [`ssh_docker_logs`](../ssh-docker-logs/SKILL.md) -- what the container
  itself said while it was running.
- [`runbooks/ssh-docker-incident-response/`](../../runbooks/ssh-docker-incident-response/SKILL.md)
  -- runbook that chains these tools for a diagnosis.
