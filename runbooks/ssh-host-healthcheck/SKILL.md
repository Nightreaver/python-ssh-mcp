---
description: Standard "is this host OK right now" pass combining identity, alerts, disk, processes, and uptime
---

# SSH Host Healthcheck

A fixed sequence for answering "is this box healthy?" without descending
into ad-hoc investigation. Read-only tier throughout -- safe to run
without any `ALLOW_*` flag, safe to run on a schedule.

Separate from [ssh-incident-response](../ssh-incident-response/SKILL.md):
that runbook starts from "host is unresponsive"; this one starts from
"tell me the state of this host". Use healthcheck first; fall into
incident response only if healthcheck surfaces something wrong.

## Sequence

1. Reachability + identity
2. Threshold check (alerts)
3. Baseline metrics in parallel
4. Interpret + escalate

## 1. Reachability + identity

```python
ssh_host_ping(host="web01")
ssh_known_hosts_verify(host="web01")
```

- `ssh_host_ping.reachable=false` -> network/firewall problem; fall into
  [ssh-incident-response](../ssh-incident-response/SKILL.md) Section 1.
- `ssh_host_ping.auth_ok=false` + `error="UnknownHost: ..."` -> host key
  drift. **Stop.** Don't re-trust from the LLM. Escalate.
- `ssh_known_hosts_verify.matches_known_hosts=false` -> same class of
  event. Stop and escalate.

Only proceed to Section 2 if both calls are clean.

## 2. Threshold check

```python
ssh_host_alerts(host="web01")
```

The single most useful call in this runbook. Returns `breaches[]` against
whatever `[hosts.<alias>.alerts]` thresholds are configured in
`hosts.toml`:

- `breaches` empty -> host is within its own declared thresholds. Still
  run Section 3 for context, but this is the "green" signal.
- `breaches` non-empty -> the host has already crossed an operator-declared
  line. Section 3 tells you how bad and which process/mount is responsible.

If no `alerts` block is configured for this host, `breaches` is always
empty -- that's a config gap, not a health signal. Flag it and move on.

## 3. Baseline metrics (parallel)

```python
ssh_host_info(host="web01")
ssh_host_disk_usage(host="web01")
ssh_host_processes(host="web01")
```

What each one adds on top of `ssh_host_alerts`:

- `ssh_host_info` -- uname, os_release, **uptime**. Recent reboot
  (uptime < 1h) reframes everything below: high load on a just-booted
  box is probably startup churn, not saturation. Also catches "this box
  is running a kernel two LTS versions behind" during audits.
- `ssh_host_disk_usage` -- full mount table, not just the ones the
  `alerts` block watches. A 99%-full `/home` that isn't in `disk_mounts`
  won't show as a breach but will still bite on the next user login.
- `ssh_host_processes` -- top CPU/memory. If `alerts` flagged a load
  breach, this tells you which PID is responsible. If `alerts` was
  clean, this tells you whether load is diffuse (normal) or concentrated
  in one runaway process (about to breach).

## 4. Interpret

Write up the state as: **status + evidence + recommended next step**.

- **Green** (no breaches, uptime normal, disk headroom everywhere, no
  obvious outlier processes) -> done. No action.
- **Yellow** (clean alerts but Section 3 found something out-of-band --
  e.g. a mount at 88% that isn't in `disk_mounts`, or a process eating
  RAM that hasn't crossed the host's threshold yet) -> note in the
  report; no paging action, but someone should look.
- **Red** (any `breaches` entry) -> cross to the relevant runbook:
  - Disk breach -> [ssh-disk-cleanup](../ssh-disk-cleanup/SKILL.md).
  - Load / memory breach caused by a Docker container ->
    [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md).
  - Host-level saturation not attributable to a container ->
    [ssh-incident-response](../ssh-incident-response/SKILL.md) Section 3+.

## Boundaries

- Read-only tier only. Every tool in this runbook is `safe`/`read`.
- Non-Linux targets (BSD, Windows): `ssh_host_alerts` silently skips
  `/proc`-backed metrics; disk usage still works, processes may return
  empty. Don't interpret an empty `breaches` on a Windows host as
  "healthy" -- it means "not measured".
- No mutations, no restart attempts, no "fix while you're here".
  Surfacing a problem is the job; fixing it is a different runbook with
  a different tier.

## When to schedule it

- Periodic pull from the orchestrator (every 5-15 min) -- correlate with
  the tool-call audit log to catch "deploy happened, then alerts fired
  2 minutes later".
- Ad-hoc before any risky operation (`compose_up`, bulk upload, fleet
  rollout) -- confirms the target isn't already degraded.
- First call in any ticket that says "something's weird on <host>" --
  before guessing, check the boring stuff.

## Related runbooks

- [ssh-incident-response](../ssh-incident-response/SKILL.md) -- when the
  host itself is unreachable or unresponsive.
- [ssh-disk-cleanup](../ssh-disk-cleanup/SKILL.md) -- targeted recovery
  for a disk breach.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  -- when a breach points at a container workload.
