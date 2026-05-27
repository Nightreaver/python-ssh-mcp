---
description: Diagnose and recover an unresponsive SSH host
---

# SSH Incident Response

When a host goes dark or behaves erratically, follow this sequence.
Read-only tier throughout -- surfacing a problem is the job; fixing it
is a different runbook with a different tier.

Separate from [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md):
that runbook starts from "tell me the state of this host"; this one
starts from "the host is unresponsive / weird, what's going on". If
healthcheck comes back red, this runbook is the next step.

## Sequence

1. Confirm reachability
2. Verify host identity
3. Collect baseline metrics
4. Targeted triage + handoff

## 1. Confirm reachability

```python
ssh_host_ping(host="web01")
```

Read the result:

- `reachable=false` -> TCP is down. Check network / firewall / cloud
  console out-of-band before continuing. Nothing in this runbook
  helps you if the box isn't on the network.
- `reachable=true, auth_ok=false, error="UnknownHost: ..."` -> host
  key changed. **Do not re-trust from the LLM.** Escalate to a human
  operator -- a key mismatch could be legitimate (host rebuilt) or
  hostile (MITM); the LLM can't distinguish them.
- `reachable=true, auth_ok=true` -> host is reachable. Proceed to
  Section 2.

## 2. Verify host identity

```python
ssh_known_hosts_verify(host="web01")
```

`matches_known_hosts=true` means the live key equals the pinned
fingerprint. Anything else is a security event -- stop and escalate
with the audit-log correlation ID.

## 3. Collect baseline

In parallel:

```python
ssh_host_info(host="web01")          # uname, os_release, uptime
ssh_host_disk_usage(host="web01")    # mount table + use_percent
ssh_host_processes(host="web01")     # top CPU / memory consumers
ssh_host_alerts(host="web01")        # threshold breaches
```

Why each one:

- `ssh_host_info` -- uptime is the silent reframer. A box up 4 minutes
  with high load is probably startup churn; up 400 days with the same
  numbers is saturation.
- `ssh_host_disk_usage` -- full partitions are the single most common
  cause of "silent" failures (logging stops, services refuse to start,
  package installs hang).
- `ssh_host_processes` -- runaway / zombie processes, or a workload
  that should not be there.
- `ssh_host_alerts` -- whether the host has already crossed an
  operator-declared threshold. Empty `breaches` is not the same as
  "healthy"; it just means "within configured limits" (and the limits
  may not be configured -- see
  [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) Section 2).

## 4. Targeted triage + handoff

Match the symptom to the right next runbook -- do **not** re-derive
their content here.

- **Disk breach or a mount near full** ->
  [ssh-disk-cleanup](../ssh-disk-cleanup/SKILL.md). It enumerates
  before pruning and handles the "never volume-prune blindly" rule.
- **A Docker container is the bottleneck (high CPU/mem in
  `ssh_host_processes`, or a service the user named is
  container-managed)** ->
  [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md).
- **A systemd service is failing or flapping** ->
  [ssh-systemd-diagnostics](../ssh-systemd-diagnostics/SKILL.md).
  Status / journalctl / show all read-only.
- **Service crashed, restart needed, no clear container or systemd
  unit** -> escalate to an operator with low-access or exec tier; do
  not attempt restart from this runbook.

## Boundaries

- Read-only tier throughout. Restart, edit, or truncate operations
  require `ALLOW_LOW_ACCESS_TOOLS` or `ALLOW_DANGEROUS_TOOLS` and live
  in the per-domain runbooks linked above.
- If this runbook surfaces a problem that needs mutation, hand off to
  a human with the correlation ID from the audit log -- never
  self-escalate the tier mid-incident.
- Non-Linux targets: `ssh_host_processes` and `ssh_host_alerts` may
  return empty on Windows / BSD. Don't read absence as health.

## Related runbooks

- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- run
  first if the request is "tell me the state", not "the host is
  broken".
- [ssh-disk-cleanup](../ssh-disk-cleanup/SKILL.md) -- targeted
  recovery for a disk breach.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  -- when a container workload is the cause.
- [ssh-systemd-diagnostics](../ssh-systemd-diagnostics/SKILL.md) --
  systemd unit-level diagnostics.
