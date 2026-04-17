---
description: Diagnose and recover an unresponsive SSH host
---

# SSH Incident Response

When a host goes dark, follow this sequence.

## 1. Confirm reachability

Call `ssh_host_ping` against the target. Read the result:

- `reachable=false` -> TCP is down. Check network/firewall out-of-band before continuing.
- `reachable=true, auth_ok=false, error="UnknownHost: ..."` -> host key changed. Do **not** re-trust from the LLM. Escalate to a human operator.
- `reachable=true, auth_ok=true` -> host is healthy. Proceed to Section 2 to investigate the reported symptom.

## 2. Verify host identity

Call `ssh_known_hosts_verify`. `matches_known_hosts=true` means the live key equals the pinned fingerprint. Anything else is a security event -- stop and escalate.

## 3. Collect baseline

In parallel:

- `ssh_host_info` -- uname + os_release + uptime.
- `ssh_host_disk_usage` -- full partitions are the most common cause of silent failure.
- `ssh_host_processes` -- top CPU/memory. Look for runaway or zombie processes.

## 4. Targeted triage

Depending on Section 3 findings:

- Disk full -> `ssh_sftp_list /var/log` and `ssh_find /var/log -name '*.gz'` to locate rotatable logs.
- Service crashed -> escalate to an operator with exec-tier access; do not attempt restart from this skill.

## Boundaries

This runbook uses **read-only** tools only. Restart, edit, or truncate operations require `ALLOW_LOW_ACCESS_TOOLS` or `ALLOW_DANGEROUS_TOOLS`. If this runbook surfaces a problem that needs mutation, hand off to a human with the correlation ID from the audit log.
