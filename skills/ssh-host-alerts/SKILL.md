---
description: Evaluate per-host health thresholds; returns breaches + observations
---

# `ssh_host_alerts`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Runs `df -PTh`, `/proc/loadavg`, `/proc/meminfo` on the remote, compares
against the per-host `alerts` block in `hosts.toml`, and returns the list of
metrics in breach. No SMTP/Slack/webhook -- reporting is what the tool
returns; the caller (or a scheduled invocation) decides what to do.

## Configuring thresholds

```toml
[hosts.web01.alerts]
disk_use_percent_max = 90     # breach when any mount > 90% full
load_avg_1min_max    = 4.0    # 1-min load avg above this = breach
mem_free_percent_min = 10     # MemAvailable / MemTotal < 10% = breach
disk_mounts = ["/", "/var"]   # optional: restrict disk check to these mounts
```

Any unset field disables that metric.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |

## Returns

```json
{
  "host": "web01.example.com",
  "breaches": [
    {"metric": "disk_use_percent", "threshold": 90, "current": 94,
     "severity": "warning", "detail": "mount=/var"}
  ],
  "metrics": {
    "disk_entries": [{"mount": "/", "use_percent": 42.0}, ...],
    "load_avg_1min": 0.15,
    "mem_free_percent": 67.3
  }
}
```

`breaches` empty = all configured thresholds are within limits.

## When to call it

- First step in a "is this host OK?" workflow.
- Periodic cron from the orchestrator (every 5 min) -- correlates breaches to
  tool-call audit records.
- Before risky operations (`compose_up`, bulk upload) to confirm capacity.

## When NOT to call it

- You want live/streaming alerting -- push metrics to Prometheus instead; this is pull.
- No thresholds configured -- the tool still runs but `breaches` is always empty.

## Example

```python
ssh_host_alerts(host="web01")
```

## Common failures

- Non-Linux target -- `/proc/loadavg` and `/proc/meminfo` don't exist; those
  metrics are silently skipped. Disk usage still works.
- Threshold misconfigured (e.g. `disk_use_percent_max = 150`) -- never
  breaches; not an error.

## Related

- [`ssh_host_disk_usage`](../ssh-host-disk-usage/SKILL.md) -- raw df, no thresholds
- [`ssh_host_processes`](../ssh-host-processes/SKILL.md)
