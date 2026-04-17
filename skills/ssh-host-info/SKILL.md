---
description: Fetch uname, /etc/os-release, and uptime from a remote host
---

# `ssh_host_info`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Baseline host fingerprint. Runs three fixed-argv commands in parallel
(`uname -a`, `cat /etc/os-release`, `uptime`) and returns parsed structured
output. No shell interpolation -- safe against any string-valued input.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |

## Returns

```json
{
  "host": "web01.example.com",
  "uname": "Linux web01 6.1.0-21-amd64 #1 SMP Debian 6.1.90-1 x86_64 GNU/Linux",
  "os_release": {"NAME": "Debian GNU/Linux", "VERSION_ID": "12", "ID": "debian"},
  "uptime": "12:34:56 up 42 days,  3:14, 2 users, load average: 0.12, 0.09, 0.05"
}
```

`os_release` is a flat dict of every `KEY=value` line from `/etc/os-release`
(quotes stripped). Missing values are simply absent.

## When to call it

- Second step after `ssh_host_ping` when you need the OS + kernel + current load.
- Triage -- correlates with disk/process state for "why is this box acting up".
- Before `ssh_find` / `ssh_sftp_list`, to confirm you're on the OS family you expect.

## When NOT to call it

- You only need reachability -- use `ssh_host_ping`.
- You need real-time metrics -- this is a point-in-time snapshot.

## Example

```python
ssh_host_info(host="db01")
# -> {"uname": "Linux db01 ...", "os_release": {"ID": "rocky", ...}, "uptime": "..."}
```

## Common failures

- `HostNotAllowed` / `HostBlocked` -- see host policy.
- Non-zero exit from any of the three commands is tolerated; the field for
  that command becomes `null` and the others still populate.

## Related

- [`ssh_host_disk_usage`](../ssh-host-disk-usage/SKILL.md) -- parallel call for storage triage.
- [`ssh_host_processes`](../ssh-host-processes/SKILL.md) -- parallel call for CPU/memory pressure.
