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

`HostInfoResult`:

| field | type | notes |
|---|---|---|
| `host` | `str` | canonical hostname |
| `uname` | `str \| None` | full `uname -a` output |
| `os_release` | `dict[str, str]` | every `KEY=value` from `/etc/os-release` (quotes stripped) |
| `uptime` | `str \| None` | raw `uptime` output |
| `output_warnings` | `list[str]` | suspicious pattern warnings (see below) |

```json
{
  "host": "web01.example.com",
  "uname": "Linux web01 6.1.0-21-amd64 #1 SMP Debian 6.1.90-1 x86_64 GNU/Linux",
  "os_release": {"NAME": "Debian GNU/Linux", "VERSION_ID": "12", "ID": "debian"},
  "uptime": "12:34:56 up 42 days,  3:14, 2 users, load average: 0.12, 0.09, 0.05",
  "output_warnings": []
}
```

`os_release` is a flat dict of every `KEY=value` line from `/etc/os-release`
(quotes stripped). Missing values are simply absent.

### `output_warnings`

After fetching, each of `uname`, `uptime`, and every `os_release` value is
scanned by `output_sanitizer.scan()` for suspicious patterns (ANSI escape
sequences, terminal control codes, shell metacharacters in unexpected positions,
and similar injection-surface tokens). Matched strings are NOT modified -- the
original text is preserved verbatim for binary safety (INC-058 pattern). When
a pattern fires, a human-readable warning is appended to `output_warnings`. An
empty list means the scan found nothing unusual.

If `output_warnings` is non-empty, treat the accompanying field values with
caution before rendering or further processing.

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
