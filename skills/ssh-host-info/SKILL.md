---
description: Fetch uname, /etc/os-release, and uptime from a remote host
---

# `ssh_host_info`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Baseline host fingerprint. Runs six fixed-argv probes in parallel
(`uname -a`, `cat /etc/os-release`, `uptime`, `nproc`, `cat /proc/cpuinfo`,
`hostname -f`) and returns parsed structured output. No shell
interpolation -- safe against any string-valued input. Each probe runs
independently (`return_exceptions=True`); a missing `nproc` or
restricted `/proc/cpuinfo` leaves that field `None` without losing its
siblings.

**POSIX-only.** Windows targets raise `PlatformNotSupported`.

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
| `cpu_model` | `str \| None` | first `model name` / `Model` / `Hardware` line from `/proc/cpuinfo` |
| `cpu_count` | `int \| None` | parsed `nproc` output |
| `hostname_fqdn` | `str \| None` | `hostname -f` output; `None` if the host doesn't have an FQDN |
| `output_warnings` | `list[str]` | suspicious pattern warnings (see below) |

```json
{
  "host": "web01.example.com",
  "uname": "Linux web01 6.1.0-21-amd64 #1 SMP Debian 6.1.90-1 x86_64 GNU/Linux",
  "os_release": {"NAME": "Debian GNU/Linux", "VERSION_ID": "12", "ID": "debian"},
  "uptime": "12:34:56 up 42 days,  3:14, 2 users, load average: 0.12, 0.09, 0.05",
  "cpu_model": "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
  "cpu_count": 8,
  "hostname_fqdn": "web01.example.com",
  "output_warnings": []
}
```

`os_release` is a flat dict of every `KEY=value` line from `/etc/os-release`
(quotes stripped). Missing values are simply absent.

Any of `cpu_model`, `cpu_count`, `hostname_fqdn` may be `None` when the
corresponding probe failed (busybox without `nproc`, container with
restricted `/proc`, host without an FQDN configured). The other fields
still populate.

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
# -> {"uname": "Linux db01 ...", "os_release": {"ID": "rocky", ...},
#     "uptime": "...", "cpu_count": 8, "cpu_model": "...", "hostname_fqdn": "db01.example.com"}
```

## Common failures

- `HostNotAllowed` / `HostBlocked` -- see host policy.
- `PlatformNotSupported` -- Windows target. None of the probes have a
  PowerShell equivalent here; use `ssh_exec_run "systeminfo"` once
  allowlisted.
- Non-zero exit from any individual probe is tolerated; the field for
  that probe becomes `null` and the others still populate.

## Related

- [`ssh_host_disk_usage`](../ssh-host-disk-usage/SKILL.md) -- parallel call for storage triage.
- [`ssh_host_processes`](../ssh-host-processes/SKILL.md) -- parallel call for CPU/memory pressure.
