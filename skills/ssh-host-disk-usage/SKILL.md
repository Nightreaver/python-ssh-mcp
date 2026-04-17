---
description: Report disk usage per filesystem on a remote host
---

# `ssh_host_disk_usage`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Runs `df -PTh` on the remote host (POSIX format, with types, human sizes)
and parses each line into a structured entry. Full partitions are the single
most common silent-failure cause on Linux boxes; this is a triage reflex.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |

## Returns

```json
{
  "host": "web01.example.com",
  "entries": [
    {
      "filesystem": "/dev/mapper/vg0-root",
      "type": "ext4",
      "size": "40G",
      "used": "12G",
      "available": "26G",
      "use_percent": "32%",
      "mount": "/"
    }
  ]
}
```

`use_percent` is the raw string from `df` (e.g. `"98%"`). Parse it yourself
if you need a number.

## When to call it

- Host is slow or unresponsive -> check for `100%` mounts first.
- Before a large upload (`ssh_upload`) -- confirm enough free space.
- Scheduled capacity checks.

## When NOT to call it

- For inode exhaustion -- `df -i` is different; not exposed (call via `ssh_exec_run` if you have `ALLOW_DANGEROUS_TOOLS=true`).
- For per-file sizes -- use `ssh_sftp_stat`.

## Example

```python
ssh_host_disk_usage(host="db01")
# -> {"entries": [{"mount": "/var", "use_percent": "92%", ...}, ...]}
```

To find almost-full mounts in a follow-up step, filter entries where
`int(use_percent.rstrip('%')) >= 90`.

## Common failures

- `HostNotAllowed` / `HostBlocked` -- see host policy.
- Unusual `df` output (BSD `df`, custom format) -> some entries may be dropped
  by the parser. The tool logs but does not raise.

## Related

- [`ssh_host_info`](../ssh-host-info/SKILL.md) -- baseline host fingerprint.
- [`ssh_find`](../ssh-find/SKILL.md) -- locate large files on a full partition.
- [`ssh_sftp_list`](../ssh-sftp-list/SKILL.md) -- browse `/var/log` or similar log dirs.
