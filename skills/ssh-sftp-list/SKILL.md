---
description: List a remote directory via SFTP with offset/limit pagination
---

# `ssh_sftp_list`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Pure-SFTP directory listing. No shell. Returns a page of entries with
metadata (kind, size, mode, mtime, symlink target). `.` and `..` are filtered.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path on the remote |
| `offset` | int | no | 0 | Skip the first N entries |
| `limit` | int | no | 100 | Return at most N entries; clamped `[1, 1000]` |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/var/log",
  "entries": [
    {
      "name": "syslog",
      "kind": "file",
      "size": 12345678,
      "mode": "0640",
      "mtime": "2026-04-14T10:00:00+00:00",
      "symlink_target": null
    }
  ],
  "offset": 0,
  "limit": 100,
  "has_more": true
}
```

`kind` is `"file" | "dir" | "symlink" | "other"`.

## When to call it

- Browse a known directory you already trust.
- Cheaper than `ssh_find` when you know exactly which directory.
- After `ssh_host_disk_usage` reports a full mount -- list `/var/log` to find rotatable files.

## When NOT to call it

- Searching for files by name -- use `ssh_find` (recursive, name pattern).
- Reading file contents -- use `ssh_sftp_download`.
- Exploring a tree from the root recursively -- too many round-trips.

## Example

```python
ssh_sftp_list(host="web01", path="/var/log", offset=0, limit=20)
# -> first 20 entries

# Pagination loop
ssh_sftp_list(host="web01", path="/var/log", offset=20, limit=20)
# -> next 20
```

## Common failures

- `PathNotAllowed` -- `path` is outside the per-host `path_allowlist` + `SSH_PATH_ALLOWLIST`. (Note: only enforced for low-access tools -- `ssh_sftp_list` itself does not enforce path policy by default.)
- SFTP "no such file" -> asyncssh raises; surfaces as a tool error.
- `limit` outside `[1, 1000]` -> `ValueError`.

## Related

- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- single-file metadata.
- [`ssh_find`](../ssh-find/SKILL.md) -- recursive name search with depth cap.
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- fetch file contents.
