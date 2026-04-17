---
description: Download a remote file via SFTP as base64-encoded bytes
---

# `ssh_sftp_download`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Read a remote file via SFTP, return the bytes as base64. Size-capped at
`SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB); larger files return
`truncated=true` with empty content -- use `ssh_find` + partial reads or
rotate/compress before downloading.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `path` | str | yes | Absolute path to a regular file |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/etc/nginx/nginx.conf",
  "size": 4096,
  "content_base64": "dXNlciBuZ2lueDsK...",
  "truncated": false
}
```

Decode with `base64.b64decode(content_base64)` on the caller side.

## When to call it

- Read a config file before editing it with `ssh_edit` or `ssh_patch`.
- Grab small-to-medium logs for offline inspection.
- Retrieve a known artifact (tarball, cert) under the size cap.

## When NOT to call it

- Very large files (multi-GB logs, database dumps) -- will return `truncated=true`.
  Rotate, compress, or filter before downloading.
- Many files at once -- this is a single-file read. Use `ssh_find` + iteration.
- Streaming tail -- not supported; use `ssh_exec_run` with `tail` if you have exec tier.

## Example

```python
import base64
r = ssh_sftp_download(host="web01", path="/etc/nginx/nginx.conf")
config = base64.b64decode(r["content_base64"]).decode("utf-8")
```

## Common failures

- `truncated=true` with empty content -- size exceeded cap. Check `size` to
  confirm and pick a subset (e.g., tail with `ssh_exec_run`) or raise the cap.
- SFTP "no such file" / "permission denied" -> tool error.

## Related

- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- check size before downloading.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- modify in-place without download-then-upload.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- write a file back (low-access tier).
