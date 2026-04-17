---
description: Upload a file atomically via SFTP (base64 payload, tmp + rename)
---

# `ssh_upload`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Decode the base64 payload, write to `<path>.ssh-mcp-tmp.<hex>`, `chmod` the
tmp file to `mode`, then `posix_rename` over the final path. Atomic from
the perspective of any reader. Size-capped at `SSH_UPLOAD_MAX_FILE_BYTES`
(default 256 MiB).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute target path |
| `content_base64` | str | yes | -- | Base64-encoded file bytes |
| `mode` | int | no | `0o644` | Octal permission bits applied to the tmp file before rename |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/release.tar.gz",
  "success": true,
  "bytes_written": 10485760,
  "message": "uploaded (atomic)"
}
```

## When to call it

- Push a fresh artifact (binary, tarball, generated config).
- Replace a file entirely (when you don't care about the old contents).
- After a `download -> modify -> upload` flow when `ssh_edit` / `ssh_patch` aren't enough.

## When NOT to call it

- Small targeted edits -- use `ssh_edit` (no need to encode the whole file).
- Multi-hunk text changes -- use `ssh_patch`.
- Files larger than `SSH_UPLOAD_MAX_FILE_BYTES` -- raise the cap or split the artifact.

## Example

```python
import base64
content = open("local-file.tar.gz", "rb").read()
ssh_upload(
    host="web01",
    path="/opt/app/release.tar.gz",
    content_base64=base64.b64encode(content).decode("ascii"),
    mode=0o644,
)
```

## Common failures

- `WriteError: payload N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES=...` -- too large.
- `binascii.Error` -- your `content_base64` isn't valid base64. Caller bug.
- `PathNotAllowed` -- outside the allowlist (canonicalized parent must be inside).
- SFTP "permission denied" -- SSH user can't write the parent directory.

## Related

- [`ssh_mkdir`](../ssh-mkdir/SKILL.md) -- create the parent directory first if needed.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- atomic surgical edit instead of full overwrite.
- [`ssh_cp`](../ssh-cp/SKILL.md) -- back up the existing file before overwriting.
