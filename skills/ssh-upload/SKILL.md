---
description: Create or replace a file atomically; pass plain text via content_text or binary via content_base64
---

# `ssh_upload`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

USE THIS INSTEAD OF `ssh_exec_run` for any pattern that creates or
replaces a whole file's content -- `cat > path <<EOF`, `tee path`,
`echo "..." > path`, `printf "..." > path`. The path goes through
`resolve_path` (canonicalize + allowlist + restricted-zones in one shot,
which `ssh_exec_run` does NOT enforce), the write is atomic
(`<path>.ssh-mcp-tmp.<hex>` then `posix_rename`), and the audit line
records the canonical path.

Size-capped at `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute target path |
| `content_text` | str | one-of | None | Plain UTF-8 content (the right choice for configs, scripts, code, JSON, Markdown). Empty string is valid -- writes a zero-byte file. |
| `content_base64` | str | one-of | None | Base64-encoded bytes (the right choice for binaries: tarballs, images, compiled artifacts). |
| `mode` | int | no | `0o644` | Octal permission bits applied to the tmp file before rename |

Pass exactly ONE of `content_text` or `content_base64`. Both set or
neither set raises `WriteError`.

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

- Write a config / script / source file / template (`content_text`).
- Push a fresh binary artifact: tarball, image, compiled binary
  (`content_base64`).
- Replace a file entirely (when you don't care about the old contents).
- After a `download -> modify -> upload` flow when `ssh_edit` / `ssh_patch`
  aren't enough.

## When NOT to call it

- Small targeted edits -- use `ssh_edit` (no need to encode the whole file).
- Multi-hunk text changes -- use `ssh_patch`.
- Files larger than `SSH_UPLOAD_MAX_FILE_BYTES` -- raise the cap or split
  the artifact.
- You want a backup of the existing file -- use `ssh_deploy` instead;
  it auto-renames the existing path to `<path>.bak-<UTC-iso8601>` first.

## Examples

```python
# Plain-text config -- no encoding needed.
ssh_upload(
    host="web01",
    path="/etc/myapp/config.toml",
    content_text="[server]\nport = 8080\nhost = \"0.0.0.0\"\n",
    mode=0o644,
)

# Empty file -- valid (the validator uses `is not None`, not truthiness).
ssh_upload(host="web01", path="/var/log/myapp/.keep", content_text="")

# Binary artifact -- still base64.
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

- `WriteError: pass exactly one of content_text or content_base64` --
  zero or two payload args. Pass one.
- `WriteError: payload N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES=...` --
  too large.
- `binascii.Error` -- your `content_base64` isn't valid base64.
- `PathNotAllowed` -- outside the allowlist (canonicalized parent must
  be inside).
- SFTP "permission denied" -- SSH user can't write the parent directory.

## Related

- [`ssh_deploy`](../ssh-deploy/SKILL.md) -- same as upload + auto-backup
  the existing file to `.bak-<UTC>` before writing.
- [`ssh_mkdir`](../ssh-mkdir/SKILL.md) -- create the parent directory
  first if needed.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- atomic surgical edit instead of
  full overwrite.
- [`ssh_cp`](../ssh-cp/SKILL.md) -- back up the existing file before
  overwriting (or use `ssh_deploy`).
