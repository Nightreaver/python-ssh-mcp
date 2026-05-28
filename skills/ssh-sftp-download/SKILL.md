---
description: Download a remote file via SFTP -- base64 to caller or streamed to a local path
---

# `ssh_sftp_download`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Read a remote file via SFTP. Two delivery modes:

- **Default (base64)**: returns the file bytes as base64 in the tool
  response. Size-capped at `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB);
  larger files return `truncated=true` with empty content.
- **`local_path` mode**: streams the remote file to a path on the MCP
  host's own filesystem. No base64 encoding; the bytestream never enters
  the LLM context. Cap is `SSH_LOCAL_TRANSFER_MAX_BYTES` (default 2 GiB).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `path` | str | yes | Absolute path to a regular file on the remote host |
| `local_path` | str | no (None) | Absolute path on the MCP-host filesystem to write the downloaded file to. Requires `SSH_LOCAL_TRANSFER_ROOTS` to include the parent directory. |

## Returns (base64 mode)

```json
{
  "host": "web01.example.com",
  "path": "/etc/nginx/nginx.conf",
  "size": 4096,
  "content_base64": "dXNlciBuZ2lueDsK...",
  "truncated": false,
  "local_path_written": null
}
```

Decode with `base64.b64decode(content_base64)` on the caller side.

## Returns (`local_path` mode)

```json
{
  "host": "web01.example.com",
  "path": "/var/backups/db-dump.tar.gz",
  "size": 1073741824,
  "content_base64": "",
  "truncated": false,
  "local_path_written": "/srv/backups/db-dump.tar.gz"
}
```

`content_base64` is always `""` in this mode -- the bytes went to disk,
not into the response. `local_path_written` holds the canonical path
after write (symlinked parents followed before the allowlist check).
The download is atomic: streamed to `<local_path>.ssh-mcp-tmp.<rand>`,
then `os.replace`-d into the final path.

## `local_path` operator setup

Disabled by default. The operator must set `SSH_LOCAL_TRANSFER_ROOTS` to a
comma-separated (or JSON) list of absolute directories on the MCP host
where writes are permitted:

```
SSH_LOCAL_TRANSFER_ROOTS=/srv/backups,/tmp/mcp-downloads
SSH_LOCAL_TRANSFER_MAX_BYTES=2147483648   # 2 GiB (default)
```

Paths outside these roots raise `LocalPathPolicyError`. The parent
directory must already exist; symlink-escape attempts are rejected.

## Choosing a mode

| Use base64 mode when | Use `local_path` mode when |
|---|---|
| File is under ~5 MiB | File is large (hundreds of MB to GB) |
| You need the content as a string in the session | You want to persist it to disk on the MCP host |
| No `SSH_LOCAL_TRANSFER_ROOTS` configured | The roots are configured and the destination fits |
| Config file you will immediately edit | Snapshot / backup / artifact you are archiving |

## When to call it

- Read a config file before editing it with `ssh_edit` or `ssh_patch`.
- Grab small-to-medium logs for offline inspection.
- Retrieve a known artifact (tarball, cert) under the size cap.
- Download a large backup or archive to the MCP host (`local_path` mode).

## When NOT to call it

- Very large files via base64 -- will return `truncated=true`. Use
  `local_path` mode, or rotate/compress/filter first.
- Many files at once -- this is a single-file read. Use `ssh_find` + iteration.
- Streaming tail -- not supported; use `ssh_exec_run` with `tail` if you have exec tier.

## Examples

```python
# Base64 mode -- small config file.
import base64
r = ssh_sftp_download(host="web01", path="/etc/nginx/nginx.conf")
config = base64.b64decode(r["content_base64"]).decode("utf-8")

# local_path mode -- large archive, no base64 in context.
# Requires SSH_LOCAL_TRANSFER_ROOTS to include /srv/backups.
r = ssh_sftp_download(
    host="db01",
    path="/var/backups/db-dump.tar.gz",
    local_path="/srv/backups/db-dump.tar.gz",
)
print(r["local_path_written"])   # canonical destination path
```

## Common failures

- `truncated=true` with empty content (base64 mode) -- size exceeded cap.
  Check `size` and switch to `local_path` mode or reduce the file first.
- `LocalPathPolicyError` -- `local_path` parent is outside
  `SSH_LOCAL_TRANSFER_ROOTS`, or the roots list is empty.
- SFTP "no such file" / "permission denied" -> tool error.

## Related

- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- check size before downloading.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- modify in-place without download-then-upload.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- write a file back (low-access tier;
  also supports `local_path` for large payloads).
