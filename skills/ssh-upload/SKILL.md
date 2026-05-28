---
description: Create or replace a file atomically; pass plain text, binary, or a local MCP-host path
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

Size-capped at `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB) for
`content_text` / `content_base64` payloads. The `local_path` mode has
a separate, larger cap: `SSH_LOCAL_TRANSFER_MAX_BYTES` (default 2 GiB).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute target path |
| `content_text` | str | one-of | None | Plain UTF-8 content (configs, scripts, code, JSON, Markdown). Empty string is valid -- writes a zero-byte file. |
| `content_base64` | str | one-of | None | Base64-encoded bytes (binaries: tarballs, images, compiled artifacts). |
| `local_path` | str | one-of | None | Absolute path on the MCP-host filesystem to stream from disk. Bypasses the LLM channel for the bytestream entirely. Requires `SSH_LOCAL_TRANSFER_ROOTS` to be configured. |
| `mode` | int | no | `0o644` | Octal permission bits applied to the tmp file before rename |

Pass exactly ONE of `content_text`, `content_base64`, or `local_path`.
Any other combination raises `WriteError`.

### Choosing a payload mode

| Mode | When to use |
|---|---|
| `content_text` | Config files, scripts, anything the LLM has as a string |
| `content_base64` | Small-to-medium binaries (under ~5 MiB) the LLM holds in context |
| `local_path` | Files larger than ~5 MiB, any binary whose base64 would fill the context window, or cases where the file already exists on the MCP host |

The `local_path` mode streams directly from the MCP host's disk without
ever encoding the bytes into a tool-call argument. This sidesteps the
base64 channel bottleneck that made the LLM defensively chunk large
uploads into many small atomic-rename calls.

### `local_path` operator setup

`local_path` is **disabled by default** (empty = disabled, no fallbacks).
The operator must configure an explicit allowlist of directories on the
MCP host:

```
# .env or client env block
SSH_LOCAL_TRANSFER_ROOTS=/home/ops/uploads,/tmp/mcp-stage
SSH_LOCAL_TRANSFER_MAX_BYTES=2147483648   # 2 GiB (default)
```

The server resolves the given path strictly (must exist + be a regular
file; symlinked parents followed before the allowlist check). Paths
outside the configured roots raise `LocalPathPolicyError`. Symlink-escape
attempts are rejected.

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/release.tar.gz",
  "success": true,
  "bytes_written": 10485760,
  "message": "uploaded (atomic)",
  "local_path_written": null
}
```

When `local_path` is used, `local_path_written` echoes the canonical
source path (after symlink resolution) for audit correlation. For the
other two payload modes it is `null`.

## When to call it

- Write a config / script / source file / template (`content_text`).
- Push a fresh binary artifact: tarball, image, compiled binary
  (`content_base64` for small binaries; `local_path` for anything large).
- Replace a file entirely (when you don't care about the old contents).
- After a `download -> modify -> upload` flow when `ssh_edit` / `ssh_patch`
  aren't enough.
- Push a large artifact (>~5 MiB) that already lives on the MCP host
  (`local_path` -- no base64 encoding, no context bloat).

## When NOT to call it

- Small targeted edits -- use `ssh_edit` (no need to encode the whole file).
- Multi-hunk text changes -- use `ssh_patch`.
- Files larger than `SSH_UPLOAD_MAX_FILE_BYTES` via base64 -- use
  `local_path` mode instead (2 GiB cap) or split the artifact.
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

# Binary artifact via base64 (small files).
import base64
content = open("local-file.tar.gz", "rb").read()
ssh_upload(
    host="web01",
    path="/opt/app/release.tar.gz",
    content_base64=base64.b64encode(content).decode("ascii"),
    mode=0o644,
)

# Large artifact via local_path (no base64, streams from MCP-host disk).
# Requires SSH_LOCAL_TRANSFER_ROOTS to include /tmp/mcp-stage.
ssh_upload(
    host="web01",
    path="/opt/app/release-2.0.tar.gz",
    local_path="/tmp/mcp-stage/release-2.0.tar.gz",
    mode=0o644,
)
```

## Common failures

- `WriteError: pass exactly one of content_text, content_base64, or local_path` --
  zero, two, or all three payload args set. Pass exactly one.
- `WriteError: payload N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES=...` --
  base64 payload too large; switch to `local_path` mode.
- `LocalPathPolicyError` -- `local_path` is outside `SSH_LOCAL_TRANSFER_ROOTS`,
  or `SSH_LOCAL_TRANSFER_ROOTS` is empty (mode disabled).
- `binascii.Error` -- your `content_base64` isn't valid base64.
- `PathNotAllowed` -- remote `path` outside the allowlist (canonicalized
  parent must be inside).
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
