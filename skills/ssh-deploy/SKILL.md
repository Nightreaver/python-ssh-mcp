---
description: Upload a file atomically with automatic backup of the previous version
---

# `ssh_deploy`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Like `ssh_upload` but with a pre-deploy backup step. If the target path
already exists AND `backup=True`, the existing file is SFTP-renamed to
`<path>.bak-<UTC-iso8601>` (e.g. `nginx.conf.bak-20260415T031500Z`) before
the new content is written. The new content then lands via the same
tmp+rename atomic dance as `ssh_upload`.

`mode` (default `0o644`) is applied to the tmp file before the final rename.
No chown/owner handling -- that would require sudo. Path-confined via
`path_allowlist` just like `ssh_upload`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `path` | str | yes | -- | Absolute target path |
| `content_text` | str | one-of | None | Plain UTF-8 content (configs, scripts, code). Empty string is valid. |
| `content_base64` | str | one-of | None | Base64-encoded bytes (for binaries). |
| `local_path` | str | one-of | None | Absolute path on the MCP-host filesystem to stream from disk. Requires `SSH_LOCAL_TRANSFER_ROOTS`. Up to 2 GiB (`SSH_LOCAL_TRANSFER_MAX_BYTES`). |
| `mode` | int | no | `0o644` | Octal perm bits |
| `backup` | bool | no | `True` | Rename existing to `<path>.bak-<ts>` before write |

Pass exactly ONE of `content_text`, `content_base64`, or `local_path`.
Same semantics as `ssh_upload` -- see
[`ssh_upload`](../ssh-upload/SKILL.md) for the full payload-mode
selection guide and operator setup for `local_path`.

The backup step (if any) runs before the new content is sourced from disk
-- the backup behavior is unchanged regardless of which payload mode is
used.

## Returns

```json
{
  "host": "docker1",
  "path": "/opt/app/nginx.conf",
  "success": true,
  "bytes_written": 4153,
  "message": "deployed; previous version at /opt/app/nginx.conf.bak-20260415T031500Z",
  "backup_path": "/opt/app/nginx.conf.bak-20260415T031500Z",
  "local_path_written": null
}
```

`backup_path` is absent when no backup was made (file didn't exist, or
`backup=False`). `local_path_written` is populated only when `local_path`
was used (echoes the canonical source path for audit correlation).

## When to call it

- Push a config file where you want a quick-rollback artifact side-by-side
  (e.g. `mv nginx.conf.bak-<ts> nginx.conf` to revert).
- Scheduled config updates where a human might review breakage after the fact.
- Any `ssh_upload` scenario where losing the previous version would be bad.
- Deploying a large release artifact (>~5 MiB) from the MCP host
  (`local_path` + `backup=True` -- the `.bak-<ts>` rollback lever is
  especially valuable for large artifacts).

## When NOT to call it

- You don't want a `.bak-<ts>` sibling created -- pass `backup=False` (same as `ssh_upload`).
- Deployment needs `chown` / different owner -- not supported; use
  `ssh_sudo_exec "chown ..."` after the deploy.
- Rolling back -- this tool creates backups, it doesn't restore them; use
  `ssh_mv` to swap a `.bak-<ts>` file back into place.

## Examples

```python
# Plain-text config -- no encoding needed.
ssh_deploy(
    host="docker1",
    path="/opt/app/nginx.conf",
    content_text="user nginx;\nworker_processes auto;\n...",
    mode=0o644,
    backup=True,
)

# Binary artifact (small -- base64 in context).
import base64
content = open("local.tar.gz", "rb").read()
ssh_deploy(
    host="docker1",
    path="/opt/app/release.tar.gz",
    content_base64=base64.b64encode(content).decode("ascii"),
)

# Large artifact from MCP-host disk (no base64, streams directly).
# Requires SSH_LOCAL_TRANSFER_ROOTS to include /srv/releases.
ssh_deploy(
    host="docker1",
    path="/opt/app/release-2.0.tar.gz",
    local_path="/srv/releases/release-2.0.tar.gz",
    backup=True,
)
```

## Common failures

- `PathNotAllowed` -- `path` outside per-host `path_allowlist`.
- `payload N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES` -- base64 payload
  too large; switch to `local_path` mode.
- `LocalPathPolicyError` -- `local_path` outside `SSH_LOCAL_TRANSFER_ROOTS`,
  or the roots list is empty (mode disabled).
- SFTP permission denied on backup rename -- SSH user can't rename in parent dir.

## Related

- [`ssh_upload`](../ssh-upload/SKILL.md) -- same atomic write without backup
- [`ssh_mv`](../ssh-mv/SKILL.md) -- use to restore a `.bak-<ts>` back into place
- [`ssh_edit`](../ssh-edit/SKILL.md) / [`ssh_patch`](../ssh-patch/SKILL.md) -- surgical in-place modification
