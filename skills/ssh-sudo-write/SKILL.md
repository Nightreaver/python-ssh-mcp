---
description: Sudo-elevated atomic write with ownership preservation; three-way payload mutex including local_path
---

# `ssh_sudo_write`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Write a file under sudo using an atomic tmp-in-parent + chmod + chown + mv
pipeline. The content never appears in argv or process listings -- it streams
via stdin after the sudo password line. The final `mv` is a same-filesystem
rename, so the update is atomic from the kernel's perspective.

Requires **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
**POSIX-only** -- Windows targets raise `PlatformNotSupported`.

## When to call it

- Writing a root-owned config file the SSH user cannot write via SFTP.
- Replacing `/etc/...` files, privileged drop-in configs, or service
  credentials that must remain owned by root or a privileged user.
- You need to preserve the existing owner/group when rewriting a file.
- Uploading a large file from the MCP host filesystem without
  base64-encoding it (`local_path` mode; see below).

## When NOT to call it

- The SSH user can write the file directly -- use `ssh_upload` (no sudo
  overhead, same atomic-rename guarantee).
- You need a surgical string replace -- use `ssh_sudo_edit` (read + replace
  + write in one call, mode and ownership preserved).
- The path matches `redact_paths_globs` under `block` bypass policy -- the
  path-policy check fires before the write; make sure `path_allowlist`
  covers the parent and `restricted_*` lists don't include it.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path on the remote host. `must_exist=False` -- new files are created. |
| `content_text` | str | no | None | Plain UTF-8 text payload. Mutually exclusive with the other two payload args. |
| `content_base64` | str | no | None | Binary-safe base64-encoded payload. Mutually exclusive with the other two. |
| `local_path` | str | no | None | Absolute path on the MCP-host filesystem to read from. Requires `SSH_LOCAL_TRANSFER_ROOTS`. Mutually exclusive with the other two. |
| `mode` | int | no | 0o644 | Octal permission bits applied to the written file. |
| `chown_user` | str | no | None | User for `chown`. When omitted, preserved from existing file (or `root` for new files). |
| `chown_group` | str | no | None | Group for `chown`. When omitted, preserved from existing file (or `root` for new files). |

Pass **exactly one** of `content_text`, `content_base64`, or `local_path`.
Passing zero or more than one raises `ValueError` before any network activity.

## Returns

```json
{
  "host": "prod-db.internal",
  "path": "/etc/app/db.conf",
  "success": true,
  "bytes_written": 1024,
  "message": "sudo-wrote (atomic, owner app:app)",
  "output_warnings": [],
  "local_path_written": null
}
```

When the file did not exist and `chown_user`/`chown_group` were omitted:

```json
{
  "output_warnings": ["file did not exist, created as root:root; pass chown_user/chown_group to set explicitly."]
}
```

## Three-way payload mutex

| Mode | Arg | Cap | Notes |
|---|---|---|---|
| Inline text | `content_text` | `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB) | UTF-8 encoded to bytes on the MCP server |
| Inline binary | `content_base64` | `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB) | Base64-decoded to bytes on the MCP server; raises on invalid b64 |
| Local file | `local_path` | `SSH_LOCAL_TRANSFER_MAX_BYTES` (2 GiB) | Read into MCP server memory then piped via stdin; no base64 in context |

The `local_path` mode avoids forcing the LLM to generate or hold large base64
payloads as a tool-call argument (the same motivation as `ssh_upload`'s
`local_path` mode from v1.10.0). The file is read into memory on the MCP
server before the sudo pipeline starts; true streaming (no in-memory buffer)
is deferred to a future release.

## `local_path` operator setup

Disabled by default. Set `SSH_LOCAL_TRANSFER_ROOTS` to a CSV or JSON list
of absolute directories on the MCP host where reads are allowed:

```
SSH_LOCAL_TRANSFER_ROOTS=/srv/deploy/configs,/tmp/mcp-stage
SSH_LOCAL_TRANSFER_MAX_BYTES=2147483648   # 2 GiB (default)
```

Paths outside these roots raise `LocalPathPolicyError`. Same allowlist as
`ssh_upload`'s `local_path` mode.

## Ownership preservation

When `chown_user` and/or `chown_group` are omitted, the tool calls
`sudo stat -c '%U:%G'` first to read the existing owner:

- **File exists**: uses the stat-returned user/group for the missing arg(s).
- **File does not exist**: defaults to `root:root` and appends a warning to
  `output_warnings`. Pass explicit `chown_user`/`chown_group` for new files
  you want to own differently.

## Atomic pipeline

The write happens via a single `sudo sh -c` script:

```
dest=<quoted>; mode=<quoted>; owner=<quoted>
umask 077
t=$(mktemp -p "$(dirname "$dest")" .ssh-mcp-tmp.XXXXXXXX) || exit 1
cat > "$t" || { rm -f "$t"; exit 2; }
chmod "$mode" "$t" || { rm -f "$t"; exit 3; }
chown "$owner" "$t" || { rm -f "$t"; exit 4; }
mv -- "$t" "$dest" || { rm -f "$t"; exit 5; }
```

Values (`dest`, `mode`, `owner`) are inlined as shell variables at the top
of the script body via `shlex.quote`, never passed as positional args to
`sh -c` (which would fail -- see ADR-0028).

If the pipeline fails mid-run (chmod/chown/mv), the tmp file stays next to
the destination as `.ssh-mcp-tmp.*`. Sweep with `find <dir> -name
'.ssh-mcp-tmp.*' -delete` if orphans accumulate.

## Examples

```python
# Write a config file, preserving existing ownership.
ssh_sudo_write(
    host="prod-app",
    path="/etc/app/db.conf",
    content_text="host=db01\nport=5432\n",
    mode=0o640,
)

# Write a secrets file with explicit ownership and tight permissions.
ssh_sudo_write(
    host="prod-app",
    path="/etc/app/.env",
    content_text="DB_PASSWORD=hunter2\n",
    mode=0o600,
    chown_user="app",
    chown_group="app",
)

# Deploy a large config from the MCP host filesystem -- no base64 needed.
# Requires SSH_LOCAL_TRANSFER_ROOTS=/srv/deploy/configs
ssh_sudo_write(
    host="prod-app",
    path="/etc/nginx/nginx.conf",
    local_path="/srv/deploy/configs/nginx.conf",
    mode=0o644,
    chown_user="root",
    chown_group="root",
)
```

## Common failures

- `ValueError: pass exactly one of ...` -- zero or multiple payload args.
- `PathNotAllowed` -- remote `path` outside `path_allowlist`.
- `PathRestricted` -- remote `path` matched `restricted_*` lists.
- `LocalPathPolicyError` -- `local_path` is outside `SSH_LOCAL_TRANSFER_ROOTS`
  or the list is empty (mode disabled).
- `SudoFileOpError: payload N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES` --
  inline payload too large; switch to `local_path` mode.
- `SudoFileOpError: local_path N bytes exceeds SSH_LOCAL_TRANSFER_MAX_BYTES` --
  local file too large even for the bigger cap.
- `SudoFileOpError: sudo atomic write ... failed at stage chmod/chown/mv` --
  sudo ran but the pipeline step failed; stderr attached to the error message.
- `PlatformNotSupported` -- Windows target.

## Related

- [`ssh_sudo_edit`](../ssh-sudo-edit/SKILL.md) -- surgical string replace
  under sudo (preserves mode AND ownership in one round-trip).
- [`ssh_sudo_read`](../ssh-sudo-read/SKILL.md) -- read the file before
  deciding what to write.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- non-sudo equivalent; same
  `local_path` mode and three-way mutex.
