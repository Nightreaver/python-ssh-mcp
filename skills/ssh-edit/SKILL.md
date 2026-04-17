---
description: Atomic in-place edit -- replace one string with another, preserving mode
---

# `ssh_edit`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Download the file via SFTP, replace `old_string` with `new_string` in
memory, write to `<path>.ssh-mcp-tmp.<hex>`, `posix_rename` over the original.
Mode is preserved. Same semantics as Claude Code's `Edit` tool: `single`
mode requires exactly one occurrence; `all` replaces every occurrence.

Size-capped at `SSH_EDIT_MAX_FILE_BYTES` (default 10 MiB).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to a regular UTF-8 file |
| `old_string` | str | yes | -- | Must appear in the file. Non-empty. |
| `new_string` | str | yes | -- | Replacement. Must differ from `old_string`. |
| `occurrence` | str | no | `"single"` | `"single"` (require exactly one match) or `"all"` (replace every match) |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/etc/nginx/nginx.conf",
  "success": true,
  "bytes_written": 4153,
  "message": "replaced 1 occurrence(s)"
}
```

## When to call it

- Tweak a single config value (`listen 80;` -> `listen 8080;`).
- Targeted multi-replace with `occurrence="all"` (e.g., bump every `version = "1.0"` to `"1.1"`).
- Anywhere you'd `sed -i` -- but safer (atomic, mode-preserved, cap-protected).

## When NOT to call it

- You only know the new content, not the old -- use `ssh_upload` to overwrite.
- You have a unified diff -- use `ssh_patch`.
- The file is binary or non-UTF-8 -- this tool decodes UTF-8 strictly. Fall
  back to `ssh_sftp_download` + offline edit + `ssh_upload`.
- The file is over 10 MiB -- raises `WriteError`. Raise `SSH_EDIT_MAX_FILE_BYTES`
  in env if legitimate.

## Example

```python
ssh_edit(
    host="web01",
    path="/etc/nginx/nginx.conf",
    old_string="listen 80;",
    new_string="listen 8080;",
    occurrence="single",
)
```

When `old_string` appears multiple times and you mean only one of them, make
the `old_string` unique by adding surrounding context:

```python
ssh_edit(
    host="web01",
    path="/etc/foo.conf",
    old_string="port = 8080  # api",      # added comment makes it unique
    new_string="port = 9090  # api",
)
```

## Common failures

- `WriteError: old_string not found` -- typo or stale read. Re-`ssh_sftp_download`.
- `WriteError: old_string appears N times; use occurrence='all' or make it unique` -- fix the input.
- `WriteError: file <size> bytes exceeds SSH_EDIT_MAX_FILE_BYTES=...` -- split into a `download -> patch -> upload` flow.
- `PathNotAllowed` -- outside the allowlist.

## Related

- [`ssh_patch`](../ssh-patch/SKILL.md) -- when you have a unified diff.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- full-file overwrite.
- [`ssh_cp`](../ssh-cp/SKILL.md) -- take a backup first if you want a manual rollback.
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- read current contents to construct `old_string`.
