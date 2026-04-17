---
description: Move or rename a file on a remote host
---

# `ssh_mv`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Tries SFTP `posix_rename` first -- atomic within a filesystem. On
`EXDEV`-class errors (cross-filesystem), falls back to `mv -- src dst`
with **fixed argv**. Both paths canonicalized + allowlist-checked.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `src` | str | yes | Absolute path; must exist |
| `dst` | str | yes | Absolute path; may not yet exist |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/new-name.txt",
  "success": true,
  "message": "moved from /opt/app/old-name.txt (sftp-rename)"
}
```

`message` ends with `(sftp-rename)` for atomic same-FS moves and `(mv-fallback)`
when the shell fallback was used.

## When to call it

- Atomic rename within a directory (preferred over copy + delete).
- Move a built artifact into a release directory after staging.
- Rename a backup before rotation.

## When NOT to call it

- Cross-host move -- not supported. Use download + upload + delete.
- A move you need to roll back -- `ssh_mv` is not transactional. Use `ssh_cp`
  + verify + `ssh_delete` if you need a checkpoint.

## Example

```python
ssh_mv(host="web01", src="/opt/app/release.tar.gz.staging", dst="/opt/app/release.tar.gz")
# -> atomic when both paths share a filesystem
```

## Common failures

- `PathNotAllowed` -- same as `ssh_cp`.
- `WriteError: mv failed (exit N): ...` -- permission denied or unexpected fs error.
  The fallback only triggers on cross-FS; other failures bubble up directly.

## Related

- [`ssh_cp`](../ssh-cp/SKILL.md) -- when you need to keep the original.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- write fresh content (also atomic via tmp + rename).
- [`ssh_delete`](../ssh-delete/SKILL.md) -- remove the source after a copy if you can't `mv`.
