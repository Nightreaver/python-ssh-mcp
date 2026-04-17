---
description: Delete a single remote file (rejects directories)
---

# `ssh_delete`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Pure SFTP `remove`. **Files only.** Directories are explicitly rejected --
use `ssh_delete_folder` for those (which has its own `recursive` + `dry_run`
controls).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `path` | str | yes | Absolute path to a regular file |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/old.tar.gz",
  "success": true,
  "message": "deleted"
}
```

## When to call it

- Remove a single, identified file (e.g., a stale backup).
- Cleanup after `ssh_cp` if the original is no longer needed.

## When NOT to call it

- Removing a directory -- use `ssh_delete_folder`.
- Removing many files matching a pattern -- call `ssh_find` first to enumerate,
  then iterate `ssh_delete`. Audit log captures each removal.
- Anything you couldn't manually undo with a backup -- prefer `ssh_mv` to a
  `.trash/` directory if you want a soft-delete.

## Example

```python
ssh_delete(host="web01", path="/var/log/nginx/access.log.10.gz")
```

## Common failures

- `PathNotAllowed` -- outside the allowlist.
- `WriteError: <path> is a directory; use ssh_delete_folder` -- explicit.
- SFTP "permission denied" / "no such file" -- the user can't see/touch it.

## Related

- [`ssh_delete_folder`](../ssh-delete-folder/SKILL.md) -- directory removal with `recursive` + `dry_run`.
- [`ssh_find`](../ssh-find/SKILL.md) -- enumerate candidates before bulk deletion.
- [`ssh_mv`](../ssh-mv/SKILL.md) -- soft-delete to a trash directory instead of removing outright.
