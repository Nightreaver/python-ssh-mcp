---
description: Remove a remote directory; recursive + dry-run supported
---

# `ssh_delete_folder`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Three modes:

1. `recursive=False` (default): SFTP `rmdir` -- must be empty.
2. `recursive=True, dry_run=True`: SFTP-walk the tree, return the would-delete list. **No mutation.** Always do this first when you're not certain.
3. `recursive=True, dry_run=False`: SFTP-walk + entry cap check + fixed-argv `rm -rf -- <canonical>`. Path re-validated against allowlist immediately before the shell runs.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to the directory |
| `recursive` | bool | no | `False` | If `False`, fail on non-empty |
| `dry_run` | bool | no | `False` | Recursive-walk and report only |

## Returns

Non-recursive or post-recursive-delete:

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/cache",
  "success": true,
  "message": "rmdir"  // or "recursively deleted N entries"
}
```

Dry-run:

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/cache",
  "would_delete": ["/opt/app/cache", "/opt/app/cache/file1", ...],
  "dry_run": true
}
```

## When to call it

- Remove a directory tree you fully own and have just dry-run-confirmed.
- Tear down a staging area after a release.
- Empty-dir cleanup (no `recursive` needed).

## When NOT to call it

- You haven't done a `dry_run` first on anything but a tiny known directory.
- The directory might contain data you can't recover. Prefer `ssh_mv` to a
  trash location, or copy elsewhere first.
- The tree exceeds `SSH_DELETE_FOLDER_MAX_ENTRIES` (default 10000) -- the tool
  raises rather than guessing. Pick a smaller subdirectory.

## Example

```python
# Always dry-run first
ssh_delete_folder(host="web01", path="/opt/app/cache", recursive=True, dry_run=True)
# Inspect would_delete; if it looks correct:
ssh_delete_folder(host="web01", path="/opt/app/cache", recursive=True)
```

## Common failures

- `PathNotAllowed` -- outside the allowlist (checked twice for recursive: walk + immediately before `rm -rf`).
- `WriteError: folder would touch >= N entries` -- the tree is too big. Narrow the path or raise the cap.
- SFTP `rmdir` of a non-empty directory -> tool error; pass `recursive=True`.

## Related

- [`ssh_delete`](../ssh-delete/SKILL.md) -- single-file removal.
- [`ssh_mv`](../ssh-mv/SKILL.md) -- safer alternative for "soft delete" via rename to trash.
- [`ssh_find`](../ssh-find/SKILL.md) -- preview directory contents before deletion.
