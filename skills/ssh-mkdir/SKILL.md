---
description: Create a remote directory, optionally with parents
---

# `ssh_mkdir`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Pure SFTP -- no shell. Creates one directory by default; `parents=True` walks
up and creates each missing ancestor (`mkdir -p` semantics). All paths in
the chain are inside the allowlist.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path of the directory to create |
| `parents` | bool | no | `False` | If `True`, create missing ancestors |
| `mode` | int | no | `0o755` | Octal permission bits |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/cache/2026-04-14",
  "success": true,
  "message": "created (with parents)"
}
```

## When to call it

- Prepare a directory before `ssh_upload`.
- Materialize a date-based or build-id directory tree on first use.
- Stage a release directory.

## When NOT to call it

- To set ACLs / extended attributes -- only `mode` is honored.
- For `mkdir -m XXXX` semantics on existing dirs -- this is create-only.
  An existing directory raises (unless on the parents path with `parents=True`).

## Example

```python
ssh_mkdir(host="web01", path="/opt/app/cache", parents=True, mode=0o755)
ssh_mkdir(host="web01", path="/opt/app/cache/today")  # parent exists now
```

## Common failures

- `PathNotAllowed` -- `path` is outside the allowlist.
- `WriteError: parent X exists and is not a directory` -- a path component is
  a file (or other non-dir). Fix the host by hand.
- SFTP "permission denied" -- the SSH user can't write to the parent.

## Related

- [`ssh_upload`](../ssh-upload/SKILL.md) -- write a file into the new directory.
- [`ssh_cp`](../ssh-cp/SKILL.md) -- copy something into it.
- [`ssh_delete_folder`](../ssh-delete-folder/SKILL.md) -- undo it.
