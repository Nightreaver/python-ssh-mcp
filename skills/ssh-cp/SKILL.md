---
description: Copy a file on a remote host
---

# `ssh_cp`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Runs `cp -a -- <src> <dst>` with **fixed argv** (the `--` separator blocks
flag injection). `src` must exist; `dst` may be inside an allowlisted root.
Both paths are canonicalized on the remote and re-checked against the path
allowlist before the shell runs.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `src` | str | yes | Absolute path; must exist; must be inside an allowlisted root |
| `dst` | str | yes | Absolute path; may not yet exist; must canonicalize inside an allowlisted root |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/release.tar.gz.bak",
  "success": true,
  "bytes_written": 0,
  "message": "copied from /opt/app/release.tar.gz"
}
```

## When to call it

- Take a backup before mutating a file (`cp foo foo.bak`, then `ssh_edit foo`).
- Stage a deployment artifact between two paths on the same host.
- Anywhere you'd type `cp -a` at a shell.

## When NOT to call it

- Cross-host copy -- not supported. Download (`ssh_sftp_download`) -> upload (`ssh_upload`).
- Recursive directory copy of a huge tree -- works but slow over `cp -a`; consider rsync via `ssh_exec_run` if you have exec tier.

## Example

```python
ssh_cp(host="web01", src="/etc/nginx/nginx.conf", dst="/etc/nginx/nginx.conf.pre-edit")
```

## Common failures

- `PathNotAllowed` -- `src` or `dst` (after canonicalization, after symlinks) is
  outside the host's `path_allowlist` + `SSH_PATH_ALLOWLIST`. Add the root or
  pick a different destination.
- `WriteError: cp failed (exit N): ...` -- usually permission denied or `dst`
  parent missing. Read the stderr text in the error.

## Related

- [`ssh_mv`](../ssh-mv/SKILL.md) -- atomic rename / move.
- [`ssh_upload`](../ssh-upload/SKILL.md) -- push fresh content from outside the host.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- atomic in-place edit (no manual backup needed).
