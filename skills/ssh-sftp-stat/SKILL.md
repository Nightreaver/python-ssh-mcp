---
description: Get metadata for a single remote file or directory
---

# `ssh_sftp_stat`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

SFTP `lstat` -- does not follow the final symlink, so you see the symlink
itself if `path` points to one. Use this to confirm a target exists with the
expected kind/size/mode before doing anything else.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |
| `path` | str | yes | Absolute path on the remote |

## Returns

```json
{
  "path": "/etc/nginx/nginx.conf",
  "kind": "file",
  "size": 4096,
  "mode": "0644",
  "mtime": "2026-04-14T09:30:00+00:00",
  "owner": "0",
  "group": "0",
  "symlink_target": null
}
```

`mode` is octal as 4 digits. `owner`/`group` are uids/gids as strings.
`symlink_target` is non-null only when `kind == "symlink"`.

## When to call it

- Confirm a file exists before `ssh_sftp_download` or `ssh_edit`.
- Detect symlinks before low-access mutation (a symlink can point out of the allowlist).
- Check the mode you'll need to preserve when writing.

## When NOT to call it

- For directory listings -- use `ssh_sftp_list`.
- For per-line file content -- use `ssh_sftp_download`.

## Example

```python
ssh_sftp_stat(host="web01", path="/etc/nginx/nginx.conf")
# -> {"kind": "file", "size": 4096, "mode": "0644", ...}
```

## Common failures

- SFTP "no such file" -> tool error; the path doesn't exist (or you can't see it).
- "permission denied" -> the SSH user can't `stat` that path.

## Related

- [`ssh_sftp_list`](../ssh-sftp-list/SKILL.md) -- directory enumeration.
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- fetch contents after stat confirms file + size is reasonable.
- [`ssh_edit`](../ssh-edit/SKILL.md) -- atomic edit, preserves mode reported here.
