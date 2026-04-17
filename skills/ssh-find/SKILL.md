---
description: Recursively search a remote directory by name pattern, depth-capped
---

# `ssh_find`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Runs `find <path> -maxdepth N -type T -name PATTERN` with **fixed argv** --
the pattern is passed as a single argv element, never interpolated into a
shell string. Pattern is regex-validated to a safe character set.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute root to search under |
| `name_pattern` | str | no | `"*"` | Glob-like pattern for `find -name`; allowed chars: letters, digits, `._*?-[]` |
| `kind` | str | no | `"f"` | One of `"f"` (file), `"d"` (dir), `"l"` (symlink) |
| `max_depth` | int | no | env default | Capped at `SSH_FIND_MAX_DEPTH` (default 10) |

## Returns

```json
{
  "host": "web01.example.com",
  "root": "/var/log",
  "matches": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
  "truncated": false
}
```

Capped at `SSH_FIND_MAX_RESULTS` (default 10000); `truncated=true` when reached.

## When to call it

- Locate large/old files before deleting (after `ssh_host_disk_usage` shows full).
- Find every config file matching `*.conf` under `/etc/<service>`.
- Search log directories for a specific archive.

## When NOT to call it

- Content search (grep) -- not supported here; use `ssh_exec_run` with grep if you have exec tier.
- Unbounded recursion of huge trees -- depth and result caps will trim. Either narrow `path` or bump caps.
- Anything needing `-exec` -- explicitly disallowed; that would bypass argv hygiene.

## Scope discipline: start narrow, widen only if you miss

Searching from `/` (or any root-of-volume) against a live server walks every
mount, container overlay, snapshot dir, and user home -- minutes of wall-clock
and MBs of output for a result the conversation context usually already points
at. The `SSH_FIND_MAX_RESULTS` / `SSH_FIND_MAX_DEPTH` caps will truncate your
output before a root-scan finishes -- a `truncated=true` result is NOT "no
matches", it's **"the scope was wrong."**

Practical ladder (try in order; stop at the first hit):

1. The exact path you think the file lives in (`/etc/nginx`, `/opt/app/logs`).
2. The parent or service root (`/etc`, `/var/log`, `/opt/app`).
3. Common roots for the file kind:
   - configs -> `/etc`
   - logs -> `/var/log`
   - user data -> `/home` or `/root`
   - app installs -> `/opt` or `/srv`
4. Only then widen to `/`, and only with a tight `name_pattern` so the walk
   can short-circuit on name match rather than dragging every inode back
   across the wire.

## Example

```python
ssh_find(host="web01", path="/var/log/nginx", name_pattern="*.gz", kind="f")
# -> {"matches": ["/var/log/nginx/access.log.1.gz", ...]}

ssh_find(host="db01", path="/var/lib/postgresql", name_pattern="*.bak", max_depth=3)
```

## Common failures

- `ValueError: name_pattern contains disallowed characters` -- keep it simple
  (no slashes, no shell metacharacters beyond `*?[]`).
- `ValueError: kind must be one of 'f', 'd', 'l'`.
- `truncated=true` -- narrow the search or raise `SSH_FIND_MAX_RESULTS`.

## Related

- [`ssh_sftp_list`](../ssh-sftp-list/SKILL.md) -- single-directory enumeration with metadata.
- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- get size/mode for individual matches.
- [`ssh_delete`](../ssh-delete/SKILL.md) -- remove individual files (low-access tier).
