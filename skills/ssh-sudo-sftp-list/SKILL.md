---
description: Sudo-elevated directory listing parsed into SftpListResult entries; use for root-owned directories
---

# `ssh_sudo_sftp_list`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

List a directory via `sudo ls -la --time-style=full-iso --` and parse the
output into the same `SftpListResult.entries` shape as `ssh_sftp_list`. Use
for directories the SSH user cannot traverse without sudo (root-owned, mode
`0700`, or directories inside paths the SSH user has no execute bit on).

Requires **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
**POSIX-only** -- Windows targets raise `PlatformNotSupported`.

## When to call it

- Listing `/root`, `/etc/ssl/private`, `/var/lib/postgresql`, or any other
  directory the SSH user cannot `lstat` without sudo.
- Discovering what root-owned files exist before deciding which
  `ssh_sudo_read` / `ssh_sudo_write` calls to make.
- Auditing ownership, mode, and mtimes of privileged files.

## When NOT to call it

- The SSH user can already traverse the directory -- use `ssh_sftp_list`
  (pure SFTP, no shell, faster, works on all platforms including Windows).
- The directory has > 10,000 entries and you need all of them -- pagination
  is applied AFTER the full `sudo ls` parse. Very large directories are
  better served by relaxing the per-host policy to let SFTP reach them
  directly, or by running a targeted `ssh_sudo_exec("ls /path | grep pattern")`.
- You are on a BusyBox host -- BusyBox `ls` does not support `--time-style=full-iso`;
  rows that do not match the expected format are silently dropped (logged at DEBUG).
  Use `ssh_sudo_exec("ls -la /path")` as a fallback (exec tier must be enabled).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to a directory on the remote host |
| `offset` | int | no | 0 | Skip the first N entries (post-parse, sorted by name) |
| `limit` | int | no | 100 | Return at most N entries; clamped `[1, 1000]` |

## Returns

```json
{
  "host": "prod-db.internal",
  "path": "/root",
  "entries": [
    {
      "name": ".bashrc",
      "kind": "file",
      "size": 3526,
      "mode": "0644",
      "mtime": "2026-05-01T14:22:33.000000000 +0000",
      "symlink_target": null
    },
    {
      "name": ".ssh",
      "kind": "dir",
      "size": 4096,
      "mode": "0700",
      "mtime": "2026-04-10T09:11:07.000000000 +0000",
      "symlink_target": null
    }
  ],
  "offset": 0,
  "limit": 100,
  "has_more": false
}
```

`.` and `..` entries are stripped. Symlinks include `symlink_target` with
the link destination. The `total N` header line from GNU ls is skipped.

## Mode field note

`mode` is derived from the `rwxrwxrwx` column of `ls -la` output, converted
to a 4-digit octal string. Setuid/setgid/sticky bits that appear as `s`/`t`
in the permission column are approximated -- the high octal digit may not
exactly reflect the kernel-level permission bits. Use `ssh_sudo_exec("stat
-c '%a' <path>")` if you need exact mode bits.

## Pagination

Pagination is applied AFTER the full listing is parsed. The entire directory
is read by the sudo pipeline on every call; `offset`/`limit` slice the
in-memory result. For directories with thousands of entries this is acceptable;
for extremely large directories (> 10,000 entries) prefer SFTP access if possible.

Entries are sorted by `name` (lexicographic) before slicing to match the
deterministic order from `ssh_sftp_list`.

## BusyBox warning

BusyBox `ls` without `--time-style=full-iso` produces a different date format
(`Jan  1 12:34` instead of `2026-01-01 12:34:56`). The parser's regex
requires the ISO format; BusyBox rows are silently skipped and logged at DEBUG.

If entries seem missing on an embedded Linux host, check whether the host
uses BusyBox: `ssh_exec_run(host=..., command="ls --help 2>&1 | head -1")`.

## Policy chain

1. `path_allowlist` -- `PathNotAllowed` if outside roots.
2. `restricted_paths` / `restricted_globs` -- `PathRestricted` if matched.
3. `redact_paths_globs` + `redact_bypass_policy` -- can fire if the directory
   is on the redact list (unusual -- redact is usually for files, not dirs).
4. sudo `ls` invocation.

## Examples

```python
# List /root directory.
result = ssh_sudo_sftp_list(host="prod-db", path="/root")
for entry in result["entries"]:
    print(entry["name"], entry["kind"], entry["mode"])

# Paginate through a large privileged directory.
offset = 0
while True:
    page = ssh_sudo_sftp_list(host="prod-db", path="/var/lib/postgresql", offset=offset, limit=100)
    for entry in page["entries"]:
        print(entry["name"])
    if not page["has_more"]:
        break
    offset += 100
```

## Common failures

- `PathNotAllowed` -- `path` outside `path_allowlist`.
- `SudoFileOpError: sudo ls -la exited N` -- sudo refused or the path is not
  a directory (or does not exist even for root).
- Empty `entries` on a directory you know has files -- check for BusyBox ls
  (see above) or verify the path is actually a directory.
- `ValueError: limit must be in 1..1000` -- limit out of range.
- `PlatformNotSupported` -- Windows target.

## Related

- [`ssh_sftp_list`](../ssh-sftp-list/SKILL.md) -- non-sudo equivalent; pure
  SFTP, no shell, cross-platform. Use when SSH user can traverse the directory.
- [`ssh_sudo_read`](../ssh-sudo-read/SKILL.md) -- read a file found in the listing.
- [`ssh_sudo_read_redacted`](../ssh-sudo-read-redacted/SKILL.md) -- read a
  secrets file found in the listing.
- [`ssh_find`](../ssh-find/SKILL.md) -- recursive search by name/size/mtime
  (SSH user scope; no sudo variant).
