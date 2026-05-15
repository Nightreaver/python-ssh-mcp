---
description: Create a hard or symbolic link from src to dst on the remote host. Hard links are O(1) -- prefer over ssh_cp for big files on the same volume. Use symbolic=True for `ln -s`.
---

# `ssh_link`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Create a POSIX hard or symbolic link. Three modes:

- **`symbolic=True` (`ln -s`)** -- create a symbolic link at `dst` whose
  target text is `src`. Pure SFTP via `sftp.symlink()`. Per GNU `ln`'s
  "Using -s ignores -L and -P", `follow_symlinks` is silently ignored
  in this mode. `src` is stored VERBATIM in the symlink (preserves
  relative-link semantics: `ln -s ../foo bar` keeps `../foo` as the
  link text on disk so it continues to resolve correctly if dst moves).
- **`symbolic=False` + `follow_symlinks=True` (default, `ln -L`)** -- if
  `src` is a symlink, the new hard link points to the inode of its
  resolved target. Pure SFTP via `sftp.link()` (asyncssh / SFTP-HARDLINK
  extension; OpenSSH's sftp-server uses `linkat(... AT_SYMLINK_FOLLOW)`).
  No shell needed.
- **`symbolic=False` + `follow_symlinks=False` (`ln -P` / `--physical`)**
  -- the new hard link points to the SYMLINK's own inode, not its
  target (`-P` is literally "make hard links directly to symbolic
  links"). SFTP can't express this, so we fall back to
  `ln -P -- <src> <dst>`. Same low-access tier as `ssh_cp` / `ssh_mv`
  -- doesn't need `ln` in `command_allowlist`.

POSIX-only. Both sides of the link go through path policy (per-host
`path_allowlist` + `restricted_paths`). Existing `dst` is NOT replaced
(no `-f`); use `ssh_delete` first if you need to overwrite.

## When to call it

- **Prefer over `ssh_cp` for large files on the same volume.** Hard linking
  is O(1): just adds a directory entry, no bytes are read or written. Copy
  is O(file-size). For multi-MiB / multi-GiB artifacts (tarballs, build
  outputs, database dumps, container images), `ssh_link` is *seconds vs
  minutes* and uses no extra disk space (the new name shares the inode).
  Only use `ssh_cp` instead when (a) src and dst are on different
  filesystems, or (b) you need a genuinely independent copy because you
  intend to modify one without affecting the other (hard links share the
  inode -- a write through either name is visible through both).
- Pin a specific build artifact under a stable path (`/opt/app/current
  -> /opt/app/build-1234`) without copying bytes.
- Maintain multiple paths to the same file for tools that hardcode
  one location.
- Migrate a directory layout incrementally without breaking either old
  or new readers.

## When NOT to call it

- You need to modify one path without affecting the other (hard links
  only) -- hard links share the inode; edits via either name are
  visible through both. Use `ssh_cp` for an independent copy. (Symlinks
  don't have this issue -- they're separate filesystem entries.)
- src and dst are on different filesystems (hard links only) -- hard
  links cannot cross filesystems. You'll get `Invalid cross-device
  link`. Use `ssh_cp` for cross-fs copying, or `symbolic=True` (symlinks
  cross filesystems freely).
- src is a directory (hard links only) -- POSIX disallows hardlinking
  directories on most filesystems. Use `ssh_cp -a` or `symbolic=True`
  for directory aliases.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `src` | str | yes | -- | Hard link: source path (inode you're linking from). Symbolic: target text stored verbatim in the symlink. |
| `dst` | str | yes | -- | Destination path (the new directory entry) |
| `symbolic` | bool | no | `False` | True = `ln -s` (symbolic link). Ignores `follow_symlinks`. |
| `follow_symlinks` | bool | no | `True` | Hard-link-only. False = `ln -P` (link to the symlink itself). |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/current",
  "success": true,
  "bytes_written": 0,
  "message": "hard link (followed symlinks) -> /opt/app/build-1234"
}
```

`message` records which mode ran and which inode the link points at, so
the audit trail captures the actual semantics.

## Path policy notes

`dst` is canonicalized normally in every mode; the parent must exist and
be in the allowlist; dst itself must NOT exist.

`src` validation differs by mode:

- **Hard link, `follow_symlinks=True` (default)** -- canonicalized
  normally (resolves any symlinks in the path); the resolved target must
  be in the allowlist + not restricted.
- **Hard link, `follow_symlinks=False` (`-P`)** -- canonicalizing src
  would resolve the symlink we want to point at, defeating `-P`. So we
  canonicalize the *parent dir* (must be allowlisted), then `lstat`
  confirms src exists in that dir. The check is "the symlink lives in
  an allowed dir," not "everywhere this symlink could ever point is
  allowed." Restricted-path check still applies to the constructed path.
- **Symbolic link (`symbolic=True`)** -- src is the target STRING (not a
  real path). POSIX permits dangling symlinks, so we don't realpath or
  lstat it -- the SFTP `symlink()` call accepts any text. Validation is
  string-based:
  1. `reject_bad_characters(src)` rejects NUL bytes / control chars.
  2. If src is relative, resolve against `dst`'s parent dir.
  3. `posixpath.normpath` collapses `..` / `//` etc.
  4. `check_in_allowlist(target_normalized, ...)` -- the resolved target
     path must be inside the allowlist (defense-in-depth: even though
     a read through the symlink would re-trigger path policy at read
     time, we also gate symlink CREATION).
  5. `check_not_restricted(target_normalized, ...)` -- same.
  6. The original `src` text is stored on disk (preserves relative-link
     semantics), but the policy decision was made on the normalized
     resolved form.

## Common failures

- `SFTPError: Failure` (default hard-link mode, dst exists) -- the
  hard-link primitive refuses to overwrite. `ssh_delete(dst)` first.
- `WriteError: ln -P failed (exit 1): File exists` (`-P` mode, dst
  exists) -- same situation, just routed through the shell.
- `WriteError: ln -P failed (exit 1): Invalid cross-device link` --
  src and dst are on different filesystems. Use `ssh_cp` (independent
  copy) or `symbolic=True` (symlinks cross filesystems freely).
- `PathNotAllowed` -- src or dst (or for `-P`, src's parent; for
  symbolic, the resolved target) outside the allowlist.
- `PathNotAllowed: path contains NUL byte` (symbolic mode) --
  `reject_bad_characters` ran. Sanitize the target string.
- `ValueError: src does not exist` (`-P` mode) -- src isn't there per
  `lstat`. Maybe a typo, maybe a dangling symlink that even `lstat`
  can't see (rare). Note: in `symbolic` mode, dangling targets are
  ALLOWED -- POSIX permits creating a symlink to a path that doesn't
  exist yet.

## Examples

```python
# Hard link: pin /opt/app/current to a specific build (most common
# case for hard links -- O(1), shares inode with build-1234).
ssh_link(host="web01", src="/opt/app/build-1234", dst="/opt/app/current")

# Symbolic link: the rolling-release pattern. dst is a symlink whose
# text is "release-v2"; flips by re-creating the symlink later.
ssh_link(host="web01", src="release-v2", dst="/opt/app/current",
         symbolic=True)
# Relative target stored verbatim -- continues to resolve correctly
# if /opt/app is moved.

# Symbolic link to a target that doesn't exist yet (legitimate
# pattern: the target gets created later by another step).
ssh_link(host="web01", src="/opt/app/release-v3", dst="/opt/app/next",
         symbolic=True)

# Hard link to a symlink itself, not its target (rare -- preserves the
# symlink relationship across a directory rename, etc.).
ssh_link(host="web01", src="/etc/alternatives/python",
         dst="/opt/migration/python.bak", follow_symlinks=False)
```

## Related

- [`ssh_cp`](../ssh-cp/SKILL.md) -- copy bytes (separate inode);
  required for cross-filesystem moves.
- [`ssh_mv`](../ssh-mv/SKILL.md) -- rename / move (one inode, new path).
- [`ssh_delete`](../ssh-delete/SKILL.md) -- use to clear `dst` when
  you need to overwrite an existing path.
- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- check whether dst
  already exists, or compare inode numbers after linking.
