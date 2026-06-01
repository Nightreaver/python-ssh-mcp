---
description: Sudo-elevated structured edit; read + apply_edit + atomic write-back with mode and ownership preserved
---

# `ssh_sudo_edit`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Sudo-elevated counterpart to `ssh_edit`. Reads the file via `sudo cat`,
applies a structured string replace in memory using `apply_edit` (the same
pure function as `ssh_edit`), then writes back via `sudo_atomic_write` --
the same atomic tmp+chmod+chown+mv pipeline used by `ssh_sudo_write`.

**Mode preservation is security-critical:** a secrets file at `0o600` stays
at `0o600` after the edit -- the tool calls `sudo stat` for both owner/group
AND permission bits before writing back. The default `0o644` in the write
helper is used only if `stat` returns `None` (edge case: file vanished between
read and write). This guarantees that a privileged-file edit cannot silently
widen permissions.

Requires **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
**POSIX-only** -- Windows targets raise `PlatformNotSupported`.

## When to call it

- Editing a root-owned config in-place without reading + modifying + writing
  three separate tool calls.
- The file is a secrets file (`0o600`, root-owned) and you need the edit to
  not change its permissions.
- You have an `old_string` that uniquely identifies the section to replace.

## When NOT to call it

- You need to replace the ENTIRE file -- use `ssh_sudo_write`.
- The SSH user can write the file directly -- use `ssh_edit` (no sudo).
- The `old_string` is not unique: with `occurrence='single'` the tool raises
  `SudoFileOpError` (wrapping `EditError`). Either make it unique (add
  surrounding context) or use `occurrence='all'`.
- The file is binary -- `ssh_sudo_edit` is text-only; binary files raise
  `SudoFileOpError: not valid UTF-8`.
- The file is over `SSH_EDIT_MAX_FILE_BYTES` (default 10 MiB) -- use
  `ssh_sudo_write(local_path=...)` to overwrite from an edited local copy.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to an existing file (`must_exist=True`). |
| `old_string` | str | yes | -- | The exact string to find and replace. Must be non-empty. |
| `new_string` | str | yes | -- | The replacement string. May be empty (deletion). |
| `occurrence` | str | no | `"single"` | `"single"`: exactly one match required. `"all"`: replace every occurrence. |

## Returns

```json
{
  "host": "prod-db.internal",
  "path": "/etc/postgresql/postgresql.conf",
  "success": true,
  "bytes_written": 4096,
  "message": "sudo-edited (replaced 1 occurrence(s))",
  "output_warnings": []
}
```

## Mode and ownership preservation

Before writing back, the tool runs two `sudo stat` calls:

1. `sudo stat -c '%U:%G'` -- owner/group. Preserved exactly.
2. `sudo stat -c '%a'` -- octal permission bits. Preserved exactly.

Both stats run after the read but before the write-back. If (race condition)
the file disappears between read and stat, the write uses `root:root` +
`0o644` as fallback defaults -- that edge is documented and acceptable.

The stat-then-write approach means: **you cannot change a file's mode or
ownership with `ssh_sudo_edit`**. For that, use `ssh_sudo_write` with
explicit `mode=`, `chown_user=`, `chown_group=`.

## `apply_edit` semantics

Identical to `ssh_edit`:

- `occurrence='single'`: the edit raises if `old_string` is not found exactly
  once. Tip: if the raw string appears twice, add surrounding context to make
  it unique (include the preceding line in `old_string`).
- `occurrence='all'`: replaces every non-overlapping occurrence.
- `old_string` is a literal string, not a regex. No special escaping needed.

## Size cap

`SSH_EDIT_MAX_FILE_BYTES` (default 10 MiB). The file is read fully into MCP
server memory. Post-edit content is also checked; a `new_string` longer than
`old_string` can push the result past the cap -- `SudoFileOpError` in that case.

## Atomic pipeline

Write-back uses `sudo_atomic_write` (same as `ssh_sudo_write`):
tmp-in-parent + chmod + chown + mv. The write does NOT call `ssh_sudo_write`
as a tool -- it calls the shared internal helper directly.

## Examples

```python
# Change a port in a privileged config. File is 0o600 root:root.
# The edit preserves both the mode and ownership.
ssh_sudo_edit(
    host="prod-db",
    path="/etc/postgresql/postgresql.conf",
    old_string="port = 5432",
    new_string="port = 5433",
)

# Rotate an environment variable in a root-owned .env.
ssh_sudo_edit(
    host="prod-app",
    path="/etc/app/.env",
    old_string="API_KEY=old-key-value",
    new_string="API_KEY=new-key-value",
)

# Replace ALL occurrences -- e.g. mass-rename a host alias.
ssh_sudo_edit(
    host="prod-app",
    path="/etc/app/config.yaml",
    old_string="db-primary.internal",
    new_string="db-replica.internal",
    occurrence="all",
)
```

## Common failures

- `SudoFileOpError: old_string not found` (wrapping `EditError`) -- the
  string is not in the file. Re-read with `ssh_sudo_read` to verify.
- `SudoFileOpError: old_string appears N times; use occurrence='all'` --
  use `occurrence='all'` or widen `old_string` with surrounding context.
- `SudoFileOpError: not valid UTF-8` -- binary file; edit tools are text-only.
- `SudoFileOpError: edited content N bytes exceeds SSH_EDIT_MAX_FILE_BYTES` --
  post-edit file grew past cap.
- `PathNotAllowed` -- path outside `path_allowlist`.
- `PathRestricted` -- path matched `restricted_*` lists.
- `SudoFileOpError: sudo cat exited N` -- read step failed (sudo refused or
  file actually missing despite `must_exist=True` path policy passing).
- `PlatformNotSupported` -- Windows target.

## Related

- [`ssh_edit`](../ssh-edit/SKILL.md) -- non-sudo equivalent; same `apply_edit`
  semantics for files the SSH user can write directly.
- [`ssh_sudo_write`](../ssh-sudo-write/SKILL.md) -- full-file overwrite under
  sudo; use when you need to replace the whole content or change mode/ownership.
- [`ssh_sudo_read`](../ssh-sudo-read/SKILL.md) -- read the file first to
  construct the exact `old_string`.
- [`ssh_sudo_read_redacted`](../ssh-sudo-read-redacted/SKILL.md) -- read with
  redaction when the file is on `redact_paths_globs`.
