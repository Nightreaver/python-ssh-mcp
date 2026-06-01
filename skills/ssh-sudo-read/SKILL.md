---
description: Sudo-elevated single-file read; full path-policy-checked, returns base64 bytes
---

# `ssh_sudo_read`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Read a file via `sudo cat --` for paths the ssh-user cannot reach directly
(root-owned configs, privileged key material stored on-host, files inside
directories the service account has no `x` bit on). Returns raw bytes as
base64 in `content_base64` -- the same `DownloadResult` shape as
`ssh_sftp_download`'s default branch so callers can switch transparently.

Requires **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
**POSIX-only** -- Windows targets raise `PlatformNotSupported`.

## When to call it

- The file is owned by root (or another privileged account) and the SSH
  user has no read access even via SFTP.
- You already confirmed via `ssh_sftp_stat` or `ssh_sftp_download` that
  the file is not reachable by the SSH user.
- The path does NOT match `redact_paths_globs` under a `block` bypass
  policy -- if it does, use `ssh_sudo_read_redacted` instead (the path-policy
  fires and refuses with `RedactBypassBlocked` before any sudo invocation).

## When NOT to call it

- The SSH user can already read the file -- use `ssh_sftp_download`.
- The path is on `redact_paths_globs` (`.env`, secrets dirs, etc.) --
  use `ssh_sudo_read_redacted` to get the structural view without
  plaintext secrets entering the LLM context.
- The file is larger than `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB) --
  `SudoFileOpError` is raised after reading the full file into memory.
- You only need to list a directory -- use `ssh_sudo_sftp_list`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname (must be in the allowlist) |
| `path` | str | yes | -- | Absolute path on the remote host. Resolved via `realpath` before policy checks. |

## Returns

```json
{
  "host": "prod-db.internal",
  "path": "/etc/ssl/private/db.key",
  "size": 1679,
  "content_base64": "LS0tLS1CRUdJTi...",
  "truncated": false,
  "local_path_written": null
}
```

Decode with `base64.b64decode(content_base64)` on the caller side.

## Policy chain

Path goes through the full `resolve_path` chain before any sudo invocation:

1. **`path_allowlist`** -- canonical path must fall inside a configured root.
   `PathNotAllowed` if not.
2. **`restricted_paths`** -- prefix-deny zones. `PathRestricted` if matched.
3. **`restricted_globs`** -- glob-deny zones. `PathRestricted` if matched.
4. **`redact_paths_globs` + `redact_bypass_policy`** -- if the canonical
   path matches a redact glob AND `redact_bypass_policy='block'`, raises
   `RedactBypassBlocked`. The error message names `ssh_sudo_read_redacted`
   as the correct tool. Under `warn` or `audit_only` the read proceeds and
   an `output_warnings` entry is appended (or the audit line is stamped).
5. **sudo invocation** -- only reached if steps 1-4 all pass.

## Size cap

`SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB). The cap is checked AFTER the
full `sudo cat` read; the file streams into MCP server memory first. For
files you know are large, inspect size with `ssh_sudo_sftp_list` first.

## Decision tree -- read vs redacted

```
Does path match redact_paths_globs?
    YES -> use ssh_sudo_read_redacted (bypass-exempt)
    NO  -> ssh_sudo_read (plain bytes, base64)
```

## Examples

```python
# Read a root-owned private key (NOT on redact list -- binary cert, not .env).
result = ssh_sudo_read(host="prod-db", path="/etc/ssl/private/db.key")
import base64
key_bytes = base64.b64decode(result["content_base64"])

# Read a privileged config file not covered by redact_paths_globs.
result = ssh_sudo_read(host="web01", path="/etc/nginx/ssl/dhparams.pem")
dhparams = base64.b64decode(result["content_base64"]).decode("utf-8")
```

## Common failures

- `RedactBypassBlocked` -- path matches `redact_paths_globs` and
  `redact_bypass_policy='block'`. Switch to `ssh_sudo_read_redacted`.
- `PathNotAllowed` -- path outside `path_allowlist`.
- `PathRestricted` -- path matched `restricted_paths` or `restricted_globs`.
- `SudoFileOpError: sudo cat exited N` -- sudo refused (wrong password,
  sudoers not configured, or the file truly doesn't exist as root either).
- `SudoFileOpError: N bytes exceeds cap` -- file over `SSH_UPLOAD_MAX_FILE_BYTES`.
- `PlatformNotSupported` -- Windows target.

## Operator setup

Sudo path tools use the same password-resolution chain as `ssh_sudo_exec`:

1. OS keyring: `service=ssh-mcp-sudo, user=<host alias>`
2. `SSH_SUDO_PASSWORD_CMD` (global subprocess command)
3. OS keyring: `service=ssh-mcp-sudo, user=default`
4. Passwordless sudoers (`sudo -n`) if none of the above produce a value

## Related

- [`ssh_sudo_read_redacted`](../ssh-sudo-read-redacted/SKILL.md) -- sudo read
  with HMAC-SHA256 secret redaction; the only sudo path exempt from
  `redact_bypass_policy=block`.
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- non-sudo equivalent
  for files the SSH user CAN reach.
- [`ssh_sudo_sftp_list`](../ssh-sudo-sftp-list/SKILL.md) -- list a
  root-owned directory before reading its contents.
- [`ssh_sudo_write`](../ssh-sudo-write/SKILL.md) -- write back a modified
  version of the file under sudo.
- [`ssh_sudo_edit`](../ssh-sudo-edit/SKILL.md) -- structured replace
  (read + edit + write in one call).
