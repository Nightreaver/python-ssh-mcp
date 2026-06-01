---
description: Sudo-elevated file read with secret redaction; bypass-exempt path for root-owned .env and secrets
---

# `ssh_sudo_read_redacted`

**Tier:** sudo (also dangerous) | **Group:** `sudo` | **Tags:** `{dangerous, sudo, group:sudo}`

Sudo-elevated counterpart to `ssh_read_redacted`. Reads via `sudo cat`,
runs the bytes through the same secret-redactor, and returns a
`RedactedReadResult` with the file's structural view (keys, comments,
shape) and per-redaction HMAC-SHA256 hash markers.

This is the **bypass-exempt** path for `redact_paths_globs` under sudo:
where `ssh_sudo_read` raises `RedactBypassBlocked` for a path matching
`redact_paths_globs` and `redact_bypass_policy='block'`, this tool is
the operator-blessed alternative -- the redact-bypass gate does NOT fire
here. Hard-deny lists (`restricted_paths` / `restricted_globs`) still
apply unconditionally.

Requires **both** `ALLOW_DANGEROUS_TOOLS=true` AND `ALLOW_SUDO=true`.
**POSIX-only** -- Windows targets raise `PlatformNotSupported`.

## When to call it

- Reading a root-owned `.env`, secrets file, or credentials file that is
  on `redact_paths_globs` (so `ssh_sudo_read` raises `RedactBypassBlocked`).
- You want the file's structure and key names visible in the LLM context
  but NOT the plaintext secret values.
- Comparing secrets across hosts: same secret produces the same hash, so
  the LLM can confirm "DB_PASSWORD is the same on prod-a and prod-b"
  without seeing the value.
- Auditing which keys a privileged config file contains when the SSH user
  has no direct read access.

## When NOT to call it

- The file is NOT on `redact_paths_globs` and you need raw bytes -- use
  `ssh_sudo_read` instead (no redaction overhead).
- The file is binary (cert, private key) -- redaction runs UTF-8 parsers;
  binary files are decoded with `errors='replace'` and all high-entropy
  byte sequences will be replaced with hash markers, making the result
  unusable. Avoid on non-text files.
- The SSH user can already read the file -- use `ssh_read_redacted`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to the file. Resolved via `realpath` before policy checks. |
| `format` | str | no | None | One of `"env"` / `"yaml"` / `"json"` / `"ini"` / `"generic"`. Auto-detected from extension when `None`. |

## Returns

```json
{
  "host": "prod-db.internal",
  "path": "/docker/app/.env",
  "format_detected": "env",
  "size_original": 512,
  "content": "DB_HOST=db01.internal\nDB_PASSWORD=<sha:b99d339ec6ca len:15>\nAPI_KEY=<sha:4f2c1a9d87e3 len:32>\n",
  "redactions": [
    {"key": "DB_PASSWORD", "hash": "b99d339ec6ca", "line": 2, "kind": "key_match"},
    {"key": "API_KEY",     "hash": "4f2c1a9d87e3", "line": 3, "kind": "key_match"}
  ],
  "truncated": false,
  "output_warnings": []
}
```

Redaction markers use the form `<sha:HHHHHHHHHHHH len:NN>` where the hex
prefix is the first 12 chars of an HMAC-SHA256 hash (keyed on
`SSH_REDACT_SALT`). Without `SSH_REDACT_SALT`, the hash is plain SHA256
and an `output_warnings` entry reminds the operator to set the salt.

## Format auto-detection

When `format=None`, the path extension determines the parser:

| Extension | Parser |
|---|---|
| `.env`, no extension | `env` (`KEY=VALUE` per line) |
| `.yml`, `.yaml` | `yaml` (`key: value` per line) |
| `.json` | `json` (flat `"key": "value"` pairs) |
| `.ini`, `.cfg`, `.conf` | `ini` (`key = value` or `key: value`) |
| anything else | `generic` (tries env / yaml / json regexes, then entropy) |

## Three layers of detection (inherited from `ssh_read_redacted`)

1. **Key-match** -- case-insensitive substring on the KEY name against the
   resolved redact-key set. Built-in defaults: `PASSWORD`, `PASSWD`, `SECRET`,
   `TOKEN`, `KEY`, `PRIVATE`, `CREDENTIAL`, `API_KEY`, `APIKEY`, `DSN`,
   `AUTH`, `BEARER`, `COOKIE`, `SESSION`, `JWT`, `OAUTH`, `SSH_KEY`, plus
   anchored variants `^PASS_` and `_PASS$`.

2. **PEM blocks** -- `-----BEGIN ... -----END ...` blocks are always redacted,
   regardless of the entropy-detection toggle.

3. **Entropy detection** (default on, `SSH_REDACT_ENTROPY_DETECTION`) --
   high-entropy-shaped strings: base64-like (>= 20 chars) and hex (>= 32 chars)
   on non-comment lines. Catches secrets in compose files and scripts where
   the key name doesn't match the default list.

## Key-token anchor shapes

| Form | Example | Matches |
|---|---|---|
| Plain substring | `PASS` | Any KEY containing `PASS` anywhere |
| Prefix anchor | `^DB_` | KEYs starting with `DB_` |
| Suffix anchor | `_SECRET$` | KEYs ending with `_SECRET` |
| Exact anchor | `^MYVAR$` | Only the key named exactly `MYVAR` |

## Bypass-policy interaction

This tool is EXEMPT from `redact_paths_globs` bypass-block. It is the
operator-blessed way to read a redact-listed path under sudo. The call
routes through `resolve_path_for_redacted_read` which skips the bypass
gate but still enforces `restricted_paths` / `restricted_globs`.

A path on BOTH `restricted_*` AND `redact_paths_globs` stays hard-denied --
restriction wins over redact-exemption.

## Policy chain

1. `path_allowlist` -- `PathNotAllowed` if outside roots.
2. `restricted_paths` / `restricted_globs` -- `PathRestricted` if matched.
3. `redact_paths_globs` bypass gate -- SKIPPED (this tool is exempt).
4. sudo `cat` invocation.

## Size cap

`SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB). Cap enforced after the
`sudo cat` read completes in memory.

## Decision tree -- which sudo read tool

```
Path on restricted_paths / restricted_globs?
    YES -> hard-deny (no tool can read it)
    NO  -> Path on redact_paths_globs (e.g. **/.env)?
               YES -> ssh_sudo_read_redacted  (bypass-exempt; secrets hashed)
               NO  -> ssh_sudo_read           (raw bytes, base64)
```

## Examples

```python
# Read a root-owned .env file -- format auto-detected from extension.
result = ssh_sudo_read_redacted(host="prod-app", path="/docker/app/.env")
# result["content"]: "DB_HOST=db01\nDB_PASSWORD=<sha:b99d339ec6ca len:15>\n"
# result["redactions"]: [{"key": "DB_PASSWORD", "hash": "b99d339ec6ca", ...}]

# Compare DB_PASSWORD across two hosts without seeing the value.
r1 = ssh_sudo_read_redacted(host="prod-a", path="/docker/app/.env")
r2 = ssh_sudo_read_redacted(host="prod-b", path="/docker/app/.env")
# If r1["redactions"][0]["hash"] == r2["redactions"][0]["hash"] -> same secret.

# Explicitly specify YAML parser when the extension doesn't hint.
result = ssh_sudo_read_redacted(
    host="prod-app",
    path="/etc/app/config.production",
    format="yaml",
)
```

## Common failures

- `PathRestricted` -- path matched `restricted_paths` or `restricted_globs`.
  Unlike `ssh_sudo_read`, there is NO escape route for restricted paths.
- `PathNotAllowed` -- path outside `path_allowlist`.
- `SudoFileOpError: sudo cat exited N` -- sudo refused or file missing.
- `SudoFileOpError: N bytes exceeds cap` -- file over `SSH_UPLOAD_MAX_FILE_BYTES`.
- `output_warnings: ["SSH_REDACT_SALT is empty..."]` -- set
  `SSH_REDACT_SALT` (>= 32 random chars) to enable HMAC-SHA256 mode.
- `PlatformNotSupported` -- Windows target.

## Operator setup

```toml
# hosts.toml [defaults] -- enable block policy so other tools refuse .env reads
redact_paths_globs = ["**/.env", "**/.env.*", "**/secrets/*"]
redact_bypass_policy = "block"
```

```
# .env
SSH_REDACT_SALT=<random-32-char-string>   # strongly recommended
SSH_REDACT_ENTROPY_DETECTION=true
SSH_REDACT_HINT_CHARS=0                   # 1-4 leaks hint chars
SSH_REDACT_KEYS_ADD=MY_CUSTOM_TOKEN       # append to defaults
```

## Related

- [`ssh_read_redacted`](../ssh-read-redacted/SKILL.md) -- non-sudo equivalent;
  same redaction layers for files the SSH user CAN reach.
- [`ssh_sudo_read`](../ssh-sudo-read/SKILL.md) -- plain bytes (no redaction)
  for paths NOT on `redact_paths_globs`.
- [`hosts.toml.example`](../../hosts.toml.example) -- full reference for all
  7 redact knobs in the `[defaults]` block.
