---
description: Read a remote config file with secret values replaced by deterministic HMAC-SHA256 hash markers
---

# `ssh_read_redacted`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Read a remote `.env` / `.yml` / `.json` / `.ini` / generic config file and
pass it through the secret-redactor before delivering to the LLM. Every
detected secret value is replaced inline with a deterministic
`<sha:abcdef123456 len:48>` marker.

The LLM gets the full file structure (keys, comments, shape) but never sees
plaintext secrets. Same secret on two hosts produces the same hash, so the
LLM can compare e.g. `DB_PASSWORD` across a fleet without seeing the value.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `path` | str | yes | -- | Absolute path to a regular file on the remote host |
| `format` | str | no | None | One of `"env"` / `"yaml"` / `"json"` / `"ini"` / `"generic"`. Auto-detected from extension when omitted. |

## Returns

```json
{
  "host": "prod-app.internal",
  "path": "/opt/app/.env",
  "format_detected": "env",
  "size_original": 1024,
  "content": "DB_HOST=db01.internal\nDB_PASSWORD=<sha:b99d339ec6ca len:15>\nAPI_KEY=<sha:4f2c1a9d87e3 len:32>\n",
  "redactions": [
    {"key": "DB_PASSWORD", "hash": "b99d339ec6ca", "line": 2, "kind": "key_match"},
    {"key": "API_KEY",     "hash": "4f2c1a9d87e3", "line": 3, "kind": "key_match"}
  ],
  "truncated": false
}
```

`content` is the file text with secrets replaced. `redactions` is a
structured list of every substitution made, mirroring the inline markers
exactly. `format_detected` names the parser that ran.

## Format auto-detection

When `format=None`, the path extension determines the parser:

| Extension | Parser |
|---|---|
| `.env`, no extension | `env` (`KEY=VALUE` per line) |
| `.yml`, `.yaml` | `yaml` (`key: value` per line) |
| `.json` | `json` (flat `"key": "value"` pairs) |
| `.ini`, `.cfg`, `.conf` | `ini` (`key = value` or `key: value`) |
| anything else | `generic` (tries env, yaml, json regexes, then entropy) |

## Three layers of detection

1. **Key-match** -- case-insensitive substring on the KEY name against the
   resolved redact-key set. Defaults include: `PASSWORD`, `PASSWD`, `SECRET`,
   `TOKEN`, `KEY`, `PRIVATE`, `CREDENTIAL`, `API_KEY`, `APIKEY`, `DSN`,
   `AUTH`, `BEARER`, `COOKIE`, `SESSION`, `JWT`, `OAUTH`, `SSH_KEY`, plus
   anchored PASS variants (`^PASS_`, `_PASS$`).

2. **PEM blocks** -- `-----BEGIN ... -----END ...` blocks are always redacted,
   regardless of the entropy-detection toggle. Private keys / certificates are
   unambiguous.

3. **Entropy detection** (default on, `SSH_REDACT_ENTROPY_DETECTION`) --
   high-entropy-shaped strings on non-comment lines: base64-like (>= 20 chars)
   and hex strings (>= 32 chars). Catches secrets in scripts and docker
   compose files where the key name doesn't match the default list.

## Key-token anchor shapes

The four anchor forms for redact-key tokens in `redact_keys_add` /
`redact_keys_replace`:

| Form | Example | Matches |
|---|---|---|
| Plain substring | `PASS` | Any KEY containing `PASS` anywhere |
| Prefix anchor | `^DB_` | KEYs starting with `DB_` |
| Suffix anchor | `_SECRET$` | KEYs ending with `_SECRET` |
| Exact anchor | `^MYVAR$` | Only the key named exactly `MYVAR` |

The built-in list uses `^PASS_` and `_PASS$` rather than bare `PASS` to
avoid over-matching `BYPASS_*`, `COMPASS_*`, etc.

## Bypass-policy interaction

This tool is EXEMPT from `redact_bypass_policy=block`. It is the
operator-blessed way to read a path that is on `redact_paths_globs`. Other
raw-content tools (`ssh_sftp_download`, listing tools) trip the bypass
policy when they hit a redact-listed path.

`restricted_paths` and `restricted_globs` still apply -- those are hard-deny
independent of the redact list. A path on both lists stays hard-denied.

## Operator setup

Minimal: no config needed. The redactor runs with built-in defaults. For
production:

```toml
# hosts.toml [defaults]
redact_paths_globs = ["**/.env", "**/.env.*", "**/secrets/*"]
redact_bypass_policy = "block"   # block raw-content tools on these paths
```

```
# .env
SSH_REDACT_SALT=<random-32-char-string>        # strongly recommended
SSH_REDACT_PATHS_GLOBS=**/.env,**/.env.*       # CSV or JSON
SSH_REDACT_BYPASS_POLICY=block
SSH_REDACT_ENTROPY_DETECTION=true
SSH_REDACT_HINT_CHARS=0                        # set 1-4 to leak hint chars
SSH_REDACT_KEYS_ADD=MY_CUSTOM_TOKEN,^INTERNAL_ # append to defaults
```

Set `SSH_REDACT_SALT` to a randomly generated value (>= 32 chars). Without
it the HMAC uses an empty salt, making the hash independent of deployment --
fine for comparing across hosts but weaker as a privacy layer if an attacker
can observe multiple hashes.

## Examples

```python
# Read an .env file -- format auto-detected from extension.
result = ssh_read_redacted(host="prod-app", path="/opt/app/.env")
# result.content: "DB_HOST=db01\nDB_PASSWORD=<sha:b99d339ec6ca len:15>\n"
# result.redactions: [{"key": "DB_PASSWORD", "hash": "b99d339ec6ca", ...}]

# Explicitly specify YAML parser for an unusual extension.
result = ssh_read_redacted(
    host="prod-app",
    path="/opt/app/config.yaml.production",
    format="yaml",
)

# Compare DB_PASSWORD across two hosts: same hash = same secret.
r1 = ssh_read_redacted(host="prod-web", path="/opt/app/.env")
r2 = ssh_read_redacted(host="prod-db",  path="/opt/app/.env")
# If r1.redactions[0]["hash"] == r2.redactions[0]["hash"] -> same value.
```

## Known limits

- YAML multi-line block scalars (`|` / `>`) are NOT parsed -- they pass
  through unchanged.
- JSON nested arrays / objects are NOT recursed; only flat `"key": "value"`
  pairs on a single line are matched.
- `ssh_exec_run cat /opt/.env` returns plaintext regardless of redact policy.
  The realistic mitigation against raw-exec bypass is to NOT allowlist
  `cat` / `less` / `head` / `tail` in `command_allowlist`. See INC-064.
- `generic` format falls back through all parsers in order; false-positive
  rate is higher than a format-specific parser on ambiguous input.

## Related

- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- raw download;
  raises `RedactBypassBlocked` (or warns) when the path matches
  `redact_paths_globs` and the bypass policy is not `audit_only`.
- [`ssh_sftp_list`](../ssh-sftp-list/SKILL.md) -- directory listing; also
  subject to `redact_bypass_policy` when listing paths inside
  `redact_paths_globs`.
- [`ssh_sudo_read_redacted`](../ssh-sudo-read-redacted/SKILL.md) -- same
  flow under sudo, for root-owned secrets files the SSH user cannot read
  directly.
- [`hosts.toml.example`](../../hosts.toml.example) -- full reference for all
  7 redact knobs in the `[defaults]` block.
