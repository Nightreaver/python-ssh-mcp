---
description: Search APT package names and descriptions on a remote host
---

# `ssh_apt_search`

**Tier:** read-only | **Group:** `pkg` | **Tags:** `{safe, read, group:pkg}`

Runs `apt-cache search <pattern>` and returns name + short description for
every matching package. Unlike `ssh_apt_list`, this searches DESCRIPTIONS
too -- useful when you know what a tool does but not what it's called.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `pattern` | str | yes | Free-text query. Argv-validated; no shell metachars |

## Returns

```json
{
  "host": "web01",
  "pattern": "ssl",
  "results": [
    {"name": "openssl", "short_description": "Secure Sockets Layer toolkit - cryptographic utility"},
    {"name": "libssl3", "short_description": "Secure Sockets Layer toolkit - shared libraries"}
  ],
  "output_warnings": []
}
```

`output_warnings` (INC-057) is non-empty when the sanitizer flagged
suspicious patterns in `short_description`. Package descriptions are
free-form upstream-controlled text, so an upstream packaging mistake
(or a hostile third-party repo) can land odd characters here -- treat
descriptions with extra suspicion when this list is non-empty.

## Examples

```python
# Find all backup tools
ssh_apt_search(host="web01", pattern="backup")

# Find packages mentioning rate-limiting in their description
ssh_apt_search(host="web01", pattern="rate-limit")
```

## When to call it

- Discovery: "what's the canonical apt package for X?" when X is a
  capability rather than a name.
- Finding a tool you only know by its function ("there must be a thing
  that does live disk imaging").

## When NOT to call it

- You already know the package name -- `ssh_apt_list` (mode=installed)
  or `ssh_apt_show` is faster and answers a tighter question.
- You want detailed info about ONE package -- use `ssh_apt_show`.
- You want only installed packages -- search results include uninstalled
  ones too. Filter via `ssh_apt_list(mode="installed", pattern=name)`
  on the names you find.

## Common failures

- `PlatformNotSupported`: no `apt` on the host (non-Debian distro or
  Windows). Probed via `command -v apt` before the call.
- Empty `results`: pattern matched no package names or descriptions.
- Very broad patterns (e.g. `pattern="library"`) return hundreds of
  hits -- the stdout cap may trim. Tighten the pattern.

## Related

- `ssh_apt_list` -- list packages by name, with optional glob
- `ssh_apt_show` -- combined `show + policy` for one package
