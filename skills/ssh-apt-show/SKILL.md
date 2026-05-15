---
description: Show combined apt-cache show + policy details for one package
---

# `ssh_apt_show`

**Tier:** read-only | **Group:** `pkg` | **Tags:** `{safe, read, group:pkg}`

Runs both `apt-cache show <pkg>` and `apt-cache policy <pkg>` and merges
them into one result -- the LLM gets dependencies AND
installed/candidate versions AND repo sources in a single tool call.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `package` | str | yes | Debian package name; lowercase shape `^[a-z0-9][a-z0-9.+-]{0,127}$` |

## Returns

```json
{
  "host": "web01",
  "package": "nginx",
  "installed_version": "1.18.0-6ubuntu14.4",
  "candidate_version": "1.18.0-6ubuntu14.4",
  "repos": [
    "http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages",
    "http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages"
  ],
  "description": "small, powerful, scalable web/proxy server\nNginx is a fast and lightweight web server...",
  "depends": ["libc6 (>= 2.34)", "libssl3 (>= 3.0.0)"],
  "recommends": ["nginx-core"],
  "suggests": [],
  "conflicts": [],
  "breaks": [],
  "replaces": [],
  "output_warnings": []
}
```

Field provenance:

- `installed_version`, `candidate_version`, `repos` -> `apt-cache policy`
- `description`, `depends`, `recommends`, `suggests`, `conflicts`,
  `breaks`, `replaces` -> `apt-cache show`

All optional fields default to `None` / `[]` so a partial parse (package
absent from one of the two commands) still constructs cleanly.

## Examples

```python
# Full picture of nginx on web01
ssh_apt_show(host="web01", package="nginx")

# Confirm the candidate update version before scheduling an upgrade
ssh_apt_show(host="web01", package="openssl")
```

## When to call it

- Pre-upgrade audit: "what version is installed, what's the candidate,
  what does it depend on?"
- Diagnosing dependency conflicts: `depends` / `conflicts` / `breaks`
  give the full picture in one call.
- Confirming where a package comes from (`repos`) before trusting it
  -- security audit context.

## When NOT to call it

- Bulk surveys (multiple packages) -- use `ssh_apt_list` with a glob
  pattern; calling `ssh_apt_show` per package is N round-trips.
- You only need "is it installed?" -- `ssh_apt_list(mode="installed",
  pattern=name)` is one round-trip vs two.
- Searching by description -- use `ssh_apt_search`.

## Common failures

- `PlatformNotSupported`: no `apt` on the host. Probed before the call.
- `installed_version=null` AND `candidate_version=null`: apt knows
  nothing about the package (typo, or only available via a
  not-yet-added repo).
- `installed_version=null`, `candidate_version` set: package is known
  but not installed. Call `ssh_sudo_exec apt-get install <pkg>` (with
  the right gates) to install.
- Validation rejects names with uppercase, slashes, or shell metachars
  -- use the lowercase Debian shape.

## Related

- `ssh_apt_list` -- list packages by name with mode + glob
- `ssh_apt_search` -- find packages by description
