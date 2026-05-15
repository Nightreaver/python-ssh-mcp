---
description: List APT packages on a remote host, filtered by mode and optional pattern
---

# `ssh_apt_list`

**Tier:** read-only | **Group:** `pkg` | **Tags:** `{safe, read, group:pkg}`

Runs `apt list <flag> [-- <pattern>]` and returns parsed package rows. Use
`mode="installed"` to answer "is X installed?", `mode="upgradable"` for the
pending-upgrade survey, or `mode="all"` to see every package known to apt's
caches (large -- always pair with a `pattern`).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `mode` | `"installed" \| "upgradable" \| "all"` | yes | -- | Required; maps to apt's `--installed` / `--upgradable` / no flag |
| `pattern` | str | no | `None` | Glob filter, e.g. `nginx*`. Argv-validated, no shell metachars |

## Returns

```json
{
  "host": "web01",
  "mode": "installed",
  "packages": [
    {
      "name": "nginx",
      "version": "1.18.0-6ubuntu14.4",
      "architecture": "amd64",
      "state": "installed"
    }
  ],
  "total": 1,
  "truncated": false,
  "output_warnings": []
}
```

`state` is the bracketed token apt prints after the version (e.g.
`"installed"`, `"installed,automatic"`, `"upgradable"`). Empty string when
the bracket is absent.

## Examples

```python
# Is nginx installed?
ssh_apt_list(host="web01", mode="installed", pattern="nginx")

# What needs upgrading?
ssh_apt_list(host="web01", mode="upgradable")

# Find every libssl* available in the caches
ssh_apt_list(host="web01", mode="all", pattern="libssl*")
```

## When to call it

- Quick "is X installed?" / "what version is on this box?" answers.
- Upgrade-pending survey before deciding whether a host needs maintenance.
- Discovery: scoping which versions of a family (e.g. `python3*`) the host has.

## When NOT to call it

- Searching by description (e.g. "give me all backup-related tools") --
  use `ssh_apt_search`, which searches descriptions too.
- Inspecting one specific package in depth (deps, repos, candidate
  version) -- use `ssh_apt_show` for the merged view.
- Mutations (install / upgrade / remove) -- use `ssh_sudo_exec apt-get ...`
  with `ALLOW_SUDO=true` + `ALLOW_DANGEROUS_TOOLS=true`.

## Common failures

- `PlatformNotSupported`: the host has no `apt` (non-Debian distro, or
  Windows). Probed via `command -v apt` before the actual call.
- `truncated=true`: `apt list --installed` on a desktop can run to ~10k
  rows; output capped at `SSH_STDOUT_CAP_BYTES` (default 1 MiB). Narrow
  with a `pattern`.
- Empty `packages` list with `total=0`: no rows matched the filter.
  For `mode="upgradable"` that is good news (nothing pending).

## Related

- `ssh_apt_search` -- search package descriptions, not just names
- `ssh_apt_show` -- combined `show + policy` for one package
- `ssh_systemctl_*` -- service-level introspection once you've confirmed
  the package is installed
