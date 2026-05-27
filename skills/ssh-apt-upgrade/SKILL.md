---
description: Upgrade all installed APT packages on a remote host
---

# `ssh_apt_upgrade`

**Tier:** dangerous | **Group:** `pkg` | **Tags:** `{dangerous, group:pkg}`

Runs `apt-get -y upgrade` on the remote host. Requires root: use a
sudoers-enabled SSH account, or use `ssh_sudo_exec` if you need an
interactive sudo gate. Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Upgrades every installed package whose `candidate_version` is higher
than its `installed_version`, subject to held packages and dependency
constraints. Does NOT remove or install packages -- if a needed upgrade
requires that, `apt-get` will skip it (you will see "kept back" in
stderr).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `timeout` | int | no | None | Per-call command timeout in seconds; defaults to `SSH_COMMAND_TIMEOUT`. Upgrades can be long -- raise this. |

## Returns

```json
{
  "host": "web01",
  "action": "upgrade",
  "packages": [],
  "exit_code": 0,
  "stdout": "Reading package lists...\n...",
  "stderr": "",
  "duration_ms": 18342,
  "stdout_truncated": false,
  "output_warnings": []
}
```

`packages` is always `[]` -- this tool takes no package argument; the
field is on the shared result model for consistency with the targeted
mutations.

## When to call it

- Scheduled patch window where you want the standard "upgrade what is
  upgradable" behaviour.
- After `ssh_apt_install([], update_first=True)` confirms the caches
  are fresh and `ssh_apt_list(mode="upgradable")` shows a sane set.

## When NOT to call it

- You want a major OS version upgrade (Ubuntu 22 -> 24, Debian 11 ->
  12). `ssh_apt_upgrade` will NOT do that. Out of scope here -- use
  `ssh_exec_run("do-release-upgrade")` with care, after taking a
  snapshot. This tool is intentionally not wrapped because its prompts
  and behaviour vary too much by distro version to model cleanly.
- You have not run `apt-get update` recently -- the upgrade will use
  stale candidates. Refresh first via `ssh_apt_install([], update_first=True)`
  or `ssh_exec_run("apt-get update")`.
- You want to upgrade just one package -- pass it to `ssh_apt_install`
  (apt's `install` upgrades to the candidate version when the package
  is already present).

## Examples

```python
# Standard patch window
ssh_apt_upgrade(host="web01", timeout=900)
```

## Validation

No user-supplied input beyond `host` and `timeout`. Argv is fixed
(`["apt-get", "-y", "upgrade"]`) so there is no injection surface.

## Common failures

- `exit_code=100`, "Unable to fetch some archives" -- repos unreachable
  or caches stale; refresh first.
- `stderr` lists "The following packages have been kept back" --
  upgrades that need new deps or removals; resolve manually with
  `ssh_apt_install` or `apt-get dist-upgrade` via `ssh_exec_run`.
- Times out on a slow link or huge upgrade set -- raise `timeout`.

## Related

- `ssh_apt_install` -- install or refresh specific packages
- `ssh_apt_list` with `mode="upgradable"` -- preview what would be touched
- `ssh_apt_autoremove` -- clean up orphan deps after an upgrade
- `ssh_apt_mark` -- pin a package before upgrading the rest
