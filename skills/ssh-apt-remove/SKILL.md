---
description: Remove (or purge) one or more APT packages on a remote host
---

# `ssh_apt_remove`

**Tier:** dangerous | **Group:** `pkg` | **Tags:** `{dangerous, group:pkg}`

Runs `apt-get -y remove -- <packages...>` on the remote host, or
`apt-get -y purge -- <packages...>` when `purge=True`. Requires root:
use a sudoers-enabled SSH account, or use `ssh_sudo_exec`. Hidden
unless `ALLOW_DANGEROUS_TOOLS=true`.

`remove` deletes the package binaries but leaves config files behind.
`purge` removes the config files too -- stronger, irreversible without
a backup. Pick `purge` when you want a clean slate; pick `remove` when
you may want to reinstall and keep tweaks intact.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `packages` | list[str] | yes | -- | One or more lowercase Debian package names; argv-validated |
| `purge` | bool | no | False | Also remove the package's config files |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

```json
{
  "host": "web01",
  "action": "remove",
  "packages": ["nginx"],
  "exit_code": 0,
  "stdout": "Reading package lists...\n...",
  "stderr": "",
  "duration_ms": 2134,
  "stdout_truncated": false,
  "output_warnings": []
}
```

`action` is `"remove"` or `"purge"` depending on the `purge` flag, so
audit consumers can tell which actually ran.

## When to call it

- Remove a package no longer needed; leftover config might be useful
  for a future reinstall -- use `purge=False`.
- Fully decommission a package, including config under `/etc/<pkg>/`,
  ahead of a clean reinstall -- use `purge=True`.

## When NOT to call it

- You want to also drop unused dependencies -- chase this call with
  `ssh_apt_autoremove`.
- You want to keep the package but stop it -- use `ssh_systemctl_stop`
  / `ssh_systemctl_disable` instead.
- Removing a package other still-running services depend on -- check
  with `ssh_apt_show` first.

## Examples

```python
# Remove nginx but keep its config files
ssh_apt_remove(host="web01", packages=["nginx"])

# Fully purge nginx and all its config
ssh_apt_remove(host="web01", packages=["nginx"], purge=True)

# Remove several at once
ssh_apt_remove(host="web01", packages=["apache2", "libapache2-mod-php"])
```

## Validation

Every package name must match `^[a-z0-9][a-z0-9.+-]{0,127}$` (Debian
package-name shape, lowercase only). Empty `packages=[]` is rejected
before any SSH I/O. The `--` separator before the package list
neutralises any would-be flag-shaped name.

## Common failures

- Empty `packages=[]` -- raises `ValueError`, no SSH call.
- `exit_code=1`, "Package ... is not installed" -- the package was not
  installed; safe to ignore in idempotent flows.
- `stderr` reports dependency conflicts -- `apt-get -y remove` will
  cascade the removal to anything that depends on the target; if that
  cascade is too broad, abort and re-plan.

## Related

- `ssh_apt_install` -- the inverse
- `ssh_apt_autoremove` -- clean up orphan deps after a removal
- `ssh_apt_show` -- check `depends` / `recommends` before removing
- `ssh_systemctl_stop` / `_disable` -- often cleaner than removing
