---
description: Install one or more APT packages on a remote host
---

# `ssh_apt_install`

**Tier:** dangerous | **Group:** `pkg` | **Tags:** `{dangerous, group:pkg}`

Runs `apt-get -y install -- <packages...>` on the remote host. Requires
root: use a sudoers-enabled SSH account, or use `ssh_sudo_exec` if you
need an interactive sudo gate. Hidden unless `ALLOW_DANGEROUS_TOOLS=true`.

Pass `update_first=True` to run `apt-get update` immediately before the
install (recommended when you do not already know the apt caches are
fresh).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` or `SSH_HOSTS_ALLOWLIST` |
| `packages` | list[str] | yes | -- | One or more lowercase Debian package names; argv-validated |
| `update_first` | bool | no | False | Run `apt-get update` first |
| `timeout` | int | no | None | Per-call command timeout in seconds; defaults to `SSH_COMMAND_TIMEOUT` |

## Returns

```json
{
  "host": "web01",
  "action": "install",
  "packages": ["nginx", "curl"],
  "exit_code": 0,
  "stdout": "Reading package lists...\nBuilding dependency tree...\n...",
  "stderr": "",
  "duration_ms": 4321,
  "stdout_truncated": false,
  "output_warnings": []
}
```

Non-zero exit codes are data (not raised). `exit_code=100` typically
means the package list could not be parsed; `exit_code=1` often means
"nothing to do or a hold blocked the install" -- check `stderr`.

## When to call it

- Install a package (or several at once) you have confirmed exists in
  the host's apt caches via `ssh_apt_show`.
- Re-install / repair a package that is already present (apt's
  `install` is idempotent).
- Pair with `update_first=True` when you have not run
  `ssh_apt_install([], update_first=True)` or equivalent recently
  and the cache may be stale.

## When NOT to call it

- You want to upgrade everything -- use `ssh_apt_upgrade`.
- You want to remove packages -- use `ssh_apt_remove`.
- You want a major OS-version upgrade -- this is out of scope; use
  `ssh_exec_run("do-release-upgrade")` with explicit care.

## Examples

```python
# Install a single package
ssh_apt_install(host="web01", packages=["nginx"])

# Install several, refreshing the cache first
ssh_apt_install(
    host="web01",
    packages=["nginx", "curl", "vim"],
    update_first=True,
)

# Long install with a generous timeout
ssh_apt_install(host="web01", packages=["build-essential"], timeout=600)
```

## Validation

Every package name must match `^[a-z0-9][a-z0-9.+-]{0,127}$` (Debian
package-name shape, lowercase only). Names containing shell
metacharacters, uppercase, slashes, or starting with `-` are rejected
before any SSH I/O. The `--` separator before the package list further
protects against any name that somehow looks like a flag.

## Common failures

- Empty `packages=[]` -- raises `ValueError` immediately, no SSH call.
- `exit_code=100`, `stderr` says "Unable to fetch some archives" --
  cache is stale or repos unreachable; retry with `update_first=True`.
- `stderr` says "E: Could not get lock /var/lib/dpkg/lock-frontend" --
  another apt process is running; wait and retry.
- `stderr` says "Permission denied" / "must be run as root" -- the SSH
  user lacks root; use a sudoers account or `ssh_sudo_exec`.

## Related

- `ssh_apt_upgrade` -- upgrade all currently-installed packages
- `ssh_apt_remove` -- the inverse
- `ssh_apt_mark` -- hold a package at its current version
- `ssh_apt_show` -- pre-flight check of dependencies and candidate version
