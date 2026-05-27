---
description: Remove orphan APT packages (deps no longer needed)
---

# `ssh_apt_autoremove`

**Tier:** dangerous | **Group:** `pkg` | **Tags:** `{dangerous, group:pkg}`

Runs `apt-get -y autoremove` on the remote host. Requires root: use a
sudoers-enabled SSH account, or use `ssh_sudo_exec`. Hidden unless
`ALLOW_DANGEROUS_TOOLS=true`.

Removes packages that were installed automatically as dependencies for
some other package, where nothing currently installed still requires
them. Typically follows a manual `ssh_apt_remove` to clean up the deps
that came along with the package you just removed.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `timeout` | int | no | None | Per-call command timeout |

## Returns

```json
{
  "host": "web01",
  "action": "autoremove",
  "packages": [],
  "exit_code": 0,
  "stdout": "Reading package lists...\n...\nThe following packages will be REMOVED:\n  libxxx libyyy\n...",
  "stderr": "",
  "duration_ms": 1842,
  "stdout_truncated": false,
  "output_warnings": []
}
```

`packages` is always `[]` -- autoremove takes no package argument. The
list of packages apt actually removed is in `stdout` (under "The
following packages will be REMOVED:").

## When to call it

- After `ssh_apt_remove` to clean up orphan dependencies.
- Periodic cleanup of a server that has been through many install /
  remove cycles.

## When NOT to call it

- You are not certain whether automatic-marker tracking is intact --
  packages incorrectly marked automatic can disappear here. Inspect
  `stdout` after the call to see what was removed.
- You want to remove a specific package -- use `ssh_apt_remove`.

## Examples

```python
# Routine cleanup
ssh_apt_autoremove(host="web01")
```

## Validation

No user-supplied input beyond `host` and `timeout`. Argv is fixed
(`["apt-get", "-y", "autoremove"]`) so there is no injection surface.

## Common failures

- `exit_code=0` and stdout shows "0 to remove" -- nothing was orphaned;
  no-op.
- An autoremove sweeps a package you wanted to keep -- restore with
  `ssh_apt_install(host=..., packages=[that_pkg])`, then optionally
  `ssh_apt_mark(action="hold", packages=[that_pkg])`.

## Related

- `ssh_apt_remove` -- the call that usually precedes this one
- `ssh_apt_mark` -- pin a package so a future autoremove leaves it
- `ssh_apt_list` -- inspect installed packages before / after
