---
description: Hold or unhold APT packages on a remote host (pin / unpin)
---

# `ssh_apt_mark`

**Tier:** dangerous | **Group:** `pkg` | **Tags:** `{dangerous, group:pkg}`

Runs `apt-mark hold|unhold -- <packages...>` on the remote host. Requires
root. Hidden unless `ALLOW_DANGEROUS_TOOLS=true`. For the read-only
`showhold` variant use the sibling tool [`ssh_apt_show_holds`](../ssh-apt-show-holds/SKILL.md).

- `hold`: pin packages at their current version so future upgrades skip
  them.
- `unhold`: undo a previous hold.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `action` | `"hold" \| "unhold"` | yes | -- | Mutation verb |
| `packages` | list[str] | yes | -- | Non-empty; one Debian package name per entry |
| `timeout` | int | no | None | Per-call command timeout |

## Returns -- `AptMutationResult`

```json
{
  "host": "web01",
  "action": "hold",
  "packages": ["nginx"],
  "exit_code": 0,
  "stdout": "nginx set on hold.\n",
  "stderr": "",
  "duration_ms": 187,
  "stdout_truncated": false,
  "output_warnings": []
}
```

## When to call it

- `hold`: keep a package frozen across `ssh_apt_upgrade` sweeps --
  pinning a kernel or a vendor-specific build.
- `unhold`: ready a previously-held package for the next upgrade.

To inventory currently-held packages, call [`ssh_apt_show_holds`](../ssh-apt-show-holds/SKILL.md)
instead -- separate read-tier tool, no root required.

## When NOT to call it

- You want to remove a package entirely -- use `ssh_apt_remove`.
- You want to downgrade or jump to a specific version -- `apt-mark`
  pins to whatever is currently installed; use `ssh_apt_install` with
  an explicit version specifier (or `ssh_exec_run`) for surgical
  version control.

## Examples

```python
# Pin nginx at its current version
ssh_apt_mark(host="web01", action="hold", packages=["nginx"])

# Release the pin
ssh_apt_mark(host="web01", action="unhold", packages=["nginx"])
```

## Validation

`action` is constrained at the FastMCP layer to `hold` | `unhold`.
`packages` MUST be non-empty -- raises `ValueError` before any SSH I/O.
Each name is validated against the Debian package-name shape
`^[a-z0-9][a-z0-9.+-]{0,127}$`.

## Common failures

- Empty `packages` -- `ValueError`, no SSH call.
- `hold` succeeds but `ssh_apt_upgrade` still upgrades the package --
  another tool (Salt, Ansible, snapd) may also be touching apt's hold
  state; check with `ssh_apt_show_holds`.

## Related

- [`ssh_apt_show_holds`](../ssh-apt-show-holds/SKILL.md) -- read-only counterpart
- `ssh_apt_install` -- can override a hold with `--force` (not exposed)
- `ssh_apt_upgrade` -- the operation that respects holds
- `ssh_apt_list` with `mode="upgradable"` -- preview what is held back
