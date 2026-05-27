---
description: List APT packages currently held (pinned) on a remote host
---

# `ssh_apt_show_holds`

**Tier:** safe / read | **Group:** `pkg` | **Tags:** `{safe, read, group:pkg}`

Runs `apt-mark showhold` on the remote host and returns the parsed list
of held packages. Read-only -- no root required, no `ALLOW_DANGEROUS_TOOLS`
gate. Sibling of [`ssh_apt_mark`](../ssh-apt-mark/SKILL.md), which performs
the mutation (`hold` / `unhold`).

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `timeout` | int | no | None | Per-call command timeout |

No `packages` argument -- the call is global to the host.

## Returns -- `AptHoldsResult`

```json
{
  "host": "web01",
  "held": ["nginx", "linux-image-generic"],
  "stdout": "nginx\nlinux-image-generic\n",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 124,
  "stdout_truncated": false,
  "output_warnings": []
}
```

`held` is parsed from stdout: one package per line, whitespace stripped,
empty lines dropped. The raw `stdout` is preserved for debugging.

## When to call it

- Audit which packages a host has pinned before / after maintenance.
- Confirm a `ssh_apt_mark(action="hold", ...)` call landed.
- Diagnose "apt-get upgrade didn't upgrade X" -- if X is in `held`, that
  is why.

## Examples

```python
# What is currently held?
result = ssh_apt_show_holds(host="web01")
if "nginx" in result["held"]:
    ...
```

## Common failures

- apt not installed -- `PlatformNotSupported` (non-Debian-family distro).
- Empty output -- `held=[]` (no pins; not an error).

## Related

- [`ssh_apt_mark`](../ssh-apt-mark/SKILL.md) -- the mutation counterpart
- `ssh_apt_list` with `mode="upgradable"` -- shows packages held back
  alongside other upgrade state
