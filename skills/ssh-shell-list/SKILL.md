---
description: List open persistent shell sessions with cwd and idle age
---

# `ssh_shell_list`

**Tier:** read-only | **Group:** `shell` | **Tags:** `{safe, read, group:shell}`

Enumerate shell sessions currently tracked in the registry. Distinct from
`ssh_session_list` / `ssh_session_stats` which report the SSH **connection
pool** state -- this reports logical session state (cwd, idle time).

## Inputs

None.

## Returns

```json
{
  "sessions": [
    {"id": "a3f1b2c9d4e50678", "host": "web01", "cwd": "/var/log/nginx",
     "idle_seconds": 42, "age_seconds": 310}
  ],
  "count": 1
}
```

## When to call it

- Audit: which sessions did this workflow leave open?
- Before `ssh_shell_close` when you don't remember the id.
- Lifecycle checks before an MCP restart.

## When NOT to call it

- You want SSH connection pool state -- use `ssh_session_list`.

## Example

```python
ssh_shell_list()
```

## Related

- [`ssh_shell_open`](../ssh-shell-open/SKILL.md)
- [`ssh_shell_close`](../ssh-shell-close/SKILL.md)
- [`ssh_session_list`](../ssh-session-list/SKILL.md) -- pool inspection, different thing
