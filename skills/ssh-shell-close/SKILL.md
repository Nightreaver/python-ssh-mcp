---
description: Close a persistent shell session (drops server-side state)
---

# `ssh_shell_close`

**Tier:** low-access | **Group:** `shell` | **Tags:** `{low-access, group:shell}`

Drop the session from the registry. No-op if the id is already gone --
returns `closed: false` in that case, no error. Underlying SSH connections
in the pool are unaffected; this only clears the session bookkeeping
(cwd, idle timestamps).

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `session_id` | str | yes | From `ssh_shell_open` |

## Returns

```json
{"session_id": "a3f1b2c9...", "closed": true}
```

## When to call it

- Workflow complete; don't leak session state.
- Confirm cleanup in an audit trail.

## When NOT to call it

- You've forgotten which sessions are open -- use `ssh_shell_list` first.
- Server restart -- all sessions are gone already; this call is a no-op.

## Example

```python
ssh_shell_close(session_id="a3f1b2c9d4e50678")
```

## Related

- [`ssh_shell_open`](../ssh-shell-open/SKILL.md)
- [`ssh_shell_list`](../ssh-shell-list/SKILL.md)
