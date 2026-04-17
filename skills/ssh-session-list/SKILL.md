---
description: List the MCP server's open pooled SSH connections
---

# `ssh_session_list`

**Tier:** read-only | **Group:** `session` | **Tags:** `{safe, read, group:session}`

Returns every open connection the MCP server is currently holding in its pool.
Useful for understanding which hosts the server has seen recently and how
long those connections have been idle.

## Inputs

None.

## Returns

```json
{
  "sessions": [
    {"user": "deploy", "host": "web01.example.com", "port": 22, "idle_seconds": 42}
  ],
  "count": 1
}
```

`idle_seconds` is wall-clock seconds since the connection was last used. The
reaper closes entries past `SSH_IDLE_TIMEOUT` (default 300s).

## When to call it

- Diagnose "why is this call slow?" -- check if the connection was reaped and is reopening.
- Before a restart -- see which targets would be disrupted.
- Resource audit.

## When NOT to call it

- To see *remote* sessions -- this is the MCP server's local pool, not `who` on the host.

## Example

```python
ssh_session_list()
# -> {"sessions": [{"host": "web01", "idle_seconds": 12, ...}], "count": 1}
```

## Common failures

None specific to this tool. Returns empty if no connections are open.

## Related

- [`ssh_session_stats`](../ssh-session-stats/SKILL.md) -- same data, aggregate count first.
