---
description: Pool summary -- open count and per-key idle time
---

# `ssh_session_stats`

**Tier:** read-only | **Group:** `session` | **Tags:** `{safe, read, group:session}`

Aggregate pool stats. Functionally a superset of `ssh_session_list` -- exposes
the open count alongside the per-entry detail.

## Inputs

None.

## Returns

```json
{
  "open": 3,
  "entries": [
    {"user": "deploy", "host": "web01.example.com", "port": 22, "idle_seconds": 12},
    {"user": "dbadmin", "host": "db01.internal", "port": 22, "idle_seconds": 84}
  ]
}
```

## When to call it

- Quick "how many sessions are open right now?" before a long workflow.
- Pool tuning -- repeated short idle times suggest the reaper interval is too aggressive.

## When NOT to call it

- For per-call observability -- use the audit log (`ssh_mcp.audit`) or OTel spans instead.

## Example

```python
ssh_session_stats()
# -> {"open": 3, "entries": [...]}
```

## Related

- [`ssh_session_list`](../ssh-session-list/SKILL.md) -- same data, verb-list framing.
