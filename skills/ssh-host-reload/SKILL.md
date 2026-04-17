---
description: Re-read hosts.toml and hot-reload the in-memory host registry
---

# `ssh_host_reload`

**Tier:** low-access | **Group:** `host` | **Tags:** `{low-access, group:host}`

**Gate:** `ALLOW_LOW_ACCESS_TOOLS=true`

Re-reads `SSH_HOSTS_FILE` from disk, validates it with Pydantic, and swaps the
in-memory host registry atomically. Returns a diff of added, removed, and
changed aliases vs the previous load.

If parsing or validation fails the existing fleet is left intact and an error
is raised -- the running server stays on the last known-good config.

**Note:** Live pooled SSH connections are NOT invalidated. They retain their
original policy until they time out or fail keepalive. For immediate policy
enforcement, restart the MCP server.

## Inputs

None beyond `ctx`.

## Returns

`HostReloadResult`:

| field | type | notes |
|---|---|---|
| `loaded` | int | Total hosts now in memory |
| `source` | str | Absolute path that was read, or `"<none>"` |
| `added` | list[str] | Aliases new in this load |
| `removed` | list[str] | Aliases dropped in this load |
| `changed` | list[str] | Aliases whose policy content changed |

## When to call it

- After editing `hosts.toml` without restarting the server.
- To verify a config change was picked up correctly.

## When NOT to call it

- For immediate SSH-level policy enforcement on live connections -- restart the
  server instead.

## Example

```python
ssh_host_reload()
```

## Related

- [`ssh_host_list`](../ssh-host-list/SKILL.md)
