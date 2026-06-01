---
description: Return MCP server identity (name + version) + capability surface (enabled tiers + groups + total tools). Fallback for the mcp://ssh-mcp/server-info resource on clients that don't surface resources to the LLM.
---

# `ssh_server_info`

**Tier:** safe / read | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Return identifying + capability info about the running MCP server:

- `name` -- always `"ssh-mcp"`.
- `version` -- the running server's SemVer (`MAJOR.MINOR.PATCH`). Sourced from `settings.VERSION`, which lives in [src/ssh_mcp/config.py](src/ssh_mcp/config.py).
- `total_tools` -- count of tools the LLM sees in `tools/list` AFTER the operator's tier + group filters have been applied. Equal to the registered catalog when no filters are configured.
- `enabled_tiers` -- which `ALLOW_*` flags are on. `"read"` is always present; `"low-access"` / `"dangerous"` / `"sudo"` appear when the matching env flag is set.
- `enabled_groups` -- the operator's `SSH_ENABLED_GROUPS` filter, verbatim. Empty list means "no filter -- all 10 groups visible" (the default). The field reports the raw setting so the LLM can distinguish "no filter configured" from "filter explicitly empty".

## Why a tool AND a resource?

Same payload is exposed two ways:

- **MCP resource** at `mcp://ssh-mcp/server-info` (primary). Resources are the semantically correct MCP surface for "what is this server?" -- they're cache-friendly, don't cost a tool slot per turn, and are the cleanest fit for static-ish metadata. But: not all MCP clients surface `resources/list` to the LLM. Claude Code and Claude Desktop hide them; Cursor exposes them.
- **`ssh_server_info` tool** (fallback). For clients where the LLM cannot see resources, the tool is the only LLM-reachable way to read the server version. Same JSON shape as the resource body; pick whichever your client surfaces.

If you have a choice, prefer the resource: it doesn't cost catalog tokens per turn.

## When to call it

- The operator (or the LLM in self-aware reasoning) asks "what version is this server?" / "do I have feature X?".
- Capability-gated logic: "if `version >= 1.12.0` then `ssh_read_redacted` is available". (Note: checking `tools/list` directly for the tool name is equivalent and cheaper.)
- Cross-fleet inventory / asset-tracking: which MCP server instances are on which version.
- Debugging client-server mismatch: when an MCP client claims a tool is missing, check whether the server version actually shipped that tool.

## When NOT to call it

- You only need the version once per session AND your client surfaces resources -- read the resource instead.
- Inside a tight tool-call loop. Server identity does not change between calls; cache the result.

## Inputs

None. The tool takes no arguments beyond the standard `ctx` parameter that FastMCP injects (and which the body explicitly ignores -- the payload comes from process-level settings).

## Returns

```json
{
  "name": "ssh-mcp",
  "version": "1.14.0",
  "total_tools": 100,
  "enabled_tiers": ["read", "low-access", "dangerous", "sudo"],
  "enabled_groups": []
}
```

Field-by-field above; `enabled_groups: []` means no `SSH_ENABLED_GROUPS` filter is configured (all 10 groups visible).

## Common failures

None expected. The tool reads process-level state and never touches SSH; the only realistic failure mode is a misconfigured FastMCP server, which would surface as a registration error at startup, not at call time.

## Related

- The MCP resource `mcp://ssh-mcp/server-info` -- same payload, primary surface, free per turn.
- [`ssh_host_list`](../ssh-host-list/SKILL.md) -- companion discovery call; returns the host registry rather than server metadata.
- [`ssh_host_ping`](../ssh-host-ping/SKILL.md) -- per-host probe; auto-injects per-host notes (operator + agent layers).
