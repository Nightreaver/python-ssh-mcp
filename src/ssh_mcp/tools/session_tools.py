"""Session / pool inspection. All tagged {"safe", "read", "group:session"}."""
from __future__ import annotations

from typing import Any

from fastmcp import Context

from ..app import mcp_server
from ._context import pool_from


@mcp_server.tool(tags={"safe", "read", "group:session"}, version="1.0")
async def ssh_session_list(ctx: Context) -> dict[str, Any]:
    """List open pooled SSH connections."""
    pool = pool_from(ctx)
    return {"sessions": pool.stats(), "count": pool.size()}


@mcp_server.tool(tags={"safe", "read", "group:session"}, version="1.0")
async def ssh_session_stats(ctx: Context) -> dict[str, Any]:
    """Pool-level stats: open count, per-key idle time."""
    pool = pool_from(ctx)
    return {"open": pool.size(), "entries": pool.stats()}
