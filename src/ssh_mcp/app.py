"""FastMCP instance lives here so tool modules can import it without cycle.

`server.py` imports this module and then imports all tool modules for their
registration side-effect. Tool modules import `mcp_server` from here directly.
"""
from __future__ import annotations

from fastmcp import FastMCP

from .config import settings
from .lifespan import ssh_lifespan

mcp_server: FastMCP = FastMCP(
    name="ssh-mcp",
    version=settings.VERSION,
    lifespan=ssh_lifespan,
)
