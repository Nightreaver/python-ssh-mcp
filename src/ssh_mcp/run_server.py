"""Thin entry point. Lifecycle belongs to the FastMCP lifespan."""
import logging

from .config import settings
from .server import mcp_server


def main() -> None:
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if settings.MCP_TRANSPORT == "stdio":
        mcp_server.run(transport="stdio")
    else:
        mcp_server.run(
            transport=settings.MCP_TRANSPORT,
            host=settings.MCP_HTTP_HOST,
            port=settings.MCP_HTTP_PORT,
        )
