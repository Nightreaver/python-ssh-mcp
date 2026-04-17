"""Thin entry point. Lifecycle belongs to the FastMCP lifespan."""
import logging

from .config import settings
from .server import mcp_server


def main() -> None:
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    mcp_server.run()
