"""Re-exports the FastMCP instance and triggers tool registration.

This module is the entry point referenced by `fastmcp.json`. FastMCP loads it
as a standalone file (via `importlib.util.spec_from_file_location`), so we use
absolute imports here -- `from .app import ...` would fail with
`attempted relative import with no known parent package`. All sibling modules
continue to use relative imports because they are imported through the proper
`ssh_mcp` package path.
"""

from ssh_mcp.app import mcp_server
from ssh_mcp.tools import (  # noqa: F401  # imports register tools on the mcp_server
    docker_tools,
    exec_tools,
    host_tools,
    low_access_tools,
    session_tools,
    sftp_read_tools,
    shell_tools,
    sudo_tools,
    systemctl_tools,
)

__all__ = ["mcp_server"]
