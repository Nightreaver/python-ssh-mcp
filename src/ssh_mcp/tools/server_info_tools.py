"""MCP server identity + capability surface (v1.5.0).

Dual surface: an MCP resource at ``mcp://ssh-mcp/server-info`` is the
PRIMARY discovery path; the ``ssh_server_info`` tool is a fallback for
clients that do not expose ``resources/list`` to the LLM (most current
clients don't). Both share ``_collect_server_info`` so payload shape
stays in lockstep.

Lives in ``group:host`` because it's a discovery call alongside
``ssh_host_list`` / ``ssh_host_ping``. Operators who don't want
metadata exposed can hide it via ``SSH_ENABLED_GROUPS`` -- but the
catalog cost is tiny (one extra entry in tools/list) so the default
is to leave it on.

The resource and the tool are intentionally NOT decorated with
``@audited``: this is server-meta, not a host-touching action, and
auditing it would just noise the log without a security signal.
"""

from __future__ import annotations

import json

from fastmcp import Context

from ..app import mcp_server
from ..config import settings
from ..models.results import ServerInfoResult


async def _collect_server_info() -> ServerInfoResult:
    """Build the server-info payload. Shared by the tool and the resource.

    Tool count is the post-Visibility-transform count -- what the LLM
    actually sees in ``tools/list`` for the current operator config, not
    the full registered catalog. Uses ``_list_tools`` for parity with
    ``.claude/scripts/catalog-size.py``.
    """
    tools = list(await mcp_server._list_tools())
    enabled_tiers: list[str] = ["read"]
    if settings.ALLOW_LOW_ACCESS_TOOLS:
        enabled_tiers.append("low-access")
    if settings.ALLOW_DANGEROUS_TOOLS:
        enabled_tiers.append("dangerous")
    if settings.ALLOW_SUDO:
        enabled_tiers.append("sudo")
    return ServerInfoResult(
        name="ssh-mcp",
        version=settings.VERSION,
        total_tools=len(tools),
        enabled_tiers=enabled_tiers,
        enabled_groups=list(settings.SSH_ENABLED_GROUPS),
    )


@mcp_server.resource(
    "mcp://ssh-mcp/server-info",
    name="server-info",
    description=(
        "Server identity + capability surface. Returns name, version, the "
        "tier flags the operator unlocked, the active SSH_ENABLED_GROUPS "
        "filter, and the total tool count the LLM sees. Primary discovery "
        "path; the ssh_server_info tool is a fallback for clients that "
        "don't expose resources to the LLM."
    ),
    mime_type="application/json",
)
async def server_info_resource() -> str:
    """Resource form -- JSON-serialized ServerInfoResult.

    Returns a string body so MCP clients with strict text-only resource
    handlers don't choke on a structured return. ``mime_type`` declares
    the body is JSON; the LLM (or operator-side tooling) parses it.
    """
    info = await _collect_server_info()
    return json.dumps(info.model_dump(), indent=2)


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_server_info(ctx: Context) -> ServerInfoResult:
    """Return server identity + capability surface (name / version /
    tier flags / enabled groups / total tools). Fallback for the
    ``mcp://ssh-mcp/server-info`` resource on clients that don't expose
    resources to the LLM. Same payload shape as the resource.

    The ``ctx`` parameter is required by FastMCP's tool registration
    (so the tool integrates with the standard tool-call machinery) but
    the payload is fully derived from process-level settings, so ctx
    itself is unused inside the body.
    """
    del ctx  # explicit unused-param signal; payload comes from process state
    return await _collect_server_info()


# Re-export for the explicit "this module owns these symbols" contract;
# the side-effect of registering tool + resource happens at import time
# via the decorators above.
__all__ = ["_collect_server_info", "server_info_resource", "ssh_server_info"]
