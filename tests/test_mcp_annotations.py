"""MCP ToolAnnotations derived from our FastMCP tags.

Without this step every read-only tool ends up marked as "destructive" in
clients (MCP spec: `destructiveHint` default is True, `readOnlyHint` default
is False). We derive the annotations post-registration from the existing
tier tags.
"""
from __future__ import annotations

import asyncio
from typing import Any


def _collect_tools() -> list[Any]:
    # Import the server + apply the derivation once.
    from ssh_mcp.lifespan import _apply_mcp_annotations
    from ssh_mcp.server import mcp_server

    async def _run() -> list[Any]:
        await _apply_mcp_annotations(mcp_server)
        return list(await mcp_server._list_tools())

    return asyncio.run(_run())


_TOOLS = {t.name: t for t in _collect_tools()}


def test_read_tools_are_readonly_not_destructive() -> None:
    """Every tool tagged `safe`/`read` must surface as readOnlyHint=True."""
    for name in ("ssh_host_ping", "ssh_host_info", "ssh_sftp_list",
                 "ssh_docker_ps", "ssh_docker_logs", "ssh_find"):
        tool = _TOOLS[name]
        ann = tool.annotations
        assert ann is not None, f"{name}: no annotations derived"
        assert ann.readOnlyHint is True, f"{name}: readOnlyHint not set"
        assert ann.destructiveHint is False, f"{name}: destructiveHint leaked True"
        assert ann.openWorldHint is True


def test_low_access_tools_are_not_readonly_but_additive() -> None:
    """Low-access file ops mutate state but are additive (non-destructive)."""
    for name in ("ssh_cp", "ssh_mv", "ssh_mkdir", "ssh_upload",
                 "ssh_edit", "ssh_patch", "ssh_deploy"):
        tool = _TOOLS[name]
        ann = tool.annotations
        assert ann is not None, f"{name}: no annotations derived"
        assert ann.readOnlyHint is False, f"{name}: readOnlyHint leaked True"
        assert ann.destructiveHint is False, (
            f"{name}: file ops are additive (no delete); destructive should be False"
        )


def test_delete_tools_are_destructive() -> None:
    """ssh_delete* / docker_rm* / docker_prune stay destructive even inside
    the low-access tier -- they actually remove data."""
    for name in ("ssh_delete", "ssh_delete_folder"):
        tool = _TOOLS[name]
        ann = tool.annotations
        assert ann is not None
        assert ann.destructiveHint is True, f"{name}: destructive must stay True"


def test_dangerous_tools_default_to_destructive() -> None:
    for name in ("ssh_exec_run", "ssh_exec_script", "ssh_docker_run",
                 "ssh_sudo_exec"):
        tool = _TOOLS[name]
        ann = tool.annotations
        assert ann is not None
        assert ann.readOnlyHint is False
        assert ann.destructiveHint is True


def test_every_registered_tool_has_annotations() -> None:
    """No tool should fall through without annotations after derivation."""
    missing = [name for name, tool in _TOOLS.items() if tool.annotations is None]
    assert not missing, f"tools without annotations: {missing}"
