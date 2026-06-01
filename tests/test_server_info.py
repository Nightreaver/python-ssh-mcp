"""Tests for the v1.5.0 server-info dual surface (resource + tool).

Covers:
- ``_collect_server_info`` returns the documented shape with values from
  the live ``settings`` + the live ``mcp_server`` tool registry.
- ``ssh_server_info`` tool returns the same payload (tool delegates to
  the helper).
- ``server_info_resource`` returns the same content as JSON.
- Tier flags reflect the live ``settings.ALLOW_*`` state.
- ``enabled_groups`` reflects ``SSH_ENABLED_GROUPS`` verbatim (or empty
  list when unset; empty == "all groups visible").
"""

from __future__ import annotations

import json

import pytest

from ssh_mcp.tools.server_info_tools import (
    _collect_server_info,
    server_info_resource,
    ssh_server_info,
)


@pytest.mark.asyncio
async def test_collect_server_info_shape() -> None:
    info = await _collect_server_info()
    assert info.name == "ssh-mcp"
    # Version is process-level; whatever Settings carries is what we report.
    assert info.version  # non-empty
    assert info.version.count(".") == 2  # SemVer MAJOR.MINOR.PATCH
    assert info.total_tools > 0
    # ``read`` is always in the enabled tiers; the others depend on flags.
    assert "read" in info.enabled_tiers
    assert isinstance(info.enabled_groups, list)


@pytest.mark.asyncio
async def test_tool_returns_same_payload_as_helper() -> None:
    helper = await _collect_server_info()
    # The Context arg is unused inside the tool body (see the `del ctx`);
    # passing None is fine for this direct-call test.
    tool_result = await ssh_server_info(ctx=None)  # type: ignore[arg-type]
    assert tool_result.model_dump() == helper.model_dump()


@pytest.mark.asyncio
async def test_resource_returns_json_body_matching_helper() -> None:
    helper = await _collect_server_info()
    body = await server_info_resource()
    parsed = json.loads(body)
    assert parsed == helper.model_dump()


@pytest.mark.asyncio
async def test_tier_list_reflects_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flip every ALLOW_* flag in the live settings singleton and confirm
    the tier list updates. The Settings instance is module-level, so a
    direct attribute set on it (within a monkeypatch.setattr) is the
    cheapest way to exercise the branch logic."""
    from ssh_mcp.config import settings

    monkeypatch.setattr(settings, "ALLOW_LOW_ACCESS_TOOLS", True)
    monkeypatch.setattr(settings, "ALLOW_DANGEROUS_TOOLS", True)
    monkeypatch.setattr(settings, "ALLOW_SUDO", True)
    info = await _collect_server_info()
    assert info.enabled_tiers == ["read", "low-access", "dangerous", "sudo"]

    monkeypatch.setattr(settings, "ALLOW_LOW_ACCESS_TOOLS", False)
    monkeypatch.setattr(settings, "ALLOW_DANGEROUS_TOOLS", False)
    monkeypatch.setattr(settings, "ALLOW_SUDO", False)
    info = await _collect_server_info()
    assert info.enabled_tiers == ["read"]


@pytest.mark.asyncio
async def test_enabled_groups_reflects_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_mcp.config import settings

    monkeypatch.setattr(settings, "SSH_ENABLED_GROUPS", ["host", "sftp-read"])
    info = await _collect_server_info()
    assert info.enabled_groups == ["host", "sftp-read"]

    # Empty list = default = "all groups visible". The field reports the
    # raw setting verbatim (no sentinel substitution) so the LLM can
    # distinguish "operator filtered nothing" from "operator filtered to []".
    monkeypatch.setattr(settings, "SSH_ENABLED_GROUPS", [])
    info = await _collect_server_info()
    assert info.enabled_groups == []
