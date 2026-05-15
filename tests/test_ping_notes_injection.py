"""ssh_host_ping auto-injects both notes layers (INC-059 + INC-060).

Pinned contracts:
- operator_notes (hosts.toml `notes` field):
  - present + setting True (default) -> populated.
  - present + setting False -> None (opt-out).
  - absent / whitespace-only -> None.
- agent_notes (sidecar at <SSH_HOST_NOTES_DIR>/<alias>.md):
  - sidecar exists + setting True (default) -> populated.
  - sidecar exists + setting False -> None (opt-out).
  - SSH_HOST_NOTES_DIR=None -> None (agent layer disabled).
  - sidecar absent -> None.
- The two layers toggle independently.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools.host_tools import ssh_host_ping

if TYPE_CHECKING:
    from pathlib import Path


def _ctx(
    *,
    notes: str | None = None,
    ping_includes_notes: bool = True,
    ping_includes_agent_notes: bool = True,
    notes_dir: Path | None = None,
) -> Any:
    """Stub Context where pool.acquire returns a fake connection that
    looks like it handshook successfully. The two SSH_PING_INCLUDES_*
    settings toggle each note layer independently; `notes_dir` controls
    where ping looks for the agent sidecar (None disables that layer)."""
    fake_conn = MagicMock()
    fake_conn.get_extra_info = MagicMock(return_value="SSH-2.0-fake")

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=fake_conn)

    kh = MagicMock()
    kh.fingerprint_for = MagicMock(return_value="SHA256:fake")

    hosts = {
        "h": HostPolicy(
            hostname="h.example.com",
            user="deploy",
            port=22,
            platform="posix",
            auth=AuthPolicy(method="agent"),
            notes=notes,
        ),
    }

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_PING_INCLUDES_NOTES=ping_includes_notes,
                SSH_PING_INCLUDES_AGENT_NOTES=ping_includes_agent_notes,
                SSH_HOST_NOTES_DIR=notes_dir,
            ),
            "hosts": hosts,
            "host_allowlist": ["h"],
            "known_hosts": kh,
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


# ---------------------------------------------------------------------------
# Default-on behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notes_present_default_setting_injects() -> None:
    """SSH_PING_INCLUDES_NOTES defaults to True; ping with notes set
    surfaces them in operator_notes."""
    notes = (
        "- NEVER install apache2 -- nginx only.\n"
        "- Owner: platform-team@\n"
    )
    out = await ssh_host_ping(host="h", ctx=_ctx(notes=notes))
    assert out.reachable is True
    assert out.operator_notes == notes.strip()


@pytest.mark.asyncio
async def test_no_notes_set_returns_none() -> None:
    out = await ssh_host_ping(host="h", ctx=_ctx(notes=None))
    assert out.operator_notes is None


@pytest.mark.asyncio
async def test_whitespace_only_notes_treated_as_absent() -> None:
    """Empty / whitespace-only operator notes are treated like 'no
    notes' rather than fooling the LLM into thinking there's guidance."""
    out = await ssh_host_ping(host="h", ctx=_ctx(notes="   \n\t\n"))
    assert out.operator_notes is None


@pytest.mark.asyncio
async def test_notes_stripped_of_surrounding_whitespace() -> None:
    """Trailing newlines from TOML multi-line strings are normalized so
    operator_notes is the readable content, not the raw multi-line slug."""
    out = await ssh_host_ping(host="h", ctx=_ctx(notes="\nhello\n\n"))
    assert out.operator_notes == "hello"


# ---------------------------------------------------------------------------
# Opt-out behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_setting_disabled_omits_notes_even_when_set() -> None:
    """SSH_PING_INCLUDES_NOTES=False: ping result has operator_notes=None
    regardless of whether the host has notes configured."""
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(notes="hard rule X", ping_includes_notes=False),
    )
    assert out.operator_notes is None


@pytest.mark.asyncio
async def test_setting_disabled_with_no_notes_still_none() -> None:
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(notes=None, ping_includes_notes=False),
    )
    assert out.operator_notes is None


# ---------------------------------------------------------------------------
# Other ping fields stay correct
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ping_fields_unaffected_by_notes_injection() -> None:
    """Adding notes injection mustn't perturb the existing ping fields."""
    out = await ssh_host_ping(host="h", ctx=_ctx(notes="some notes"))
    assert out.host == "h.example.com"
    assert out.reachable is True
    assert out.auth_ok is True
    assert out.latency_ms >= 0
    assert out.server_banner == "SSH-2.0-fake"
    assert out.known_host_fingerprint == "SHA256:fake"


# ---------------------------------------------------------------------------
# INC-060: Agent-layer auto-injection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_notes_injected_when_sidecar_exists(tmp_path: Path) -> None:
    """Default behavior: sidecar exists + setting True (default) -> the
    agent_notes field carries the file's content verbatim."""
    body = "## 2026-04-25T10:00:00Z\nlearned: deploy is in docker group\n"
    (tmp_path / "h.md").write_text(body, encoding="utf-8")
    out = await ssh_host_ping(host="h", ctx=_ctx(notes_dir=tmp_path))
    assert out.agent_notes == body


@pytest.mark.asyncio
async def test_agent_notes_none_when_sidecar_missing(tmp_path: Path) -> None:
    """No sidecar file -> agent_notes is None (not an empty string)."""
    out = await ssh_host_ping(host="h", ctx=_ctx(notes_dir=tmp_path))
    assert out.agent_notes is None


@pytest.mark.asyncio
async def test_agent_notes_setting_off_omits_even_when_sidecar_exists(
    tmp_path: Path,
) -> None:
    (tmp_path / "h.md").write_text("learned facts\n", encoding="utf-8")
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(notes_dir=tmp_path, ping_includes_agent_notes=False),
    )
    assert out.agent_notes is None


@pytest.mark.asyncio
async def test_agent_notes_none_when_notes_dir_disabled() -> None:
    """SSH_HOST_NOTES_DIR=None disables the entire agent layer; no read
    is even attempted."""
    out = await ssh_host_ping(host="h", ctx=_ctx(notes_dir=None))
    assert out.agent_notes is None


@pytest.mark.asyncio
async def test_agent_notes_zero_byte_sidecar_returns_none(tmp_path: Path) -> None:
    """A 0-byte sidecar (operator cleared it via ssh_host_notes_set with
    empty content) is treated as 'no agent notes' rather than carrying
    an empty string."""
    (tmp_path / "h.md").write_text("", encoding="utf-8")
    out = await ssh_host_ping(host="h", ctx=_ctx(notes_dir=tmp_path))
    assert out.agent_notes is None


@pytest.mark.asyncio
async def test_both_layers_independent(tmp_path: Path) -> None:
    """The two settings + sources are fully independent. Toggling one
    doesn't affect the other."""
    (tmp_path / "h.md").write_text("agent learned this\n", encoding="utf-8")

    # Operator on, agent off.
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(
            notes="hard rule X",
            notes_dir=tmp_path,
            ping_includes_notes=True,
            ping_includes_agent_notes=False,
        ),
    )
    assert out.operator_notes == "hard rule X"
    assert out.agent_notes is None

    # Operator off, agent on.
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(
            notes="hard rule X",
            notes_dir=tmp_path,
            ping_includes_notes=False,
            ping_includes_agent_notes=True,
        ),
    )
    assert out.operator_notes is None
    assert out.agent_notes == "agent learned this\n"

    # Both on (default).
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(notes="hard rule X", notes_dir=tmp_path),
    )
    assert out.operator_notes == "hard rule X"
    assert out.agent_notes == "agent learned this\n"

    # Both off.
    out = await ssh_host_ping(
        host="h",
        ctx=_ctx(
            notes="hard rule X",
            notes_dir=tmp_path,
            ping_includes_notes=False,
            ping_includes_agent_notes=False,
        ),
    )
    assert out.operator_notes is None
    assert out.agent_notes is None
