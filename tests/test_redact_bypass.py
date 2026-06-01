"""Redact-bypass policy integration -- block / warn / audit_only modes on
path-bearing tools.

Covers:

- ``block`` mode raises ``RedactBypassBlocked`` from ``ssh_sftp_download``
  with the standard "use ssh_read_redacted" message.
- ``warn`` mode delivers raw content + appends REDACT_BYPASS_WARNING to
  ``output_warnings`` AND records ``redact_bypass: true`` on the audit
  line (v1.5.0).
- ``audit_only`` mode delivers raw content silently to the LLM AND
  records ``redact_bypass: true`` on the audit line so operators can
  grep ``jq 'select(.redact_bypass)'`` for forensic review (v1.5.0).
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.redact_policy import REDACT_BYPASS_WARNING
from ssh_mcp.ssh.errors import RedactBypassBlocked
from ssh_mcp.tools import sftp_read_tools
from ssh_mcp.tools.sftp_read_tools import ssh_sftp_download


class _FakeAttrs:
    def __init__(self, size: int) -> None:
        self.size = size


class _FakeRemoteReadFile:
    def __init__(self, content: bytes) -> None:
        self._buf = content
        self._pos = 0

    async def __aenter__(self) -> _FakeRemoteReadFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def read(self, _chunk: int = -1) -> bytes:
        out = self._buf[self._pos :]
        self._pos = len(self._buf)
        return out


class _FakeSftp:
    def __init__(self, *, content: bytes) -> None:
        self._content = content

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def stat(self, _path: str) -> _FakeAttrs:
        return _FakeAttrs(size=len(self._content))

    def open(self, _path: str, _mode: str) -> Any:
        return _FakeRemoteReadFile(self._content)


def _ctx(
    *,
    bypass_policy: str = "warn",
    redact_globs: list[str] | None = None,
    content: bytes = b"DB_PASSWORD=hunter2\n",
) -> Any:
    sftp = _FakeSftp(content=content)
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp = MagicMock(return_value=sftp)
    policy = HostPolicy(
        hostname="h.example.com",
        user="deploy",
        port=22,
        platform="posix",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],
    )
    hosts = {"h": policy}
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_PATH_ALLOWLIST=["/"],
        SSH_REDACT_PATHS_GLOBS=redact_globs or [],
        SSH_REDACT_BYPASS_POLICY=bypass_policy,  # type: ignore[arg-type]
    )

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": hosts,
            "host_allowlist": ["h"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


def _bypass_path_canonicalize(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the realpath shell + canonicalize step -- tests use already-
    canonical paths, and we want the policy gates (allowlist / restricted
    / restricted_globs / redact-bypass) to run on the literal input."""

    async def _fake_canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(sftp_read_tools, "resolve_path", _real_resolve_path_wrapper(monkeypatch))


def _only_audit_event(caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    """Same shape as tests/test_audit.py::_only_audit_event -- pull the
    single JSON line written to the ``ssh_mcp.audit`` logger and parse it.

    A bypass-flag assertion compares ``event.get("redact_bypass")`` so the
    test stays robust when the field is omitted on the no-bypass path (per
    the audit-line-stays-lean convention).
    """
    lines = [r.message for r in caplog.records if r.name == "ssh_mcp.audit"]
    assert len(lines) == 1, f"expected 1 audit line, got {len(lines)}: {lines}"
    return json.loads(lines[0])


def _real_resolve_path_wrapper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Wrap resolve_path so canonicalize-and-check uses a fake
    canonicalize, but ALL other gates (restricted, restricted_globs,
    bypass-block) still run on the literal input path.
    """
    from ssh_mcp.services import path_policy

    async def _fake_canonicalize(
        _conn: Any,
        path: str,
        *_a: Any,
        **_kw: Any,
    ) -> str:
        return path

    monkeypatch.setattr(path_policy, "canonicalize", _fake_canonicalize)
    return path_policy.resolve_path


# --- block mode ---------------------------------------------------------


@pytest.mark.asyncio
async def test_block_mode_raises_redact_bypass_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="block", redact_globs=["**/.env"])

    with pytest.raises(RedactBypassBlocked) as exc:
        await ssh_sftp_download(host="h", path="/opt/app/.env", ctx=ctx)
    # Message should name the alternative tool.
    assert "ssh_read_redacted" in str(exc.value)
    assert exc.value.suggested_tool == "ssh_read_redacted"


@pytest.mark.asyncio
async def test_block_mode_passes_through_non_matching_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="block", redact_globs=["**/.env"])

    # /opt/app/main.py doesn't match **/.env -> no raise, normal delivery.
    result = await ssh_sftp_download(host="h", path="/opt/app/main.py", ctx=ctx)
    assert result.truncated is False
    # No bypass warning on a clean path.
    assert REDACT_BYPASS_WARNING not in result.output_warnings


# --- warn mode ----------------------------------------------------------


@pytest.mark.asyncio
async def test_warn_mode_delivers_raw_content_with_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="warn", redact_globs=["**/.env"])

    result = await ssh_sftp_download(host="h", path="/opt/app/.env", ctx=ctx)
    assert result.truncated is False
    # Warn delivers raw bytes -- payload non-empty.
    assert result.content_base64 != ""
    # Standard warning string attached.
    assert REDACT_BYPASS_WARNING in result.output_warnings


@pytest.mark.asyncio
async def test_warn_mode_no_warning_on_non_matching_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="warn", redact_globs=["**/.env"])

    result = await ssh_sftp_download(host="h", path="/opt/app/main.py", ctx=ctx)
    assert REDACT_BYPASS_WARNING not in result.output_warnings


# --- audit_only mode (silent from LLM POV, audit line marked) -----------


@pytest.mark.asyncio
async def test_audit_only_delivers_silently(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """audit_only mode: tool delivers raw content; ``output_warnings`` is
    NOT updated. The LLM sees raw bytes + no warning, same as if the path
    wasn't on the redact list at all.

    v1.5.0: the audit line for the call now carries
    ``redact_bypass: true`` so operators can grep
    ``jq 'select(.redact_bypass)'`` for forensic review even though the
    LLM was kept silent.
    """
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="audit_only", redact_globs=["**/.env"])

    result = await ssh_sftp_download(host="h", path="/opt/app/.env", ctx=ctx)
    assert result.truncated is False
    assert result.content_base64 != ""
    # No LLM-visible warning in audit_only mode.
    assert REDACT_BYPASS_WARNING not in result.output_warnings
    # ...but the audit line records the bypass.
    event = _only_audit_event(caplog)
    assert (
        event.get("redact_bypass") is True
    ), f"audit_only must stamp redact_bypass on the audit line; got {event}"


# --- warn mode also records the audit-line flag (v1.5.0) ---------------


@pytest.mark.asyncio
async def test_warn_mode_also_records_audit_bypass(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """warn mode does BOTH: surfaces REDACT_BYPASS_WARNING to the LLM via
    ``output_warnings`` AND records ``redact_bypass: true`` on the audit
    line. The two channels are independent -- operators monitoring audit
    sinks see the bypass even if the LLM-side warning was stripped /
    ignored downstream.

    (``block`` mode doesn't need this assertion because the raise already
    shows up in the audit line as ``result=error`` with
    ``error="RedactBypassBlocked"``.)
    """
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="warn", redact_globs=["**/.env"])

    result = await ssh_sftp_download(host="h", path="/opt/app/.env", ctx=ctx)
    # LLM-visible warning still present (existing warn-mode behaviour).
    assert REDACT_BYPASS_WARNING in result.output_warnings
    # Audit-line bypass flag also present (v1.5.0 addition).
    event = _only_audit_event(caplog)
    assert (
        event.get("redact_bypass") is True
    ), f"warn mode must also stamp redact_bypass on the audit line; got {event}"


@pytest.mark.asyncio
async def test_non_matching_path_does_not_stamp_audit_bypass(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Regression guard: when the path isn't on the redact list, the
    audit line omits ``redact_bypass`` entirely (per the audit-line-stays-
    lean convention -- no ``false`` entries).
    """
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    _bypass_path_canonicalize(monkeypatch)
    ctx = _ctx(bypass_policy="audit_only", redact_globs=["**/.env"])

    await ssh_sftp_download(host="h", path="/opt/app/main.py", ctx=ctx)
    event = _only_audit_event(caplog)
    assert "redact_bypass" not in event, f"non-bypass calls must NOT carry redact_bypass; got {event}"
