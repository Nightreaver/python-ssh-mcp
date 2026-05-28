"""ssh_upload / ssh_deploy `local_path` mode (v1.3.0).

Streams bytes from the MCP server's OWN filesystem into the SFTP write,
bypassing the MCP JSON channel so the LLM never has to base64-encode the
payload. Covers:

- Three-way mutex enforcement (passing 2 of {text, b64, local_path} ⇒ error).
- Cap enforcement against ``SSH_LOCAL_TRANSFER_MAX_BYTES`` (NOT the
  256 MiB ``SSH_UPLOAD_MAX_FILE_BYTES`` upload cap).
- Happy path: bytes streamed via SFTP, ``bytes_written`` reflects the
  actual transfer, ``local_path_written`` carries the canonical source.
- Audit log surfaces the canonical local path (via the result's `path`
  resolution, which the audit decorator picks up from `out["path"]`).
- ssh_deploy also honors `local_path` and produces the same shape.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools.low_access import _helpers as low_access_helpers
from ssh_mcp.tools.low_access import upload_tools
from ssh_mcp.tools.low_access_tools import WriteError, ssh_deploy, ssh_upload

if TYPE_CHECKING:
    from pathlib import Path


def _policy() -> HostPolicy:
    return HostPolicy(
        hostname="web01",
        user="deploy",
        port=22,
        platform="posix",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],
    )


class _FakeSftpFile:
    """SFTP file stub: collects writes into an in-memory bytearray."""

    def __init__(self, sink: bytearray) -> None:
        self._sink = sink

    async def __aenter__(self) -> _FakeSftpFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def write(self, chunk: bytes | bytearray) -> None:
        self._sink.extend(chunk)


class _FakeSftp:
    """Records open/chmod/posix_rename calls + captures written bytes.

    ``opened_paths`` and ``renames`` let tests assert the atomic
    tmp→final pattern fired. ``written`` is the concrete byte string the
    tool streamed -- compared against the local source for the happy
    path.
    """

    def __init__(self) -> None:
        self.written = bytearray()
        self.opened_paths: list[str] = []
        self.chmod_calls: list[tuple[str, int]] = []
        self.renames: list[tuple[str, str]] = []
        self.lstat_calls: list[str] = []
        self.removes: list[str] = []
        self.lstat_should_raise = True  # default: target doesn't exist

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def open(self, path: str, mode: str) -> _FakeSftpFile:
        self.opened_paths.append(path)
        return _FakeSftpFile(self.written)

    async def chmod(self, path: str, mode: int) -> None:
        self.chmod_calls.append((path, mode))

    async def posix_rename(self, src: str, dst: str) -> None:
        self.renames.append((src, dst))

    async def lstat(self, path: str) -> Any:
        self.lstat_calls.append(path)
        if self.lstat_should_raise:
            import asyncssh

            raise asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file")
        attrs = MagicMock()
        attrs.permissions = 0o100644
        attrs.size = 0
        return attrs

    async def remove(self, path: str) -> None:
        self.removes.append(path)


def _ctx(
    sftp: _FakeSftp,
    *,
    local_roots: list[str] | None = None,
    max_bytes: int = 2 << 30,
) -> Any:
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)

    async def fake_run(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("ssh_upload local_path path must not shell out")

    conn.run = fake_run

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp_policy = MagicMock(return_value=sftp)
    pool.sftp = MagicMock(return_value=sftp)

    hosts = {"web01": _policy()}
    settings = Settings(
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_PATH_ALLOWLIST=["/"],
        ALLOW_LOW_ACCESS_TOOLS=True,
        SSH_LOCAL_TRANSFER_ROOTS=list(local_roots or []),
        SSH_LOCAL_TRANSFER_MAX_BYTES=max_bytes,
    )

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": hosts,
            "host_allowlist": ["web01"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


def _bypass_path_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _resolve(_conn: Any, path: str, _policy_arg: Any, _settings: Any, *_a: Any, **_kw: Any) -> str:
        return path

    # INC-043-style split: `ssh_upload` / `ssh_deploy` use `_prepare_creatable`
    # from `low_access._helpers` -- that's where `resolve_path` is resolved.
    # `upload_tools` itself does not import `resolve_path` directly (only
    # `resolve_local_path`), so patching only the helpers module is enough.
    monkeypatch.setattr(low_access_helpers, "resolve_path", _resolve)
    # Defensive: also patch upload_tools in case future helper refactors add
    # a direct binding there. `raising=False` because the attribute may not
    # exist on this module.
    monkeypatch.setattr(upload_tools, "resolve_path", _resolve, raising=False)


# ---------------------------------------------------------------------------
# Three-way mutex on (content_text, content_base64, local_path)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_text_and_local_path_both_set_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two payload sources ⇒ error. The new mutex message must call out
    "Multiple were set" so future maintainers can grep it."""
    _bypass_path_policy(monkeypatch)
    src = tmp_path / "src.bin"
    src.write_bytes(b"hi")
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)])

    with pytest.raises(WriteError, match="Multiple were set"):
        await ssh_upload(
            host="web01",
            path="/tmp/dst.bin",
            ctx=ctx,
            content_text="x",
            local_path=str(src),
        )


@pytest.mark.asyncio
async def test_base64_and_local_path_both_set_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_path_policy(monkeypatch)
    src = tmp_path / "src.bin"
    src.write_bytes(b"hi")
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)])

    with pytest.raises(WriteError, match="Multiple were set"):
        await ssh_upload(
            host="web01",
            path="/tmp/dst.bin",
            ctx=ctx,
            content_base64="aGk=",
            local_path=str(src),
        )


# ---------------------------------------------------------------------------
# Cap enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_path_over_cap_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Set the cap below the file's actual size; the call must refuse
    BEFORE opening the SFTP channel (no writes recorded on the stub)."""
    _bypass_path_policy(monkeypatch)
    src = tmp_path / "big.bin"
    src.write_bytes(b"x" * 1024)
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)], max_bytes=128)

    with pytest.raises(WriteError, match="SSH_LOCAL_TRANSFER_MAX_BYTES=128"):
        await ssh_upload(
            host="web01",
            path="/tmp/dst.bin",
            ctx=ctx,
            local_path=str(src),
        )
    assert sftp.opened_paths == []
    assert sftp.renames == []


@pytest.mark.asyncio
async def test_local_path_disabled_when_roots_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty allowlist ⇒ mode disabled; error names the setting."""
    _bypass_path_policy(monkeypatch)
    src = tmp_path / "x.bin"
    src.write_bytes(b"data")
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[])  # empty -> disabled

    from ssh_mcp.ssh.errors import LocalPathPolicyError

    with pytest.raises(LocalPathPolicyError, match="SSH_LOCAL_TRANSFER_ROOTS"):
        await ssh_upload(
            host="web01",
            path="/tmp/dst.bin",
            ctx=ctx,
            local_path=str(src),
        )


# ---------------------------------------------------------------------------
# Happy path: streamed upload with bytes_written verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_path_upload_streams_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Larger-than-one-chunk source ⇒ bytes_written reflects the actual
    streamed total and the SFTP stub has the exact byte sequence written
    via the tmp+rename atomic pattern."""
    _bypass_path_policy(monkeypatch)
    payload = b"abcd" * (300 * 1024)  # ~1.17 MiB -> 5 chunks at 256 KiB
    src = tmp_path / "payload.bin"
    src.write_bytes(payload)
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)])

    out = await ssh_upload(
        host="web01",
        path="/var/data/payload.bin",
        ctx=ctx,
        local_path=str(src),
    )

    assert out.success is True
    assert out.bytes_written == len(payload)
    assert out.local_path_written == str(src.resolve())
    assert "streamed" in (out.message or "")
    # Atomic dance: one open(tmp), one rename(tmp -> final).
    assert len(sftp.opened_paths) == 1
    assert sftp.opened_paths[0].startswith("/var/data/payload.bin.ssh-mcp-tmp.")
    assert len(sftp.renames) == 1
    assert sftp.renames[0][1] == "/var/data/payload.bin"
    # And the bytes the stub captured are exactly what was on disk.
    assert bytes(sftp.written) == payload


@pytest.mark.asyncio
async def test_local_path_audit_records_remote_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The audit line's `path_hash` should hash the REMOTE canonical path
    (existing contract). The new `local_path_written` field surfaces the
    local source on the result body so an operator can correlate the two.

    The local path is NOT a tool arg the audit decorator stamps directly
    -- the decorator only consumes ``host`` / ``path`` / ``src`` / ``dst``
    from kwargs and the canonical ``path`` from the result. So this test
    pins:
    1. The audit `path_hash` reflects the REMOTE path (no local-path
       leakage into the wrong slot).
    2. The local canonical source is preserved on the WriteResult so the
       audit-line's correlation_id can be tied back to it via the
       structured response.
    """
    _bypass_path_policy(monkeypatch)
    src = tmp_path / "audit_src.bin"
    src.write_bytes(b"audit-me")
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)])

    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    out = await ssh_upload(
        host="web01",
        path="/var/data/audit.bin",
        ctx=ctx,
        local_path=str(src),
    )

    assert out.local_path_written == str(src.resolve())
    audit_lines = [r.getMessage() for r in caplog.records if r.name == "ssh_mcp.audit"]
    assert audit_lines, "expected at least one audit line"
    # Audit's path_hash is sha256-derived; we can't reverse it. Sanity-check
    # the line carries `tool=ssh_upload`, `host=web01`, `result=ok`, and a
    # `path_hash` slot (the canonical remote path post-resolve).
    import json

    parsed = [json.loads(line) for line in audit_lines]
    upload_lines = [p for p in parsed if p.get("tool") == "ssh_upload"]
    assert upload_lines, f"no ssh_upload audit line in {parsed}"
    line = upload_lines[-1]
    assert line["result"] == "ok"
    assert line["host"] == "web01"
    assert "path_hash" in line


# ---------------------------------------------------------------------------
# ssh_deploy parallel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_path_deploy_streams_with_no_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ssh_deploy(backup=False) on a brand-new target ⇒ no backup_path
    field; result body still carries local_path_written and the right
    bytes count."""
    _bypass_path_policy(monkeypatch)
    payload = b"deploy-me"
    src = tmp_path / "deploy.bin"
    src.write_bytes(payload)
    sftp = _FakeSftp()
    ctx = _ctx(sftp, local_roots=[str(tmp_path)])

    result = await ssh_deploy(
        host="web01",
        path="/etc/app/config.bin",
        ctx=ctx,
        local_path=str(src),
        backup=False,
    )

    assert result["success"] is True
    assert result["bytes_written"] == len(payload)
    assert result["local_path_written"] == str(src.resolve())
    assert "backup_path" not in result
    assert bytes(sftp.written) == payload
