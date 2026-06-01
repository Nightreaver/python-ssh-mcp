"""ssh_sftp_download `local_path` mode (v1.10.0).

The MCP server streams the remote file directly onto its OWN filesystem
instead of base64-encoding it through the MCP JSON channel. Covers:

- Happy path: file is streamed in chunks; response carries empty
  `content_base64`, `truncated=False`, and `local_path_written=<canonical>`.
- The downloaded bytes match the source byte-for-byte.
- Cap enforcement against `SSH_LOCAL_TRANSFER_MAX_BYTES` -- raises BEFORE
  any local-disk work happens.
- Error mid-transfer leaves no partial file at the destination (tmp file
  is unlinked).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import sftp_read_tools
from ssh_mcp.tools.sftp_read_tools import SftpDownloadError, ssh_sftp_download

if TYPE_CHECKING:
    from pathlib import Path


class _FakeAttrs:
    def __init__(self, size: int) -> None:
        self.size = size


class _FakeRemoteReadFile:
    """Returns ``content`` over multiple ``.read(chunk)`` calls."""

    def __init__(self, content: bytes) -> None:
        self._buf = content
        self._pos = 0

    async def __aenter__(self) -> _FakeRemoteReadFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def read(self, chunk: int = -1) -> bytes:
        if self._pos >= len(self._buf):
            return b""
        if chunk < 0:
            out = self._buf[self._pos :]
            self._pos = len(self._buf)
            return out
        end = min(self._pos + chunk, len(self._buf))
        out = self._buf[self._pos : end]
        self._pos = end
        return out


class _FakeRemoteRaisingReadFile:
    """Raises after some bytes -- exercises the partial-cleanup branch."""

    def __init__(self, content: bytes, raise_after: int) -> None:
        self._buf = content
        self._pos = 0
        self._raise_after = raise_after

    async def __aenter__(self) -> _FakeRemoteRaisingReadFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def read(self, chunk: int = -1) -> bytes:
        if self._pos >= self._raise_after:
            raise RuntimeError("simulated transport failure mid-stream")
        if self._pos >= len(self._buf):
            return b""
        end = min(
            self._pos + min(chunk if chunk > 0 else len(self._buf), self._raise_after - self._pos),
            len(self._buf),
        )
        out = self._buf[self._pos : end]
        self._pos = end
        return out


class _FakeSftp:
    def __init__(
        self,
        *,
        content: bytes,
        raise_at: int | None = None,
    ) -> None:
        self._content = content
        self._raise_at = raise_at

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def stat(self, _path: str) -> _FakeAttrs:
        return _FakeAttrs(size=len(self._content))

    def open(self, _path: str, _mode: str) -> Any:
        if self._raise_at is not None:
            return _FakeRemoteRaisingReadFile(self._content, self._raise_at)
        return _FakeRemoteReadFile(self._content)


def _download_ctx(
    *,
    content: bytes,
    local_roots: list[str],
    max_bytes: int = 2 << 30,
    raise_at: int | None = None,
) -> Any:
    sftp = _FakeSftp(content=content, raise_at=raise_at)
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp = MagicMock(return_value=sftp)
    hosts = {
        "h": HostPolicy(
            hostname="h.example.com",
            user="deploy",
            port=22,
            platform="posix",
            auth=AuthPolicy(method="agent"),
            path_allowlist=["/"],
        ),
    }
    settings = Settings(
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_PATH_ALLOWLIST=["/"],
        SSH_LOCAL_TRANSFER_ROOTS=local_roots,
        SSH_LOCAL_TRANSFER_MAX_BYTES=max_bytes,
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


def _bypass_path_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _resolve(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(sftp_read_tools, "resolve_path", _resolve)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_to_local_path_writes_file_byte_perfect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_path_policy(monkeypatch)
    payload = b"chunked" * (50 * 1024)  # ~350 KiB, spans multiple chunks
    dest = tmp_path / "out.bin"
    ctx = _download_ctx(content=payload, local_roots=[str(tmp_path)])

    result = await ssh_sftp_download(
        host="h",
        path="/var/data/big.bin",
        ctx=ctx,
        local_path=str(dest),
    )

    assert result.content_base64 == ""
    assert result.truncated is False
    assert result.size == len(payload)
    assert result.local_path_written == str(dest.resolve())
    # The bytes that actually landed on disk match the source verbatim.
    assert dest.read_bytes() == payload


# ---------------------------------------------------------------------------
# Cap enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_cap_enforced_without_touching_local_disk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remote size > SSH_LOCAL_TRANSFER_MAX_BYTES ⇒ raises BEFORE any
    tmp file is opened. Asserts no leftover tmp file in the destination
    dir after the call."""
    _bypass_path_policy(monkeypatch)
    payload = b"x" * 4096
    dest = tmp_path / "out.bin"
    ctx = _download_ctx(
        content=payload,
        local_roots=[str(tmp_path)],
        max_bytes=1024,
    )

    with pytest.raises(SftpDownloadError, match="SSH_LOCAL_TRANSFER_MAX_BYTES=1024"):
        await ssh_sftp_download(
            host="h",
            path="/var/data/huge.bin",
            ctx=ctx,
            local_path=str(dest),
        )
    # No partial file, no leftover tmp.
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Mid-transfer failure leaves no partial file
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_partial_failure_cleans_up_tmp_no_partial_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The streaming loop raises mid-transfer; the destination directory
    must end empty (tmp unlinked) and the final path must not exist."""
    _bypass_path_policy(monkeypatch)
    payload = b"abcd" * (200 * 1024)  # ~800 KiB
    dest = tmp_path / "halfdone.bin"
    ctx = _download_ctx(
        content=payload,
        local_roots=[str(tmp_path)],
        raise_at=200 * 1024,  # raise after the first ~200 KiB
    )

    with pytest.raises(RuntimeError, match="simulated transport failure"):
        await ssh_sftp_download(
            host="h",
            path="/var/data/half.bin",
            ctx=ctx,
            local_path=str(dest),
        )

    assert not dest.exists(), "no partial final file should be left behind"
    # Tmp files match the pattern '<name>.ssh-mcp-tmp.<hex>' -- assert none
    # survive the cleanup arm.
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith("halfdone.bin.ssh-mcp-tmp.")]
    assert leftovers == [], f"tmp files leaked after failed download: {leftovers}"


# ---------------------------------------------------------------------------
# Local-path mode disabled when allowlist is empty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_local_path_disabled_when_roots_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_path_policy(monkeypatch)
    dest = tmp_path / "out.bin"
    ctx = _download_ctx(content=b"hi", local_roots=[])

    from ssh_mcp.ssh.errors import LocalPathPolicyError

    with pytest.raises(LocalPathPolicyError, match="SSH_LOCAL_TRANSFER_ROOTS"):
        await ssh_sftp_download(
            host="h",
            path="/var/data/x.bin",
            ctx=ctx,
            local_path=str(dest),
        )


# ---------------------------------------------------------------------------
# Existing base64 behavior unchanged when local_path is omitted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_without_local_path_uses_base64_channel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No `local_path` ⇒ classic base64 round-trip. local_path_written
    is None and the bytes come back inline."""
    import base64

    _bypass_path_policy(monkeypatch)
    payload = b"inline payload"
    ctx = _download_ctx(content=payload, local_roots=[str(tmp_path)])

    result = await ssh_sftp_download(host="h", path="/var/data/x.bin", ctx=ctx)
    assert result.local_path_written is None
    assert result.truncated is False
    assert base64.b64decode(result.content_base64) == payload
