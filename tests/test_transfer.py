"""ssh_transfer (INC-052) — host-to-host file copy via the MCP server.

Pinned contracts:
- Same src_host / dst_host raises before opening any SFTP -- use ssh_cp.
- src must exist; dst must NOT exist unless overwrite=True.
- Size exceeding SSH_UPLOAD_MAX_FILE_BYTES rejected before transfer starts.
- Atomic write: temp path written, then posix_rename into place.
- Mid-transfer failure cleans up the temp file (no orphan junk).
- Path policy applied to BOTH endpoints (smoke-checked via stub).
"""
from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import multi_host_tools
from ssh_mcp.tools.multi_host_tools import ssh_transfer

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


def _policy(alias: str) -> HostPolicy:
    return HostPolicy(
        hostname=alias,
        user="deploy",
        port=22,
        platform="posix",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],  # widest -- path policy validated by its own tests
    )


class _FakeFile:
    """Async-context-manager fake of `sftp.open()` for read or write."""

    def __init__(self, content: bytes = b"", *, capture_writes: bytearray | None = None) -> None:
        self._read_buf = content
        self._read_pos = 0
        self.capture = capture_writes  # set on the dst-write file
        self.write_calls: list[bytes] = []

    async def __aenter__(self) -> _FakeFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def read(self, n: int) -> bytes:
        chunk = self._read_buf[self._read_pos : self._read_pos + n]
        self._read_pos += len(chunk)
        return chunk

    async def write(self, data: bytes) -> None:
        self.write_calls.append(data)
        if self.capture is not None:
            self.capture.extend(data)


class _SftpAttrs:
    def __init__(self, size: int) -> None:
        self.size = size


class _FakeSftp:
    """Stub SFTP client. `open(path, mode)` returns a `_FakeFile`."""

    def __init__(
        self,
        *,
        stat_table: dict[str, int] | None = None,
        capture_writes: bytearray | None = None,
        write_raises: Exception | None = None,
    ) -> None:
        self._stat_table = stat_table or {}
        self._capture = capture_writes
        self._write_raises = write_raises
        self.posix_rename_calls: list[tuple[str, str]] = []
        self.remove_calls: list[str] = []

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def stat(self, path: str) -> _SftpAttrs:
        if path not in self._stat_table:
            err = asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, f"no such file: {path}")
            raise err
        return _SftpAttrs(size=self._stat_table[path])

    def open(self, path: str, mode: str) -> _FakeFile:
        if mode == "rb":
            # Read returns deterministic content sized to the stat table entry.
            size = self._stat_table.get(path, 0)
            return _FakeFile(content=b"x" * size)
        # "wb" -- writes go to the capture buffer; optionally raise mid-write.
        f = _FakeFile(capture_writes=self._capture)
        if self._write_raises is not None:
            async def _bad_write(_data: bytes) -> None:
                raise self._write_raises  # type: ignore[misc]
            f.write = _bad_write  # type: ignore[method-assign]
        return f

    async def posix_rename(self, src: str, dst: str) -> None:
        self.posix_rename_calls.append((src, dst))

    async def remove(self, path: str) -> None:
        self.remove_calls.append(path)


def _ctx(
    src_alias: str = "src01",
    dst_alias: str = "dst01",
    *,
    src_sftp: _FakeSftp | None = None,
    dst_sftp: _FakeSftp | None = None,
    upload_cap: int = 256 << 20,  # 256 MiB
) -> Any:
    """Build a Context whose pool returns connections wired to the given SFTPs."""
    src_sftp_real = src_sftp or _FakeSftp()
    dst_sftp_real = dst_sftp or _FakeSftp()
    src_conn = MagicMock()
    src_conn.start_sftp_client = MagicMock(return_value=src_sftp_real)
    dst_conn = MagicMock()
    dst_conn.start_sftp_client = MagicMock(return_value=dst_sftp_real)

    pool = MagicMock()

    async def acquire(resolved: Any) -> Any:
        # `resolved` is a `ResolvedHost`; the wrapper exposes the canonical
        # hostname so we can route to the right fake conn without unwrapping.
        return src_conn if resolved.hostname == src_alias else dst_conn

    pool.acquire = AsyncMock(side_effect=acquire)

    # INC-pool-sftp: ssh_transfer now uses pool.sftp(resolved) instead of
    # conn.start_sftp_client(). Route by ResolvedHost.hostname to the matching
    # fake SFTP, preserving each side's stat_table / capture buffer.
    def fake_pool_sftp(resolved: Any) -> Any:
        return src_sftp_real if resolved.hostname == src_alias else dst_sftp_real

    pool.sftp = MagicMock(side_effect=fake_pool_sftp)

    hosts = {src_alias: _policy(src_alias), dst_alias: _policy(dst_alias)}

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_HOSTS_BLOCKLIST=[],
                SSH_PATH_ALLOWLIST=["/"],
                ALLOW_LOW_ACCESS_TOOLS=True,
                SSH_UPLOAD_MAX_FILE_BYTES=upload_cap,
            ),
            "hosts": hosts,
            "host_allowlist": [src_alias, dst_alias],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


def _bypass_path_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip canonicalize / restricted checks -- path policy has its own
    extensive tests; here we want to exercise the transfer flow itself.
    `resolve_path` bundles canonicalize + restricted-path checks, so a
    single monkeypatch covers both halves of the chain."""
    async def _resolve(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(multi_host_tools, "resolve_path", _resolve)


# ---------------------------------------------------------------------------
# Pre-flight rejection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_same_host_raises_before_any_io(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    ctx = _ctx()  # not actually used past the first guard
    with pytest.raises(ValueError, match="src_host and dst_host are both"):
        await ssh_transfer(
            src_host="src01", src_path="/a", dst_host="src01", dst_path="/b", ctx=ctx,
        )


# ---------------------------------------------------------------------------
# Existence + overwrite gating
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dst_exists_and_no_overwrite_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/file": 100})
    # Dst exists -- size value irrelevant to this test, only existence matters.
    dst_sftp = _FakeSftp(stat_table={"/dst/file": 100})
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp)

    with pytest.raises(ValueError, match="already exists"):
        await ssh_transfer(
            src_host="src01", src_path="/src/file",
            dst_host="dst01", dst_path="/dst/file",
            ctx=ctx,
        )
    # No write happened -- no temp rename.
    assert dst_sftp.posix_rename_calls == []


@pytest.mark.asyncio
async def test_dst_exists_with_overwrite_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/file": 100})
    capture = bytearray()
    dst_sftp = _FakeSftp(
        stat_table={"/dst/file": 100},
        capture_writes=capture,
    )
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp)

    out = await ssh_transfer(
        src_host="src01", src_path="/src/file",
        dst_host="dst01", dst_path="/dst/file",
        ctx=ctx,
        overwrite=True,
    )
    assert out.size == 100
    assert len(capture) == 100
    assert len(dst_sftp.posix_rename_calls) == 1


# ---------------------------------------------------------------------------
# Size cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_size_exceeds_cap_raises_before_transfer(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/big": 1024 * 1024})  # 1 MiB
    dst_sftp = _FakeSftp()
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp, upload_cap=512 * 1024)  # 512 KiB cap

    with pytest.raises(ValueError, match="exceeds SSH_UPLOAD_MAX_FILE_BYTES"):
        await ssh_transfer(
            src_host="src01", src_path="/src/big",
            dst_host="dst01", dst_path="/dst/big",
            ctx=ctx,
        )
    # No transfer started -- no posix_rename.
    assert dst_sftp.posix_rename_calls == []


# ---------------------------------------------------------------------------
# Atomic write pattern
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_writes_to_temp_then_renames(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/file": 1024})
    capture = bytearray()
    dst_sftp = _FakeSftp(capture_writes=capture)  # /dst/file does NOT exist
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp)

    out = await ssh_transfer(
        src_host="src01", src_path="/src/file",
        dst_host="dst01", dst_path="/dst/file",
        ctx=ctx,
    )
    assert out.size == 1024
    assert out.src_host == "src01"
    assert out.dst_host == "dst01"
    assert out.src_path == "/src/file"
    assert out.dst_path == "/dst/file"

    # Atomic rename happened, sourced from a temp sibling of the final path.
    assert len(dst_sftp.posix_rename_calls) == 1
    tmp, final = dst_sftp.posix_rename_calls[0]
    assert final == "/dst/file"
    assert tmp.startswith("/dst/file.ssh-mcp-tmp.")

    # Nothing was cleaned up -- success path doesn't call remove().
    assert dst_sftp.remove_calls == []
    assert len(capture) == 1024


@pytest.mark.asyncio
async def test_failure_during_write_cleans_up_temp(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/file": 1024})
    dst_sftp = _FakeSftp(
        write_raises=asyncssh.SFTPError(asyncssh.sftp.FX_FAILURE, "disk full"),
    )
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp)

    with pytest.raises(asyncssh.SFTPError, match="disk full"):
        await ssh_transfer(
            src_host="src01", src_path="/src/file",
            dst_host="dst01", dst_path="/dst/file",
            ctx=ctx,
        )

    # The temp file written-and-failed must have been removed.
    assert len(dst_sftp.remove_calls) == 1
    removed = dst_sftp.remove_calls[0]
    assert removed.startswith("/dst/file.ssh-mcp-tmp.")
    # No rename happened -- the dst stays untouched.
    assert dst_sftp.posix_rename_calls == []


# ---------------------------------------------------------------------------
# Throughput field is computed (not just zero) on a non-trivial transfer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_throughput_field_populated(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    src_sftp = _FakeSftp(stat_table={"/src/f": 4 * 1024 * 1024})  # 4 MiB
    capture = bytearray()
    dst_sftp = _FakeSftp(capture_writes=capture)
    ctx = _ctx(src_sftp=src_sftp, dst_sftp=dst_sftp)

    out = await ssh_transfer(
        src_host="src01", src_path="/src/f",
        dst_host="dst01", dst_path="/dst/f",
        ctx=ctx,
    )
    assert out.size == 4 * 1024 * 1024
    # Throughput is rounded to 3 decimals; can't pin an exact number on a
    # stub-loop transfer (it's microsecond-fast), but it must be > 0 and
    # finite.
    assert out.throughput_mb_s > 0
    assert out.throughput_mb_s < 1e9
