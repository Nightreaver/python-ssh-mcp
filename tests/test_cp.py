"""ssh_cp -- ``cp -a`` wrapper and ``bytes_written`` plumbing.

Pinned contracts:
- Successful file copy populates ``WriteResult.bytes_written`` with the
  src file's byte count (read via SFTP lstat before the shell call).
  Regression: prior versions returned 0 unconditionally, leaving callers
  with a misleading "copied 0 bytes" success line for non-empty files.
- Directory copies leave ``bytes_written=0`` -- aggregating a whole tree
  is too expensive for a best-effort metric.
- ``cp -a`` non-zero exit raises ``WriteError`` with the stderr tail.
- The shell argv is fixed (``cp -a -- src dst``); src/dst go through
  path policy first.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import low_access_tools
from ssh_mcp.tools.low_access_tools import WriteError, ssh_cp


def _policy(alias: str = "web01", platform: str = "posix") -> HostPolicy:
    return HostPolicy(
        hostname=alias,
        user="deploy",
        port=22,
        platform=platform,  # type: ignore[arg-type]
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],
    )


class _FakeSftp:
    """SFTP stub exposing ``lstat`` -- enough for ``ssh_cp``'s pre-copy
    size probe. ``size`` and ``permissions`` are set by the test."""

    def __init__(self, *, size: int = 0, permissions: int = 0o100644) -> None:
        self._size = size
        self._permissions = permissions
        self.lstat_calls: list[str] = []

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def lstat(self, path: str) -> Any:
        self.lstat_calls.append(path)
        attrs = MagicMock()
        attrs.permissions = self._permissions
        attrs.size = self._size
        return attrs


class _FakeRunResult:
    def __init__(self, exit_status: int = 0, stderr: str = "") -> None:
        self.exit_status = exit_status
        self.stderr = stderr


def _ctx(
    sftp: _FakeSftp | None = None,
    *,
    run_result: _FakeRunResult | None = None,
    run_calls: list[str] | None = None,
) -> Any:
    sftp = sftp or _FakeSftp()
    captured = run_calls if run_calls is not None else []

    async def fake_run(cmd: str, *, check: bool = False, **__: Any) -> _FakeRunResult:
        captured.append(cmd)
        return run_result or _FakeRunResult()

    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)
    conn.run = fake_run

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp_policy = MagicMock(return_value=sftp)
    pool.sftp = MagicMock(return_value=sftp)

    hosts = {"web01": _policy()}

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_PATH_ALLOWLIST=["/"],
                ALLOW_LOW_ACCESS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": ["web01"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


def _bypass_path_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Identity stubs for the path-policy resolvers; ssh_cp's flow is what
    we're testing here, not the canonicalizer."""

    async def _resolve(
        _conn: Any, path: str, _policy_arg: Any, _settings: Any, *_a: Any, **_kw: Any
    ) -> str:
        return path

    monkeypatch.setattr(low_access_tools, "resolve_path", _resolve)


# ---------------------------------------------------------------------------
# Regression: bytes_written must reflect the src file's size, not 0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cp_populates_bytes_written_from_src_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """The core bug: ssh_cp reported `bytes_written=0` on every successful
    copy because the result was constructed without the field. Pin the
    fix -- a 1234-byte src must surface bytes_written=1234.
    """
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=1234, permissions=0o100644)
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_cp(host="web01", src="/opt/app/data.bin", dst="/opt/app/data.bak", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 1234, (
        f"ssh_cp returned bytes_written={out.bytes_written}; expected 1234. "
        "Regression: the result must surface the src file size."
    )
    assert out.path == "/opt/app/data.bak"
    assert run_calls == ["cp -a -- /opt/app/data.bin /opt/app/data.bak"]
    assert sftp.lstat_calls == ["/opt/app/data.bin"]


@pytest.mark.asyncio
async def test_cp_empty_file_reports_zero_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A legitimately empty src reports bytes_written=0 -- the same value
    the pre-fix bug produced, but here it's correct rather than a sentinel.
    """
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=0, permissions=0o100644)
    ctx = _ctx(sftp)

    out = await ssh_cp(host="web01", src="/tmp/empty", dst="/tmp/empty.bak", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 0


@pytest.mark.asyncio
async def test_cp_directory_leaves_bytes_written_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """``cp -a dir/ /elsewhere/`` is a recursive copy; aggregating tree
    size on the wire is too expensive for a best-effort metric. The src
    being a directory means lstat returns a non-regular-file mode, so
    the size probe declines to surface a number.
    """
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=4096, permissions=0o040755)  # S_IFDIR
    ctx = _ctx(sftp)

    out = await ssh_cp(host="web01", src="/opt/app/tree", dst="/opt/app/tree.bak", ctx=ctx)

    assert out.success is True
    # The 4096 from the dir inode is intentionally NOT propagated -- it's
    # meaningless to a caller reading "bytes copied".
    assert out.bytes_written == 0


@pytest.mark.asyncio
async def test_cp_sftp_stat_failure_does_not_break_the_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the pre-copy lstat hiccups (transient SFTP error), the copy
    itself must still run. ``bytes_written`` falls back to 0 -- same
    fallback as the no-pre-stat path.
    """
    _bypass_path_policy(monkeypatch)

    class _ExplodingSftp(_FakeSftp):
        async def lstat(self, path: str) -> Any:
            raise asyncssh.SFTPError(asyncssh.sftp.FX_FAILURE, "transient")

    sftp = _ExplodingSftp()
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_cp(host="web01", src="/a", dst="/b", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 0  # fallback
    assert run_calls == ["cp -a -- /a /b"]  # copy still happened


# ---------------------------------------------------------------------------
# cp exit != 0 -> WriteError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cp_non_zero_exit_raises_write_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=10)
    ctx = _ctx(
        sftp,
        run_result=_FakeRunResult(exit_status=1, stderr="cp: cannot stat\n"),
    )

    with pytest.raises(WriteError, match=r"cp failed \(exit 1\)"):
        await ssh_cp(host="web01", src="/a", dst="/b", ctx=ctx)
