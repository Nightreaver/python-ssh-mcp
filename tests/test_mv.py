"""ssh_mv -- SFTP rename + cross-fs `mv --` fallback and ``bytes_written``.

Pinned contracts:
- Successful rename populates ``WriteResult.bytes_written`` with the src
  file's byte count (read via SFTP lstat before the rename). Same shape
  as ssh_cp -- regression: the field used to default to 0.
- Cross-device fallback (EXDEV from SFTP) shells out to ``mv -- src dst``
  and also surfaces the captured size.
- Directory moves leave ``bytes_written=0`` -- not a regular file,
  skip the size capture.
- Non-EXDEV SFTPError propagates (no shell fallback).
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import low_access_tools
from ssh_mcp.tools.low_access_tools import WriteError, ssh_mv


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
    """SFTP stub for ssh_mv -- exposes ``lstat`` + ``posix_rename``.

    ``rename_raises`` lets a test simulate EXDEV (FX_FAILURE in OpenSSH's
    sshd_protocol_v3 mapping) so the cross-fs branch is exercised.
    """

    def __init__(
        self,
        *,
        size: int = 0,
        permissions: int = 0o100644,
        rename_raises: Exception | None = None,
    ) -> None:
        self._size = size
        self._permissions = permissions
        self._rename_raises = rename_raises
        self.lstat_calls: list[str] = []
        self.rename_calls: list[tuple[str, str]] = []

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

    async def posix_rename(self, src: str, dst: str) -> None:
        self.rename_calls.append((src, dst))
        if self._rename_raises is not None:
            raise self._rename_raises


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
    async def _resolve(
        _conn: Any, path: str, _policy_arg: Any, _settings: Any, *_a: Any, **_kw: Any
    ) -> str:
        return path

    monkeypatch.setattr(low_access_tools, "resolve_path", _resolve)


# ---------------------------------------------------------------------------
# Same-fs rename: bytes_written carries src size
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mv_sftp_rename_populates_bytes_written(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=2048, permissions=0o100644)
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_mv(host="web01", src="/opt/a", dst="/opt/b", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 2048
    assert sftp.rename_calls == [("/opt/a", "/opt/b")]
    assert run_calls == []  # no shell fallback on same-fs
    assert "sftp-rename" in (out.message or "")


@pytest.mark.asyncio
async def test_mv_directory_leaves_bytes_written_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Directory rename via SFTP succeeds, but ``bytes_written`` stays 0 --
    aggregating tree size is too expensive for a best-effort metric.
    """
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(size=4096, permissions=0o040755)  # S_IFDIR
    ctx = _ctx(sftp)

    out = await ssh_mv(host="web01", src="/opt/tree", dst="/opt/tree.new", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 0


# ---------------------------------------------------------------------------
# Cross-fs fallback: EXDEV from SFTP -> shell `mv --`
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mv_cross_fs_fallback_uses_shell_and_reports_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SFTP rename refuses cross-device with FX_FAILURE; the shell `mv --`
    fallback runs and the result carries the src size."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(
        size=512,
        permissions=0o100644,
        rename_raises=asyncssh.SFTPError(asyncssh.sftp.FX_FAILURE, "cross-device"),
    )
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_mv(host="web01", src="/opt/a", dst="/mnt/other/b", ctx=ctx)

    assert out.success is True
    assert out.bytes_written == 512
    assert run_calls == ["mv -- /opt/a /mnt/other/b"]
    assert "mv-fallback" in (out.message or "")


@pytest.mark.asyncio
async def test_mv_cross_fs_shell_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(
        size=10,
        rename_raises=asyncssh.SFTPError(asyncssh.sftp.FX_FAILURE, "cross-device"),
    )
    ctx = _ctx(sftp, run_result=_FakeRunResult(exit_status=1, stderr="mv: no perm\n"))

    with pytest.raises(WriteError, match=r"mv failed \(exit 1\)"):
        await ssh_mv(host="web01", src="/opt/a", dst="/mnt/other/b", ctx=ctx)


# ---------------------------------------------------------------------------
# Non-EXDEV SFTP errors propagate without shell fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mv_permission_denied_propagates_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-cross-device SFTP error (FX_PERMISSION_DENIED) must NOT trigger
    the shell fallback -- the cross-fs branch is reserved for the codes
    ``_is_cross_device`` recognises.
    """
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(
        rename_raises=asyncssh.SFTPError(asyncssh.sftp.FX_PERMISSION_DENIED, "denied"),
    )
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    with pytest.raises(asyncssh.SFTPError, match="denied"):
        await ssh_mv(host="web01", src="/opt/a", dst="/opt/b", ctx=ctx)
    assert run_calls == []
