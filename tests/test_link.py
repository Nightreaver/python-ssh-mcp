"""ssh_link (INC-056): hard links via SFTP (-L) or shell `ln -P` (-P).

Pinned contracts:
- `follow_symlinks=True` (default) calls SFTP `link()` directly with
  the canonicalized src + dst.
- `follow_symlinks=False` falls back to shell `ln -P -- <src> <dst>`
  via `conn.run` with shlex-joined argv.
- Both modes route src and dst through path policy.
- `-P` mode validates src via parent-canonicalize + lstat (NOT full
  canonicalize -- canonicalizing would defeat the point).
- Existing dst raises (no force / overwrite).
- POSIX-only (require_posix).
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools.low_access import link_tools
from ssh_mcp.tools.low_access_tools import WriteError, ssh_link


def _policy(alias: str = "web01", platform: str = "posix") -> HostPolicy:
    return HostPolicy(
        hostname=alias,
        user="deploy",
        port=22,
        platform=platform,  # type: ignore[arg-type]
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],  # widest -- path policy validated by its own tests
    )


class _FakeSftp:
    def __init__(
        self,
        *,
        link_raises: Exception | None = None,
        symlink_raises: Exception | None = None,
        lstat_missing: list[str] | None = None,
    ) -> None:
        self.link_raises = link_raises
        self.symlink_raises = symlink_raises
        self.lstat_missing = lstat_missing or []
        self.link_calls: list[tuple[str, str]] = []
        self.symlink_calls: list[tuple[str, str]] = []
        self.lstat_calls: list[str] = []

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def link(self, src: str, dst: str) -> None:
        self.link_calls.append((src, dst))
        if self.link_raises is not None:
            raise self.link_raises

    async def symlink(self, src: str, dst: str) -> None:
        self.symlink_calls.append((src, dst))
        if self.symlink_raises is not None:
            raise self.symlink_raises

    async def lstat(self, path: str) -> Any:
        self.lstat_calls.append(path)
        if path in self.lstat_missing:
            raise asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, f"missing: {path}")
        attrs = MagicMock()
        attrs.permissions = 0o100644  # regular file
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
    """Stub Context whose pool returns a conn wired to the given fake SFTP
    + a `conn.run` that records argv strings and returns `run_result`."""
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
    # INC-pool-sftp: tools now go through pool.sftp_policy(...) / pool.sftp(...)
    # which are async context managers yielding the SFTPClient. Wire them to
    # the same _FakeSftp the test set up so the existing assertions on
    # symlink_calls / link_calls / lstat_calls still work.
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
    """Stub canonicalize_and_check / check_not_restricted to identity --
    path policy has its own dedicated tests; here we exercise ssh_link's
    flow choices, not the canonicalizer.

    INC-043-style split: `ssh_link` body lives in `low_access.link_tools`;
    patch the bindings on that submodule -- patching the facade is a no-op.
    """

    async def _canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(link_tools, "canonicalize_and_check", _canon)
    monkeypatch.setattr(link_tools, "check_not_restricted", lambda *_a, **_kw: None)


# ---------------------------------------------------------------------------
# Default mode (-L): pure SFTP
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_uses_sftp_link(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_link(
        host="web01",
        src="/opt/app/build-1234",
        dst="/opt/app/current",
        ctx=ctx,
    )
    assert sftp.link_calls == [("/opt/app/build-1234", "/opt/app/current")]
    assert run_calls == []  # no shell fallback
    assert out.success is True
    assert out.path == "/opt/app/current"
    assert "followed symlinks" in out.message


@pytest.mark.asyncio
async def test_default_propagates_sftp_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing dst -- SFTP raises FX_FAILURE / FX_FILE_ALREADY_EXISTS;
    we don't catch it. The LLM gets a real SFTPError it can react to."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(link_raises=asyncssh.SFTPError(asyncssh.sftp.FX_FAILURE, "dst exists"))
    ctx = _ctx(sftp)

    with pytest.raises(asyncssh.SFTPError, match="dst exists"):
        await ssh_link(host="web01", src="/a", dst="/b", ctx=ctx)


# ---------------------------------------------------------------------------
# -P mode: shell fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_p_mode_uses_shell_ln_p(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_link(
        host="web01",
        src="/etc/alternatives/python",
        dst="/opt/migration/python.bak",
        ctx=ctx,
        follow_symlinks=False,
    )
    # No SFTP link call -- shell path took over.
    assert sftp.link_calls == []
    # lstat verified src existence in -P mode.
    assert sftp.lstat_calls == ["/etc/alternatives/python"]
    # Shell fallback ran ln -P with shlex-joined argv.
    assert len(run_calls) == 1
    cmd = run_calls[0]
    assert cmd.startswith("ln -P --")
    assert "/etc/alternatives/python" in cmd
    assert "/opt/migration/python.bak" in cmd
    assert "physical" in out.message


@pytest.mark.asyncio
async def test_p_mode_lstat_missing_raises_clean_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """src not present per lstat -> ValueError with the canonical path,
    not a raw SFTPError."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp(lstat_missing=["/etc/missing"])
    ctx = _ctx(sftp)

    with pytest.raises(ValueError, match="src does not exist"):
        await ssh_link(
            host="web01",
            src="/etc/missing",
            dst="/opt/x",
            ctx=ctx,
            follow_symlinks=False,
        )


@pytest.mark.asyncio
async def test_p_mode_shell_failure_raises_writeerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    ctx = _ctx(
        sftp,
        run_result=_FakeRunResult(exit_status=1, stderr="ln: failed to create hard link"),
    )

    with pytest.raises(WriteError, match="ln -P failed.*exit 1.*failed to create"):
        await ssh_link(
            host="web01",
            src="/a",
            dst="/b",
            ctx=ctx,
            follow_symlinks=False,
        )


@pytest.mark.asyncio
async def test_p_mode_rejects_directory_only_src(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare directory path with no filename can't be a hardlink
    source -- raise before any SFTP call."""
    _bypass_path_policy(monkeypatch)
    ctx = _ctx()

    with pytest.raises(ValueError, match="must include a filename"):
        await ssh_link(
            host="web01",
            src="/etc/",
            dst="/opt/x",
            ctx=ctx,
            follow_symlinks=False,
        )


# ---------------------------------------------------------------------------
# Platform gate
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Symbolic mode (-s): SFTP symlink, both-sides path validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_symbolic_uses_sftp_symlink_with_verbatim_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sftp.symlink receives src VERBATIM (not canonicalized) so relative
    semantics are preserved on disk."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    out = await ssh_link(
        host="web01",
        src="/opt/app/release-v2",
        dst="/opt/app/current",
        ctx=ctx,
        symbolic=True,
    )
    # sftp.symlink called with the original src; no hard-link path taken.
    assert sftp.symlink_calls == [("/opt/app/release-v2", "/opt/app/current")]
    assert sftp.link_calls == []
    assert run_calls == []
    assert "symbolic link" in out.message


@pytest.mark.asyncio
async def test_symbolic_relative_target_passed_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Relative targets are stored as-is on disk -- this is the whole point
    of relative symlinks (they continue to resolve correctly if dst moves)."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    ctx = _ctx(sftp)

    await ssh_link(
        host="web01",
        src="../release-v2",
        dst="/opt/app/current",
        ctx=ctx,
        symbolic=True,
    )
    assert sftp.symlink_calls == [("../release-v2", "/opt/app/current")]


@pytest.mark.asyncio
async def test_symbolic_dangling_target_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSIX permits dangling symlinks (target need not exist). The tool's
    symbolic-mode code path does NOT call realpath on the target -- it
    only does string-based allowlist + restricted-paths checks. So a
    target that doesn't exist on disk is accepted."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    ctx = _ctx(sftp)

    await ssh_link(
        host="web01",
        src="/will-exist-later/release-v3",  # doesn't exist; fine
        dst="/opt/app/future",
        ctx=ctx,
        symbolic=True,
    )
    # No lstat call on the target either -- truly no remote check.
    assert sftp.lstat_calls == []
    assert sftp.symlink_calls == [
        ("/will-exist-later/release-v3", "/opt/app/future"),
    ]


@pytest.mark.asyncio
async def test_symbolic_target_outside_allowlist_raises() -> None:
    """Both sides of the link checked: target outside allowlist rejected
    even though POSIX would let the symlink be created."""
    from ssh_mcp.ssh.errors import PathNotAllowed

    # Real path policy this time -- with a narrow allowlist.
    pool = MagicMock()

    async def fake_run(*_a: Any, **_kw: Any) -> _FakeRunResult:
        return _FakeRunResult()

    sftp = _FakeSftp()
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)
    conn.run = fake_run
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp_policy = MagicMock(return_value=sftp)
    pool.sftp = MagicMock(return_value=sftp)

    hosts = {
        "web01": HostPolicy(
            hostname="web01",
            user="deploy",
            port=22,
            platform="posix",
            auth=AuthPolicy(method="agent"),
            path_allowlist=["/opt/app"],  # narrow
        ),
    }

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_PATH_ALLOWLIST=[],
                ALLOW_LOW_ACCESS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": ["web01"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    # Stub canonicalize_and_check on the dst to skip the realpath round-trip
    # (we want to exercise the symbolic-target check, not the dst check).
    async def _canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch_inline = pytest.MonkeyPatch()
    # Patch the submodule binding (ssh_link's body lives in `link_tools`).
    monkeypatch_inline.setattr(link_tools, "canonicalize_and_check", _canon)
    try:
        with pytest.raises(PathNotAllowed, match="outside the allowlist"):
            await ssh_link(
                host="web01",
                src="/etc/shadow",  # outside /opt/app
                dst="/opt/app/leak",  # inside /opt/app
                ctx=_Ctx(),
                symbolic=True,
            )
        # No symlink was created -- the check raised before the SFTP call.
        assert sftp.symlink_calls == []
    finally:
        monkeypatch_inline.undo()


@pytest.mark.asyncio
async def test_symbolic_relative_target_resolved_against_dst_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relative target is policy-checked AS-IF resolved relative to dst's
    parent dir. If dst is /opt/app/current and target is `../bad`, the
    check evaluates `/opt/bad`, which may or may not be allowlisted."""
    from ssh_mcp.ssh.errors import PathNotAllowed

    sftp = _FakeSftp()

    pool = MagicMock()
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)

    async def fake_run(*_a: Any, **_kw: Any) -> _FakeRunResult:
        return _FakeRunResult()

    conn.run = fake_run
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp_policy = MagicMock(return_value=sftp)
    pool.sftp = MagicMock(return_value=sftp)

    hosts = {
        "web01": HostPolicy(
            hostname="web01",
            user="deploy",
            port=22,
            platform="posix",
            auth=AuthPolicy(method="agent"),
            path_allowlist=["/opt/app"],
        ),
    }

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_PATH_ALLOWLIST=[],
                ALLOW_LOW_ACCESS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": ["web01"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    async def _canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    mp = pytest.MonkeyPatch()
    mp.setattr(link_tools, "canonicalize_and_check", _canon)
    try:
        # dst=/opt/app/current; target=../../etc/foo -> resolves to /etc/foo
        # which is OUTSIDE /opt/app -> PathNotAllowed.
        with pytest.raises(PathNotAllowed, match="outside the allowlist"):
            await ssh_link(
                host="web01",
                src="../../etc/foo",
                dst="/opt/app/current",
                ctx=_Ctx(),
                symbolic=True,
            )
        assert sftp.symlink_calls == []
    finally:
        mp.undo()


@pytest.mark.asyncio
async def test_symbolic_rejects_nul_bytes_in_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """reject_bad_characters runs on the target before any policy check."""
    from ssh_mcp.ssh.errors import PathNotAllowed

    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    ctx = _ctx(sftp)

    with pytest.raises(PathNotAllowed, match="NUL"):
        await ssh_link(
            host="web01",
            src="/opt/app/release\x00bad",
            dst="/opt/app/current",
            ctx=ctx,
            symbolic=True,
        )
    assert sftp.symlink_calls == []


@pytest.mark.asyncio
async def test_symbolic_ignores_follow_symlinks_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GNU `ln`: 'Using -s ignores -L and -P.' Same here -- pass
    follow_symlinks=False with symbolic=True and it does NOT trigger the
    shell `ln -P` path. Pure SFTP symlink."""
    _bypass_path_policy(monkeypatch)
    sftp = _FakeSftp()
    run_calls: list[str] = []
    ctx = _ctx(sftp, run_calls=run_calls)

    await ssh_link(
        host="web01",
        src="/opt/app/release",
        dst="/opt/app/current",
        ctx=ctx,
        symbolic=True,
        follow_symlinks=False,  # ignored
    )
    assert sftp.symlink_calls == [("/opt/app/release", "/opt/app/current")]
    assert sftp.link_calls == []
    assert run_calls == []  # no shell fallback


# ---------------------------------------------------------------------------
# Platform gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_windows_target_raises_platform_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _bypass_path_policy(monkeypatch)
    pool = MagicMock()
    pool.acquire = AsyncMock()
    hosts = {"win01": _policy("win01", platform="windows")}

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
            "host_allowlist": ["win01"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    from ssh_mcp.ssh.errors import PlatformNotSupported

    with pytest.raises(PlatformNotSupported, match="ssh_link"):
        await ssh_link(host="win01", src="/a", dst="/b", ctx=_Ctx())
