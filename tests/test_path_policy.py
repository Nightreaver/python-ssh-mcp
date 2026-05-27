"""services/path_policy — canonicalize, allowlist enforcement, bad-char rejection."""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.path_policy import (
    canonicalize,
    canonicalize_and_check,
    check_in_allowlist,
    effective_allowlist,
    reject_bad_characters,
)
from ssh_mcp.ssh.errors import PathNotAllowed


@dataclass
class FakeProcResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


class FakeConn:
    """Scripted conn.run -- keyed by shlex.join(argv).

    Real code now passes the shell-joined string to `conn.run` (asyncssh's
    `run` crashes on a list with "can't concat list to bytes"). Script keys
    match that shape so tests stay faithful to what the real transport sees.

    Also provides a stub ``start_sftp_client`` whose SFTP ``realpath`` raises
    by default. Reason: ``_canonicalize_posix`` now falls back to SFTP
    realpath when the shell call fails (chroot fix), and existing
    ``test_canonicalize_failure_raises``-style tests expect the original
    ``PathNotAllowed`` to propagate. The default raise keeps that contract
    -- tests that need a working SFTP override ``start_sftp_client``.
    """

    def __init__(self) -> None:
        self.script: dict[str, FakeProcResult] = {}
        self.calls: list[str] = []

    def set(self, argv: list[str], *, stdout: str = "", stderr: str = "", exit_status: int = 0) -> None:
        import shlex

        self.script[shlex.join(argv)] = FakeProcResult(
            stdout=stdout, stderr=stderr, exit_status=exit_status
        )

    async def run(self, command: str, *, check: bool = False) -> FakeProcResult:
        self.calls.append(command)
        try:
            return self.script[command]
        except KeyError as exc:
            raise AssertionError(f"unscripted conn.run({command!r})") from exc

    def start_sftp_client(self) -> _FakeUnavailableSftp:
        return _FakeUnavailableSftp()


class _FakeUnavailableSftp:
    """Default SFTP stub for ``FakeConn`` -- every realpath / stat raises.

    Models the canonical "shell realpath failed AND host has no usable SFTP"
    case, which is what the pre-chroot-fix tests implicitly assumed.
    """

    async def __aenter__(self) -> _FakeUnavailableSftp:
        return self

    async def __aexit__(self, *_) -> None:  # type: ignore[no-untyped-def]
        return None

    async def realpath(self, _path: str) -> str:
        import asyncssh

        raise asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file (stub)")

    async def stat(self, _path: str) -> object:
        import asyncssh

        raise asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file (stub)")


def _policy(allow: list[str]) -> HostPolicy:
    return HostPolicy(
        hostname="web.internal",
        user="deploy",
        port=22,
        path_allowlist=allow,
        auth=AuthPolicy(method="agent"),
    )


def _settings(allow: list[str] | None = None) -> Settings:
    return Settings(  # type: ignore[call-arg]
        SSH_PATH_ALLOWLIST=allow or [],
        SSH_HOSTS_ALLOWLIST=["web.internal"],
    )


# --- reject_bad_characters ---


def test_nul_rejected() -> None:
    with pytest.raises(PathNotAllowed, match="NUL"):
        reject_bad_characters("/etc/pass\x00wd")


def test_control_char_rejected() -> None:
    with pytest.raises(PathNotAllowed, match="control"):
        reject_bad_characters("/etc/conf\x1b")


def test_empty_rejected() -> None:
    with pytest.raises(PathNotAllowed, match="empty"):
        reject_bad_characters("")


# --- check_in_allowlist ---


def test_exact_match_allowed() -> None:
    check_in_allowlist("/opt/app", ["/opt/app"])


def test_subdirectory_allowed() -> None:
    check_in_allowlist("/opt/app/config.yml", ["/opt/app"])


def test_sibling_rejected() -> None:
    with pytest.raises(PathNotAllowed):
        check_in_allowlist("/opt/app2", ["/opt/app"])


def test_empty_allowlist_rejects_everything() -> None:
    with pytest.raises(PathNotAllowed, match="no SSH_PATH_ALLOWLIST"):
        check_in_allowlist("/opt/app", [])


def test_star_sentinel_allows_any_path() -> None:
    check_in_allowlist("/etc/shadow", ["*"])
    check_in_allowlist("/", ["*"])
    check_in_allowlist("/home/user/deep/nested/path", ["*"])


def test_slash_sentinel_allows_any_path() -> None:
    # "/" is the other natural spelling of "allow everything" -- both supported.
    check_in_allowlist("/etc/shadow", ["/"])
    check_in_allowlist("/opt/app/config", ["/"])


def test_sentinel_alongside_other_roots_still_allows() -> None:
    # Sentinel wins; extra roots are irrelevant.
    check_in_allowlist("/anywhere", ["/opt/app", "*"])


# --- restricted paths ---


def test_check_not_restricted_empty_list_is_noop() -> None:
    from ssh_mcp.services.path_policy import check_not_restricted

    check_not_restricted("/opt/app/file", [])  # no raise


def test_check_not_restricted_allows_outside_zone() -> None:
    from ssh_mcp.services.path_policy import check_not_restricted

    check_not_restricted("/opt/app/file", ["/mnt/shared"])


def test_check_not_restricted_rejects_inside_zone() -> None:
    from ssh_mcp.services.path_policy import check_not_restricted
    from ssh_mcp.ssh.errors import PathRestricted

    with pytest.raises(PathRestricted, match="restricted"):
        check_not_restricted("/mnt/shared/data.csv", ["/mnt/shared"])


def test_check_not_restricted_rejects_exact_root_match() -> None:
    from ssh_mcp.services.path_policy import check_not_restricted
    from ssh_mcp.ssh.errors import PathRestricted

    with pytest.raises(PathRestricted):
        check_not_restricted("/mnt/shared", ["/mnt/shared"])


def test_check_not_restricted_sibling_allowed() -> None:
    # /mnt/shared2 is NOT inside /mnt/shared.
    from ssh_mcp.services.path_policy import check_not_restricted

    check_not_restricted("/mnt/shared2/data", ["/mnt/shared"])


def test_check_not_restricted_multiple_zones() -> None:
    from ssh_mcp.services.path_policy import check_not_restricted
    from ssh_mcp.ssh.errors import PathRestricted

    zones = ["/mnt/shared", "/mnt/backups"]
    with pytest.raises(PathRestricted, match="backups"):
        check_not_restricted("/mnt/backups/db.sql", zones)


def test_effective_restricted_paths_unions_host_and_env() -> None:
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy
    from ssh_mcp.services.path_policy import effective_restricted_paths

    policy = HostPolicy(
        hostname="docker1",
        user="root",
        auth=AuthPolicy(method="agent"),
        restricted_paths=["/mnt/shared"],
    )
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_ALLOWLIST=["docker1"],
        SSH_RESTRICTED_PATHS=["/mnt/fleet"],
    )
    merged = effective_restricted_paths(policy, settings)
    assert merged == ["/mnt/shared", "/mnt/fleet"]


def test_effective_restricted_paths_dedupes() -> None:
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy
    from ssh_mcp.services.path_policy import effective_restricted_paths

    policy = HostPolicy(
        hostname="docker1",
        user="root",
        auth=AuthPolicy(method="agent"),
        restricted_paths=["/mnt/shared"],
    )
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_ALLOWLIST=["docker1"],
        SSH_RESTRICTED_PATHS=["/mnt/shared"],
    )
    merged = effective_restricted_paths(policy, settings)
    assert merged == ["/mnt/shared"]


def test_host_policy_rejects_relative_restricted_path() -> None:
    from pydantic import ValidationError

    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    with pytest.raises(ValidationError, match="restricted_paths"):
        HostPolicy(
            hostname="docker1",
            user="root",
            auth=AuthPolicy(method="agent"),
            restricted_paths=["relative/path"],
        )


def test_trailing_slash_in_root_normalized() -> None:
    # An allowlist entry of "/opt/app/" should still match "/opt/app/foo".
    check_in_allowlist("/opt/app/foo", ["/opt/app/"])


# --- effective_allowlist merge ---


def test_allowlist_merges_per_host_plus_env_dedup_preserve_order() -> None:
    policy = _policy(["/opt/app", "/var/log"])
    settings = _settings(["/var/log", "/etc/nginx"])
    merged = effective_allowlist(policy, settings)
    assert merged == ["/opt/app", "/var/log", "/etc/nginx"]


# --- canonicalize (fake conn) ---


@pytest.mark.asyncio
async def test_canonicalize_success() -> None:
    conn = FakeConn()
    conn.set(["realpath", "-e", "--", "/opt/app/config"], stdout="/opt/app/config\n")
    assert await canonicalize(conn, "/opt/app/config", must_exist=True) == "/opt/app/config"


@pytest.mark.asyncio
async def test_canonicalize_must_exist_false_adds_m_flag() -> None:
    conn = FakeConn()
    conn.set(["realpath", "-m", "--", "/opt/app/new.txt"], stdout="/opt/app/new.txt\n")
    result = await canonicalize(conn, "/opt/app/new.txt", must_exist=False)
    assert result == "/opt/app/new.txt"


@pytest.mark.asyncio
async def test_canonicalize_failure_raises() -> None:
    conn = FakeConn()
    conn.set(
        ["realpath", "-e", "--", "/missing"],
        stderr="realpath: /missing: No such file or directory",
        exit_status=1,
    )
    with pytest.raises(PathNotAllowed, match="cannot canonicalize"):
        await canonicalize(conn, "/missing", must_exist=True)


@pytest.mark.asyncio
async def test_canonicalize_rejects_bad_input_before_wire() -> None:
    conn = FakeConn()  # no script — assertion fires if we call run()
    with pytest.raises(PathNotAllowed):
        await canonicalize(conn, "/bad\x00path", must_exist=True)
    assert conn.calls == []


# --- canonicalize_and_check end-to-end ---


@pytest.mark.asyncio
async def test_canonicalize_and_check_traversal_blocked() -> None:
    conn = FakeConn()
    # Caller asks for /opt/app/../../../etc/passwd; server canonicalizes to /etc/passwd
    conn.set(
        ["realpath", "-e", "--", "/opt/app/../../../etc/passwd"],
        stdout="/etc/passwd\n",
    )
    with pytest.raises(PathNotAllowed, match="outside the allowlist"):
        await canonicalize_and_check(
            conn, "/opt/app/../../../etc/passwd", ["/opt/app"], must_exist=True
        )


@pytest.mark.asyncio
async def test_canonicalize_and_check_symlink_out_of_allowlist() -> None:
    conn = FakeConn()
    conn.set(
        ["realpath", "-e", "--", "/opt/app/evil_link"],
        stdout="/root/.ssh/authorized_keys\n",
    )
    with pytest.raises(PathNotAllowed):
        await canonicalize_and_check(
            conn, "/opt/app/evil_link", ["/opt/app"], must_exist=True
        )


@pytest.mark.asyncio
async def test_canonicalize_and_check_inside_allowlist() -> None:
    conn = FakeConn()
    conn.set(["realpath", "-e", "--", "/opt/app/real"], stdout="/opt/app/real\n")
    result = await canonicalize_and_check(conn, "/opt/app/real", ["/opt/app"], must_exist=True)
    assert result == "/opt/app/real"


# ---------------------------------------------------------------------------
# pool + policy half-contract guard
# ---------------------------------------------------------------------------
#
# ``pool`` and ``policy`` are jointly required for the pool-cached SFTP code
# path (Windows realpath probe). Passing one without the other silently fell
# back to per-call SFTP in earlier revisions, which masked bugs at the call
# site. The both-or-neither check raises ``TypeError`` so the mismatched
# call fails loudly and is fixed at its origin.


@pytest.mark.asyncio
async def test_canonicalize_rejects_pool_without_policy() -> None:
    from unittest.mock import MagicMock

    conn = FakeConn()
    with pytest.raises(TypeError, match="pool and policy must be passed together"):
        await canonicalize(conn, "/opt/app/x", must_exist=False, pool=MagicMock(), policy=None)


@pytest.mark.asyncio
async def test_canonicalize_rejects_policy_without_pool() -> None:
    conn = FakeConn()
    policy = HostPolicy(hostname="h", user="u", auth=AuthPolicy(method="agent"))
    with pytest.raises(TypeError, match="pool and policy must be passed together"):
        await canonicalize(conn, "/opt/app/x", must_exist=False, pool=None, policy=policy)


# ---------------------------------------------------------------------------
# Windows canonicalize: single SFTPClient channel per call (fallback path)
# ---------------------------------------------------------------------------
#
# Regression: ``_canonicalize_windows`` used to open TWO SFTP channels per
# call when no pool was threaded in (one for ``realpath``, one for the
# ``must_exist`` stat). DSM-style servers cap MaxSessions and the doubled
# channel pressure would surface as ChannelOpenError on bursty workloads.
# The fix consolidates both probes into one ``async with`` block. The pool-
# cached path already shared a channel via cache, so the regression only
# bit callers (docker tools + unit tests) on the fallback path.


@pytest.mark.asyncio
async def test_windows_canonicalize_opens_single_sftp_channel_in_fallback() -> None:
    from typing import Any
    from unittest.mock import MagicMock

    sftp_open_count = {"n": 0}

    class _FakeSftp:
        async def __aenter__(self) -> _FakeSftp:
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

        async def realpath(self, _path: str) -> str:
            return "C:\\opt\\app"

        async def stat(self, _path: str) -> Any:
            return MagicMock()

    class _FakeWinConn:
        def start_sftp_client(self) -> _FakeSftp:
            sftp_open_count["n"] += 1
            return _FakeSftp()

    conn = _FakeWinConn()
    # must_exist=True exercises BOTH probes (realpath + stat); the fix
    # must collapse them onto one SFTPClient.
    result = await canonicalize(
        conn,  # type: ignore[arg-type]
        "C:\\opt\\app",
        must_exist=True,
        platform="windows",
    )
    assert result == "C:\\opt\\app"
    assert sftp_open_count["n"] == 1, (
        f"_canonicalize_windows opened {sftp_open_count['n']} SFTP channels; "
        "expected exactly 1 (single channel for realpath + must_exist stat). "
        "Regression: the fallback path is reopening a channel per probe."
    )


@pytest.mark.asyncio
async def test_windows_canonicalize_must_exist_false_also_single_channel() -> None:
    """``must_exist=False`` only runs realpath -- still must be one channel,
    never zero (we always do the realpath probe)."""
    from typing import Any

    sftp_open_count = {"n": 0}

    class _FakeSftp:
        async def __aenter__(self) -> _FakeSftp:
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

        async def realpath(self, _path: str) -> str:
            return "C:\\opt\\app"

    class _FakeWinConn:
        def start_sftp_client(self) -> _FakeSftp:
            sftp_open_count["n"] += 1
            return _FakeSftp()

    conn = _FakeWinConn()
    result = await canonicalize(
        conn,  # type: ignore[arg-type]
        "C:\\opt\\app",
        must_exist=False,
        platform="windows",
    )
    assert result == "C:\\opt\\app"
    assert sftp_open_count["n"] == 1


@pytest.mark.asyncio
async def test_canonicalize_and_check_rejects_half_contract() -> None:
    from unittest.mock import MagicMock

    conn = FakeConn()
    with pytest.raises(TypeError, match="pool and policy must be passed together"):
        await canonicalize_and_check(
            conn, "/opt/app/x", ["/opt/app"], must_exist=False, pool=MagicMock(), policy=None
        )


# ---------------------------------------------------------------------------
# Chrooted-SFTP fallback (POSIX): shell `realpath` fails because the user
# shell sees the real-FS view (e.g. /volume1/docker/...) while the SFTP
# subsystem sees the chroot view (e.g. /docker/...). The LLM gets paths
# from SFTP discovery (`ssh_sftp_list`), so canonicalizing those against
# the shell view ENOENTs. _canonicalize_posix falls back to SFTP-protocol
# realpath, which resolves in the same view subsequent SFTP ops will use.
# ---------------------------------------------------------------------------


class _FakeSftpForRealpath:
    """SFTPClient stub exposing only ``realpath`` + ``stat`` -- enough for
    the chroot-fallback code path in ``_canonicalize_posix``."""

    def __init__(
        self,
        *,
        realpath_map: dict[str, str] | None = None,
        realpath_raises: Exception | None = None,
        stat_missing: set[str] | None = None,
    ) -> None:
        self._realpath_map = realpath_map or {}
        self._realpath_raises = realpath_raises
        self._stat_missing = stat_missing or set()
        self.realpath_calls: list[str] = []
        self.stat_calls: list[str] = []

    async def __aenter__(self) -> _FakeSftpForRealpath:
        return self

    async def __aexit__(self, *_) -> None:  # type: ignore[no-untyped-def]
        return None

    async def realpath(self, path: str) -> str:
        self.realpath_calls.append(path)
        if self._realpath_raises is not None:
            raise self._realpath_raises
        if path in self._realpath_map:
            return self._realpath_map[path]
        # Default: return the input unchanged (mimics a server that just
        # echoes the path back, like DSM chroot SFTP appears to).
        return path

    async def stat(self, path: str) -> object:
        import asyncssh

        self.stat_calls.append(path)
        if path in self._stat_missing:
            raise asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file")

        class _Attrs:
            permissions = 0o100644
            size = 0

        return _Attrs()


class _FakeConnWithSftp(FakeConn):
    """FakeConn extension that also serves the SFTP-protocol realpath
    fallback via ``start_sftp_client``."""

    def __init__(self, *, sftp: _FakeSftpForRealpath) -> None:
        super().__init__()
        self._sftp = sftp
        self.start_sftp_calls = 0

    def start_sftp_client(self) -> _FakeSftpForRealpath:
        self.start_sftp_calls += 1
        return self._sftp


@pytest.mark.asyncio
async def test_canonicalize_falls_back_to_sftp_realpath_on_shell_enoent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The chroot scenario: shell realpath returns ENOENT, SFTP realpath
    resolves the path in the chroot view. The fallback fires and the
    returned canonical path is the SFTP view's answer.
    """
    import logging

    sftp = _FakeSftpForRealpath(realpath_map={"/docker/grafana": "/docker/grafana"})
    conn = _FakeConnWithSftp(sftp=sftp)
    conn.set(
        ["realpath", "-e", "--", "/docker/grafana"],
        stderr="realpath: /docker/grafana: No such file or directory",
        exit_status=1,
    )
    caplog.set_level(logging.WARNING, logger="ssh_mcp.services.path_policy")

    result = await canonicalize(conn, "/docker/grafana", must_exist=True)  # type: ignore[arg-type]

    assert result == "/docker/grafana"
    assert sftp.realpath_calls == ["/docker/grafana"]
    # must_exist=True triggers a verifying stat after the SFTP realpath.
    assert sftp.stat_calls == ["/docker/grafana"]
    # The warning is the operator's signal that something view-mismatched.
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("SFTP-protocol realpath fallback" in m for m in warnings), (
        f"expected fallback warning in logs, got {warnings!r}"
    )
    assert any("chrooted SFTP" in m for m in warnings)


@pytest.mark.asyncio
async def test_canonicalize_skips_sftp_when_shell_realpath_succeeds() -> None:
    """Non-chroot path: shell realpath works on the first try, SFTP is
    NEVER consulted -- zero extra round-trip cost for healthy hosts.
    """
    sftp = _FakeSftpForRealpath()
    conn = _FakeConnWithSftp(sftp=sftp)
    conn.set(["realpath", "-e", "--", "/opt/app/x"], stdout="/opt/app/x\n")

    result = await canonicalize(conn, "/opt/app/x", must_exist=True)  # type: ignore[arg-type]

    assert result == "/opt/app/x"
    assert sftp.realpath_calls == [], "SFTP fallback must not fire on healthy shell realpath"
    assert conn.start_sftp_calls == 0


@pytest.mark.asyncio
async def test_canonicalize_raises_when_both_realpaths_fail() -> None:
    """Neither shell nor SFTP can resolve the path -- raise
    ``PathNotAllowed`` with a message that names BOTH failures so the
    operator knows the host is truly broken (not just chroot-shaped).
    """
    import asyncssh

    sftp = _FakeSftpForRealpath(
        realpath_raises=asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file"),
    )
    conn = _FakeConnWithSftp(sftp=sftp)
    conn.set(
        ["realpath", "-e", "--", "/ghost/path"],
        stderr="realpath: /ghost/path: No such file or directory",
        exit_status=1,
    )

    with pytest.raises(PathNotAllowed) as exc_info:
        await canonicalize(conn, "/ghost/path", must_exist=True)  # type: ignore[arg-type]
    msg = str(exc_info.value)
    assert "shell realpath says" in msg
    assert "SFTP-protocol realpath fallback also failed" in msg


@pytest.mark.asyncio
async def test_canonicalize_chroot_must_exist_rejects_when_sftp_stat_missing() -> None:
    """``must_exist=True`` + shell ENOENT + SFTP realpath succeeds + SFTP
    stat says missing -> still ``PathNotAllowed``. The chroot view also
    doesn't have the file, so the contract holds: caller asked for an
    existing path, we say no.
    """
    sftp = _FakeSftpForRealpath(
        realpath_map={"/docker/missing": "/docker/missing"},
        stat_missing={"/docker/missing"},
    )
    conn = _FakeConnWithSftp(sftp=sftp)
    conn.set(
        ["realpath", "-e", "--", "/docker/missing"],
        stderr="realpath: /docker/missing: No such file or directory",
        exit_status=1,
    )

    with pytest.raises(PathNotAllowed, match="does not exist"):
        await canonicalize(conn, "/docker/missing", must_exist=True)  # type: ignore[arg-type]
    assert sftp.realpath_calls == ["/docker/missing"]
    assert sftp.stat_calls == ["/docker/missing"]


@pytest.mark.asyncio
async def test_canonicalize_chroot_must_exist_false_skips_stat_verification() -> None:
    """``must_exist=False`` (write targets: upload / mkdir / deploy) does
    NOT run the verifying stat after the SFTP fallback -- the contract is
    "path doesn't need to exist yet". Saves one SFTP round-trip per call.
    """
    sftp = _FakeSftpForRealpath(realpath_map={"/docker/new": "/docker/new"})
    conn = _FakeConnWithSftp(sftp=sftp)
    conn.set(
        ["realpath", "-m", "--", "/docker/new"],
        stderr="realpath: /docker/new: No such file or directory",
        exit_status=1,
    )

    result = await canonicalize(conn, "/docker/new", must_exist=False)  # type: ignore[arg-type]
    assert result == "/docker/new"
    assert sftp.stat_calls == [], "must_exist=False must not trigger the verifying stat"
