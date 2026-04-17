"""Windows-target support: platform gate, path policy, SFTP find walk.

Uses FakeConn / FakeSFTP shims to exercise the Windows branches without a
live remote. See ADR-0023 for the scope decision (SFTP + file-ops only; no
docker, no exec, no sudo, no shell sessions on Windows targets).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.path_policy import (
    canonicalize,
    check_in_allowlist,
    check_not_restricted,
    effective_allowlist,
)
from ssh_mcp.ssh.errors import PathNotAllowed, PathRestricted, PlatformNotSupported
from ssh_mcp.tools._context import require_posix


def _win_policy(**kw: Any) -> HostPolicy:
    defaults = {
        "hostname": "winbox",
        "user": "Administrator",
        "auth": AuthPolicy(method="agent"),
        "platform": "windows",
    }
    defaults.update(kw)
    return HostPolicy(**defaults)


def _posix_policy(**kw: Any) -> HostPolicy:
    defaults = {
        "hostname": "web01",
        "user": "deploy",
        "auth": AuthPolicy(method="agent"),
    }
    defaults.update(kw)
    return HostPolicy(**defaults)


# --- HostPolicy.platform ---


class TestPlatformField:
    def test_default_is_posix(self) -> None:
        p = _posix_policy()
        assert p.platform == "posix"

    def test_windows_accepted(self) -> None:
        p = _win_policy()
        assert p.platform == "windows"

    @pytest.mark.parametrize("alias", ["linux", "macos", "bsd", "darwin"])
    def test_legacy_aliases_normalize_to_posix(self, alias: str) -> None:
        p = _posix_policy(platform=alias)
        assert p.platform == "posix"

    def test_unknown_platform_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            _posix_policy(platform="plan9")


# --- path_allowlist validator accepts Windows paths ---


class TestWindowsPathAllowlist:
    @pytest.mark.parametrize(
        "entry",
        ["C:\\opt\\app", "C:/opt/app", "D:\\data", "c:/users/public"],
    )
    def test_windows_absolute_entries_accepted(self, entry: str) -> None:
        p = _win_policy(path_allowlist=[entry])
        assert entry in p.path_allowlist

    def test_relative_still_rejected(self) -> None:
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            _win_policy(path_allowlist=["opt/app"])

    def test_restricted_paths_accepts_windows(self) -> None:
        p = _win_policy(
            path_allowlist=["C:\\opt"],
            restricted_paths=["C:\\opt\\secrets"],
        )
        assert "C:\\opt\\secrets" in p.restricted_paths


# --- require_posix ---


class TestRequirePosix:
    def test_allows_posix(self) -> None:
        require_posix(_posix_policy(), tool="ssh_foo", reason="x")  # no raise

    def test_raises_on_windows(self) -> None:
        with pytest.raises(PlatformNotSupported, match="platform=windows"):
            require_posix(_win_policy(), tool="ssh_foo", reason="uses POSIX shell")

    def test_error_names_the_tool(self) -> None:
        with pytest.raises(PlatformNotSupported, match="ssh_foo"):
            require_posix(_win_policy(), tool="ssh_foo", reason="x")

    def test_error_suggests_sftp_alternative(self) -> None:
        with pytest.raises(PlatformNotSupported, match="SFTP"):
            require_posix(_win_policy(), tool="ssh_foo", reason="x")


# --- Platform-aware prefix matching (case + separators) ---


class TestWindowsAllowlistMatching:
    def test_backslash_vs_forward_slash_equivalent(self) -> None:
        # Allowlist entry with backslashes, canonical result with forward
        # slashes (SFTP often normalizes to forward slashes).
        check_in_allowlist("C:/opt/app/foo.txt", ["C:\\opt\\app"], "windows")

    def test_case_insensitive(self) -> None:
        check_in_allowlist("c:/OPT/APP/foo", ["C:\\opt\\app"], "windows")

    def test_outside_rejected(self) -> None:
        with pytest.raises(PathNotAllowed):
            check_in_allowlist("C:/other/secrets", ["C:\\opt\\app"], "windows")

    def test_adjacent_prefix_rejected(self) -> None:
        # Classic "C:\opt\app" vs "C:\opt\appmalicious" confusion.
        with pytest.raises(PathNotAllowed):
            check_in_allowlist("C:/opt/appmalicious/x", ["C:\\opt\\app"], "windows")

    def test_restricted_zone_matches_case_insensitive(self) -> None:
        with pytest.raises(PathRestricted):
            check_not_restricted(
                "C:/Opt/Secrets/creds.txt",
                ["C:\\opt\\secrets"],
                "windows",
            )

    def test_posix_remains_case_sensitive(self) -> None:
        # Same path but POSIX: capital-letter allowlist must NOT match
        # lowercase canonical.
        with pytest.raises(PathNotAllowed):
            check_in_allowlist("/opt/app/file", ["/OPT/APP"], "posix")


# --- effective_allowlist / restricted_paths normalization ---


class TestEffectiveListsPlatformAware:
    def test_windows_allowlist_normalized_with_ntpath(self) -> None:
        from ssh_mcp.config import Settings

        policy = _win_policy(path_allowlist=["C:\\opt\\app\\..\\data"])
        merged = effective_allowlist(policy, Settings())
        # ntpath.normpath folds the `..` and keeps backslash separators.
        assert merged == ["C:\\opt\\data"]

    def test_posix_allowlist_normalized_with_posixpath(self) -> None:
        from ssh_mcp.config import Settings

        policy = _posix_policy(path_allowlist=["/opt/app/../data"])
        merged = effective_allowlist(policy, Settings())
        assert merged == ["/opt/data"]


# --- FakeConn / FakeSFTP for canonicalize() ---


@dataclass
class _FakeAttrs:
    permissions: int = 0o100644
    size: int = 0
    mtime: int = 0
    uid: int = 1000
    gid: int = 1000


@dataclass
class _FakeSFTP:
    # Map canonical-path -> optional exception to raise, else attrs.
    paths: dict[str, _FakeAttrs] = field(default_factory=dict)
    # realpath() result map (input -> output).
    realpath_map: dict[str, str] = field(default_factory=dict)

    async def __aenter__(self) -> _FakeSFTP:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def realpath(self, path: str) -> str:
        if path in self.realpath_map:
            return self.realpath_map[path]
        return path  # echo unchanged (asyncssh behavior for absolute paths)

    async def stat(self, path: str) -> _FakeAttrs:
        if path in self.paths:
            return self.paths[path]
        import asyncssh

        raise asyncssh.SFTPError(
            asyncssh.sftp.FX_NO_SUCH_FILE, f"no such file: {path}"
        )


class _FakeConn:
    def __init__(self, sftp: _FakeSFTP) -> None:
        self._sftp = sftp

    def start_sftp_client(self) -> _FakeSFTP:  # returns an async-context-manager
        return self._sftp


class TestWindowsCanonicalize:
    @pytest.mark.asyncio
    async def test_must_exist_true_uses_sftp_realpath(self) -> None:
        sftp = _FakeSFTP(
            paths={"C:/opt/app/file.txt": _FakeAttrs()},
            realpath_map={"C:\\opt\\app\\file.txt": "C:/opt/app/file.txt"},
        )
        conn = _FakeConn(sftp)
        canonical = await canonicalize(
            conn, "C:\\opt\\app\\file.txt", must_exist=True, platform="windows"
        )
        assert canonical == "C:/opt/app/file.txt"

    @pytest.mark.asyncio
    async def test_must_exist_false_passes_for_nonexistent(self) -> None:
        # realpath returns the normalized path; stat isn't called because
        # must_exist=False.
        sftp = _FakeSFTP(realpath_map={"C:\\opt\\app\\new.txt": "C:/opt/app/new.txt"})
        conn = _FakeConn(sftp)
        canonical = await canonicalize(
            conn, "C:\\opt\\app\\new.txt", must_exist=False, platform="windows"
        )
        assert canonical == "C:/opt/app/new.txt"

    @pytest.mark.asyncio
    async def test_relative_path_rejected_when_realpath_fails(self) -> None:
        # Simulate SFTP server refusing realpath on non-existing path by
        # returning the input unchanged but un-absolute.
        sftp = _FakeSFTP(realpath_map={})
        conn = _FakeConn(sftp)
        with pytest.raises(PathNotAllowed):
            await canonicalize(
                conn, "relative/path", must_exist=False, platform="windows",
            )

    @pytest.mark.asyncio
    async def test_must_exist_true_fails_when_stat_missing(self) -> None:
        # realpath succeeds but stat says no such file -> PathNotAllowed.
        sftp = _FakeSFTP(
            paths={},
            realpath_map={"C:\\ghost": "C:/ghost"},
        )
        conn = _FakeConn(sftp)
        with pytest.raises(PathNotAllowed):
            await canonicalize(
                conn, "C:\\ghost", must_exist=True, platform="windows",
            )

    @pytest.mark.asyncio
    async def test_sftp_realpath_cygwin_form_is_normalized(self) -> None:
        """OpenSSH-for-Windows returns /C:/Users/... from SFTP realpath.

        Without the leading-slash strip in ``_canonicalize_windows``,
        ``_is_windows_absolute`` rejects the result and every Windows SFTP
        call fails with "canonicalized path is not absolute". This guards
        the fix against silent regression.
        """
        sftp = _FakeSFTP(
            paths={"C:/Users/foo": _FakeAttrs()},
            realpath_map={"C:\\Users\\foo": "/C:/Users/foo"},
        )
        conn = _FakeConn(sftp)
        canonical = await canonicalize(
            conn, "C:\\Users\\foo", must_exist=True, platform="windows",
        )
        assert canonical == "C:/Users/foo"

    @pytest.mark.asyncio
    async def test_unc_realpath_is_not_stripped(self) -> None:
        """UNC paths (`//host/share/...`) must NOT hit the Cygwin-strip branch.

        The predicate is tight enough to exclude them by shape, but the
        test pins that contract so a future refactor broadening the strip
        (e.g. to handle WSL `/mnt/c/...`) can't break UNC support.
        """
        sftp = _FakeSFTP(
            paths={"//fileserver/share/app": _FakeAttrs()},
            realpath_map={"\\\\fileserver\\share\\app": "//fileserver/share/app"},
        )
        conn = _FakeConn(sftp)
        canonical = await canonicalize(
            conn, "\\\\fileserver\\share\\app", must_exist=True, platform="windows",
        )
        assert canonical == "//fileserver/share/app"
