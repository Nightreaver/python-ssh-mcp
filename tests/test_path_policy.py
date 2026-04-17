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
