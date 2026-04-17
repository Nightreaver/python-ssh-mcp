"""E2E tests for path_allowlist + restricted_paths enforcement.

The effective allowlist is ``policy.path_allowlist`` UNION-ed with ``settings.SSH_PATH_ALLOWLIST``
and a single ``"*"`` sentinel in either disables confinement. The operator's
real ``hosts.toml`` sets ``path_allowlist = ["*"]`` for every host -- convenient
for day-to-day MCP use, lethal for testing confinement. So each test here
rebuilds a SECOND context (``narrow_ctx``) where both the policy and the
settings declare narrow roots. This way the tests fail loud if path gating
ever regresses to "allow everything via one silent wildcard".

Tests exercise both positive (in-scope path succeeds) and negative cases
(out-of-scope / restricted → explicit refusal). Windows paths branch via
``policy.platform`` so the same shape runs against both POSIX and Windows.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.services.hooks import HookRegistry
from ssh_mcp.services.shell_sessions import SessionRegistry
from ssh_mcp.ssh.errors import PathNotAllowed, PathRestricted
from ssh_mcp.tools.sftp_read_tools import ssh_sftp_stat

from .conftest import HOSTS_FILE, _Ctx, skip_if_unreachable

if TYPE_CHECKING:
    from ssh_mcp.models.policy import HostPolicy

pytestmark = pytest.mark.e2e


def pytest_generate_tests(metafunc):
    if "alias" not in metafunc.fixturenames:
        return
    from ssh_mcp.hosts import load_hosts

    if not HOSTS_FILE.exists():
        metafunc.parametrize("alias", [], ids=[])
        return
    settings = Settings(SSH_HOSTS_FILE=HOSTS_FILE)
    hosts = load_hosts(HOSTS_FILE, settings)
    names = sorted(hosts.keys())
    metafunc.parametrize("alias", names, ids=names)


def _narrow_ctx(
    *,
    alias: str,
    e2e_pool,
    e2e_hosts: dict[str, HostPolicy],
    e2e_known_hosts,
    allowlist: list[str],
    restricted: list[str] | None = None,
) -> _Ctx:
    """Rebuild the ctx with narrowed policy + settings for this host only.

    We keep the operator's real connection params (hostname, port, user, auth,
    platform, known_hosts pinning) so the pool still works, but replace
    ``path_allowlist`` + ``restricted_paths`` on the cloned HostPolicy. Both
    the policy-level AND settings-level lists must be narrow -- the effective
    allowlist is their union, so a wildcard in either tier would mask the test.
    """
    base_policy = e2e_hosts[alias]
    narrow_policy = base_policy.model_copy(
        update={
            "path_allowlist": allowlist,
            "restricted_paths": restricted or [],
        }
    )
    narrow_hosts = dict(e2e_hosts)
    narrow_hosts[alias] = narrow_policy

    narrow_settings = Settings(
        SSH_HOSTS_FILE=HOSTS_FILE,
        SSH_KNOWN_HOSTS=e2e_known_hosts.path,
        SSH_PATH_ALLOWLIST=[],          # empty: don't widen past the policy
        SSH_RESTRICTED_PATHS=[],        # likewise
        ALLOW_LOW_ACCESS_TOOLS=True,
        SSH_CONNECT_TIMEOUT=5,
        SSH_COMMAND_TIMEOUT=15,
    )
    return _Ctx(
        {
            "pool": e2e_pool,
            "settings": narrow_settings,
            "hosts": narrow_hosts,
            "known_hosts": e2e_known_hosts,
            "hooks": HookRegistry(),
            "shell_sessions": SessionRegistry(),
        }
    )


def _in_scope_paths(policy: HostPolicy) -> tuple[str, str]:
    """(narrow_allowlist_root, path_inside_that_root)."""
    if policy.platform == "windows":
        return "C:\\Windows", "C:\\Windows\\System32\\drivers\\etc\\hosts"
    return "/etc", "/etc/hostname"


def _out_of_scope_path(policy: HostPolicy) -> str:
    """A path that exists on the host but sits OUTSIDE the narrow root.

    Exists-and-outside is the interesting case because it proves the allowlist
    check rejects the path as *policy*, not as "realpath couldn't resolve".
    For POSIX we use `/root` (canonical home of root, present on every Linux
    box). For Windows, `C:\\Program Files` is universal and sits outside
    `C:\\Windows`. Both are readable via realpath even for non-privileged
    callers because path resolution doesn't need listdir rights.
    """
    if policy.platform == "windows":
        return "C:\\Program Files"
    return "/root"


# --- Allowlist: positive + negative --------------------------------------


async def test_allowlist_accepts_in_scope(
    alias, e2e_pool, e2e_hosts, e2e_known_hosts, e2e_reachable,
):
    """A path inside the narrow allowlist resolves cleanly via ssh_sftp_stat."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    root, good = _in_scope_paths(policy)
    ctx = _narrow_ctx(
        alias=alias, e2e_pool=e2e_pool, e2e_hosts=e2e_hosts,
        e2e_known_hosts=e2e_known_hosts, allowlist=[root],
    )
    result = await ssh_sftp_stat(host=alias, path=good, ctx=ctx)
    assert result.kind == "file", result


async def test_allowlist_rejects_out_of_scope(
    alias, e2e_pool, e2e_hosts, e2e_known_hosts, e2e_reachable,
):
    """An existing-but-out-of-scope path raises PathNotAllowed.

    Crucial that the path EXISTS on the target: a missing-path error is a
    different failure mode (realpath exit != 0) that would spuriously pass
    a pytest.raises(PathNotAllowed). Using `/root` (POSIX) and
    `C:\\Program Files` (Windows) guarantees the path resolves and the
    rejection is the allowlist's doing.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    root, _ = _in_scope_paths(policy)
    bad = _out_of_scope_path(policy)
    ctx = _narrow_ctx(
        alias=alias, e2e_pool=e2e_pool, e2e_hosts=e2e_hosts,
        e2e_known_hosts=e2e_known_hosts, allowlist=[root],
    )
    with pytest.raises(PathNotAllowed) as excinfo:
        await ssh_sftp_stat(host=alias, path=bad, ctx=ctx)
    msg = str(excinfo.value)
    # Confirm the rejection came from the allowlist check, not "file missing".
    assert "outside the allowlist" in msg, (
        f"expected allowlist-rejection message, got: {msg!r}"
    )


# --- Restricted paths: blocks sensitive, permits siblings ---------------


async def test_restricted_paths_blocks_sensitive_file(
    alias, e2e_pool, e2e_hosts, e2e_known_hosts, e2e_reachable,
):
    """A path inside a restricted root raises PathRestricted even when
    it's also inside the allowlist. Restricted wins.

    POSIX case: `/etc` is allowed, but ``/etc/shadow`` is restricted ->
    ``ssh_sftp_stat("/etc/shadow")`` must refuse. On steven@host this would
    ALSO fail with EACCES at the SFTP layer, but the MCP catches it earlier
    at the policy layer -- verifying this avoids leaking existence info.

    Windows case: ``C:\\Windows`` is allowed, restricted root is
    ``C:\\Windows\\System32\\drivers\\etc`` -> the hosts file is refused.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        allow_root = "C:\\Windows"
        restricted_root = "C:\\Windows\\System32\\drivers\\etc"
        target = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    else:
        allow_root = "/etc"
        restricted_root = "/etc/ssh"
        target = "/etc/ssh/sshd_config"

    ctx = _narrow_ctx(
        alias=alias, e2e_pool=e2e_pool, e2e_hosts=e2e_hosts,
        e2e_known_hosts=e2e_known_hosts,
        allowlist=[allow_root], restricted=[restricted_root],
    )
    with pytest.raises(PathRestricted) as excinfo:
        await ssh_sftp_stat(host=alias, path=target, ctx=ctx)
    msg = str(excinfo.value)
    assert "restricted zone" in msg, (
        f"expected restricted-zone message, got: {msg!r}"
    )


async def test_restricted_paths_permits_siblings(
    alias, e2e_pool, e2e_hosts, e2e_known_hosts, e2e_reachable,
):
    """Siblings of a restricted root stay reachable.

    Guards against accidental over-restriction: if we ban ``/etc/ssh``,
    ``/etc/hostname`` must still work. This is specifically about prefix
    precision -- a buggy implementation that rejects any path starting
    with `/etc` as soon as `/etc/ssh` is restricted would fail here.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        allow_root = "C:\\Windows"
        restricted_root = "C:\\Windows\\System32\\drivers\\etc"
        target = "C:\\Windows\\System32\\drivers\\INPUT.INF"
        # INPUT.INF is a standard driver INF always present; if missing on
        # some builds, any sibling of drivers\etc\ works. The test is about
        # the allowlist not over-reaching, not about the file's existence.
        # We fall back to the drivers dir itself which is guaranteed present.
    else:
        allow_root = "/etc"
        restricted_root = "/etc/ssh"
        target = "/etc/hostname"

    ctx = _narrow_ctx(
        alias=alias, e2e_pool=e2e_pool, e2e_hosts=e2e_hosts,
        e2e_known_hosts=e2e_known_hosts,
        allowlist=[allow_root], restricted=[restricted_root],
    )
    if policy.platform == "windows":
        # Windows: stat the drivers dir itself, which is the sibling we can
        # be sure exists on every build.
        target = "C:\\Windows\\System32\\drivers"
        result = await ssh_sftp_stat(host=alias, path=target, ctx=ctx)
        assert result.kind in ("dir", "file")
    else:
        result = await ssh_sftp_stat(host=alias, path=target, ctx=ctx)
        assert result.kind == "file"


async def test_restricted_root_itself_blocked(
    alias, e2e_pool, e2e_hosts, e2e_known_hosts, e2e_reachable,
):
    """The restricted ROOT itself -- not just its children -- is blocked.

    If ``/etc/ssh`` is restricted, ``ssh_sftp_stat("/etc/ssh")`` must raise.
    Otherwise a caller could bypass confinement by targeting the directory
    head rather than a child file.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        allow_root = "C:\\Windows"
        restricted_root = "C:\\Windows\\System32\\drivers\\etc"
        target = restricted_root  # the zone itself
    else:
        allow_root = "/etc"
        restricted_root = "/etc/ssh"
        target = restricted_root

    ctx = _narrow_ctx(
        alias=alias, e2e_pool=e2e_pool, e2e_hosts=e2e_hosts,
        e2e_known_hosts=e2e_known_hosts,
        allowlist=[allow_root], restricted=[restricted_root],
    )
    with pytest.raises(PathRestricted):
        await ssh_sftp_stat(host=alias, path=target, ctx=ctx)
