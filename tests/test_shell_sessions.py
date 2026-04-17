"""SessionRegistry + wrap_command/strip_sentinel -- no SSH."""
from __future__ import annotations

import asyncio
import time

import pytest

from ssh_mcp.services.shell_sessions import (
    SENTINEL,
    SessionRegistry,
    strip_sentinel,
    wrap_command,
)


def test_open_assigns_unique_ids() -> None:
    r = SessionRegistry()
    a = r.open("web01")
    b = r.open("web01")
    assert a.id != b.id
    assert r.size() == 2


def test_default_cwd_is_tilde() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    assert s.cwd == "~"


def test_get_returns_none_for_unknown() -> None:
    r = SessionRegistry()
    assert r.get("nope") is None


def test_close_returns_true_first_time_false_second() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    assert r.close(s.id) is True
    assert r.close(s.id) is False
    assert r.get(s.id) is None


def test_list_shape() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    rows = r.list()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == s.id
    assert row["host"] == "web01"
    assert row["cwd"] == "~"
    assert row["idle_seconds"] >= 0
    assert row["age_seconds"] >= 0


def test_touch_updates_last_used() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    original = s.last_used
    time.sleep(0.01)
    r.touch(s.id)
    assert s.last_used > original


def test_reap_idle_drops_stale_sessions() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    # Force it to look ancient.
    s.last_used = time.monotonic() - 3600
    closed = r.reap_idle(max_idle_seconds=300)
    assert closed == [s.id]
    assert r.size() == 0


def test_reap_idle_keeps_fresh_sessions() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    closed = r.reap_idle(max_idle_seconds=300)
    assert closed == []
    assert r.get(s.id) is not None


# --- command wrapping ---


def test_wrap_command_includes_cwd_and_sentinel() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    s.cwd = "/var/log"
    wrapped = wrap_command(s, "ls -la")
    # shlex.quote leaves paths without metacharacters unquoted -- "/var/log"
    # needs no escaping. Spaces or quotes would force quoting (see next test).
    assert "cd /var/log" in wrapped
    assert "ls -la" in wrapped
    assert SENTINEL in wrapped


def test_wrap_command_preserves_exit_code() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    wrapped = wrap_command(s, "false")
    # The last line must re-exit with $? stored before the sentinel printf.
    assert "exit $__sshmcp_rc" in wrapped


def test_wrap_command_quotes_cwd_with_spaces() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    s.cwd = "/home/user/my dir"
    wrapped = wrap_command(s, "ls")
    assert "'/home/user/my dir'" in wrapped


# --- sentinel stripping ---


def test_strip_sentinel_extracts_cwd_and_removes_marker_line() -> None:
    stdout = f"hello\nworld\n{SENTINEL}/var/log\n"
    clean, cwd = strip_sentinel(stdout)
    assert clean == "hello\nworld"
    assert cwd == "/var/log"


def test_strip_sentinel_missing_returns_none() -> None:
    stdout = "hello\nworld\n"  # no sentinel (truncated or killed)
    clean, cwd = strip_sentinel(stdout)
    assert clean == "hello\nworld\n"
    assert cwd is None


def test_strip_sentinel_finds_last_occurrence() -> None:
    # A naughty command that prints something that looks like the sentinel
    # MID-output should still resolve to the real trailing sentinel.
    stdout = f"log line {SENTINEL}/fake\nactual output\n{SENTINEL}/real\n"
    _clean, cwd = strip_sentinel(stdout)
    assert cwd == "/real"


# --- per-host persistent_session gate ---


def test_host_policy_defaults_persistent_session_true() -> None:
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    p = HostPolicy(hostname="web01", user="deploy", auth=AuthPolicy(method="agent"))
    assert p.persistent_session is True


def test_host_policy_accepts_persistent_session_false() -> None:
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    p = HostPolicy(
        hostname="prod-db",
        user="dbadmin",
        auth=AuthPolicy(method="agent"),
        persistent_session=False,
    )
    assert p.persistent_session is False


def test_settings_allow_persistent_sessions_defaults_true() -> None:
    from ssh_mcp.config import Settings

    s = Settings()
    assert s.ALLOW_PERSISTENT_SESSIONS is True


def test_settings_allow_persistent_sessions_respects_override() -> None:
    from ssh_mcp.config import Settings

    s = Settings(ALLOW_PERSISTENT_SESSIONS=False)
    assert s.ALLOW_PERSISTENT_SESSIONS is False


# --- per-session lock (INC-023) ---


def test_shell_session_has_asyncio_lock() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    assert isinstance(s.lock, asyncio.Lock)


@pytest.mark.asyncio
async def test_session_lock_serializes_concurrent_callers() -> None:
    """Two callers trying to 'exec' on the same session serialize on the lock."""
    r = SessionRegistry()
    s = r.open("web01")

    entered: list[int] = []
    exited: list[int] = []

    async def fake_exec(marker: int) -> None:
        async with s.lock:
            entered.append(marker)
            await asyncio.sleep(0.01)
            exited.append(marker)

    # Launch two concurrently; if the lock works, entries alternate with exits.
    await asyncio.gather(fake_exec(1), fake_exec(2))
    assert entered == [1, 2] or entered == [2, 1]
    # Each caller must exit before the next one enters -- this is the
    # "serialized" invariant the per-session lock is here to enforce.
    assert exited[0] == entered[0]
    assert exited[1] == entered[1]


# --- INC-047: set_cwd + exec_scope enforcement ---


def test_set_cwd_outside_exec_scope_raises() -> None:
    """INC-047: calling `set_cwd` without holding the lock is a bug; we want
    it to raise loudly instead of silently racing with concurrent callers.

    This is the regression that supersedes INC-027: the prior concern was
    "nothing enforces callers hold `session.lock` before writing `cwd`".
    Now `set_cwd` IS the enforcement: a missing `exec_scope()` wrapper
    trips the first test that exercises the new cwd update.
    """
    r = SessionRegistry()
    s = r.open("web01")
    with pytest.raises(RuntimeError, match="exec_scope"):
        s.set_cwd("/tmp")


@pytest.mark.asyncio
async def test_set_cwd_inside_exec_scope_succeeds() -> None:
    r = SessionRegistry()
    s = r.open("web01")
    async with s.exec_scope():
        s.set_cwd("/opt/app")
    assert s.cwd == "/opt/app"


@pytest.mark.asyncio
async def test_exec_scope_serializes_like_raw_lock() -> None:
    """The new `exec_scope()` sugar is a thin wrapper around `session.lock`;
    nothing changes about the INC-023 serialization invariant that the test
    above asserts. Mirror that test but use the new API so a future refactor
    of `exec_scope` internals can't regress serialization silently.
    """
    r = SessionRegistry()
    s = r.open("web01")

    entered: list[int] = []
    exited: list[int] = []

    async def fake_exec(marker: int) -> None:
        async with s.exec_scope():
            entered.append(marker)
            await asyncio.sleep(0.01)
            exited.append(marker)

    await asyncio.gather(fake_exec(1), fake_exec(2))
    assert exited[0] == entered[0]
    assert exited[1] == entered[1]
