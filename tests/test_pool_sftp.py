"""Self-healing SFTP pool (INC-...): cached SFTPClient + invalidate-on-channel-failure.

Pin the contract distilled from the DSM 7.3.2 incident:
- Pool caches ONE SFTPClient per connection -- not one per call.
- ChannelOpenError / ConnectionLost inside the with-block invalidates the
  pool entry; subsequent sftp() opens a fresh connection.
- SFTPError (permission, no-such-file) does NOT invalidate.
- Per-key locking serializes concurrent first-acquires.
- Reaper closes the SFTPClient before the carrier connection.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import patch

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy, ResolvedHost
from ssh_mcp.ssh.known_hosts import KnownHosts
from ssh_mcp.ssh.pool import ConnectionPool

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeSFTPClient:
    """Stand-in for asyncssh.SFTPClient.

    The pool calls ``await conn.start_sftp_client()`` to get one, then
    holds onto it across many ``async with pool.sftp(...)`` uses.
    ``exit()`` is invoked synchronously on close / invalidate.
    """

    def __init__(self) -> None:
        self.exit_called = 0
        # When set, the NEXT op inside the with-block raises this.
        self.raise_on_op: Exception | None = None

    def exit(self) -> None:
        self.exit_called += 1

    async def stat(self, _path: str) -> Any:
        if self.raise_on_op is not None:
            exc = self.raise_on_op
            self.raise_on_op = None
            raise exc
        return {"size": 0}


class FakeConn:
    """Stand-in for asyncssh.SSHClientConnection."""

    def __init__(self, sftp: FakeSFTPClient | None = None) -> None:
        self.closed = False
        self._sftp_factory: list[FakeSFTPClient] = [sftp or FakeSFTPClient()]
        self.start_sftp_calls = 0

    def is_closed(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    async def start_sftp_client(self) -> FakeSFTPClient:
        self.start_sftp_calls += 1
        if not self._sftp_factory:
            self._sftp_factory.append(FakeSFTPClient())
        # Pop on each open so a fresh connection (after invalidate) gets a
        # fresh SFTPClient and we can distinguish "same as before" vs. "new".
        return self._sftp_factory.pop(0)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _policy(host: str = "web01.internal", user: str = "deploy") -> HostPolicy:
    return HostPolicy(
        hostname=host,
        user=user,
        port=22,
        auth=AuthPolicy(method="agent"),
    )


def _resolved(policy: HostPolicy) -> ResolvedHost:
    return ResolvedHost(hostname=policy.hostname, policy=policy)


def _settings(idle_timeout: int = 300) -> Settings:
    return Settings(  # type: ignore[call-arg]
        SSH_IDLE_TIMEOUT=idle_timeout,
        SSH_HOSTS_ALLOWLIST=["web01.internal"],
    )


@pytest.fixture
def known_hosts_obj(tmp_path: Any) -> KnownHosts:
    return KnownHosts(tmp_path / "missing_known_hosts")


def _opener_for(conns: list[FakeConn]) -> Any:
    """Return a patcher that hands out the next FakeConn on each open."""
    iter_conns = iter(conns)

    async def fake_open(*, policy: Any, settings: Any, known_hosts: Any, pool: Any) -> Any:
        return next(iter_conns)

    return patch("ssh_mcp.ssh.pool.open_connection", fake_open)


# ---------------------------------------------------------------------------
# Phase 2: cached SFTPClient is reused
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cached_sftp_is_reused(known_hosts_obj: KnownHosts) -> None:
    """Two sequential pool.sftp() calls share the same SFTPClient instance."""
    sftp = FakeSFTPClient()
    conn = FakeConn(sftp=sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([conn]):
        async with pool.sftp(resolved) as s1:
            assert s1 is sftp
        async with pool.sftp(resolved) as s2:
            assert s2 is sftp

    # SFTPClient opened exactly once even though sftp() was entered twice.
    assert conn.start_sftp_calls == 1
    await pool.close_all()


# ---------------------------------------------------------------------------
# Phase 1: invalidate drops connection + SFTPClient
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalidate_drops_connection_and_sftp(known_hosts_obj: KnownHosts) -> None:
    """After invalidate(key), the next sftp() acquires a fresh conn + sftp."""
    first_sftp = FakeSFTPClient()
    second_sftp = FakeSFTPClient()
    first_conn = FakeConn(sftp=first_sftp)
    second_conn = FakeConn(sftp=second_sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()
    resolved = _resolved(policy)
    key = (policy.user, policy.hostname, policy.port)

    with _opener_for([first_conn, second_conn]):
        async with pool.sftp(resolved) as s1:
            assert s1 is first_sftp
        await pool.invalidate(key)
        # The previous SFTPClient was closed and the connection torn down.
        assert first_sftp.exit_called == 1
        assert first_conn.closed is True
        async with pool.sftp(resolved) as s2:
            assert s2 is second_sftp
    assert first_conn.start_sftp_calls == 1
    assert second_conn.start_sftp_calls == 1
    await pool.close_all()


@pytest.mark.asyncio
async def test_invalidate_missing_key_is_noop(known_hosts_obj: KnownHosts) -> None:
    """Calling invalidate on an empty pool key must not raise."""
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    await pool.invalidate(("nobody", "ghost.example", 22))
    assert pool.size() == 0


# ---------------------------------------------------------------------------
# Phase 1: channel-level errors trigger invalidation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_open_error_inside_with_block_invalidates(
    known_hosts_obj: KnownHosts,
) -> None:
    """ChannelOpenError mid-op invalidates the pool entry; next sftp() is fresh."""
    poisoned_sftp = FakeSFTPClient()
    poisoned_sftp.raise_on_op = asyncssh.ChannelOpenError(1, "session request failed")
    poisoned_conn = FakeConn(sftp=poisoned_sftp)
    fresh_sftp = FakeSFTPClient()
    fresh_conn = FakeConn(sftp=fresh_sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([poisoned_conn, fresh_conn]):
        with pytest.raises(asyncssh.ChannelOpenError):
            async with pool.sftp(resolved) as s:
                await s.stat("/x")  # triggers raise_on_op
        # Pool entry got dropped + closed.
        assert poisoned_sftp.exit_called == 1
        assert poisoned_conn.closed is True
        assert pool.size() == 0
        # Next acquire opens fresh resources.
        async with pool.sftp(resolved) as s2:
            assert s2 is fresh_sftp
    await pool.close_all()


@pytest.mark.asyncio
async def test_connection_lost_inside_with_block_invalidates(
    known_hosts_obj: KnownHosts,
) -> None:
    """Same contract as ChannelOpenError -- ConnectionLost also invalidates."""
    poisoned_sftp = FakeSFTPClient()
    poisoned_sftp.raise_on_op = asyncssh.ConnectionLost("peer closed")
    poisoned_conn = FakeConn(sftp=poisoned_sftp)
    fresh_sftp = FakeSFTPClient()
    fresh_conn = FakeConn(sftp=fresh_sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([poisoned_conn, fresh_conn]):
        with pytest.raises(asyncssh.ConnectionLost):
            async with pool.sftp(resolved) as s:
                await s.stat("/x")
        assert poisoned_conn.closed is True
        async with pool.sftp(resolved) as s2:
            assert s2 is fresh_sftp
    await pool.close_all()


@pytest.mark.asyncio
async def test_sftp_error_does_not_invalidate(known_hosts_obj: KnownHosts) -> None:
    """SFTPError is data, not channel health -- the pool entry stays."""
    sftp = FakeSFTPClient()
    # Use a real SFTPError code so the constructor signature matches asyncssh.
    sftp.raise_on_op = asyncssh.SFTPError(asyncssh.sftp.FX_NO_SUCH_FILE, "no such file")
    conn = FakeConn(sftp=sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([conn]):
        with pytest.raises(asyncssh.SFTPError):
            async with pool.sftp(resolved) as s:
                await s.stat("/missing")
        # Pool entry survives -- not closed, not invalidated.
        assert sftp.exit_called == 0
        assert conn.closed is False
        assert pool.size() == 1
        # Same SFTPClient still served from cache on the next call.
        async with pool.sftp(resolved) as s2:
            assert s2 is sftp
    # Only ONE underlying start_sftp_client call across both with-blocks.
    assert conn.start_sftp_calls == 1
    await pool.close_all()


# ---------------------------------------------------------------------------
# Concurrency: 5 parallel first-acquires open exactly ONE conn + ONE sftp
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_first_acquires_open_one_resource(
    known_hosts_obj: KnownHosts,
) -> None:
    """Per-key lock serializes opens for both the connection and the SFTPClient."""
    sftp = FakeSFTPClient()
    open_calls: list[int] = []

    class SlowSftpConn(FakeConn):
        async def start_sftp_client(self) -> FakeSFTPClient:  # type: ignore[override]
            open_calls.append(1)
            await asyncio.sleep(0.01)
            return await super().start_sftp_client()

    conn = SlowSftpConn(sftp=sftp)

    async def delayed_open(*, policy: Any, settings: Any, known_hosts: Any, pool: Any) -> Any:
        await asyncio.sleep(0.01)
        return conn

    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    async def use_sftp() -> Any:
        async with pool.sftp(resolved) as s:
            return s

    with patch("ssh_mcp.ssh.pool.open_connection", delayed_open):
        results = await asyncio.gather(*(use_sftp() for _ in range(5)))

    # All five callers got the same SFTPClient...
    assert all(r is sftp for r in results)
    # ...opened exactly once (locking worked).
    assert len(open_calls) == 1
    assert conn.start_sftp_calls == 1
    await pool.close_all()


# ---------------------------------------------------------------------------
# Reaper closes the cached SFTPClient before the connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reaper_closes_cached_sftp_before_connection(
    known_hosts_obj: KnownHosts,
) -> None:
    """Aging an entry past idle timeout drops it; SFTP exit() runs before conn.close()."""
    sftp = FakeSFTPClient()
    conn = FakeConn(sftp=sftp)
    # Track ordering: record snapshot of (conn.closed, sftp.exit_called) at
    # exit() and at close(). If sftp closed first, at exit time conn is
    # still open.
    order: list[str] = []
    original_exit = sftp.exit
    original_close = conn.close

    def tracking_exit() -> None:
        order.append("sftp")
        original_exit()

    def tracking_close() -> None:
        order.append("conn")
        original_close()

    sftp.exit = tracking_exit  # type: ignore[method-assign]
    conn.close = tracking_close  # type: ignore[method-assign]

    pool = ConnectionPool(_settings(idle_timeout=0))
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([conn]):
        async with pool.sftp(resolved):
            pass
        # Force the entry to look stale.
        for entry in pool._entries.values():
            entry.last_used = time.monotonic() - 3600
        await pool._reap_once()

    assert pool.size() == 0
    assert order == ["sftp", "conn"], "SFTPClient.exit() must run before conn.close()"
    assert sftp.exit_called == 1
    assert conn.closed is True


# ---------------------------------------------------------------------------
# Regression: 5-call SFTP burst with one channel failure recovers cleanly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_burst_with_channel_failure_recovers(known_hosts_obj: KnownHosts) -> None:
    """Pin the DSM 7.3.2 incident:
    - Multiple SFTP ops on one host share the cached SFTPClient.
    - One op raises ChannelOpenError -> the pool drops the entry.
    - The NEXT sequential acquire opens a fresh connection + fresh SFTPClient.

    Without invalidate-on-channel-failure, the next call would reuse the
    poisoned connection and the host's SFTP surface would stay broken
    until the server restart.

    We sequence the good ops BEFORE the failing op so the assertion on
    pool size after the failure is deterministic -- a fully parallel
    burst would let in-flight good ops race with the invalidate and
    re-open a fresh entry before the 6th acquire runs.
    """
    first_sftp = FakeSFTPClient()
    first_conn = FakeConn(sftp=first_sftp)
    second_sftp = FakeSFTPClient()
    second_conn = FakeConn(sftp=second_sftp)

    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    poison = asyncssh.ChannelOpenError(1, "session request failed")

    # 5 good ops sharing the cached SFTPClient (the bug-reproducer is the
    # burst-on-cold-pool case; that part is covered by the dedicated
    # concurrency test above. Here we focus on the recovery semantics).
    with _opener_for([first_conn, second_conn]):
        for _ in range(5):
            async with pool.sftp(resolved):
                pass
        # All 5 calls shared the SAME SFTPClient.
        assert first_conn.start_sftp_calls == 1

        # The 6th call observes the channel-level failure.
        async def _trigger_failure() -> None:
            async with pool.sftp(resolved) as s:
                s.raise_on_op = poison
                await s.stat("/anything")

        with pytest.raises(asyncssh.ChannelOpenError):
            await _trigger_failure()

        # Poisoned entry was torn down.
        assert first_sftp.exit_called == 1
        assert first_conn.closed is True
        assert pool.size() == 0

        # 7th sequential acquire: fresh resources, totally clean.
        async with pool.sftp(resolved) as s:
            assert s is second_sftp
        assert second_conn.start_sftp_calls == 1

    await pool.close_all()


# ---------------------------------------------------------------------------
# sftp_policy() is the same contract for callers without a ResolvedHost
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sftp_policy_uses_same_cached_client(known_hosts_obj: KnownHosts) -> None:
    """pool.sftp(resolved) and pool.sftp_policy(policy) share one entry."""
    sftp = FakeSFTPClient()
    conn = FakeConn(sftp=sftp)
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()
    resolved = _resolved(policy)

    with _opener_for([conn]):
        async with pool.sftp(resolved) as s1:
            assert s1 is sftp
        async with pool.sftp_policy(policy) as s2:
            assert s2 is sftp
    # Both call sites resolve to the same cached SFTPClient.
    assert conn.start_sftp_calls == 1
    await pool.close_all()


# ---------------------------------------------------------------------------
# Bounded retry: _acquire_sftp tolerates an invalidate-mid-acquire race,
# but gives up after 3 attempts so a runaway invalidate() loop fails loud
# rather than hanging forever.
# ---------------------------------------------------------------------------
#
# These tests exercise the retry budget in ``ConnectionPool._acquire_sftp``
# by patching ``acquire_policy`` to inject ``invalidate(key)`` between the
# conn acquire and the entry lookup. Without this, the only way to reach
# the retry paths is a real concurrent invalidate race -- which is rare and
# nondeterministic to reproduce in a test.


@pytest.mark.asyncio
async def test_acquire_sftp_retries_after_one_invalidate_race(
    known_hosts_obj: KnownHosts,
) -> None:
    """First acquire_policy returns, then invalidate fires before
    ``_acquire_sftp`` looks up the entry. The retry loop must notice the
    missing entry and re-acquire on iteration 2.
    """
    first_sftp = FakeSFTPClient()
    second_sftp = FakeSFTPClient()
    first_conn = FakeConn(sftp=first_sftp)
    second_conn = FakeConn(sftp=second_sftp)

    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()
    resolved = _resolved(policy)
    key = (policy.user, policy.hostname, policy.port)

    real_acquire_policy = pool.acquire_policy
    call_count = {"n": 0}

    async def racing_acquire_policy(p: Any) -> Any:
        call_count["n"] += 1
        conn = await real_acquire_policy(p)
        if call_count["n"] == 1:
            # Inject the race: drop the entry before _acquire_sftp's
            # `self._entries.get(key)` line runs.
            await pool.invalidate(key)
        return conn

    pool.acquire_policy = racing_acquire_policy  # type: ignore[method-assign]

    with _opener_for([first_conn, second_conn]):
        async with pool.sftp(resolved) as s:
            assert s is second_sftp, "retry must reach the second connection's SFTPClient"

    # acquire_policy called twice: once that got invalidated, once that succeeded.
    assert call_count["n"] == 2
    # First conn was force-closed by invalidate. The first SFTPClient was
    # never opened (the race fires BEFORE _acquire_sftp can call
    # start_sftp_client) -- nothing to close on that side.
    assert first_conn.closed is True
    assert first_conn.start_sftp_calls == 0, "race fires before SFTP open on iter 1"
    # Second conn is the live one.
    assert second_conn.start_sftp_calls == 1
    await pool.close_all()


# ---------------------------------------------------------------------------
# SFTP subsystem refusal: translate asyncssh's raw "Session request failed"
# into a structured ``SFTPSubsystemUnavailable`` so the LLM sees a
# remediation hint instead of a cryptic transport string.
# ---------------------------------------------------------------------------
#
# Triggered by hardened sshd configs (DSM 7.x, OPNsense, some appliances)
# where ``Subsystem sftp ...`` is missing or commented out. The carrier
# connection accepts the channel; the subsystem request is refused with
# ``SSH_MSG_CHANNEL_FAILURE`` -> asyncssh raises
# ``ChannelOpenError(OPEN_REQUEST_SESSION_FAILED, "Session request failed")``.
# Channel-based tools (exec / sudo_exec / ping) keep working on the same
# connection -- only the sftp subsystem is unavailable -- so we MUST NOT
# invalidate the pool entry on this specific error.


@pytest.mark.asyncio
async def test_subsystem_refusal_translates_to_structured_error(
    known_hosts_obj: KnownHosts,
) -> None:
    """asyncssh ChannelOpenError(OPEN_REQUEST_SESSION_FAILED, ...) becomes
    ``SFTPSubsystemUnavailable`` with user/host/port populated.
    """
    from ssh_mcp.ssh.errors import SFTPSubsystemUnavailable

    class _RefusingConn(FakeConn):
        async def start_sftp_client(self) -> Any:  # type: ignore[override]
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_REQUEST_SESSION_FAILED,
                "Session request failed",
            )

    conn = _RefusingConn()
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()  # default: web01.internal -- inside allowlist
    resolved = _resolved(policy)

    with _opener_for([conn]), pytest.raises(SFTPSubsystemUnavailable) as exc_info:
        async with pool.sftp(resolved):
            pass

    err = exc_info.value
    assert err.user == policy.user
    assert err.host == policy.hostname
    assert err.port == policy.port
    # Message must spell out the actionable remediation (sshd_config).
    msg = str(err)
    assert policy.hostname in msg
    assert "sshd_config" in msg
    assert "Subsystem sftp" in msg
    # Cause chain preserved -- forensics can still inspect the underlying
    # ChannelOpenError if needed.
    assert isinstance(err.__cause__, asyncssh.ChannelOpenError)
    await pool.close_all()


@pytest.mark.asyncio
async def test_subsystem_refusal_does_not_invalidate_pool_entry(
    known_hosts_obj: KnownHosts,
) -> None:
    """The carrier connection is healthy -- channel-based tools should keep
    working on the same conn. The pool entry MUST survive the refusal.
    """
    from ssh_mcp.ssh.errors import SFTPSubsystemUnavailable

    class _RefusingConn(FakeConn):
        async def start_sftp_client(self) -> Any:  # type: ignore[override]
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_REQUEST_SESSION_FAILED,
                "Session request failed",
            )

    conn = _RefusingConn()
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()
    resolved = _resolved(policy)

    with _opener_for([conn]):
        with pytest.raises(SFTPSubsystemUnavailable):
            async with pool.sftp(resolved):
                pass
        # Entry survives -- conn is still in the pool, ready for exec calls.
        assert pool.size() == 1
        assert conn.closed is False
    await pool.close_all()


@pytest.mark.asyncio
async def test_other_channel_open_error_codes_propagate_raw(
    known_hosts_obj: KnownHosts,
) -> None:
    """Only ``OPEN_REQUEST_SESSION_FAILED`` gets translated. Resource-
    shortage / admin-prohibited / unknown-channel-type carry different
    semantics and must propagate as raw ``ChannelOpenError`` so the LLM
    (or the caller) handles them on their own terms.
    """

    class _ResourceShortageConn(FakeConn):
        async def start_sftp_client(self) -> Any:  # type: ignore[override]
            # SSH_OPEN_RESOURCE_SHORTAGE = 4 (RFC 4254 §5.1)
            raise asyncssh.ChannelOpenError(4, "resource shortage")

    conn = _ResourceShortageConn()
    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    resolved = _resolved(_policy())

    with _opener_for([conn]), pytest.raises(asyncssh.ChannelOpenError) as exc_info:
        async with pool.sftp(resolved):
            pass
    assert exc_info.value.code == 4
    assert "resource shortage" in str(exc_info.value).lower()
    await pool.close_all()


@pytest.mark.asyncio
async def test_acquire_sftp_raises_runtime_after_three_retries(
    known_hosts_obj: KnownHosts,
) -> None:
    """A pathological invalidate loop -- 4 consecutive races, the 4th being
    one too many -- raises RuntimeError so the caller sees a real signal
    instead of an infinite spin.
    """
    sftps = [FakeSFTPClient() for _ in range(4)]
    conns = [FakeConn(sftp=s) for s in sftps]

    pool = ConnectionPool(_settings())
    pool.bind({}, known_hosts_obj)
    policy = _policy()
    resolved = _resolved(policy)
    key = (policy.user, policy.hostname, policy.port)

    real_acquire_policy = pool.acquire_policy

    async def always_racing_acquire_policy(p: Any) -> Any:
        conn = await real_acquire_policy(p)
        # Invalidate on EVERY call -- the entry is gone before
        # _acquire_sftp can pin it. Exhausts the 3-retry budget.
        await pool.invalidate(key)
        return conn

    pool.acquire_policy = always_racing_acquire_policy  # type: ignore[method-assign]

    with _opener_for(conns), pytest.raises(RuntimeError, match="kept being invalidated mid-acquire"):
        async with pool.sftp(resolved):
            pass

    # Each of the 3 retries opened a fresh connection (and then invalidated
    # it). The 4th conn in the opener queue is unused -- proves the loop
    # is bounded to 3 attempts, not "spin until the queue empties".
    assert all(c.closed for c in conns[:3]), "first 3 conns should have been closed by invalidate"
    assert conns[3].start_sftp_calls == 0, "4th conn must not have been touched"
    await pool.close_all()
