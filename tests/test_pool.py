"""ConnectionPool behaviour: reuse, reaper, close_all. No real SSH."""
from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import patch

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.ssh.errors import HostBlocked, HostNotAllowed
from ssh_mcp.ssh.known_hosts import KnownHosts
from ssh_mcp.ssh.pool import ConnectionPool


class FakeConn:
    def __init__(self) -> None:
        self.closed = False
        self._waiters: list[asyncio.Future[None]] = []

    def is_closed(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _make_policy(host: str = "web01.internal", user: str = "deploy") -> HostPolicy:
    return HostPolicy(
        hostname=host, user=user, port=22, auth=AuthPolicy(method="agent")
    )


def _make_settings(idle_timeout: int = 300, allowlist: list[str] | None = None) -> Settings:
    return Settings(  # type: ignore[call-arg]
        SSH_IDLE_TIMEOUT=idle_timeout,
        SSH_HOSTS_ALLOWLIST=["web01.internal"] if allowlist is None else allowlist,
    )


def _patch_opener(return_value: FakeConn, call_counter: list[int]) -> Any:
    async def fake_open(
        *, policy: HostPolicy, settings: Settings, known_hosts: Any, pool: Any
    ) -> FakeConn:
        call_counter.append(1)
        return return_value

    return patch("ssh_mcp.ssh.pool.open_connection", fake_open)


@pytest.fixture
def known_hosts_obj(tmp_path: Any) -> KnownHosts:
    # Missing file → empty known_hosts (warning logged). Good for tests.
    return KnownHosts(tmp_path / "missing_known_hosts")


@pytest.mark.asyncio
async def test_acquire_reuses_connection(known_hosts_obj: KnownHosts) -> None:
    conn = FakeConn()
    counter: list[int] = []
    pool = ConnectionPool(_make_settings())
    pool.bind({}, known_hosts_obj)
    policy = _make_policy()

    with _patch_opener(conn, counter):
        c1 = await pool.acquire(policy)
        c2 = await pool.acquire(policy)

    assert c1 is conn
    assert c2 is conn
    assert len(counter) == 1, "second acquire must reuse the first connection"
    assert pool.size() == 1
    await pool.close_all()
    assert conn.closed


@pytest.mark.asyncio
async def test_host_not_allowlisted_rejected(known_hosts_obj: KnownHosts) -> None:
    pool = ConnectionPool(_make_settings(allowlist=["only-this.internal"]))
    pool.bind({}, known_hosts_obj)
    policy = _make_policy("other.internal")

    with pytest.raises(HostNotAllowed):
        await pool.acquire(policy)


@pytest.mark.asyncio
async def test_empty_registry_is_default_deny(known_hosts_obj: KnownHosts) -> None:
    pool = ConnectionPool(_make_settings(allowlist=[]))
    pool.bind({}, known_hosts_obj)
    policy = _make_policy()
    with pytest.raises(HostNotAllowed, match="no hosts configured"):
        await pool.acquire(policy)


@pytest.mark.asyncio
async def test_reaper_closes_idle(known_hosts_obj: KnownHosts) -> None:
    conn = FakeConn()
    counter: list[int] = []
    pool = ConnectionPool(_make_settings(idle_timeout=0))
    pool.bind({}, known_hosts_obj)
    policy = _make_policy()

    with _patch_opener(conn, counter):
        await pool.acquire(policy)

    # Force the entry to look stale, then reap manually (don't wait 60s).
    for entry in pool._entries.values():
        entry.last_used = time.monotonic() - 3600
    await pool._reap_once()
    assert pool.size() == 0
    assert conn.closed


@pytest.mark.asyncio
async def test_concurrent_acquires_open_one(known_hosts_obj: KnownHosts) -> None:
    conn = FakeConn()
    counter: list[int] = []
    pool = ConnectionPool(_make_settings())
    pool.bind({}, known_hosts_obj)
    policy = _make_policy()

    async def delayed_open(
        *, policy: HostPolicy, settings: Settings, known_hosts: Any, pool: Any
    ) -> FakeConn:
        counter.append(1)
        await asyncio.sleep(0.01)
        return conn

    with patch("ssh_mcp.ssh.pool.open_connection", delayed_open, create=True):
        c1, c2, c3 = await asyncio.gather(
            pool.acquire(policy), pool.acquire(policy), pool.acquire(policy)
        )

    assert c1 is conn
    assert c2 is conn
    assert c3 is conn
    assert len(counter) == 1, "per-key lock must serialize opens"
    await pool.close_all()


@pytest.mark.asyncio
async def test_pool_blocks_blocklisted_hostname(known_hosts_obj: KnownHosts) -> None:
    # Defense-in-depth: even if a caller hands the pool a policy whose hostname is
    # on the blocklist, the pool rejects before opening a connection.
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_ALLOWLIST=["prod-db.internal"],
        SSH_HOSTS_BLOCKLIST=["prod-db.internal"],
    )
    pool = ConnectionPool(settings)
    pool.bind({}, known_hosts_obj)
    policy = _make_policy("prod-db.internal")
    with pytest.raises(HostBlocked):
        await pool.acquire(policy)


@pytest.mark.asyncio
async def test_stats_reports_idle_seconds(known_hosts_obj: KnownHosts) -> None:
    conn = FakeConn()
    counter: list[int] = []
    pool = ConnectionPool(_make_settings())
    pool.bind({}, known_hosts_obj)
    policy = _make_policy()
    with _patch_opener(conn, counter):
        await pool.acquire(policy)
    stats = pool.stats()
    assert len(stats) == 1
    assert stats[0]["host"] == "web01.internal"
    assert stats[0]["user"] == "deploy"
    assert stats[0]["port"] == 22
    assert stats[0]["idle_seconds"] >= 0
    await pool.close_all()
