"""Keyed connection pool with idle reaper. See DESIGN.md §5.3 and ADR-0012."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .connection import open_connection
from .errors import HostNotAllowed

if TYPE_CHECKING:
    import asyncssh

    from ..config import Settings
    from ..models.policy import HostPolicy
    from .known_hosts import KnownHosts

logger = logging.getLogger(__name__)


@dataclass
class _Entry:
    conn: asyncssh.SSHClientConnection | None = None
    last_used: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class ConnectionPool:
    """Lazy, keyed connection pool.

    Entries are keyed by ``(user, hostname, port)``. Idle entries are reaped by a
    background task running every 60 s. Concurrent acquires for the same key are
    serialized via per-key locks so we only open one underlying connection.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._entries: dict[tuple[str, str, int], _Entry] = {}
        self._hosts: dict[str, HostPolicy] = {}
        self._known_hosts: KnownHosts | None = None
        self._reaper: asyncio.Task[None] | None = None
        self._closing = False

    # --- setup ---

    def bind(self, hosts: dict[str, HostPolicy], known_hosts: KnownHosts) -> None:
        """Attach host registry and known_hosts. Called from lifespan after load."""
        self._hosts = hosts
        self._known_hosts = known_hosts

    def start_reaper(self) -> None:
        """Start the idle reaper. Safe to call multiple times."""
        if self._reaper is None or self._reaper.done():
            self._reaper = asyncio.create_task(self._reap_loop(), name="ssh-idle-reaper")

    # --- introspection ---

    def host(self, name: str) -> HostPolicy | None:
        return self._hosts.get(name)

    def size(self) -> int:
        return sum(1 for e in self._entries.values() if e.conn is not None)

    def stats(self) -> list[dict[str, object]]:
        now = time.monotonic()
        out: list[dict[str, object]] = []
        for (user, host, port), entry in self._entries.items():
            if entry.conn is None:
                continue
            out.append(
                {
                    "user": user,
                    "host": host,
                    "port": port,
                    "idle_seconds": int(now - entry.last_used),
                }
            )
        return out

    # --- acquire / close ---

    async def acquire(self, policy: HostPolicy) -> asyncssh.SSHClientConnection:
        """Return a connection for the given policy, opening one if needed."""
        self._check_allowed(policy)
        if self._known_hosts is None:
            raise RuntimeError("ConnectionPool.bind() must be called before acquire()")

        key = (policy.user, policy.hostname, policy.port)
        entry = self._entries.setdefault(key, _Entry())
        async with entry.lock:
            if entry.conn is not None and not entry.conn.is_closed():
                entry.last_used = time.monotonic()
                return entry.conn
            logger.info("opening SSH connection to %s@%s:%d", *key)
            entry.conn = await open_connection(
                policy=policy,
                settings=self._settings,
                known_hosts=self._known_hosts,
                pool=self,
            )
            entry.last_used = time.monotonic()
            return entry.conn

    async def close_all(self) -> None:
        self._closing = True
        if self._reaper is not None and not self._reaper.done():
            self._reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reaper

        for key, entry in list(self._entries.items()):
            if entry.conn is not None:
                entry.conn.close()
                with contextlib.suppress(Exception):
                    await entry.conn.wait_closed()
            self._entries.pop(key, None)

    # --- internals ---

    def _check_allowed(self, policy: HostPolicy) -> None:
        # 1. Default-deny when nothing is configured.
        if not self._hosts and not self._settings.SSH_HOSTS_ALLOWLIST:
            raise HostNotAllowed(
                "no hosts configured: add hosts.toml or set SSH_HOSTS_ALLOWLIST"
            )

        # 2. Hostname must be known.
        allowed = set(self._hosts) | set(self._settings.SSH_HOSTS_ALLOWLIST)
        if policy.hostname not in allowed and not any(
            h.hostname == policy.hostname for h in self._hosts.values()
        ):
            raise HostNotAllowed(f"host {policy.hostname!r} is not allowlisted")

        # 3. Blocklist check (deny wins) — defense-in-depth for policies built outside resolve().
        from ..services.host_policy import check_policy

        check_policy(policy, self._settings)

    async def _reap_loop(self) -> None:
        while not self._closing:
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                return
            await self._reap_once()

    async def _reap_once(self) -> None:
        now = time.monotonic()
        idle = self._settings.SSH_IDLE_TIMEOUT
        stale: list[tuple[str, str, int]] = []
        # Snapshot the items first. Acquire / release elsewhere in this
        # class can insert or drop entries while we're deciding which are
        # stale; iterating `self._entries.items()` directly would raise
        # `RuntimeError: dictionary changed size during iteration` when
        # a concurrent `pool.acquire` touches the dict. `list(...)` is
        # a cheap snapshot — one reference per entry, bounded by pool size.
        for key, entry in list(self._entries.items()):
            if entry.conn is None:
                continue
            if (now - entry.last_used) > idle:
                stale.append(key)

        for key in stale:
            entry = self._entries.get(key)
            if entry is None or entry.conn is None:
                continue
            logger.info("reaping idle connection %s@%s:%d", *key)
            entry.conn.close()
            with contextlib.suppress(Exception):
                await entry.conn.wait_closed()
            self._entries.pop(key, None)
