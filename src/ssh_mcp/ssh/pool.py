"""Keyed connection pool with idle reaper. See DESIGN.md §5.3 and ADR-0012.

Naming convention: methods prefixed with ``_`` (e.g. ``_check_allowed``,
``_reap_loop``) are pool-internals not for tool-layer use. Public methods
(``acquire``, ``acquire_policy``, ``sftp``, ``sftp_policy``, ``invalidate``,
``close``, ``stats``, ``host``) are the documented surface; ``acquire_policy``
is a sibling-module contract called from :mod:`ssh_mcp.ssh.connection` for
the proxy-jump bastion path, where hop policies come from the in-memory
hosts registry rather than user input. Tools should always go through
``acquire(ResolvedHost)`` and ``sftp(ResolvedHost)``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import asyncssh

from .connection import open_connection
from .errors import HostNotAllowed, SFTPSubsystemUnavailable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ..config import Settings
    from ..models.policy import HostPolicy, ResolvedHost
    from .known_hosts import KnownHosts

logger = logging.getLogger(__name__)


@dataclass
class _Entry:
    conn: asyncssh.SSHClientConnection | None = None
    # Cached SFTPClient per connection. SFTP subsystem channels are an
    # expensive setup on the server side (DSM 7.x's sshd will exhaust
    # MaxSessions if we open one per call). asyncssh's SFTPClient
    # multiplexes concurrent requests on a single channel, so sharing
    # across awaits is idiomatic. Closed alongside the connection on
    # invalidate / reap / close_all.
    sftp: asyncssh.SFTPClient | None = None
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

    async def acquire(self, resolved: ResolvedHost) -> asyncssh.SSHClientConnection:
        """Return a connection for the given resolved host, opening one if needed.

        Public entry point for tool call sites: takes the post-resolution
        `ResolvedHost` so the type system encodes that the host has cleared
        host_policy.resolve() (alias lookup + allowlist + blocklist). The
        bastion / proxy_chain path inside `connection.open_connection` calls
        `acquire_policy` directly with a `HostPolicy`, since hop hosts are
        loaded from `hosts.toml` (already canonical) rather than user-resolved.
        """
        return await self.acquire_policy(resolved.policy)

    async def acquire_policy(self, policy: HostPolicy) -> asyncssh.SSHClientConnection:
        """Open or reuse a connection for the given `HostPolicy`.

        Sibling-module contract for :mod:`ssh_mcp.ssh.connection`; bypasses
        the `ResolvedHost` wrapper so the bastion path (where hop policies
        come from the in-memory hosts registry, not user input) doesn't
        have to fake a `ResolvedHost`. The `_check_allowed` blocklist +
        allowlist gate still runs here, regardless of caller. Not for
        tool-layer use -- tools must go through :meth:`acquire`.
        """
        self._check_allowed(policy)
        if self._known_hosts is None:
            raise RuntimeError("ConnectionPool.bind() must be called before acquire()")

        key = (policy.user, policy.hostname, policy.port)
        entry = self._entries.setdefault(key, _Entry())
        async with entry.lock:
            if entry.conn is not None and not entry.conn.is_closed():
                entry.last_used = time.monotonic()
                return entry.conn
            # Connection is missing or closed -- if we had a cached SFTPClient
            # tied to the now-defunct connection, drop it too so we don't try
            # to reuse a dangling channel on the next sftp() call.
            self._close_sftp_in_place(entry)
            logger.info("opening SSH connection to %s@%s:%d", *key)
            entry.conn = await open_connection(
                policy=policy,
                settings=self._settings,
                known_hosts=self._known_hosts,
                pool=self,
            )
            entry.last_used = time.monotonic()
            return entry.conn

    @contextlib.asynccontextmanager
    async def sftp(self, resolved: ResolvedHost) -> AsyncIterator[asyncssh.SFTPClient]:
        """Yield a cached SFTPClient for the host.

        Self-healing: on ``asyncssh.ChannelOpenError`` /
        ``asyncssh.ConnectionLost`` raised inside the ``async with`` block,
        the underlying connection (and cached SFTPClient) are invalidated
        and the error is re-raised so the caller decides whether to retry.
        ``asyncssh.SFTPError`` is intentionally NOT caught here -- those are
        data-layer errors (permission denied, no such file) and have nothing
        to do with channel health.

        Concurrent reads against the same SFTPClient are fine -- asyncssh
        multiplexes requests on a single SFTP subsystem channel.
        """
        async with self._sftp_for_policy(resolved.policy) as client:
            yield client

    @contextlib.asynccontextmanager
    async def sftp_policy(self, policy: HostPolicy) -> AsyncIterator[asyncssh.SFTPClient]:
        """Sibling of :meth:`sftp` for callers that hold a raw ``HostPolicy``.

        Used by :mod:`ssh_mcp.services.path_policy` where the canonicalization
        helpers operate on the live `HostPolicy` rather than a `ResolvedHost`
        (the resolution has already happened upstream in the tool call site).
        """
        async with self._sftp_for_policy(policy) as client:
            yield client

    @contextlib.asynccontextmanager
    async def _sftp_for_policy(self, policy: HostPolicy) -> AsyncIterator[asyncssh.SFTPClient]:
        key = (policy.user, policy.hostname, policy.port)
        client = await self._acquire_sftp(policy)
        try:
            yield client
        except (asyncssh.ChannelOpenError, asyncssh.ConnectionLost):
            # Channel-level failure -- the cached SFTPClient (and likely the
            # connection too) is poisoned. Drop the whole entry so the next
            # caller opens a fresh connection + fresh SFTP channel. We do
            # NOT retry here: the LLM gets the error and decides whether to
            # re-issue the request.
            logger.warning(
                "SFTP channel failure on %s@%s:%d; invalidating pool entry",
                *key,
            )
            await self.invalidate(key)
            raise

    async def _acquire_sftp(self, policy: HostPolicy) -> asyncssh.SFTPClient:
        """Open or reuse the cached SFTPClient for this connection.

        Acquires the per-key lock so concurrent first-acquires open exactly
        ONE SFTP channel. Once the cache is warm, callers proceed without
        the lock (asyncssh handles channel-level multiplexing).

        Resilient to a concurrent ``invalidate`` between the connection
        acquire and the sftp slot lookup -- if the entry vanished, we
        re-acquire the connection (which re-creates the entry) and try
        again. Bounded retry; if we keep losing the race something is
        seriously wrong and we surface a RuntimeError to the caller.
        """
        key = (policy.user, policy.hostname, policy.port)
        # We need to ensure conn + entry survive together. Tight loop with
        # a small retry budget covers the rare invalidate-mid-acquire race
        # without papering over a genuine systemic failure.
        for _ in range(3):
            conn = await self.acquire_policy(policy)
            entry = self._entries.get(key)
            if entry is None:
                # Invalidated between acquire_policy return and our lookup.
                continue
            if entry.sftp is not None:
                return entry.sftp

            async with entry.lock:
                # Re-check under the lock: another waiter may have opened
                # it OR invalidate may have run and dropped the entry.
                current = self._entries.get(key)
                if current is not entry:
                    # Entry was replaced; retry the whole acquire.
                    continue
                if entry.sftp is not None:
                    return entry.sftp
                logger.info("opening cached SFTP subsystem to %s@%s:%d", *key)
                try:
                    entry.sftp = await conn.start_sftp_client()
                except asyncssh.ChannelOpenError as exc:
                    # Translate the specific "SSH server refused the sftp
                    # subsystem" case (DSM, hardened sshd configs, missing
                    # `Subsystem sftp ...` line) into a structured error so
                    # the LLM sees a remediation hint instead of asyncssh's
                    # raw "Session request failed" string. Other
                    # ChannelOpenError codes (resource shortage, admin
                    # prohibition) have different semantics -- let them
                    # propagate raw. We do NOT invalidate the pool entry
                    # here: the carrier connection is healthy, only the
                    # subsystem is unavailable, and channel-based tools
                    # (exec, sudo_exec, ping) will still work on it.
                    if exc.code == asyncssh.OPEN_REQUEST_SESSION_FAILED:
                        raise SFTPSubsystemUnavailable(
                            user=policy.user,
                            host=policy.hostname,
                            port=policy.port,
                        ) from exc
                    raise
                entry.last_used = time.monotonic()
                return entry.sftp
        raise RuntimeError(
            f"pool entry for {key!r} kept being invalidated mid-acquire; "
            f"check for invalidate() loops in the call site."
        )

    async def invalidate(self, key: tuple[str, str, int]) -> None:
        """Force-close the cached connection + SFTPClient for ``key`` and drop the entry.

        Idempotent -- calling on a missing key is a no-op. Triggered when a
        caller (typically :meth:`sftp`) observes a channel-level failure
        that proves the cached resources are unusable. Synchronous close on
        the SFTPClient (asyncssh's :meth:`SFTPClient.exit` is sync), async
        close on the SSH connection.
        """
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        logger.warning("invalidating pool entry %s@%s:%d", *key)
        self._close_sftp_in_place(entry)
        conn = entry.conn
        entry.conn = None
        if conn is not None:
            conn.close()
            with contextlib.suppress(Exception):
                await conn.wait_closed()

    @staticmethod
    def _close_sftp_in_place(entry: _Entry) -> None:
        """Close the cached SFTPClient on ``entry`` (if any) and clear the slot.

        Best-effort: SFTPClient.exit() is synchronous and can raise if the
        channel is already torn down; we swallow any exception so close
        always finishes the slot reset.
        """
        sftp = entry.sftp
        entry.sftp = None
        if sftp is not None:
            with contextlib.suppress(Exception):
                sftp.exit()

    async def close_all(self) -> None:
        self._closing = True
        if self._reaper is not None and not self._reaper.done():
            self._reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reaper

        for key, entry in list(self._entries.items()):
            self._close_sftp_in_place(entry)
            if entry.conn is not None:
                entry.conn.close()
                with contextlib.suppress(Exception):
                    await entry.conn.wait_closed()
            self._entries.pop(key, None)

    # --- internals ---

    def _check_allowed(self, policy: HostPolicy) -> None:
        # 1. Default-deny when nothing is configured.
        if not self._hosts and not self._settings.SSH_HOSTS_ALLOWLIST:
            raise HostNotAllowed("no hosts configured: add hosts.toml or set SSH_HOSTS_ALLOWLIST")

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
            stale_entry = self._entries.get(key)
            if stale_entry is None or stale_entry.conn is None:
                continue
            logger.info("reaping idle connection %s@%s:%d", *key)
            # Close the cached SFTPClient FIRST -- otherwise its server-side
            # channel becomes a zombie once the carrier connection drops.
            self._close_sftp_in_place(stale_entry)
            stale_entry.conn.close()
            with contextlib.suppress(Exception):
                await stale_entry.conn.wait_closed()
            self._entries.pop(key, None)
