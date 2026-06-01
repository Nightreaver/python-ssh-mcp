"""Shared helpers for the low-access tier (split from `low_access_tools.py`).

Stateless plumbing reused by the per-topic tool modules (``fs_tools``,
``link_tools``, ``upload_tools``, ``edit_tools``). Nothing here registers a
tool -- that's the job of the sibling modules.

Public-ish names (`WriteError`) are surfaced via the facade so existing
imports keep working; private names start with ``_``.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from typing import TYPE_CHECKING

import asyncssh

# asyncssh.sftp does not list FX_* in its public ``__all__``, even though they
# exist at runtime and the asyncssh docs reference them. Import from
# ``asyncssh.constants`` instead — that's the public re-export surface mypy
# can verify, and it removes the need for ``# type: ignore[attr-defined]``.
from asyncssh.constants import FX_NO_SUCH_FILE
from fastmcp import Context

from ...services.local_path_policy import LOCAL_STREAM_CHUNK_BYTES
from ...services.path_policy import resolve_path
from ...services.redact_policy import REDACT_BYPASS_WARNING, check_redact_bypass
from .._context import pool_from, resolve_host, settings_from

if TYPE_CHECKING:
    from pathlib import Path

    from ...config import Settings
    from ...models.policy import HostPolicy
    from ...ssh.pool import ConnectionPool


_TMP_SUFFIX_BYTES = 8


class WriteError(Exception):
    """Raised when a low-access write op fails policy or runtime."""


async def _prepare_existing(
    ctx: Context, host: str, path: str
) -> tuple[ConnectionPool, HostPolicy, Settings, asyncssh.SSHClientConnection, str]:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)
    return pool, policy, settings, conn, canonical


async def _prepare_creatable(
    ctx: Context, host: str, path: str
) -> tuple[ConnectionPool, HostPolicy, Settings, asyncssh.SSHClientConnection, str]:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=False, pool=pool)
    return pool, policy, settings, conn, canonical


def _tmp_sibling(path: str) -> str:
    token = secrets.token_hex(_TMP_SUFFIX_BYTES)
    return f"{path}.ssh-mcp-tmp.{token}"


async def _atomic_write(
    sftp: asyncssh.SFTPClient,
    final_path: str,
    data: bytes,
    mode: int,
) -> None:
    tmp = _tmp_sibling(final_path)
    try:
        async with sftp.open(tmp, "wb") as f:
            await f.write(data)
        await sftp.chmod(tmp, mode)
        await sftp.posix_rename(tmp, final_path)
    # Narrow the catch so that `asyncio.CancelledError` (BaseException on 3.8+)
    # and genuine programming errors (MemoryError, KeyboardInterrupt) don't get
    # swallowed and replaced by a re-raised generic. The real failure modes for
    # the write-chmod-rename dance are SFTP-layer errors (no space, perm denied,
    # rename across devices) and local OS-level errors during `sftp.open`.
    except (asyncssh.Error, OSError):
        with contextlib.suppress(asyncssh.SFTPError):
            await sftp.remove(tmp)
        raise


async def _atomic_write_stream(
    sftp: asyncssh.SFTPClient,
    final_path: str,
    local_path: Path,
    mode: int,
) -> int:
    """Stream `local_path` into a tmp sibling of `final_path` via SFTP,
    then atomically rename. Returns the byte count actually transferred.

    Used by the v1.3.0 ``local_path`` upload mode. The whole file never
    sits in RAM -- we read 256 KiB at a time from the local disk via a
    threadpool (open/read are blocking syscalls) and ship each chunk
    through the SFTP channel. asyncssh's window-based flow control
    pipelines the writes, so a serial read/write loop already saturates
    the SFTP channel.

    Failure cleanup mirrors :func:`_atomic_write`: any ``asyncssh.Error``
    or ``OSError`` triggers a best-effort ``sftp.remove(tmp)`` so a crash
    mid-transfer never leaves an unnamed tmp file lying around.
    """
    tmp = _tmp_sibling(final_path)
    bytes_transferred = 0
    try:
        # ``open(..., "rb")`` is a blocking syscall -- run it in a thread
        # so the event loop stays responsive. Same goes for each chunk
        # ``.read()`` below.
        fh = await asyncio.to_thread(open, local_path, "rb")
        try:
            async with sftp.open(tmp, "wb") as dst:
                while True:
                    chunk = await asyncio.to_thread(fh.read, LOCAL_STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    await dst.write(chunk)
                    bytes_transferred += len(chunk)
        finally:
            await asyncio.to_thread(fh.close)
        await sftp.chmod(tmp, mode)
        await sftp.posix_rename(tmp, final_path)
    except (asyncssh.Error, OSError):
        with contextlib.suppress(asyncssh.SFTPError):
            await sftp.remove(tmp)
        raise
    return bytes_transferred


def _is_missing(exc: asyncssh.SFTPError) -> bool:
    """INC-014: use asyncssh's named constant rather than a bare magic number."""
    return getattr(exc, "code", None) == FX_NO_SUCH_FILE


def _bypass_warnings(canonical: str, policy: HostPolicy, settings: Settings) -> list[str]:
    """Return the ``output_warnings`` entries that the redact-bypass layer
    wants attached for ``canonical``.

    Used by file-ops tools after ``_prepare_existing`` / ``_prepare_creatable``.
    ``block`` mode already raised in ``resolve_path``; we only see ``warn``
    or ``audit_only`` (or ``None``) here. ``warn`` ⇒ the standard
    REDACT_BYPASS_WARNING string. ``audit_only`` ⇒ empty list (the audit
    layer is the operator's notification channel; the LLM stays uninformed).

    Returns an empty list in the common case (path not on the redact
    list).
    """
    mode = check_redact_bypass(canonical, policy, settings)
    if mode == "warn":
        return [REDACT_BYPASS_WARNING]
    return []
