"""Low-access tier: SFTP-mediated file mutation. See ADR-0006.

Every tool here carries tags={"low-access", "group:file-ops"}. They are
hidden unless `ALLOW_LOW_ACCESS_TOOLS=true`. SFTP-first; shell fallbacks
use fixed argv with `--` separators and never string interpolation.
"""
from __future__ import annotations

import base64
import contextlib
import posixpath
import secrets
import shlex
import stat as stat_module
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import asyncssh
from fastmcp import Context

from ..app import mcp_server
from ..models.results import WriteResult
from ..services.audit import audited
from ..services.edit_service import EditError, PatchError, apply_edit, apply_unified_diff
from ..services.path_policy import (
    canonicalize_and_check,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
)
from ._context import pool_from, require_posix, resolve_host, settings_from

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import HostPolicy
    from ..ssh.pool import ConnectionPool


_TMP_SUFFIX_BYTES = 8


# --------- helpers ---------


async def _prepare_existing(
    ctx: Context, host: str, path: str
) -> tuple[ConnectionPool, HostPolicy, Settings, asyncssh.SSHClientConnection, str]:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    allowlist = effective_allowlist(policy, settings)
    canonical = await canonicalize_and_check(
        conn, path, allowlist, must_exist=True, platform=policy.platform
    )
    check_not_restricted(
        canonical, effective_restricted_paths(policy, settings), policy.platform
    )
    return pool, policy, settings, conn, canonical


async def _prepare_creatable(
    ctx: Context, host: str, path: str
) -> tuple[ConnectionPool, HostPolicy, Settings, asyncssh.SSHClientConnection, str]:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    allowlist = effective_allowlist(policy, settings)
    canonical = await canonicalize_and_check(
        conn, path, allowlist, must_exist=False, platform=policy.platform
    )
    check_not_restricted(
        canonical, effective_restricted_paths(policy, settings), policy.platform
    )
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


# --------- ssh_mkdir ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_mkdir(
    host: str,
    path: str,
    ctx: Context,
    parents: bool = False,
    mode: int = 0o755,
) -> WriteResult:
    """Create a directory. With `parents=True`, behave like `mkdir -p`."""
    _pool, _policy, _settings, conn, canonical = await _prepare_creatable(ctx, host, path)
    async with conn.start_sftp_client() as sftp:
        if parents:
            await _mkdir_p(sftp, canonical, mode)
        else:
            await sftp.mkdir(canonical, asyncssh.SFTPAttrs(permissions=mode))
    return WriteResult(
        host=_policy.hostname,
        path=canonical,
        success=True,
        message="created" if not parents else "created (with parents)",
    )


async def _mkdir_p(sftp: asyncssh.SFTPClient, canonical: str, mode: int) -> None:
    parts = canonical.split("/")
    cur = ""
    for part in parts:
        cur = cur + "/" + part if cur else ("/" if part == "" else part)
        if cur == "" or cur == "/":
            continue
        try:
            attrs = await sftp.stat(cur)
            if not stat_module.S_ISDIR(attrs.permissions or 0):
                raise WriteError(f"parent {cur!r} exists and is not a directory")
        except asyncssh.SFTPError as exc:
            if _is_missing(exc):
                await sftp.mkdir(cur, asyncssh.SFTPAttrs(permissions=mode))
            else:
                raise


class WriteError(Exception):
    pass


def _is_missing(exc: asyncssh.SFTPError) -> bool:
    # INC-014: use asyncssh's named constant rather than a bare magic number.
    return getattr(exc, "code", None) == asyncssh.sftp.FX_NO_SUCH_FILE


# --------- ssh_delete ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_delete(host: str, path: str, ctx: Context) -> WriteResult:
    """Delete a single file. Rejects directories — use ssh_delete_folder."""
    _pool, _policy, _settings, conn, canonical = await _prepare_existing(ctx, host, path)
    async with conn.start_sftp_client() as sftp:
        attrs = await sftp.lstat(canonical)
        if stat_module.S_ISDIR(attrs.permissions or 0):
            raise WriteError(f"{canonical!r} is a directory; use ssh_delete_folder")
        await sftp.remove(canonical)
    return WriteResult(
        host=_policy.hostname, path=canonical, success=True, message="deleted"
    )


# --------- ssh_delete_folder ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_delete_folder(
    host: str,
    path: str,
    ctx: Context,
    recursive: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Remove a directory. Non-recursive = rmdir (must be empty).

    `recursive=True` walks the tree via SFTP up to `SSH_DELETE_FOLDER_MAX_ENTRIES`
    and falls back to `rm -rf -- <canonical>` (fixed argv, re-validated).
    `dry_run=True` returns what would be deleted without touching anything.
    """
    _pool, policy, settings, conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_DELETE_FOLDER_MAX_ENTRIES
    async with conn.start_sftp_client() as sftp:
        if not recursive:
            if dry_run:
                return {
                    "host": policy.hostname,
                    "path": canonical,
                    "would_delete": [canonical],
                    "dry_run": True,
                }
            await sftp.rmdir(canonical)
            return WriteResult(
                host=policy.hostname, path=canonical, success=True, message="rmdir"
            ).model_dump()

        entries = await _walk_tree(sftp, canonical, cap)
        if len(entries) >= cap:
            raise WriteError(
                f"folder would touch >= {cap} entries; raise SSH_DELETE_FOLDER_MAX_ENTRIES"
            )

        if dry_run:
            return {
                "host": policy.hostname,
                "path": canonical,
                "would_delete": entries,
                "dry_run": True,
            }

    # Re-validate against allowlist (defense in depth) before shelling out
    # or doing the SFTP recursive walk on Windows.
    allowlist = effective_allowlist(policy, settings)
    re_canonical = await canonicalize_and_check(
        conn, canonical, allowlist, must_exist=True, platform=policy.platform
    )
    if re_canonical != canonical:
        raise WriteError(
            f"path changed between walk and rm -rf: was {canonical!r}, now {re_canonical!r}"
        )

    if policy.platform == "windows":
        # No `rm -rf` shell fallback on Windows; remove each entry via SFTP in
        # reverse-depth order (files and leaf dirs first). `entries` came from
        # _walk_tree which appends parents before children, so reversed order
        # gives us children first. Each unlink/rmdir is its own SFTP op -- ~1
        # roundtrip each -- so this is slow for large trees. That's the tradeoff
        # for not requiring a remote shell; operators with huge Windows trees
        # can fall back to ssh_exec_run under ALLOW_DANGEROUS_TOOLS.
        async with conn.start_sftp_client() as sftp:
            for entry in reversed(entries):
                try:
                    attrs = await sftp.lstat(entry)
                except asyncssh.SFTPError:
                    continue
                if stat_module.S_ISDIR(attrs.permissions or 0) and not stat_module.S_ISLNK(
                    attrs.permissions or 0
                ):
                    await sftp.rmdir(entry)
                else:
                    await sftp.remove(entry)
        return WriteResult(
            host=policy.hostname, path=canonical, success=True,
            message=f"recursively deleted {len(entries)} entries (SFTP)",
        ).model_dump()

    result = await conn.run(shlex.join(["rm", "-rf", "--", canonical]), check=False)
    if result.exit_status != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes | bytearray):
            stderr = stderr.decode(errors="replace")
        raise WriteError(f"rm -rf failed (exit {result.exit_status}): {stderr.strip()}")
    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        message=f"recursively deleted {len(entries)} entries",
    ).model_dump()


async def _walk_tree(sftp: asyncssh.SFTPClient, root: str, cap: int) -> list[str]:
    out: list[str] = [root]
    queue: list[str] = [root]
    while queue and len(out) < cap:
        cur = queue.pop()
        try:
            names = await sftp.listdir(cur)
        except asyncssh.SFTPError:
            continue
        for name in names:
            if name in (".", ".."):
                continue
            full = posixpath.join(cur, name)
            attrs = await sftp.lstat(full)
            out.append(full)
            if stat_module.S_ISDIR(attrs.permissions or 0) and not stat_module.S_ISLNK(
                attrs.permissions or 0
            ):
                queue.append(full)
            if len(out) >= cap:
                break
    return out


# --------- ssh_cp ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_cp(host: str, src: str, dst: str, ctx: Context) -> WriteResult:
    """Copy a file. Uses `cp -a -- src dst` with fixed argv (no shell).

    POSIX-only -- relies on the `cp` binary. Windows targets raise
    `PlatformNotSupported`; use `ssh_sftp_download` + `ssh_upload` as a
    cross-platform alternative.
    """
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_cp", reason="uses `cp -a`; no cross-platform equivalent wired yet")
    pool, policy, settings, conn, src_canonical = await _prepare_existing(ctx, host, src)
    dst_canonical = await canonicalize_and_check(
        conn, dst, effective_allowlist(policy, settings),
        must_exist=False, platform=policy.platform,
    )
    check_not_restricted(
        dst_canonical, effective_restricted_paths(policy, settings), policy.platform,
    )
    result = await conn.run(
        shlex.join(["cp", "-a", "--", src_canonical, dst_canonical]), check=False
    )
    if result.exit_status != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes | bytearray):
            stderr = stderr.decode(errors="replace")
        raise WriteError(f"cp failed (exit {result.exit_status}): {stderr.strip()}")
    return WriteResult(
        host=policy.hostname,
        path=dst_canonical,
        success=True,
        message=f"copied from {src_canonical}",
    )


# --------- ssh_mv ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_mv(host: str, src: str, dst: str, ctx: Context) -> WriteResult:
    """Move a file. SFTP rename first; falls back to `mv --` across filesystems.

    On Windows targets the POSIX `mv --` fallback is skipped -- SFTP rename
    covers same-volume moves natively, and cross-volume moves on Windows
    need a separate implementation we haven't written.
    """
    pool, policy, settings, conn, src_canonical = await _prepare_existing(ctx, host, src)
    dst_canonical = await canonicalize_and_check(
        conn, dst, effective_allowlist(policy, settings),
        must_exist=False, platform=policy.platform,
    )
    check_not_restricted(
        dst_canonical, effective_restricted_paths(policy, settings), policy.platform,
    )
    async with conn.start_sftp_client() as sftp:
        try:
            await sftp.posix_rename(src_canonical, dst_canonical)
            mode = "sftp-rename"
        except asyncssh.SFTPError as exc:
            # EXDEV, permission denied on cross-fs, etc. → shell fallback.
            if _is_cross_device(exc) and policy.platform == "posix":
                result = await conn.run(
                    shlex.join(["mv", "--", src_canonical, dst_canonical]), check=False
                )
                if result.exit_status != 0:
                    stderr = result.stderr
                    if isinstance(stderr, bytes | bytearray):
                        stderr = stderr.decode(errors="replace")
                    raise WriteError(f"mv failed (exit {result.exit_status}): {stderr.strip()}") from exc
                mode = "mv-fallback"
            else:
                raise

    return WriteResult(
        host=policy.hostname,
        path=dst_canonical,
        success=True,
        message=f"moved from {src_canonical} ({mode})",
    )


def _is_cross_device(exc: asyncssh.SFTPError) -> bool:
    # INC-014: named constants rather than magic numbers. FX_FAILURE is how
    # most sshd builds surface EXDEV; the other two are defensive. The shell
    # fallback will produce a cleaner error on any non-EXDEV reason.
    code = getattr(exc, "code", None)
    return code in {
        asyncssh.sftp.FX_FAILURE,
        asyncssh.sftp.FX_OP_UNSUPPORTED,
        asyncssh.sftp.FX_LINK_LOOP,
    }


# --------- ssh_upload ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_upload(
    host: str,
    path: str,
    content_base64: str,
    ctx: Context,
    mode: int = 0o644,
) -> WriteResult:
    """Upload a file. Written to `<path>.ssh-mcp-tmp.<rand>` then atomically renamed."""
    _pool, policy, settings, conn, canonical = await _prepare_creatable(ctx, host, path)
    data = base64.b64decode(content_base64, validate=True)
    cap = settings.SSH_UPLOAD_MAX_FILE_BYTES
    if len(data) > cap:
        raise WriteError(f"payload {len(data)} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES={cap}")
    async with conn.start_sftp_client() as sftp:
        await _atomic_write(sftp, canonical, data, mode)
    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(data),
        message="uploaded (atomic)",
    )


# --------- ssh_edit ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_edit(
    host: str,
    path: str,
    old_string: str,
    new_string: str,
    ctx: Context,
    occurrence: Literal["single", "all"] = "single",
) -> WriteResult:
    """Structured edit: replace `old_string` with `new_string` atomically."""
    _pool, policy, settings, conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_EDIT_MAX_FILE_BYTES
    async with conn.start_sftp_client() as sftp:
        attrs = await sftp.stat(canonical)
        size = attrs.size or 0
        if size > cap:
            raise WriteError(
                f"file {size} bytes exceeds SSH_EDIT_MAX_FILE_BYTES={cap}"
            )
        async with sftp.open(canonical, "rb") as f:
            raw = await f.read()
        # INC-010: surface a clean WriteError on non-UTF-8 files rather than
        # letting a raw UnicodeDecodeError escape. Using errors='replace' would
        # be worse -- we'd write back mangled bytes. Caller should fall back
        # to ssh_sftp_download + offline edit + ssh_upload for binary files.
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WriteError(
                f"{canonical!r} is not valid UTF-8 (offset {exc.start}); "
                f"edit/patch tools are text-only. Use download + upload for binaries."
            ) from exc
        try:
            outcome = apply_edit(text, old_string, new_string, occurrence=occurrence)
        except EditError as exc:
            raise WriteError(str(exc)) from exc
        mode = int((attrs.permissions or 0o644) & 0o7777)
        await _atomic_write(sftp, canonical, outcome.new_text.encode("utf-8"), mode)

    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(outcome.new_text.encode("utf-8")),
        message=f"replaced {outcome.replacements} occurrence(s)",
    )


# --------- ssh_patch ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_patch(
    host: str,
    path: str,
    unified_diff: str,
    ctx: Context,
) -> WriteResult:
    """Apply a unified diff to a single file atomically."""
    _pool, policy, settings, conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_EDIT_MAX_FILE_BYTES
    async with conn.start_sftp_client() as sftp:
        attrs = await sftp.stat(canonical)
        size = attrs.size or 0
        if size > cap:
            raise WriteError(
                f"file {size} bytes exceeds SSH_EDIT_MAX_FILE_BYTES={cap}"
            )
        async with sftp.open(canonical, "rb") as f:
            raw = await f.read()
        # INC-010: surface a clean WriteError on non-UTF-8 files rather than
        # letting a raw UnicodeDecodeError escape. Using errors='replace' would
        # be worse -- we'd write back mangled bytes. Caller should fall back
        # to ssh_sftp_download + offline edit + ssh_upload for binary files.
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WriteError(
                f"{canonical!r} is not valid UTF-8 (offset {exc.start}); "
                f"edit/patch tools are text-only. Use download + upload for binaries."
            ) from exc
        try:
            outcome = apply_unified_diff(text, unified_diff)
        except PatchError as exc:
            raise WriteError(str(exc)) from exc
        mode = int((attrs.permissions or 0o644) & 0o7777)
        await _atomic_write(sftp, canonical, outcome.new_text.encode("utf-8"), mode)

    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(outcome.new_text.encode("utf-8")),
        message=f"{outcome.hunks_applied} hunk(s) applied",
    )


# --------- ssh_deploy ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_deploy(
    host: str,
    path: str,
    content_base64: str,
    ctx: Context,
    mode: int = 0o644,
    backup: bool = True,
) -> dict[str, Any]:
    """Deploy a file atomically with optional pre-deploy backup.

    Extends ``ssh_upload`` with auto-backup. If ``backup=True`` and the path
    already exists, the existing file is renamed to
    ``<path>.bak-<UTC-iso8601>`` via SFTP ``posix_rename`` before the new
    content is written. The new content then lands via the same tmp+rename
    atomic dance as ``ssh_upload``.

    Does NOT handle chown/owner changes -- that would require sudo (see
    ``ssh_sudo_exec`` in the dangerous tier). ``mode`` sets the file's
    permission bits and is applied to the tmp file before the final rename.
    """
    _pool, policy, settings, conn, canonical = await _prepare_creatable(ctx, host, path)
    data = base64.b64decode(content_base64, validate=True)
    cap = settings.SSH_UPLOAD_MAX_FILE_BYTES
    if len(data) > cap:
        raise WriteError(f"payload {len(data)} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES={cap}")

    backup_path: str | None = None
    async with conn.start_sftp_client() as sftp:
        # If the target exists AND caller asked for a backup, rename-out-of-way.
        if backup:
            try:
                attrs = await sftp.lstat(canonical)
            except asyncssh.SFTPError:
                attrs = None
            if attrs is not None and not stat_module.S_ISDIR(attrs.permissions or 0):
                ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
                backup_path = f"{canonical}.bak-{ts}"
                await sftp.posix_rename(canonical, backup_path)
        await _atomic_write(sftp, canonical, data, mode)

    msg = "deployed (atomic)"
    if backup_path:
        msg = f"deployed; previous version at {backup_path}"
    result = WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(data),
        message=msg,
    ).model_dump()
    if backup_path:
        result["backup_path"] = backup_path
    return result
