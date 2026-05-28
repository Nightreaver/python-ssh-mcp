"""Low-access filesystem tools: ``ssh_mkdir``, ``ssh_delete``,
``ssh_delete_folder``, ``ssh_cp``, ``ssh_mv``.

POSIX-leaning. SFTP-first where possible, with shell fallbacks via fixed
argv. See ADR-0006 / docstring on the parent facade.
"""

from __future__ import annotations

import posixpath
import shlex
import stat as stat_module
from typing import Any

import asyncssh
from fastmcp import Context

from ...app import mcp_server
from ...models.results import WriteResult
from ...services.audit import audited
from ...services.path_policy import (
    canonicalize_and_check,
    effective_allowlist,
    resolve_path,
)
from .._context import require_posix, resolve_host
from ._helpers import (
    WriteError,
    _is_missing,
    _prepare_creatable,
    _prepare_existing,
)

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
    pool, policy, _settings, _conn, canonical = await _prepare_creatable(ctx, host, path)
    async with pool.sftp_policy(policy) as sftp:
        if parents:
            await _mkdir_p(sftp, canonical, mode)
        else:
            await sftp.mkdir(canonical, asyncssh.SFTPAttrs(permissions=mode))
    return WriteResult(
        host=policy.hostname,
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


# --------- ssh_delete ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_delete(host: str, path: str, ctx: Context) -> WriteResult:
    """Delete a single file. Rejects directories — use ssh_delete_folder."""
    pool, policy, _settings, _conn, canonical = await _prepare_existing(ctx, host, path)
    async with pool.sftp_policy(policy) as sftp:
        attrs = await sftp.lstat(canonical)
        if stat_module.S_ISDIR(attrs.permissions or 0):
            raise WriteError(f"{canonical!r} is a directory; use ssh_delete_folder")
        await sftp.remove(canonical)
    return WriteResult(host=policy.hostname, path=canonical, success=True, message="deleted")


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
    pool, policy, settings, conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_DELETE_FOLDER_MAX_ENTRIES
    async with pool.sftp_policy(policy) as sftp:
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
            raise WriteError(f"folder would touch >= {cap} entries; raise SSH_DELETE_FOLDER_MAX_ENTRIES")

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
        conn, canonical, allowlist, must_exist=True, platform=policy.platform, pool=pool, policy=policy
    )
    if re_canonical != canonical:
        raise WriteError(f"path changed between walk and rm -rf: was {canonical!r}, now {re_canonical!r}")

    if policy.platform == "windows":
        # No `rm -rf` shell fallback on Windows; remove each entry via SFTP in
        # reverse-depth order (files and leaf dirs first). `entries` came from
        # _walk_tree which appends parents before children, so reversed order
        # gives us children first. Each unlink/rmdir is its own SFTP op -- ~1
        # roundtrip each -- so this is slow for large trees. That's the tradeoff
        # for not requiring a remote shell; operators with huge Windows trees
        # can fall back to ssh_exec_run under ALLOW_DANGEROUS_TOOLS.
        async with pool.sftp_policy(policy) as sftp:
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
            host=policy.hostname,
            path=canonical,
            success=True,
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
    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_cp", reason="uses `cp -a`; no cross-platform equivalent wired yet")
    pool, policy, settings, conn, src_canonical = await _prepare_existing(ctx, host, src)
    dst_canonical = await resolve_path(conn, dst, policy, settings, must_exist=False, pool=pool)

    # Capture src size BEFORE the copy so ``bytes_written`` surfaces a
    # meaningful number on the result. The pre-copy stat is cheap (one
    # SFTP round-trip) and accurate for the file case; for directory
    # copies (``cp -a dir/ /elsewhere/``) we leave the field at 0 since
    # aggregating tree size is too expensive for a best-effort metric.
    src_size = 0
    try:
        async with pool.sftp_policy(policy) as sftp:
            attrs = await sftp.lstat(src_canonical)
        if stat_module.S_ISREG(attrs.permissions or 0):
            src_size = int(attrs.size or 0)
    except asyncssh.SFTPError:
        # The src was just canonicalized with must_exist=True, so the
        # stat failing here would be surprising. Swallow rather than
        # racing the copy on a transient SFTP hiccup -- bytes_written=0
        # is the same fallback we'd get without this block.
        pass

    result = await conn.run(shlex.join(["cp", "-a", "--", src_canonical, dst_canonical]), check=False)
    if result.exit_status != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes | bytearray):
            stderr = stderr.decode(errors="replace")
        raise WriteError(f"cp failed (exit {result.exit_status}): {stderr.strip()}")
    return WriteResult(
        host=policy.hostname,
        path=dst_canonical,
        success=True,
        bytes_written=src_size,
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
    dst_canonical = await resolve_path(conn, dst, policy, settings, must_exist=False, pool=pool)

    # Pre-capture src size for ``bytes_written``. Same-fs rename writes
    # nothing on disk, but operators reading the result still want a
    # number describing what landed at ``dst``; cross-fs fallback actually
    # copies, where the field is genuinely "bytes transferred". The size
    # comes from one SFTP lstat before the rename -- skip for non-regular
    # files (directory moves) since aggregating a tree is too expensive
    # for a best-effort metric. Matches ``ssh_cp``'s contract.
    src_size = 0
    async with pool.sftp_policy(policy) as sftp:
        try:
            attrs = await sftp.lstat(src_canonical)
            if stat_module.S_ISREG(attrs.permissions or 0):
                src_size = int(attrs.size or 0)
        except asyncssh.SFTPError:
            # Stat hiccup is non-fatal -- the rename below will surface
            # any real problem. ``bytes_written=0`` is the same fallback
            # we'd report without the probe.
            pass

        try:
            await sftp.posix_rename(src_canonical, dst_canonical)
            mode = "sftp-rename"
        except asyncssh.SFTPError as exc:
            # EXDEV, permission denied on cross-fs, etc. → shell fallback.
            if _is_cross_device(exc) and policy.platform == "posix":
                result = await conn.run(shlex.join(["mv", "--", src_canonical, dst_canonical]), check=False)
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
        bytes_written=src_size,
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
