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
    check_in_allowlist,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
    reject_bad_characters,
    resolve_path,
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
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True)
    return pool, policy, settings, conn, canonical


async def _prepare_creatable(
    ctx: Context, host: str, path: str
) -> tuple[ConnectionPool, HostPolicy, Settings, asyncssh.SSHClientConnection, str]:
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=False)
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
    return WriteResult(host=_policy.hostname, path=canonical, success=True, message="deleted")


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
        conn, canonical, allowlist, must_exist=True, platform=policy.platform
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
    dst_canonical = await resolve_path(conn, dst, policy, settings, must_exist=False)
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
    dst_canonical = await resolve_path(conn, dst, policy, settings, must_exist=False)
    async with conn.start_sftp_client() as sftp:
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
        message=f"moved from {src_canonical} ({mode})",
    )


# --------- ssh_link ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_link(
    host: str,
    src: str,
    dst: str,
    ctx: Context,
    symbolic: bool = False,
    follow_symlinks: bool = True,
) -> WriteResult:
    """Create a hard or symbolic link from `src` to `dst` on the remote host.

    `symbolic=True` (`ln -s`): create a symbolic link at `dst` whose target
    text is `src`. Pure SFTP via `sftp.symlink()`. Per GNU `ln`'s "Using -s
    ignores -L and -P", `follow_symlinks` is silently ignored in this mode.
    `src` is stored VERBATIM in the symlink (preserves relative-link
    semantics: `ln -s ../foo bar` keeps `../foo` as the link text).

    `symbolic=False` + `follow_symlinks=True` (default, like `ln -L`):
    create a hard link. The link points to the inode of src's resolved
    target. Pure SFTP -- asyncssh's `sftp.link()` invokes the
    SFTP-HARDLINK extension, which OpenSSH's sftp-server implements via
    `linkat(... AT_SYMLINK_FOLLOW)`.

    `symbolic=False` + `follow_symlinks=False` (like `ln -P` /
    `--physical`): hard link to the SYMLINK's own inode, not its target.
    SFTP can't express "don't follow" for hard links, so this falls back
    to a shell `ln -P -- <src> <dst>` invocation. Same low-access tier as
    `ssh_cp` / `ssh_mv` -- doesn't require `ln` in `command_allowlist`.

    PATH POLICY. `dst` is always canonicalized; its parent must exist and
    be in the allowlist. For `src`:

    - hard link `-L` (default): canonicalized normally (resolves symlinks);
      the resolved target must be in the allowlist + not restricted.
    - hard link `-P`: parent-canonicalize + `lstat` (canonicalizing src
      would defeat `-P`'s point). The check is "the symlink lives in an
      allowed dir," not "everywhere it could point is allowed."
    - symbolic link: src is treated as a TARGET STRING, not a real path
      (POSIX permits dangling symlinks; src may not exist yet). Validated
      string-wise: relative paths resolved against dst's parent dir,
      normalized via `posixpath.normpath`, then checked against allowlist
      + restricted_paths. `reject_bad_characters` rejects NUL / control
      bytes up front.

    Existing dst raises `SFTPError` (sftp paths) or `WriteError` (shell
    path); use `ssh_delete` first if you need to overwrite.

    POSIX-only. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(
        resolved,
        tool="ssh_link",
        reason="POSIX hard / symbolic links via SFTP / `ln`",
    )
    conn = await pool.acquire(resolved)

    allowlist = effective_allowlist(policy, settings)
    restricted = effective_restricted_paths(policy, settings)

    dst_canonical = await canonicalize_and_check(
        conn,
        dst,
        allowlist,
        must_exist=False,
        platform=policy.platform,
    )
    check_not_restricted(dst_canonical, restricted, policy.platform)

    # Three modes, three different src-validation + creation strategies.
    # Body is dispatch + WriteResult assembly; the per-mode helpers own
    # the policy checks and the SFTP / shell call. See per-helper
    # docstrings for the policy contract specific to each mode.
    if symbolic:
        await _create_symbolic_link(
            conn=conn,
            src=src,
            dst_canonical=dst_canonical,
            allowlist=allowlist,
            restricted=restricted,
            platform=policy.platform,
        )
        return WriteResult(
            host=policy.hostname,
            path=dst_canonical,
            success=True,
            message=f"symbolic link -> {src}",
        )

    if follow_symlinks:
        src_canonical = await _create_hard_link_followed(
            conn=conn,
            src=src,
            dst_canonical=dst_canonical,
            allowlist=allowlist,
            restricted=restricted,
            platform=policy.platform,
        )
        return WriteResult(
            host=policy.hostname,
            path=dst_canonical,
            success=True,
            message=f"hard link (followed symlinks) -> {src_canonical}",
        )

    src_full = await _create_hard_link_unfollowed(
        conn=conn,
        src=src,
        dst_canonical=dst_canonical,
        allowlist=allowlist,
        restricted=restricted,
        platform=policy.platform,
    )
    return WriteResult(
        host=policy.hostname,
        path=dst_canonical,
        success=True,
        message=f"hard link (physical, unfollowed symlinks) -> {src_full}",
    )


async def _create_symbolic_link(
    *,
    conn: asyncssh.SSHClientConnection,
    src: str,
    dst_canonical: str,
    allowlist: list[str],
    restricted: list[str],
    platform: Literal["posix", "windows"],
) -> None:
    """`-s` mode: validate src as a path STRING (no realpath, may not
    exist) and create the symlink via `sftp.symlink()`.

    Relative targets resolve against dst's parent dir for the policy
    check ONLY -- the on-disk link text is `src` VERBATIM so relative
    semantics are preserved (`ln -s ../foo bar` keeps `../foo`).
    """
    reject_bad_characters(src)
    if posixpath.isabs(src):
        target_for_check = posixpath.normpath(src)
    else:
        dst_parent = posixpath.dirname(dst_canonical) or "/"
        target_for_check = posixpath.normpath(posixpath.join(dst_parent, src))
    check_in_allowlist(target_for_check, allowlist, platform)
    check_not_restricted(target_for_check, restricted, platform)

    async with conn.start_sftp_client() as sftp:
        # Pass src VERBATIM -- preserves relative-link semantics on disk.
        await sftp.symlink(src, dst_canonical)


async def _create_hard_link_followed(
    *,
    conn: asyncssh.SSHClientConnection,
    src: str,
    dst_canonical: str,
    allowlist: list[str],
    restricted: list[str],
    platform: Literal["posix", "windows"],
) -> str:
    """`-L` mode (default): canonicalize src normally (resolves symlinks)
    and create the hard link via `sftp.link()` (SFTP-HARDLINK extension,
    OpenSSH `linkat(... AT_SYMLINK_FOLLOW)`).

    Returns the canonical src path so the caller can include it in the
    audit-friendly result message.
    """
    src_canonical = await canonicalize_and_check(
        conn,
        src,
        allowlist,
        must_exist=True,
        platform=platform,
    )
    check_not_restricted(src_canonical, restricted, platform)
    async with conn.start_sftp_client() as sftp:
        await sftp.link(src_canonical, dst_canonical)
    return src_canonical


async def _create_hard_link_unfollowed(
    *,
    conn: asyncssh.SSHClientConnection,
    src: str,
    dst_canonical: str,
    allowlist: list[str],
    restricted: list[str],
    platform: Literal["posix", "windows"],
) -> str:
    """`-P` mode: parent-canonicalize, lstat-verify, shell `ln -P --`.

    Canonicalizing src would defeat `-P`'s "don't follow symlinks" point,
    so we validate via parent-canonicalize + lstat instead -- the check
    is "the symlink lives in an allowed dir," not "everywhere it could
    point is allowed." Returns the assembled src path for the audit
    message.
    """
    src_parent = posixpath.dirname(src) or "/"
    src_filename = posixpath.basename(src)
    if not src_filename:
        raise ValueError(f"src must include a filename, not just a directory: {src!r}")
    src_parent_canonical = await canonicalize_and_check(
        conn,
        src_parent,
        allowlist,
        must_exist=True,
        platform=platform,
    )
    check_not_restricted(src_parent_canonical, restricted, platform)
    src_full = posixpath.join(src_parent_canonical, src_filename)
    async with conn.start_sftp_client() as sftp:
        try:
            await sftp.lstat(src_full)
        except asyncssh.SFTPError as exc:
            if _is_missing(exc):
                raise ValueError(f"src does not exist: {src_full!r}") from exc
            raise
    check_not_restricted(src_full, restricted, platform)

    cmd = shlex.join(["ln", "-P", "--", src_full, dst_canonical])
    result = await conn.run(cmd, check=False)
    if result.exit_status != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes | bytearray):
            stderr = stderr.decode(errors="replace")
        raise WriteError(
            f"ln -P failed (exit {result.exit_status}): {stderr.strip() if stderr else 'no stderr'}"
        )
    return src_full


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
    ctx: Context,
    content_base64: str | None = None,
    content_text: str | None = None,
    mode: int = 0o644,
) -> WriteResult:
    """Create or replace a file. Written to `<path>.ssh-mcp-tmp.<rand>` then
    atomically renamed -- a crash mid-write leaves the temp, never a partial
    final file.

    USE THIS INSTEAD OF `ssh_exec_run` for `cat > path <<EOF`, `tee path`,
    `echo "..." > path`, `printf "..." > path`, and any other pattern that
    creates or replaces a file's whole content. The path goes through
    `canonicalize_and_check` + `restricted_paths` (none of which `ssh_exec_run`
    enforces), the write is atomic, and the audit line records the canonical
    path. Heredoc-via-shell offers none of these.

    PAYLOAD: pass exactly one of `content_text` (plain UTF-8) or
    `content_base64` (binary-safe). `content_text` is the right choice for
    config files, scripts, Markdown, JSON, code -- anything you would type
    in an editor. `content_base64` is the right choice for binaries
    (tarballs, images, compiled artifacts) where invalid UTF-8 must round
    trip cleanly.
    """
    _pool, policy, settings, conn, canonical = await _prepare_creatable(ctx, host, path)
    data = _resolve_upload_payload(content_text, content_base64)
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


def _resolve_upload_payload(
    content_text: str | None,
    content_base64: str | None,
) -> bytes:
    """Validate exactly-one-of and return the bytes that will hit disk.

    Both fields keyword-only at the tool surface. Callers MUST pass one and
    only one -- the empty-string case for `content_text` is a deliberate
    valid input (write a zero-byte file), so we can't use truthiness.
    """
    if content_text is not None and content_base64 is not None:
        raise WriteError(
            "ssh_upload / ssh_deploy: pass exactly one of content_text "
            "(plain UTF-8) or content_base64 (binary-safe). Both were set."
        )
    if content_text is not None:
        return content_text.encode("utf-8")
    if content_base64 is not None:
        return base64.b64decode(content_base64, validate=True)
    raise WriteError(
        "ssh_upload / ssh_deploy: pass exactly one of content_text "
        "(plain UTF-8) or content_base64 (binary-safe). Neither was set."
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
            raise WriteError(f"file {size} bytes exceeds SSH_EDIT_MAX_FILE_BYTES={cap}")
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
            raise WriteError(f"file {size} bytes exceeds SSH_EDIT_MAX_FILE_BYTES={cap}")
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
    ctx: Context,
    content_base64: str | None = None,
    content_text: str | None = None,
    mode: int = 0o644,
    backup: bool = True,
) -> dict[str, Any]:
    """Deploy a file atomically with optional pre-deploy backup.

    Extends ``ssh_upload`` with auto-backup. If ``backup=True`` and the path
    already exists, the existing file is renamed to
    ``<path>.bak-<UTC-iso8601>`` via SFTP ``posix_rename`` before the new
    content is written. The new content then lands via the same tmp+rename
    atomic dance as ``ssh_upload``.

    PAYLOAD: pass exactly one of ``content_text`` (plain UTF-8) or
    ``content_base64`` (binary-safe). Same semantics as ``ssh_upload``.

    Does NOT handle chown/owner changes -- that would require sudo (see
    ``ssh_sudo_exec`` in the dangerous tier). ``mode`` sets the file's
    permission bits and is applied to the tmp file before the final rename.
    """
    _pool, policy, settings, conn, canonical = await _prepare_creatable(ctx, host, path)
    data = _resolve_upload_payload(content_text, content_base64)
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
