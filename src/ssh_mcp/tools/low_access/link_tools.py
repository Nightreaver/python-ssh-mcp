"""Low-access link tool: ``ssh_link`` (hard / symbolic, POSIX-only).

Three modes (symbolic, hard-followed, hard-unfollowed) each have distinct
policy + creation paths; the per-mode helpers own the actual SFTP / shell
calls. See ADR-0006 / docstring on the parent facade.
"""

from __future__ import annotations

import posixpath
import shlex
from typing import TYPE_CHECKING, Literal

import asyncssh
from fastmcp import Context

from ...app import mcp_server
from ...models.results import WriteResult
from ...services.audit import audited
from ...services.path_policy import (
    canonicalize_and_check,
    check_in_allowlist,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
    reject_bad_characters,
)
from ...services.redact_policy import (
    resolve_restricted_globs,
    should_block_redact_bypass,
)
from ...ssh.errors import RedactBypassBlocked
from .._context import pool_from, require_posix, resolve_host, settings_from
from ._helpers import WriteError, _bypass_warnings, _is_missing

if TYPE_CHECKING:
    from ...models.policy import HostPolicy
    from ...ssh.pool import ConnectionPool


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
    restricted_globs = resolve_restricted_globs(policy, settings)

    dst_canonical = await canonicalize_and_check(
        conn,
        dst,
        allowlist,
        must_exist=False,
        platform=policy.platform,
        pool=pool,
        policy=policy,
    )
    check_not_restricted(dst_canonical, restricted, policy.platform, restricted_globs=restricted_globs)
    # Redact-bypass: link tools share the deny semantics of every other
    # path-bearing tool. ``block`` raises before any link is created;
    # ``warn`` attaches to ``output_warnings`` on the result.
    if should_block_redact_bypass(dst_canonical, policy, settings):
        raise RedactBypassBlocked(dst_canonical)
    warnings = _bypass_warnings(dst_canonical, policy, settings)

    # Three modes, three different src-validation + creation strategies.
    # Body is dispatch + WriteResult assembly; the per-mode helpers own
    # the policy checks and the SFTP / shell call. See per-helper
    # docstrings for the policy contract specific to each mode.
    if symbolic:
        await _create_symbolic_link(
            pool=pool,
            policy=policy,
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
            output_warnings=warnings,
        )

    if follow_symlinks:
        src_canonical = await _create_hard_link_followed(
            conn=conn,
            pool=pool,
            policy=policy,
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
            output_warnings=warnings,
        )

    src_full = await _create_hard_link_unfollowed(
        conn=conn,
        pool=pool,
        policy=policy,
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
        output_warnings=warnings,
    )


async def _create_symbolic_link(
    *,
    pool: ConnectionPool,
    policy: HostPolicy,
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

    async with pool.sftp_policy(policy) as sftp:
        # Pass src VERBATIM -- preserves relative-link semantics on disk.
        await sftp.symlink(src, dst_canonical)


async def _create_hard_link_followed(
    *,
    conn: asyncssh.SSHClientConnection,
    pool: ConnectionPool,
    policy: HostPolicy,
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
        pool=pool,
        policy=policy,
    )
    check_not_restricted(src_canonical, restricted, platform)
    async with pool.sftp_policy(policy) as sftp:
        await sftp.link(src_canonical, dst_canonical)
    return src_canonical


async def _create_hard_link_unfollowed(
    *,
    conn: asyncssh.SSHClientConnection,
    pool: ConnectionPool,
    policy: HostPolicy,
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
        pool=pool,
        policy=policy,
    )
    check_not_restricted(src_parent_canonical, restricted, platform)
    src_full = posixpath.join(src_parent_canonical, src_filename)
    async with pool.sftp_policy(policy) as sftp:
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
