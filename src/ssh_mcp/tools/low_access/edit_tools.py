"""Low-access text-edit tools: ``ssh_edit`` (string replace) and
``ssh_patch`` (unified diff). Both UTF-8-only, atomic via tmp+rename.
"""

from __future__ import annotations

from typing import Literal

from fastmcp import Context

from ...app import mcp_server
from ...models.results import WriteResult
from ...services.audit import audited
from ...services.edit_service import EditError, PatchError, apply_edit, apply_unified_diff
from ._helpers import WriteError, _atomic_write, _prepare_existing

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
    pool, policy, settings, _conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_EDIT_MAX_FILE_BYTES
    async with pool.sftp_policy(policy) as sftp:
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
    pool, policy, settings, _conn, canonical = await _prepare_existing(ctx, host, path)
    cap = settings.SSH_EDIT_MAX_FILE_BYTES
    async with pool.sftp_policy(policy) as sftp:
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
