"""Low-access write tools: ``ssh_upload`` + ``ssh_deploy``.

Three payload sources behind a single tool surface: ``content_text``,
``content_base64``, ``local_path`` (v1.3.0). Mutex + local-path policy
enforcement live in :func:`_resolve_upload_payload` and run BEFORE any
SSH connection is acquired.
"""

from __future__ import annotations

import asyncio
import base64
import stat as stat_module
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import asyncssh
from fastmcp import Context

from ...app import mcp_server
from ...models.results import WriteResult
from ...services.audit import audited
from ...services.local_path_policy import resolve_local_path
from .._context import settings_from
from ._helpers import (
    WriteError,
    _atomic_write,
    _atomic_write_stream,
    _bypass_warnings,
    _prepare_creatable,
)

if TYPE_CHECKING:
    from pathlib import Path

    from ...config import Settings


# --------- ssh_upload ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_upload(
    host: str,
    path: str,
    ctx: Context,
    content_base64: str | None = None,
    content_text: str | None = None,
    local_path: str | None = None,
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

    PAYLOAD: pass exactly one of `content_text`, `content_base64`, or
    `local_path`.

    - `content_text` (plain UTF-8): the right choice for config files,
      scripts, Markdown, JSON, code -- anything you would type in an editor.
    - `content_base64` (binary-safe): the right choice for binaries
      (tarballs, images, compiled artifacts) where invalid UTF-8 must
      round-trip cleanly. Subject to ``SSH_UPLOAD_MAX_FILE_BYTES``
      (default 256 MiB) since the payload crosses the MCP JSON channel.
    - `local_path` (v1.3.0): absolute path on the MCP server's OWN
      filesystem. The bytes are streamed from local disk directly into
      the SFTP write -- never round-tripping through the LLM as base64.
      Requires the operator to allowlist the source directory via
      ``SSH_LOCAL_TRANSFER_ROOTS``; subject to the larger
      ``SSH_LOCAL_TRANSFER_MAX_BYTES`` cap (default 2 GiB). Use this for
      anything bigger than a few MiB where the LLM has been chunking.
    """
    # Validate cheap local-side inputs (mutex, base64 decode, local_path
    # policy + cap) BEFORE acquiring an SSH connection -- a bad payload
    # shouldn't cost a remote handshake.
    settings = settings_from(ctx)
    payload = await _resolve_upload_payload(content_text, content_base64, local_path, settings)
    pool, policy, _settings, _conn, canonical = await _prepare_creatable(ctx, host, path)
    warnings = _bypass_warnings(canonical, policy, settings)
    if isinstance(payload, _InlinePayload):
        cap = settings.SSH_UPLOAD_MAX_FILE_BYTES
        if len(payload.data) > cap:
            raise WriteError(f"payload {len(payload.data)} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES={cap}")
        async with pool.sftp_policy(policy) as sftp:
            await _atomic_write(sftp, canonical, payload.data, mode)
        return WriteResult(
            host=policy.hostname,
            path=canonical,
            success=True,
            bytes_written=len(payload.data),
            message="uploaded (atomic)",
            output_warnings=warnings,
        )

    # `local_path` streaming path. Cap and policy were enforced inside
    # `_resolve_upload_payload`; here we just stream from disk.
    async with pool.sftp_policy(policy) as sftp:
        bytes_written = await _atomic_write_stream(sftp, canonical, payload.local_path, mode)
    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=bytes_written,
        message=f"uploaded from {payload.local_path} (atomic, streamed)",
        local_path_written=str(payload.local_path),
        output_warnings=warnings,
    )


@dataclass(slots=True, frozen=True)
class _InlinePayload:
    """Bytes already in memory (content_text / content_base64 branch)."""

    data: bytes


@dataclass(slots=True, frozen=True)
class _LocalFilePayload:
    """Streaming source on the MCP-host filesystem (`local_path` branch)."""

    local_path: Path


_UploadPayload = _InlinePayload | _LocalFilePayload


# Shared body of the mutex error -- both "multiple" and "none" violations
# point operators at the same fix, only the trailing diagnosis differs.
_PAYLOAD_MUTEX_HINT = (
    "ssh_upload / ssh_deploy: pass exactly one of content_text "
    "(plain UTF-8), content_base64 (binary-safe), or local_path "
    "(absolute MCP-host filesystem path, requires SSH_LOCAL_TRANSFER_ROOTS)."
)


async def _resolve_upload_payload(
    content_text: str | None,
    content_base64: str | None,
    local_path: str | None,
    settings: Settings,
) -> _UploadPayload:
    """Validate exactly-one-of and return either an in-memory bytes blob
    or a resolved local-disk source.

    All three fields keyword-only at the tool surface. Callers MUST pass
    exactly one -- the empty-string case for ``content_text`` is a
    deliberate valid input (write a zero-byte file), so we can't use
    truthiness.

    Three-way mutex (v1.3.0): adding ``local_path`` made the previous
    two-source check insufficient. We count the non-None sources rather
    than handle each pair, so a future fourth source slots in cleanly.

    For ``local_path``: the path is canonicalized against
    ``SSH_LOCAL_TRANSFER_ROOTS`` (via :func:`resolve_local_path`), then
    its on-disk size is checked against ``SSH_LOCAL_TRANSFER_MAX_BYTES``.
    Both gates fire BEFORE any SFTP work begins so we never start a
    transfer the cap would later reject.
    """
    sources_set = sum(s is not None for s in (content_text, content_base64, local_path))
    if sources_set > 1:
        raise WriteError(f"{_PAYLOAD_MUTEX_HINT} Multiple were set.")
    if sources_set == 0:
        raise WriteError(f"{_PAYLOAD_MUTEX_HINT} None was set.")
    if content_text is not None:
        return _InlinePayload(content_text.encode("utf-8"))
    if content_base64 is not None:
        return _InlinePayload(base64.b64decode(content_base64, validate=True))
    if local_path is not None:
        canonical_local = resolve_local_path(local_path, settings, mode="read")
        # `stat` is a blocking syscall -- trivial on a local SSD, but a
        # hung NFS / removable-media mount under an allowlisted root would
        # otherwise block the event loop for the whole call's duration.
        st = await asyncio.to_thread(canonical_local.stat)
        size = st.st_size
        cap = settings.SSH_LOCAL_TRANSFER_MAX_BYTES
        if size > cap:
            raise WriteError(
                f"local_path {canonical_local!s} is {size} bytes which exceeds "
                f"SSH_LOCAL_TRANSFER_MAX_BYTES={cap}"
            )
        return _LocalFilePayload(canonical_local)
    # Unreachable: sources_set == 1 means exactly one of the three was
    # not-None and we just dispatched on each. Kept as an explicit raise
    # rather than `assert` so `python -O` (which strips asserts) still
    # surfaces a clean failure if invariants are ever broken.
    raise WriteError(f"{_PAYLOAD_MUTEX_HINT} None was set.")


# --------- ssh_deploy ---------


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_deploy(
    host: str,
    path: str,
    ctx: Context,
    content_base64: str | None = None,
    content_text: str | None = None,
    local_path: str | None = None,
    mode: int = 0o644,
    backup: bool = True,
) -> dict[str, Any]:
    """Deploy a file atomically with optional pre-deploy backup.

    Extends ``ssh_upload`` with auto-backup. If ``backup=True`` and the path
    already exists, the existing file is renamed to
    ``<path>.bak-<UTC-iso8601>`` via SFTP ``posix_rename`` before the new
    content is written. The new content then lands via the same tmp+rename
    atomic dance as ``ssh_upload``.

    PAYLOAD: pass exactly one of ``content_text`` (plain UTF-8),
    ``content_base64`` (binary-safe), or ``local_path`` (absolute MCP-host
    filesystem path, streamed via the local-allowlist gate -- requires
    ``SSH_LOCAL_TRANSFER_ROOTS``). Same semantics as ``ssh_upload``.

    Does NOT handle chown/owner changes -- that would require sudo (see
    ``ssh_sudo_exec`` in the dangerous tier). ``mode`` sets the file's
    permission bits and is applied to the tmp file before the final rename.
    """
    # See `ssh_upload` for the rationale: validate payload (mutex,
    # local_path policy + cap) before paying for an SSH connection.
    settings = settings_from(ctx)
    payload = await _resolve_upload_payload(content_text, content_base64, local_path, settings)
    pool, policy, _settings, _conn, canonical = await _prepare_creatable(ctx, host, path)
    deploy_warnings = _bypass_warnings(canonical, policy, settings)
    if isinstance(payload, _InlinePayload):
        cap = settings.SSH_UPLOAD_MAX_FILE_BYTES
        if len(payload.data) > cap:
            raise WriteError(f"payload {len(payload.data)} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES={cap}")

    backup_path: str | None = None
    bytes_written: int
    async with pool.sftp_policy(policy) as sftp:
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
        if isinstance(payload, _InlinePayload):
            await _atomic_write(sftp, canonical, payload.data, mode)
            bytes_written = len(payload.data)
        else:
            bytes_written = await _atomic_write_stream(sftp, canonical, payload.local_path, mode)

    if isinstance(payload, _LocalFilePayload):
        msg = f"deployed from {payload.local_path} (atomic, streamed)"
    else:
        msg = "deployed (atomic)"
    if backup_path:
        msg = f"{msg}; previous version at {backup_path}"
    write_kwargs: dict[str, Any] = {
        "host": policy.hostname,
        "path": canonical,
        "success": True,
        "bytes_written": bytes_written,
        "message": msg,
        "output_warnings": deploy_warnings,
    }
    if isinstance(payload, _LocalFilePayload):
        write_kwargs["local_path_written"] = str(payload.local_path)
    result = WriteResult(**write_kwargs).model_dump()
    if backup_path:
        result["backup_path"] = backup_path
    return result
