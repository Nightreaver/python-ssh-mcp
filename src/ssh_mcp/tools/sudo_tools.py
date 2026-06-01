"""Sudo tier: privileged execution + privileged path-bearing operations.

Tagged ``{"dangerous", "sudo", "group:sudo"}``. Hidden unless BOTH
``ALLOW_DANGEROUS_TOOLS=true`` AND ``ALLOW_SUDO=true`` are set (the lifespan
applies a Visibility transform per flag; either missing hides the tool).

Password is resolved per call via ``fetch_sudo_password`` and piped on stdin.
Command allowlist (``ALLOW_ANY_COMMAND`` opt-in or a populated
``command_allowlist``) applies the same way as the plain exec tier.

v1.5.0 added five path-bearing sudo tools (``ssh_sudo_read``,
``ssh_sudo_read_redacted``, ``ssh_sudo_write``, ``ssh_sudo_edit``,
``ssh_sudo_sftp_list``) so the redact-policy boundary stays reachable on
production-hardened hosts where the ssh-user has minimal rights and
everything material runs under sudo. Previously the only sudo path for
reading a root-owned ``.env`` was ``ssh_sudo_exec("cat /etc/...")``
which bypassed ``path_allowlist`` / ``restricted_paths`` /
``restricted_globs`` / ``redact_paths_globs`` entirely. INC-064
mitigation: partial -- the new tools are policy-checked; the cheatsheet
catches the common ``sudo cat`` shapes and reroutes them here.
"""

from __future__ import annotations

import base64
from typing import Literal

from fastmcp import Context

from ..app import mcp_server
from ..models.results import (
    DownloadResult,
    ExecResult,
    RedactedReadResult,
    SftpListResult,
    WriteResult,
)
from ..services.audit import audited
from ..services.edit_service import EditError, apply_edit
from ..services.exec_cheatsheet import cheatsheet_hint_warning, cheatsheet_precheck
from ..services.exec_policy import check_command
from ..services.local_path_policy import resolve_local_path
from ..services.path_policy import resolve_path, resolve_path_for_redacted_read
from ..services.redact_policy import (
    resolve_entropy_detection,
    resolve_hint_chars,
    resolve_redact_keys,
    resolve_salt,
)
from ..services.redactor import Format, detect_format, redact_text
from ..services.sudo_file_ops import (
    sudo_atomic_write,
    sudo_ls_parsed,
    sudo_read_bytes,
    sudo_stat_mode,
    sudo_stat_owner,
)
from ..ssh.errors import SudoFileOpError
from ..ssh.sudo import fetch_sudo_password, run_sudo, run_sudo_script
from ._context import pool_from, require_posix, resolve_host, settings_from


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_exec(
    host: str,
    command: str,
    ctx: Context,
    timeout: int | None = None,
) -> ExecResult:
    """Run a command under sudo on the remote host.

    Passwordless sudoers entries use ``sudo -n``. Otherwise the password is
    resolved per-host (OS keyring ``ssh-mcp-sudo / <alias>``) with fall-back
    to the global ``SSH_SUDO_PASSWORD_CMD`` and the legacy keyring entry
    ``ssh-mcp-sudo / default``, then piped on stdin via ``sudo -S``. Password
    never appears in argv, process listings, or audit records.

    Non-zero exit codes are returned as data (ADR-0005). Wrong sudo password
    surfaces as a non-zero ``exit_code`` with ``stderr`` from sudo; it is not
    raised.

    Default-on cheatsheet rejection mirrors ``ssh_exec_run`` -- see
    skills/ssh-exec-run/SKILL.md and the SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS
    opt-out.
    """
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    cheatsheet_match = cheatsheet_precheck(
        command,
        settings.SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS,
        tool_name="ssh_sudo_exec",
        policy=policy,
        settings=settings,
    )
    require_posix(resolved, tool="ssh_sudo_exec", reason="no `sudo` on Windows")
    check_command(command, policy, settings)
    conn = await pool.acquire(resolved)

    password = fetch_sudo_password(settings, host)
    result = await run_sudo(
        conn,
        command,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        password=password,
    )
    if cheatsheet_match is not None:
        # Prepend cheatsheet hint so the redirect signal precedes sanitizer
        # flags from INC-057/058. Tool name surfaces 'ssh_sudo_exec' so the
        # LLM points at the right refactoring target.
        result.output_warnings.insert(
            0, cheatsheet_hint_warning(match=cheatsheet_match, tool_name="ssh_sudo_exec")
        )
    return result


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_run_script(
    host: str,
    script: str,
    ctx: Context,
    timeout: int | None = None,
) -> ExecResult:
    """Run a multi-line shell script under sudo via ``sudo -S sh -s --``.

    The script body never appears in argv or process listings -- it's streamed
    via stdin. No command allowlist check is applied to the body (same
    rationale as ``ssh_exec_script`` -- allowlist inspects argv tokens, not
    stdin content). Inspect what you execute.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_run_script", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)

    password = fetch_sudo_password(settings, host)
    result = await run_sudo_script(
        conn,
        script,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        password=password,
    )
    return result


# ---------------------------------------------------------------------------
# v1.5.0: sudo-tier path-bearing tools. See the module docstring for the
# motivating use-case (production-hardened hosts where ssh-user has minimal
# rights). All five take a ``path`` argument and route through
# ``resolve_path`` (full policy chain: allowlist + restricted_paths +
# restricted_globs + redact-bypass) before any sudo invocation.
# ---------------------------------------------------------------------------


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_read(host: str, path: str, ctx: Context) -> DownloadResult:
    """Read a file via ``sudo cat`` for paths the ssh-user can't reach directly.

    Returns base64 bytes in ``content_base64`` (same shape as
    ``ssh_sftp_download``'s default branch). Size-capped at
    ``SSH_UPLOAD_MAX_FILE_BYTES`` (default 256 MiB); larger files raise
    ``SudoFileOpError``. Path goes through the full policy chain
    (``path_allowlist`` + ``restricted_paths`` + ``restricted_globs`` +
    ``redact_paths_globs`` bypass-policy) -- the redact-block fires
    BEFORE any sudo invocation if the path matches a redact glob under
    ``redact_bypass_policy='block'``; use ``ssh_sudo_read_redacted``
    for those.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_read", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    data = await sudo_read_bytes(conn, canonical, alias=host, settings=settings)
    return DownloadResult(
        host=policy.hostname,
        path=canonical,
        size=len(data),
        content_base64=base64.b64encode(data).decode("ascii"),
        truncated=False,
    )


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_read_redacted(
    host: str,
    path: str,
    ctx: Context,
    format: Literal["env", "yaml", "json", "ini", "generic"] | None = None,
) -> RedactedReadResult:
    """Sudo-elevated counterpart to ``ssh_read_redacted``.

    Reads via ``sudo cat``, runs the bytes through the secret-redactor,
    and returns the structural view + per-redaction hashes. Same
    bypass-exemption as the non-sudo sibling: ``redact_paths_globs``
    block does NOT fire here (this IS the operator-blessed alternative),
    but ``restricted_paths`` / ``restricted_globs`` still hard-deny.
    Format auto-detected from the extension when ``format=None``.
    Size cap: ``SSH_UPLOAD_MAX_FILE_BYTES``.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_read_redacted", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)
    canonical = await resolve_path_for_redacted_read(conn, path, policy, settings, must_exist=True, pool=pool)

    fmt: Format = format if format is not None else detect_format(canonical)
    data = await sudo_read_bytes(conn, canonical, alias=host, settings=settings)
    text = data.decode("utf-8", errors="replace")

    keys = resolve_redact_keys(policy, settings)
    salt = resolve_salt(settings)
    hint_chars = resolve_hint_chars(policy, settings)
    entropy_detection = resolve_entropy_detection(policy, settings)
    redacted, records = redact_text(
        text,
        keys=keys,
        salt=salt,
        entropy_detection=entropy_detection,
        hint_chars=hint_chars,
        format=fmt,
    )

    extra_warnings: list[str] = []
    if not salt:
        extra_warnings.append(
            "SSH_REDACT_SALT is empty; hashes are plain SHA256, attackers with a known "
            "plaintext can confirm the hash without the salt. Set SSH_REDACT_SALT (>= 32 chars) "
            "to enable HMAC-SHA256 mode."
        )

    return RedactedReadResult(
        host=policy.hostname,
        path=canonical,
        size_original=len(data),
        content=redacted,
        format_detected=fmt,
        redactions=[
            {"key": rec.key, "hash": rec.hash, "line": rec.line, "kind": rec.kind} for rec in records
        ],
        truncated=False,
        output_warnings=extra_warnings,
    )


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_write(
    host: str,
    path: str,
    ctx: Context,
    content_text: str | None = None,
    content_base64: str | None = None,
    local_path: str | None = None,
    mode: int = 0o644,
    chown_user: str | None = None,
    chown_group: str | None = None,
) -> WriteResult:
    """Sudo-elevated atomic write: tmp-in-parent + chmod + chown + mv.

    PAYLOAD: pass exactly one of ``content_text`` (plain UTF-8),
    ``content_base64`` (binary-safe), or ``local_path`` (absolute path on
    the MCP-host filesystem). The ``local_path`` mode reads the local
    file into memory on the MCP server, then pipes the bytes via stdin
    into the sudo pipeline -- avoiding the LLM having to generate large
    base64 payloads as a tool-call argument. Requires
    ``SSH_LOCAL_TRANSFER_ROOTS`` to allowlist the source directory
    (same operator setup as ``ssh_upload``'s local_path mode). Capped at
    ``SSH_LOCAL_TRANSFER_MAX_BYTES`` (default 2 GiB) instead of the
    smaller 256 MiB base64 cap. The bytestream still flows through MCP
    server memory; true streaming (no in-memory buffer) is deferred to
    a future v1.14 helper.

    OWNERSHIP: when ``chown_user`` / ``chown_group`` are omitted, the
    tool calls ``sudo stat`` first to read the existing owner and
    preserves it. If the file does NOT exist, ownership defaults to
    ``root:root`` and a warning is appended to ``output_warnings``
    so the operator (or the LLM) sees that an explicit owner should
    be passed for new files.

    Implementation: ``sudo sh -c '... mktemp -p dirname ... mv ...'``
    so the final rename is atomic on the same filesystem. Caps the
    inline (text/base64) payload at ``SSH_UPLOAD_MAX_FILE_BYTES``;
    the ``local_path`` payload at ``SSH_LOCAL_TRANSFER_MAX_BYTES``.
    """
    settings = settings_from(ctx)
    sources_set = sum(s is not None for s in (content_text, content_base64, local_path))
    if sources_set > 1:
        raise ValueError(
            "ssh_sudo_write: pass exactly one of content_text (plain UTF-8), "
            "content_base64 (binary-safe), or local_path (absolute MCP-host "
            "filesystem path, requires SSH_LOCAL_TRANSFER_ROOTS). Multiple were set."
        )
    if sources_set == 0:
        raise ValueError(
            "ssh_sudo_write: pass exactly one of content_text (plain UTF-8), "
            "content_base64 (binary-safe), or local_path (absolute MCP-host "
            "filesystem path, requires SSH_LOCAL_TRANSFER_ROOTS). None was set."
        )

    local_path_written: str | None = None
    if content_text is not None:
        data = content_text.encode("utf-8")
    elif content_base64 is not None:
        data = base64.b64decode(content_base64, validate=True)
    else:
        assert local_path is not None  # narrowed by the count check above
        canonical_local = resolve_local_path(local_path, settings, mode="read")
        size = canonical_local.stat().st_size
        if size > settings.SSH_LOCAL_TRANSFER_MAX_BYTES:
            raise SudoFileOpError(
                f"local_path {canonical_local!s} is {size} bytes which exceeds "
                f"SSH_LOCAL_TRANSFER_MAX_BYTES={settings.SSH_LOCAL_TRANSFER_MAX_BYTES}"
            )
        data = canonical_local.read_bytes()
        local_path_written = str(canonical_local)

    if local_path_written is None and len(data) > settings.SSH_UPLOAD_MAX_FILE_BYTES:
        raise SudoFileOpError(
            f"payload {len(data)} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES="
            f"{settings.SSH_UPLOAD_MAX_FILE_BYTES}"
        )

    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_write", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)
    # must_exist=False because writes target both new and existing paths.
    canonical = await resolve_path(conn, path, policy, settings, must_exist=False, pool=pool)

    warnings: list[str] = []
    effective_user = chown_user
    effective_group = chown_group
    if effective_user is None or effective_group is None:
        existing = await sudo_stat_owner(conn, canonical, alias=host, settings=settings)
        if existing is not None:
            stat_user, stat_group = existing
            effective_user = effective_user or stat_user
            effective_group = effective_group or stat_group
        else:
            effective_user = effective_user or "root"
            effective_group = effective_group or "root"
            warnings.append(
                "file did not exist, created as root:root; pass chown_user/chown_group " "to set explicitly."
            )

    await sudo_atomic_write(
        conn,
        canonical,
        data,
        alias=host,
        settings=settings,
        mode=mode,
        chown_user=effective_user,
        chown_group=effective_group,
    )

    msg = f"sudo-wrote (atomic, owner {effective_user}:{effective_group})"
    if local_path_written is not None:
        msg = f"sudo-wrote from {local_path_written} (atomic, owner {effective_user}:{effective_group})"
    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(data),
        message=msg,
        output_warnings=warnings,
        local_path_written=local_path_written,
    )


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_edit(
    host: str,
    path: str,
    old_string: str,
    new_string: str,
    ctx: Context,
    occurrence: Literal["single", "all"] = "single",
) -> WriteResult:
    """Sudo-elevated structured edit: read via sudo, apply replace, write back.

    Reuses :func:`ssh_mcp.services.edit_service.apply_edit` -- same
    semantics as ``ssh_edit`` (single requires exactly one occurrence;
    all replaces every occurrence). Existing ownership is preserved via
    a pre-step ``sudo stat`` (same logic as ``ssh_sudo_write`` when both
    chown args are omitted). Size cap: ``SSH_EDIT_MAX_FILE_BYTES``
    (default 10 MiB) -- the file is read into memory then written back.
    """
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_edit", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    data = await sudo_read_bytes(
        conn,
        canonical,
        alias=host,
        settings=settings,
        cap=settings.SSH_EDIT_MAX_FILE_BYTES,
    )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SudoFileOpError(
            f"{canonical!r} is not valid UTF-8 (offset {exc.start}); " "edit tools are text-only."
        ) from exc

    try:
        outcome = apply_edit(text, old_string, new_string, occurrence=occurrence)
    except EditError as exc:
        raise SudoFileOpError(str(exc)) from exc

    # Preserve existing ownership AND mode: by the time we got here the
    # file must exist (must_exist=True at resolve), so stat should always
    # return a value. Defensive None handling kept for the chroot / race
    # edge. Preserving mode is security-critical: a secret file at 0o600
    # must not get widened to 0o644 by the edit pipeline.
    existing_owner = await sudo_stat_owner(conn, canonical, alias=host, settings=settings)
    if existing_owner is not None:
        chown_user, chown_group = existing_owner
    else:
        chown_user, chown_group = "root", "root"
    existing_mode = await sudo_stat_mode(conn, canonical, alias=host, settings=settings)
    if existing_mode is None:
        existing_mode = 0o644

    new_bytes = outcome.new_text.encode("utf-8")
    # The edit cannot grow the file past the read cap by more than the
    # difference between old_string and new_string * replacements; in
    # practice it's bounded but we re-check defensively.
    if len(new_bytes) > settings.SSH_EDIT_MAX_FILE_BYTES:
        raise SudoFileOpError(
            f"edited content {len(new_bytes)} bytes exceeds SSH_EDIT_MAX_FILE_BYTES="
            f"{settings.SSH_EDIT_MAX_FILE_BYTES}"
        )

    await sudo_atomic_write(
        conn,
        canonical,
        new_bytes,
        alias=host,
        settings=settings,
        mode=existing_mode,
        chown_user=chown_user,
        chown_group=chown_group,
    )

    return WriteResult(
        host=policy.hostname,
        path=canonical,
        success=True,
        bytes_written=len(new_bytes),
        message=f"sudo-edited (replaced {outcome.replacements} occurrence(s))",
    )


@mcp_server.tool(tags={"dangerous", "sudo", "group:sudo"}, version="1.0")
@audited(tier="sudo")
async def ssh_sudo_sftp_list(
    host: str,
    path: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> SftpListResult:
    """Sudo-elevated directory listing via ``sudo ls -la --time-style=full-iso``.

    Use for directories the ssh-user can't traverse without sudo. Output
    parsed into the same ``SftpListResult.entries`` shape as
    ``ssh_sftp_list``. Pagination is applied AFTER the parse -- the sudo
    pipeline returns the full listing, then we slice. Fine for typical
    directories; very large ones (>10k entries) are better served by
    relaxing the per-host policy to let SFTP reach them directly.

    BusyBox-style ls without ``--time-style=full-iso`` will produce
    unparseable rows that are silently skipped (logged at DEBUG).
    """
    if limit <= 0 or limit > 1000:
        raise ValueError("limit must be in 1..1000")
    if offset < 0:
        raise ValueError("offset must be >= 0")

    settings = settings_from(ctx)
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_sudo_sftp_list", reason="no `sudo` on Windows")
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    all_entries = await sudo_ls_parsed(conn, canonical, alias=host, settings=settings)
    # Sort by name to match ssh_sftp_list's deterministic order.
    all_entries.sort(key=lambda e: e.name)
    page = all_entries[offset : offset + limit]
    return SftpListResult(
        host=policy.hostname,
        path=canonical,
        entries=page,
        offset=offset,
        limit=limit,
        has_more=(offset + len(page)) < len(all_entries),
    )
