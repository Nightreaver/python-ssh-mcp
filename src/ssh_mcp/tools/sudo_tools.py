"""Sudo tier: privileged execution. See DESIGN.md section 4.4.

Tagged ``{"dangerous", "sudo", "group:sudo"}``. Hidden unless BOTH
``ALLOW_DANGEROUS_TOOLS=true`` AND ``ALLOW_SUDO=true`` are set (the lifespan
applies a Visibility transform per flag; either missing hides the tool).

Password is resolved per call via ``fetch_sudo_password`` and piped on stdin.
Command allowlist (``ALLOW_ANY_COMMAND`` opt-in or a populated
``command_allowlist``) applies the same way as the plain exec tier.
"""
from __future__ import annotations

from fastmcp import Context

from ..app import mcp_server
from ..models.results import ExecResult
from ..services.audit import audited
from ..services.exec_policy import check_command
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
    fetched from ``SSH_SUDO_PASSWORD_CMD`` / OS keychain / ``SSH_SUDO_PASSWORD``
    and piped on stdin via ``sudo -S``. Password never appears in argv,
    process listings, or audit records.

    Non-zero exit codes are returned as data (ADR-0005). Wrong sudo password
    surfaces as a non-zero ``exit_code`` with ``stderr`` from sudo; it is not
    raised.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_sudo_exec", reason="no `sudo` on Windows")
    check_command(command, policy, settings)
    conn = await pool.acquire(policy)

    password = fetch_sudo_password(settings)
    result = await run_sudo(
        conn,
        command,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        password=password,
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
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_sudo_run_script", reason="no `sudo` on Windows")
    conn = await pool.acquire(policy)

    password = fetch_sudo_password(settings)
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
