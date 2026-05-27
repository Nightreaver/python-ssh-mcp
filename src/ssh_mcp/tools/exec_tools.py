"""Exec tier: arbitrary remote command execution. See DESIGN.md §4.3.

All tools tagged `{"dangerous", "group:exec"}`. Hidden unless
`ALLOW_DANGEROUS_TOOLS=true`. Non-zero exit codes are returned as data;
only transport failures and timeouts raise.
"""

from __future__ import annotations

from datetime import timedelta

from fastmcp import Context
from fastmcp.server.dependencies import Progress
from fastmcp.server.tasks import TaskConfig

from ..app import mcp_server
from ..models.results import ExecResult
from ..services.audit import audited
from ..services.exec_cheatsheet import (
    cheatsheet_hint_warning,
    cheatsheet_precheck,
)
from ..services.exec_policy import check_command
from ..ssh.exec import run as exec_run
from ..ssh.exec import run_streaming as exec_run_streaming
from ._context import pool_from, require_posix, resolve_host, settings_from


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_exec_run(
    host: str,
    command: str,
    ctx: Context,
    timeout: int | None = None,
) -> ExecResult:
    """Run an arbitrary command on the remote host. Last-resort tool; prefer a
    dedicated wrapper when one exists. Default-on cheatsheet rejection -- see
    skills/ssh-exec-run/SKILL.md. Non-zero exit is data, not raised. POSIX-only.
    """
    settings = settings_from(ctx)
    # Cheatsheet pre-check FIRST -- before pool acquire, before check_command,
    # before host resolution. We want the LLM to see the redirect hint without
    # any side-effect (no connect, no audit-line for the rejected attempt).
    # Under the opt-out (SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true) the precheck
    # returns the match without raising; we use that match in B2 wiring below
    # to PREPEND a "consider <wrapper> next time" hint to output_warnings.
    cheatsheet_match = cheatsheet_precheck(
        command,
        settings.SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS,
        tool_name="ssh_exec_run",
    )
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(
        resolved,
        tool="ssh_exec_run",
        reason="relies on POSIX shell (sh) + pkill for timeout cleanup",
    )
    check_command(command, policy, settings)
    conn = await pool.acquire(resolved)

    result = await exec_run(
        conn,
        command,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
    )
    if cheatsheet_match is not None:
        # Prepend so the most actionable signal ("use a different tool") is
        # surfaced first; sanitizer flags (INC-057/058) coexist after it.
        result.output_warnings.insert(
            0, cheatsheet_hint_warning(match=cheatsheet_match, tool_name="ssh_exec_run")
        )
    return result


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_exec_script(
    host: str,
    script: str,
    ctx: Context,
    timeout: int | None = None,
) -> ExecResult:
    """Run a shell script body via stdin to `sh -s --`.

    The script is streamed via stdin so it never appears in argv, process
    listings, or audit lines. No allowlist check against the script body —
    inspect what you execute. Set `ALLOW_DANGEROUS_TOOLS=false` to disable.

    POSIX-only: pipes to `sh -s --`. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_exec_script", reason="pipes to `sh -s --`")
    conn = await pool.acquire(resolved)

    result = await exec_run(
        conn,
        "sh -s --",
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        stdin=script,
    )
    return result


@mcp_server.tool(
    tags={"dangerous", "group:exec"},
    version="1.0",
    task=TaskConfig(mode="optional", poll_interval=timedelta(seconds=3)),
)
@audited(tier="dangerous")
async def ssh_exec_run_streaming(
    host: str,
    command: str,
    ctx: Context,
    progress: Progress = Progress(),  # noqa: B008  -- FastMCP dependency-injection sentinel; the framework replaces this at call time.
    timeout: int | None = None,
) -> ExecResult:
    """Long-running command variant. Emits stdout tail to the progress channel.

    `task=TaskConfig(mode="optional")` — client may call this synchronously for
    short commands or as a background task for long ones. See DESIGN.md §PI-2.

    Default-on cheatsheet rejection -- see skills/ssh-exec-run/SKILL.md.

    POSIX-only. Windows targets raise `PlatformNotSupported`.
    """
    settings = settings_from(ctx)
    cheatsheet_match = cheatsheet_precheck(
        command,
        settings.SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS,
        tool_name="ssh_exec_run_streaming",
    )
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_exec_run_streaming", reason="relies on POSIX shell + pkill cleanup")
    check_command(command, policy, settings)
    conn = await pool.acquire(resolved)

    await progress.set_total(None)

    async def on_chunk(stream: str, chunk: str) -> None:
        # Emit the tail of the latest chunk so operators see progress in MCP
        # clients that surface task progress messages.
        tail = chunk.rstrip("\n").splitlines()[-1] if chunk.strip() else ""
        if tail:
            await progress.set_message(f"{stream}: {tail[:200]}")
            await progress.increment()

    result = await exec_run_streaming(
        conn,
        command,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        chunk_cb=on_chunk,
    )
    if cheatsheet_match is not None:
        # See ssh_exec_run: prepend hint so cheatsheet redirect is the first
        # entry, sanitizer flags (if any) follow.
        result.output_warnings.insert(
            0, cheatsheet_hint_warning(match=cheatsheet_match, tool_name="ssh_exec_run_streaming")
        )
    return result
