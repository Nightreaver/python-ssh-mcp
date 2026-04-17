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
    """Run an arbitrary command on the remote host. **Last-resort tool.**

    PREFER a dedicated tool when one exists -- they are safer (narrower blast
    radius), cheaper (no command_allowlist round-trip), and audit cleaner.
    Only fall back to `ssh_exec_run` when no dedicated tool fits.

    Mapping cheat sheet (use the LEFT side if the task matches):
      mkdir -p <dir>             -> ssh_mkdir
      rm <file>                  -> ssh_delete
      rm -rf <dir>               -> ssh_delete_folder
      cp -a <src> <dst>          -> ssh_cp
      mv <src> <dst>             -> ssh_mv
      <upload local content>     -> ssh_upload  (base64 payload, atomic)
      <sed-style edit>           -> ssh_edit    (old_text/new_text, atomic)
      <apply unified diff>       -> ssh_patch
      find <path> -name ...      -> ssh_find
      df / ps / uname / uptime   -> ssh_host_disk_usage / ssh_host_processes / ssh_host_info
      cat <file>                 -> ssh_sftp_download
      ls <dir>                   -> ssh_sftp_list
      stat <file>                -> ssh_sftp_stat
      docker <anything>          -> ssh_docker_* (22 tools)
      sudo <cmd>                 -> ssh_sudo_exec (separate gate)

    When `ssh_exec_run` IS right:
      - ad-hoc diagnostic one-liners (`systemctl status nginx`, `journalctl -u ...`)
      - composed pipelines (`foo | grep | awk`)
      - commands with no equivalent wrapper tool

    Non-zero exit codes are data (see `exit_code`), not raised. Timeouts return
    `timed_out=True` with any partial output captured. Commands are allowlist-
    checked (`command_allowlist` / `SSH_COMMAND_ALLOWLIST`). Caller owns quoting.

    POSIX-only: assumes `sh -c`, `pkill` for timeout cleanup, and POSIX quoting
    via `shlex`. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(
        policy,
        tool="ssh_exec_run",
        reason="relies on POSIX shell (sh) + pkill for timeout cleanup",
    )
    check_command(command, policy, settings)
    conn = await pool.acquire(policy)

    result = await exec_run(
        conn,
        command,
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
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
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_exec_script", reason="pipes to `sh -s --`")
    conn = await pool.acquire(policy)

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

    POSIX-only. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_exec_run_streaming", reason="relies on POSIX shell + pkill cleanup")
    check_command(command, policy, settings)
    conn = await pool.acquire(policy)

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
    return result
