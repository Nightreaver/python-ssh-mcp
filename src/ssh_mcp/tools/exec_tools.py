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

    DO NOT USE FOR FILE WRITES. The single most common misuse of this tool is
    `cat > path <<'EOF' ... EOF` / `tee path` / `echo "..." > path` /
    `printf "..." > path` to create or replace a file's content. These ALL
    have a dedicated tool that is safer (path-policy + atomic temp+rename +
    audit), structured, and visible in the file-ops tier. The mapping table
    below lists every pattern. If you find yourself writing a heredoc, STOP
    and use ssh_upload (whole file) or ssh_edit (string replacement) or
    ssh_patch (unified diff).

    Mapping cheat sheet (use the LEFT side if the task matches):
      mkdir -p <dir>                    -> ssh_mkdir
      rm <file>                         -> ssh_delete
      rm -rf <dir>                      -> ssh_delete_folder
      cp -a <src> <dst>                 -> ssh_cp
      mv <src> <dst>                    -> ssh_mv
      cat > <path> <<EOF ... EOF        -> ssh_upload (use content_text=)
      tee <path>                        -> ssh_upload (use content_text=)
      echo "..." > <path>               -> ssh_upload (use content_text=)
      printf "..." > <path>             -> ssh_upload (use content_text=)
      cat > <path> <<EOF ... EOF (with backup needed) -> ssh_deploy
      sed -i 's/old/new/' <path>        -> ssh_edit
      patch < <diff>                    -> ssh_patch
      find <path> -name ...             -> ssh_find
      df / ps / uname / uptime          -> ssh_host_disk_usage / ssh_host_processes / ssh_host_info
      ip addr / ip -j addr show         -> ssh_host_network
      id / groups / getent passwd       -> ssh_user_info
      cat <file>                        -> ssh_sftp_download
      ls <dir>                          -> ssh_sftp_list
      stat <file>                       -> ssh_sftp_stat
      md5sum / sha256sum / shaXsum      -> ssh_file_hash
      systemctl status / is-active / is-enabled -> ssh_systemctl_*
      journalctl -u ...                 -> ssh_journalctl
      docker <anything>                 -> ssh_docker_* (22 tools)
      sudo <cmd>                        -> ssh_sudo_exec (separate gate)
      <run same cmd on N hosts>         -> ssh_broadcast
      <copy file from host A to host B> -> ssh_transfer

    When `ssh_exec_run` IS right:
      - ad-hoc READ-ONLY diagnostic one-liners with no dedicated tool
      - composed pipelines (`foo | grep | awk`) where no per-step tool fits
      - vendor-specific or one-off commands (apk, dnf, brew, ...) with no
        wrapper

    Non-zero exit codes are data (see `exit_code`), not raised. Timeouts return
    `timed_out=True` with any partial output captured. Commands are allowlist-
    checked (`command_allowlist` / `SSH_COMMAND_ALLOWLIST`). Caller owns quoting.

    POSIX-only: assumes `sh -c`, `pkill` for timeout cleanup, and POSIX quoting
    via `shlex`. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
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

    POSIX-only. Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
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
    return result
