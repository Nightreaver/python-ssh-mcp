"""Multi-host operations: fan-out a command across a fleet, copy files
between two remotes via the MCP server (INC-052).

Sibling to `exec_tools.py` + `low_access_tools.py`. Stays a separate
module because the multi-host orchestration shape (resolve N policies,
gate per-host) is distinct from the single-host exec / file-ops surfaces.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from typing import TYPE_CHECKING

import asyncssh

# Import FX_NO_SUCH_FILE from ``asyncssh.constants`` rather than
# ``asyncssh.sftp`` — the latter doesn't list it in ``__all__`` even though
# it's the documented public surface, which trips mypy strict.
from asyncssh.constants import FX_NO_SUCH_FILE
from fastmcp import Context

from ..app import mcp_server
from ..models.results import BroadcastResult, ExecResult, TransferResult
from ..services.audit import audited
from ..services.exec_policy import check_command
from ..services.path_policy import resolve_path
from ..ssh.errors import HostBlocked, HostNotAllowed
from ..ssh.exec import run as exec_run
from ._context import pool_from, require_posix, resolve_host, settings_from

if TYPE_CHECKING:
    from ..models.policy import ResolvedHost


# Hard cap on the per-call fleet size. An LLM that types "broadcast to *every*
# alias" with a fat list shouldn't fan out to thousands of connections in one
# call -- the pool's per-host caps don't help here because each alias is its
# own pool key. Operators with genuinely large fleets split across calls.
_BROADCAST_MAX_HOSTS = 50


@mcp_server.tool(tags={"dangerous", "group:exec"}, version="1.0")
@audited(tier="dangerous")
async def ssh_broadcast(
    hosts: list[str],
    command: str,
    ctx: Context,
    timeout: int | None = None,
) -> BroadcastResult:
    """Run the same command on multiple pre-configured hosts in parallel.

    PURPOSE: fleet operations where one command should run against several
    hosts and you want a structured per-host result -- e.g. "what kernel
    runs on web01..web10", "tail the last 5 nginx error lines on every edge
    node", "show systemd unit X status across the api tier".

    PER-HOST GATING. Each host's command is independently checked against
    that host's `command_allowlist` and `platform`. A failure on one host
    does NOT abort the others; per-host failures (`CommandNotAllowed`,
    `PlatformNotSupported`, `ConnectError`, `AuthenticationFailed`,
    `UnknownHost`, `HostKeyMismatch`) appear in `errors` keyed by alias.
    Non-zero exit codes and timeouts are data (per ADR-0005) and appear
    in `results[alias]` with `failed` listing.

    UNKNOWN OR BLOCKED ALIASES ARE LOUD. If any entry in `hosts` resolves
    to `HostNotAllowed` or `HostBlocked`, the whole call raises before any
    fan-out -- typos and policy denials are caller errors, not transient
    per-host failures. Fix the call rather than digging through `errors`.

    LIMITS. Hard cap of 50 hosts per call. Duplicates in `hosts` are
    deduplicated before fan-out. Per-host stdout/stderr caps are the same
    `SSH_STDOUT_CAP_BYTES` / `SSH_STDERR_CAP_BYTES` as `ssh_exec_run`, so
    a fleet of chatty hosts can return up to N*cap bytes total -- prefer
    targeted commands (`grep`, `head`, structured output) over raw dumps.

    POSIX-ONLY PER HOST. Each host's `platform` field is checked
    independently. Windows hosts in the list are recorded as
    `PlatformNotSupported` errors; other hosts in the same call still run.

    EXAMPLES:
      ssh_broadcast(hosts=["web01", "web02", "web03"], command="uname -r")
      ssh_broadcast(hosts=["api01", "api02"], command="systemctl is-active myapp")

    See also: `ssh_exec_run` for single-host calls; `ssh_host_list` to see
    what aliases are loaded.
    """
    if not hosts:
        raise ValueError("hosts cannot be empty")
    if len(hosts) > _BROADCAST_MAX_HOSTS:
        raise ValueError(
            f"hosts list has {len(hosts)} entries; max is {_BROADCAST_MAX_HOSTS}. "
            f"Split into multiple ssh_broadcast calls."
        )

    seen: set[str] = set()
    deduped: list[str] = []
    for h in hosts:
        if h in seen:
            continue
        seen.add(h)
        deduped.append(h)

    settings = settings_from(ctx)
    pool = pool_from(ctx)
    effective_timeout = float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT)

    # Resolve every alias up front -- typos and blocklist hits are caller
    # errors, not per-host transient failures. Surface them in one ValueError
    # so the LLM can fix the call, not pick through `errors` to find them.
    policies: dict[str, ResolvedHost] = {}
    rejected: list[str] = []
    for alias in deduped:
        try:
            policies[alias] = resolve_host(ctx, alias)
        except (HostNotAllowed, HostBlocked) as exc:
            rejected.append(f"{alias} ({type(exc).__name__})")
    if rejected:
        raise ValueError(
            f"unknown / blocked hosts in broadcast: {', '.join(rejected)}. "
            f"Check hosts.toml + SSH_HOSTS_ALLOWLIST / SSH_HOSTS_BLOCKLIST."
        )

    async def _run_one(alias: str, resolved: ResolvedHost) -> tuple[str, ExecResult | None, str | None]:
        policy = resolved.policy
        try:
            require_posix(
                resolved,
                tool="ssh_broadcast",
                reason="relies on POSIX shell (sh) + pkill for timeout cleanup",
            )
            check_command(command, policy, settings)
            conn = await pool.acquire(resolved)
            result = await exec_run(
                conn,
                command,
                host=policy.hostname,
                timeout=effective_timeout,
                stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
                stderr_cap=settings.SSH_STDERR_CAP_BYTES,
            )
            return alias, result, None
        except Exception as exc:
            # Catch-all so one host's transport-layer surprise (broken pipe,
            # asyncio cancellation race, asyncssh internal error) doesn't
            # bring down the whole broadcast. Class name only -- full text
            # stays at DEBUG via the audit logger.
            return alias, None, type(exc).__name__

    start = time.monotonic()
    outcomes = await asyncio.gather(
        *(_run_one(alias, resolved) for alias, resolved in policies.items()),
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)

    results: dict[str, ExecResult] = {}
    succeeded: list[str] = []
    failed: list[str] = []
    errors: dict[str, str] = {}
    for alias, result, err in outcomes:
        if result is not None:
            results[alias] = result
            if result.exit_code == 0 and not result.timed_out:
                succeeded.append(alias)
            else:
                failed.append(alias)
        else:
            errors[alias] = err or "UnknownError"
            failed.append(alias)

    return BroadcastResult(
        command=command,
        results=results,
        succeeded=succeeded,
        failed=failed,
        errors=errors,
        elapsed_ms=elapsed_ms,
    )


# 256 KiB SFTP read/write chunk. asyncssh's window-based flow control
# pipelines these so a serial read-then-write loop already saturates the
# SFTP channel; smaller chunks add request overhead, larger ones don't
# improve throughput once the window is full.
_TRANSFER_CHUNK_BYTES = 256 * 1024

# Width of the random suffix appended to the destination temp path.
_TRANSFER_TMP_TOKEN_BYTES = 8


@mcp_server.tool(tags={"low-access", "group:file-ops"}, version="1.0")
@audited(tier="low-access")
async def ssh_transfer(
    src_host: str,
    src_path: str,
    dst_host: str,
    dst_path: str,
    ctx: Context,
    overwrite: bool = False,
) -> TransferResult:
    """Copy a file from one remote host to another via the MCP server.

    Streams `src_host:src_path -> dst_host:dst_path` through SFTP channels
    on both connections. Neither host needs to reach the other -- the data
    transits through the MCP server, which is the whole point: works in
    firewalled inter-host topologies where direct A->B SSH is blocked.

    THROUGHPUT NOTE. The transfer is bottlenecked by the slower of (src ->
    MCP) and (MCP -> dst). On a residential MCP machine bridging two cloud
    hosts this caps near the operator's upload bandwidth. For inter-host
    gigabit + when A and B already trust each other, an `scp`/`rsync`
    invoked via `ssh_exec_run` between the two hosts will be faster (no
    transit through the MCP host).

    PATH POLICY. Both `src_path` and `dst_path` route through `resolve_path`
    independently (canonicalize + allowlist + restricted-zones in one shot).
    Each host's own `path_allowlist` / `restricted_paths` apply. The src must
    exist; dst must NOT exist unless `overwrite=True`.

    ATOMIC. The destination is written to `<dst_path>.ssh-mcp-tmp.<rand>`
    then `posix_rename`-d into place -- same pattern as `ssh_upload`. A
    crash mid-transfer leaves the temp file (which is harmless and gets
    garbage-collected by ops cleanup); the final path is never partial.

    SIZE CAP. The src file size is checked against
    `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB) before the transfer
    starts. Larger files raise immediately rather than starting a copy
    that the cap would interrupt.

    PLATFORM. Cross-platform via SFTP -- works for any combination of
    POSIX <-> Windows hosts as long as both expose SFTP (the canonical
    Windows path forms are handled by `resolve_path`).

    EXAMPLES:
      ssh_transfer(
          src_host="build01", src_path="/build/artifacts/app-1.2.tar.gz",
          dst_host="prod01",  dst_path="/opt/app/releases/app-1.2.tar.gz",
      )
      ssh_transfer(
          src_host="db01", src_path="/var/backups/dump.sql",
          dst_host="db02", dst_path="/var/restores/dump.sql",
          overwrite=True,
      )
    """
    if src_host == dst_host:
        raise ValueError(
            f"src_host and dst_host are both {src_host!r} -- use ssh_cp for "
            f"single-host copies (cheaper, no SFTP-to-SFTP relay)."
        )

    pool = pool_from(ctx)
    settings = settings_from(ctx)
    src_resolved = resolve_host(ctx, src_host)
    dst_resolved = resolve_host(ctx, dst_host)
    src_policy = src_resolved.policy
    dst_policy = dst_resolved.policy

    # Each connection acquired before path resolution (canonicalize_and_check
    # runs SFTP `realpath` on the live connection).
    src_conn = await pool.acquire(src_resolved)
    dst_conn = await pool.acquire(dst_resolved)

    src_canonical = await resolve_path(
        src_conn,
        src_path,
        src_policy,
        settings,
        must_exist=True,
        pool=pool,
    )
    dst_canonical = await resolve_path(
        dst_conn,
        dst_path,
        dst_policy,
        settings,
        must_exist=False,
        pool=pool,
    )

    cap = settings.SSH_UPLOAD_MAX_FILE_BYTES
    tmp_path = f"{dst_canonical}.ssh-mcp-tmp.{secrets.token_hex(_TRANSFER_TMP_TOKEN_BYTES)}"

    start = time.monotonic()
    bytes_transferred = 0
    src_size = 0
    # Two independent pool keys -- nest the context managers so each side's
    # invalidate-on-channel-failure semantics fire on the correct key. The
    # SFTPClient instances are pool-cached and (per Phase 2) shared across
    # concurrent SFTP-using tools on the same host.
    async with (
        pool.sftp(src_resolved) as src_sftp,
        pool.sftp(dst_resolved) as dst_sftp,
    ):
        # Size check up front -- avoid starting a copy the cap will reject.
        attrs = await src_sftp.stat(src_canonical)
        src_size = int(attrs.size or 0)
        if src_size > cap:
            raise ValueError(f"src file {src_size} bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES={cap}")

        # Existence check on dst -- only when caller hasn't opted in to overwrite.
        if not overwrite:
            try:
                await dst_sftp.stat(dst_canonical)
            except asyncssh.SFTPError as exc:
                if getattr(exc, "code", None) != FX_NO_SUCH_FILE:
                    raise
            else:
                raise ValueError(
                    f"destination {dst_canonical!r} already exists on {dst_policy.hostname!r}; "
                    f"pass overwrite=True to replace it."
                )

        # Stream the file. Same atomic-write pattern as `ssh_upload`: write
        # to a temp sibling then `posix_rename` into place. Cleanup the
        # temp on failure so a crashed transfer doesn't leave junk.
        try:
            async with (
                src_sftp.open(src_canonical, "rb") as src_f,
                dst_sftp.open(tmp_path, "wb") as dst_f,
            ):
                while True:
                    chunk = await src_f.read(_TRANSFER_CHUNK_BYTES)
                    if not chunk:
                        break
                    await dst_f.write(chunk)
                    bytes_transferred += len(chunk)
            await dst_sftp.posix_rename(tmp_path, dst_canonical)
        except (asyncssh.Error, OSError):
            with contextlib.suppress(asyncssh.SFTPError):
                await dst_sftp.remove(tmp_path)
            raise

    duration_ms = int((time.monotonic() - start) * 1000)
    # Avoid div-by-zero on absurdly fast (LAN, cached) tiny transfers.
    seconds = max(duration_ms / 1000.0, 0.001)
    throughput_mb_s = (bytes_transferred / (1024.0 * 1024.0)) / seconds

    return TransferResult(
        src_host=src_policy.hostname,
        src_path=src_canonical,
        dst_host=dst_policy.hostname,
        dst_path=dst_canonical,
        size=bytes_transferred,
        duration_ms=duration_ms,
        throughput_mb_s=round(throughput_mb_s, 3),
    )
