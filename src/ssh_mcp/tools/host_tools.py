"""Read-only host tools. All tagged {"safe", "read", "group:host"}.

Low-access host management tools (ssh_host_reload) are also here since they
operate on the in-memory host registry rather than remote SSH targets.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from fastmcp import Context

from ..app import mcp_server
from ..hosts import load_hosts
from ..models.results import (
    DiskUsageEntry,
    DiskUsageResult,
    HostInfoResult,
    HostListEntry,
    HostListResult,
    HostReloadResult,
    PingResult,
    ProcessEntry,
    ProcessListResult,
)
from ..services.alerts import breach_to_dict, evaluate
from ..services.audit import audited
from ..ssh.errors import ConnectError, UnknownHost
from ._context import hosts_from, known_hosts_from, pool_from, require_posix, resolve_host, settings_from

if TYPE_CHECKING:
    import asyncssh


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_ping(host: str, ctx: Context) -> PingResult:
    """TCP + SSH handshake probe. Returns reachability, auth status, and latency."""
    pool = pool_from(ctx)
    kh = known_hosts_from(ctx)
    policy = resolve_host(ctx, host)

    start = time.monotonic()
    banner: str | None = None
    auth_ok = False
    reachable = False
    try:
        conn = await pool.acquire(policy)
        reachable = True
        auth_ok = True
        ext = conn.get_extra_info("server_version")
        if isinstance(ext, bytes | bytearray):
            banner = ext.decode(errors="replace")
        elif isinstance(ext, str):
            banner = ext
    except UnknownHost:
        reachable = True  # TCP reached, key verification failed
        auth_ok = False
    except ConnectError:
        reachable = False

    return PingResult(
        host=policy.hostname,
        reachable=reachable,
        auth_ok=auth_ok,
        latency_ms=int((time.monotonic() - start) * 1000),
        server_banner=banner,
        known_host_fingerprint=kh.fingerprint_for(policy.hostname, policy.port),
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_info(host: str, ctx: Context) -> HostInfoResult:
    """Fetch uname, /etc/os-release, and uptime. Fixed argv — no shell interpolation.

    POSIX-only: parses `uname -a`, `/etc/os-release`, `uptime`. Windows targets
    raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_host_info", reason="parses uname / /etc/os-release / uptime")
    conn = await pool.acquire(policy)

    # `return_exceptions=True` so one probe failing (e.g. missing `uptime`
    # on a minimal busybox image) doesn't cancel its siblings and lose the
    # parts we *can* read. Failed probes surface as empty strings downstream
    # -- the parsers already treat empty as "unavailable".
    uname_r, os_release_r, uptime_r = await asyncio.gather(
        _run_capture(conn, ["uname", "-a"]),
        _run_capture(conn, ["cat", "/etc/os-release"]),
        _run_capture(conn, ["uptime"]),
        return_exceptions=True,
    )
    uname = uname_r if isinstance(uname_r, str) else ""
    os_release_raw = os_release_r if isinstance(os_release_r, str) else ""
    uptime_raw = uptime_r if isinstance(uptime_r, str) else ""
    return HostInfoResult(
        host=policy.hostname,
        uname=uname.strip() or None,
        os_release=_parse_os_release(os_release_raw),
        uptime=uptime_raw.strip() or None,
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_disk_usage(host: str, ctx: Context) -> DiskUsageResult:
    """`df -PTh` on the remote host, parsed into structured entries. POSIX-only."""
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_host_disk_usage", reason="uses `df -PTh`")
    conn = await pool.acquire(policy)
    raw = await _run_capture(conn, ["df", "-PTh"])
    return DiskUsageResult(host=policy.hostname, entries=_parse_df(raw))


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_processes(host: str, ctx: Context, top: int = 20) -> ProcessListResult:
    """Top-N processes by CPU. `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu`, head -N.

    POSIX-only (uses `ps`). Windows targets raise `PlatformNotSupported`.
    """
    if not 1 <= top <= 200:
        raise ValueError("top must be between 1 and 200")
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_host_processes", reason="uses POSIX `ps`")
    conn = await pool.acquire(policy)
    raw = await _run_capture(conn, ["ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu"])
    return ProcessListResult(
        host=policy.hostname,
        entries=_parse_ps(raw, top),
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_alerts(host: str, ctx: Context) -> dict[str, Any]:
    """Evaluate per-host alert thresholds from `[hosts.<name>.alerts]`.

    Pulls disk usage + load avg + memory free %, compares against the
    thresholds configured for this host in ``hosts.toml``. Returns the list of
    metrics in breach (possibly empty) plus the raw observations. No
    notifications are sent -- the tool reports, the caller decides. Run
    periodically via a cron or on-demand as part of a diagnostic flow.

    POSIX-only: reads `/proc/loadavg`, `/proc/meminfo`, and `df -PTh`.
    Windows targets raise `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_host_alerts", reason="reads /proc/loadavg, /proc/meminfo, df")
    conn = await pool.acquire(policy)

    # Same pattern as `ssh_host_info`: tolerate partial probe failure so a
    # missing `/proc/loadavg` (containers with restricted procfs) doesn't
    # lose the disk + memory reads too.
    df_r, loadavg_r, meminfo_r = await asyncio.gather(
        _run_capture(conn, ["df", "-PTh"]),
        _run_capture(conn, ["cat", "/proc/loadavg"]),
        _run_capture(conn, ["cat", "/proc/meminfo"]),
        return_exceptions=True,
    )
    df_raw = df_r if isinstance(df_r, str) else ""
    loadavg_raw = loadavg_r if isinstance(loadavg_r, str) else ""
    meminfo_raw = meminfo_r if isinstance(meminfo_r, str) else ""

    disk_entries = [{"mount": e.mount, "use_percent": e.use_percent} for e in _parse_df(df_raw)]
    load_1min: float | None = None
    toks = loadavg_raw.split()
    if toks:
        try:
            load_1min = float(toks[0])
        except ValueError:
            load_1min = None
    mem_total_kb, mem_free_kb = _parse_meminfo_free(meminfo_raw)

    result = evaluate(
        host=policy.hostname,
        policy=policy.alerts,
        disk_entries=disk_entries,
        load_1min=load_1min,
        mem_total_kb=mem_total_kb,
        mem_free_kb=mem_free_kb,
    )
    return {
        "host": result.host,
        "breaches": [breach_to_dict(b) for b in result.breaches],
        "metrics": result.metrics,
    }


def _parse_meminfo_free(raw: str) -> tuple[int | None, int | None]:
    """Parse /proc/meminfo. `MemAvailable` (free+reclaimable) is preferred over
    `MemFree` because modern kernels use most of free memory for buffers/cache.
    """
    total = available = None
    for line in raw.splitlines():
        if line.startswith("MemTotal:"):
            total = _meminfo_kb(line)
        elif line.startswith("MemAvailable:"):
            available = _meminfo_kb(line)
    return total, available


def _meminfo_kb(line: str) -> int | None:
    parts = line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_known_hosts_verify(host: str, ctx: Context) -> dict[str, Any]:
    """Verify the live server key matches known_hosts by attempting a real connect.

    Success means asyncssh's built-in verification passed (fingerprint matches).
    Failure returns the specific reason without auto-trusting anything.
    """
    pool = pool_from(ctx)
    kh = known_hosts_from(ctx)
    policy = resolve_host(ctx, host)
    expected = kh.fingerprint_for(policy.hostname, policy.port)

    try:
        conn = await pool.acquire(policy)
        live_fp = _extract_host_fingerprint(conn)
        return {
            "host": policy.hostname,
            "expected_fingerprint": expected,
            "live_fingerprint": live_fp,
            "matches_known_hosts": True,
            "error": None,
        }
    except UnknownHost as exc:
        return {
            "host": policy.hostname,
            "expected_fingerprint": expected,
            "live_fingerprint": None,
            "matches_known_hosts": False,
            "error": f"UnknownHost: {exc}",
        }
    except ConnectError as exc:
        return {
            "host": policy.hostname,
            "expected_fingerprint": expected,
            "live_fingerprint": None,
            "matches_known_hosts": False,
            "error": f"ConnectError: {exc}",
        }


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
async def ssh_host_list(ctx: Context) -> HostListResult:
    """List all host aliases currently loaded in the running server.

    Returns sanitized metadata only — never exposes credentials (key paths,
    passwords, passphrases, proxy-jump credentials). The ``auth_method`` field
    names the method in use (``"agent"``, ``"key"``, or ``"password"``) but
    carries no secret value.

    Entries are sorted by alias for stable, predictable output.
    """
    hosts = hosts_from(ctx)
    entries: list[HostListEntry] = [
        HostListEntry(
            alias=alias,
            hostname=policy.hostname,
            port=policy.port,
            platform=policy.platform,
            user=policy.user,
            auth_method=policy.auth.method,
        )
        for alias, policy in sorted(hosts.items())
    ]
    return HostListResult(hosts=entries, count=len(entries))


@mcp_server.tool(tags={"low-access", "group:host"}, version="1.0")
@audited(tier="low-access")
async def ssh_host_reload(ctx: Context) -> HostReloadResult:
    """Re-read ``SSH_HOSTS_FILE`` from disk and swap the in-memory host registry.

    Validates the new config before touching anything. If ``load_hosts`` raises
    (parse error, Pydantic validation failure, circular proxy chain, etc.) the
    existing fleet is left intact and the error is re-raised as a ``ValueError``
    with the original message.

    The swap is atomic within a single asyncio coroutine: ``dict.clear()``
    followed by ``dict.update()`` on the same dict object preserves dict
    identity, so any code that captured a reference to
    ``ctx.lifespan_context["hosts"]`` keeps seeing the live registry.

    **Live pooled connections are not invalidated.** Existing SSH connections
    keyed by ``(user, host, port)`` retain the policy snapshot they were
    created under. They will be re-evaluated on the next ``pool.acquire()``
    call or when their keepalive/idle timeout expires. For immediate effect,
    restart the MCP server.

    Returns a diff of added, removed, and changed aliases vs the previous load.
    ``changed`` = aliases whose ``HostPolicy`` content differs (compared via
    ``model_dump()`` equality).
    """
    settings = settings_from(ctx)

    # Validate-then-swap: load_hosts must succeed before we touch the live dict.
    try:
        new_hosts = load_hosts(settings.SSH_HOSTS_FILE, settings)
    except Exception as exc:
        raise ValueError(f"hosts reload failed: {exc}") from exc

    hosts = hosts_from(ctx)
    old_snapshot = {alias: policy.model_dump() for alias, policy in hosts.items()}

    old_keys = set(old_snapshot)
    new_keys = set(new_hosts)

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted(
        alias for alias in old_keys & new_keys if new_hosts[alias].model_dump() != old_snapshot[alias]
    )

    # Atomic in single-coroutine asyncio: neither clear() nor update() yields,
    # so no other coroutine can observe a partially-updated registry.
    hosts.clear()
    hosts.update(new_hosts)

    source = str(settings.SSH_HOSTS_FILE) if settings.SSH_HOSTS_FILE is not None else "<none>"
    return HostReloadResult(
        loaded=len(new_hosts),
        source=source,
        added=added,
        removed=removed,
        changed=changed,
    )


# ---- helpers ----


async def _run_capture(conn: asyncssh.SSHClientConnection, argv: list[str]) -> str:
    """Run a fixed argv on the remote, capture stdout, ignore non-zero exit.

    asyncssh.conn.run expects a STRING, not a list -- lists trigger
    "can't concat list to bytes" in asyncssh's internal request encoding.
    shlex.join quotes each element so the shell reconstructs argv exactly
    and untrusted input cannot shell-escape.
    """
    import shlex

    result = await conn.run(shlex.join(argv), check=False)
    out = result.stdout
    if isinstance(out, bytes | bytearray):
        return out.decode(errors="replace")
    return out or ""


def _parse_os_release(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def _parse_df(raw: str) -> list[DiskUsageEntry]:
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []
    entries: list[DiskUsageEntry] = []
    for line in lines[1:]:
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        entries.append(
            DiskUsageEntry(
                filesystem=parts[0],
                type=parts[1],
                size=parts[2],
                used=parts[3],
                available=parts[4],
                use_percent=parts[5],
                mount=parts[6],
            )
        )
    return entries


def _parse_ps(raw: str, top: int) -> list[ProcessEntry]:
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if len(lines) < 2:
        return []
    entries: list[ProcessEntry] = []
    for line in lines[1 : 1 + top]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            entries.append(
                ProcessEntry(
                    pid=int(parts[0]),
                    user=parts[1],
                    pcpu=float(parts[2]),
                    pmem=float(parts[3]),
                    command=parts[4],
                )
            )
        except ValueError:
            continue
    return entries


def _extract_host_fingerprint(conn: asyncssh.SSHClientConnection) -> str | None:
    """Best-effort: pull the server host key fingerprint from a live connection."""
    key = conn.get_server_host_key()
    if key is None:
        return None
    return key.get_fingerprint("sha256")
