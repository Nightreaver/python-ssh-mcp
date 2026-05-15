"""Read-only host probes + the `ssh_host_reload` admin tool.

Read-only probes carry the ``{"safe", "read", "group:host"}`` tagset; the
single low-access tool (`ssh_host_reload`) lives here too because it
operates on the in-memory host registry rather than a remote SSH target,
so it shares the same module shape but no probe code.

Per-host agent-notes tools (`ssh_host_notes`, `ssh_host_notes_append`,
`ssh_host_notes_set`) live in :mod:`ssh_mcp.tools.host_notes_tools`. The
sidecar mechanics they share with `ssh_host_ping` (notes auto-injection,
INC-060) and `ssh_host_list` (`has_notes` flag, INC-055) live in
:mod:`ssh_mcp.services.host_notes` -- this module imports the public
helpers from there rather than duplicating them.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import TYPE_CHECKING, Any

from fastmcp import Context

from ..app import mcp_server
from ..hosts import load_hosts
from ..models.results import (
    AlertBreach,
    DiskUsageEntry,
    DiskUsageResult,
    HostAlertsResult,
    HostInfoResult,
    HostListEntry,
    HostListResult,
    HostNetworkResult,
    HostReloadResult,
    NetworkInterfaceAddress,
    NetworkInterfaceEntry,
    PingResult,
    ProcessEntry,
    ProcessListResult,
    UserInfoResult,
)
from ..services.alerts import evaluate
from ..services.audit import audited
from ..services.host_notes import either_notes_present, read_sidecar, try_resolve_sidecar_path
from ..services.output_sanitizer import scan as scan_output
from ..ssh.errors import ConnectError, UnknownHost
from ._context import hosts_from, known_hosts_from, pool_from, require_posix, resolve_host, settings_from

if TYPE_CHECKING:
    import asyncssh


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_ping(host: str, ctx: Context) -> PingResult:
    """TCP + SSH handshake probe. Returns reachability, auth status, latency.

    BOTH note layers auto-inject when their respective settings are on
    (defaults: both True). Ping is the canonical "starting work on this
    host" probe, so the LLM gets the operator's hard rules AND its past
    self's learned facts into context without having to remember a
    separate `ssh_host_notes` call.

    - `operator_notes` (INC-059, gated by `SSH_PING_INCLUDES_NOTES`):
      hard-rule baseline from `hosts.toml`'s `notes` field.
    - `agent_notes` (INC-060, gated by `SSH_PING_INCLUDES_AGENT_NOTES`):
      the LLM's own session-spanning sidecar at
      `<SSH_HOST_NOTES_DIR>/<alias>.md`. Can grow to 256 KiB by default;
      flip the setting off if context inflation matters more than
      memory continuity.

    Either field is `None` when its setting is off, the host has no
    notes at that layer, or (for agent notes) the alias didn't pass
    the filename regex / sidecar didn't exist.
    """
    pool = pool_from(ctx)
    kh = known_hosts_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy

    start = time.monotonic()
    banner: str | None = None
    auth_ok = False
    reachable = False
    try:
        conn = await pool.acquire(resolved)
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

    op_notes: str | None = None
    if settings.SSH_PING_INCLUDES_NOTES and policy.notes and policy.notes.strip():
        op_notes = policy.notes.strip()

    # INC-060: also include the agent-side notes (LLM's own sidecar)
    # when enabled. Same alias-regex + sidecar-path resolution as
    # `ssh_host_notes` -- defense-in-depth against future code paths
    # that bypass `resolve_host` (which already filters aliases).
    agent_notes: str | None = None
    if settings.SSH_PING_INCLUDES_AGENT_NOTES:
        sidecar = try_resolve_sidecar_path(settings.SSH_HOST_NOTES_DIR, host)
        if sidecar is not None:
            agent_notes = read_sidecar(sidecar)

    return PingResult(
        host=policy.hostname,
        reachable=reachable,
        auth_ok=auth_ok,
        latency_ms=int((time.monotonic() - start) * 1000),
        server_banner=banner,
        known_host_fingerprint=kh.fingerprint_for(policy.hostname, policy.port),
        operator_notes=op_notes,
        agent_notes=agent_notes,
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_info(host: str, ctx: Context) -> HostInfoResult:
    """Fetch uname, /etc/os-release, uptime, CPU info, and FQDN.

    Fixed argv -- no shell interpolation. Each probe runs independently
    (`return_exceptions=True`) so a missing `uptime` / `nproc` /
    `/proc/cpuinfo` / `hostname -f` doesn't lose its siblings.

    POSIX-only: parses `uname -a`, `/etc/os-release`, `uptime`, `nproc`,
    `/proc/cpuinfo`, `hostname -f`. Windows targets raise
    `PlatformNotSupported`.
    """
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(
        resolved,
        tool="ssh_host_info",
        reason="parses uname / /etc/os-release / uptime / cpuinfo / hostname",
    )
    conn = await pool.acquire(resolved)

    # `return_exceptions=True` so one probe failing (e.g. missing `uptime`
    # on a minimal busybox image, restricted /proc in a container) doesn't
    # cancel its siblings and lose the parts we *can* read. Failed probes
    # surface as empty strings downstream -- the parsers treat empty as
    # "unavailable" and the model fields stay None.
    uname_r, os_release_r, uptime_r, nproc_r, cpuinfo_r, hostname_r = await asyncio.gather(
        _run_capture(conn, ["uname", "-a"]),
        _run_capture(conn, ["cat", "/etc/os-release"]),
        _run_capture(conn, ["uptime"]),
        _run_capture(conn, ["nproc"]),
        _run_capture(conn, ["cat", "/proc/cpuinfo"]),
        _run_capture(conn, ["hostname", "-f"]),
        return_exceptions=True,
    )
    uname = uname_r if isinstance(uname_r, str) else ""
    os_release_raw = os_release_r if isinstance(os_release_r, str) else ""
    uptime_raw = uptime_r if isinstance(uptime_r, str) else ""
    nproc_raw = nproc_r if isinstance(nproc_r, str) else ""
    cpuinfo_raw = cpuinfo_r if isinstance(cpuinfo_r, str) else ""
    hostname_raw = hostname_r if isinstance(hostname_r, str) else ""

    os_release = _parse_os_release(os_release_raw)
    # Sprint 5: free-form fields the LLM reads as strings (uname / uptime /
    # parsed os_release values) flow from remote `_run_capture`, which
    # bypasses the standard exec sanitizer. Scan them here so any
    # ANSI / NUL / bidi / LLM-protocol-marker content is flagged on the
    # result model. cpu_count / cpu_model / hostname_fqdn use stricter
    # parsers (digit-only / first-line / single-line) that already drop
    # injection-shaped content, so they don't need a scan.
    warnings = _dedupe_warnings(
        scan_output(uname.strip()),
        scan_output(uptime_raw.strip()),
        *(scan_output(v) for v in os_release.values()),
    )

    return HostInfoResult(
        host=policy.hostname,
        uname=uname.strip() or None,
        os_release=os_release,
        uptime=uptime_raw.strip() or None,
        cpu_count=_parse_cpu_count(nproc_raw),
        cpu_model=_parse_cpu_model(cpuinfo_raw),
        hostname_fqdn=_parse_fqdn(hostname_raw),
        output_warnings=warnings,
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_network(host: str, ctx: Context) -> HostNetworkResult:
    """List network interfaces with addresses + state from `ip -j addr show`.

    Returns structured per-interface JSON: name, oper-state, MAC, addresses
    (family + address + prefix length). The raw `ip` output carries dozens
    of kernel-internal fields (broadcast, valid_life_time, scope, link_index,
    ...) that bloat the schema with no operational value -- those are
    deliberately stripped here.

    POSIX-only and `iproute2`-required: uses `ip -j addr show`. Hosts
    without `ip` (busybox without netlink, very old systems) get an empty
    `interfaces` list rather than a raise -- consumers can fall back to
    `ssh_exec_run "ifconfig"` or whatever the host supports.
    """
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_host_network", reason="uses iproute2 `ip -j addr show`")
    conn = await pool.acquire(resolved)
    raw = await _run_capture(conn, ["ip", "-j", "addr", "show"])
    return HostNetworkResult(host=policy.hostname, interfaces=_parse_ip_json(raw))


_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_user_info(
    host: str,
    ctx: Context,
    username: str | None = None,
) -> UserInfoResult:
    """Structured /etc/passwd row + group memberships for one user.

    `username=None` queries the SSH user that this connection authenticates
    as (`id -un` on the remote). Otherwise the requested name is validated
    against POSIX 3.437 (`^[a-z_][a-z0-9_-]{0,31}\\$?$`) before being passed
    to `getent` / `id` -- shell metacharacters can't smuggle through.

    Reads only world-readable `/etc/passwd` via `getent`; no sudo. Note:
    `getent passwd <name>` may consult LDAP / NSS backends in addition to
    the local file -- the result reflects the host's actual identity store.

    POSIX-only.
    """
    if username is not None and not _USERNAME_RE.match(username):
        raise ValueError(
            f"username {username!r} contains characters that POSIX usernames "
            f"don't permit (allowed: ^[a-z_][a-z0-9_-]{{0,31}}\\$?$)"
        )
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_user_info", reason="uses POSIX `getent passwd` + `id`")
    conn = await pool.acquire(resolved)

    # If username is None, ask the remote who we are (`id -un`). Cheap;
    # avoids assuming `policy.user` matches the actual logged-in identity
    # (sudoers ProxyCommand setups, identity_agent surprises, etc.).
    if username is None:
        whoami_raw = await _run_capture(conn, ["id", "-un"])
        username = whoami_raw.strip() or policy.user
        if not _USERNAME_RE.match(username):
            raise ValueError(f"remote `id -un` returned {username!r} -- not a recognizable POSIX username")

    passwd_r, groups_r, primary_r = await asyncio.gather(
        _run_capture(conn, ["getent", "passwd", username]),
        _run_capture(conn, ["id", "-Gn", username]),
        _run_capture(conn, ["id", "-gn", username]),
        return_exceptions=True,
    )
    passwd_raw = passwd_r if isinstance(passwd_r, str) else ""
    groups_raw = groups_r if isinstance(groups_r, str) else ""
    primary_raw = primary_r if isinstance(primary_r, str) else ""

    parsed = _parse_passwd_line(passwd_raw)
    if parsed is None:
        raise ValueError(f"user {username!r} not found via getent on host {policy.hostname!r}")
    # Sprint 5: GECOS is the only free-form, attacker-controllable text
    # in this result -- on shared boxes, any user with shell access can
    # `chfn` their own entry. Scan it for injection-shaped content
    # (ANSI / NUL / bidi / LLM markers / fake-turn lines) and surface
    # warnings to the LLM. The other fields (name / uid / gid / home /
    # shell / groups) are constrained by /etc/passwd / `id` formats.
    warnings = scan_output(parsed["gecos"])
    return UserInfoResult(
        host=policy.hostname,
        username=parsed["name"],
        uid=parsed["uid"],
        gid=parsed["gid"],
        gecos=parsed["gecos"],
        home=parsed["home"],
        shell=parsed["shell"],
        primary_group=primary_raw.strip() or "",
        groups=[g for g in groups_raw.split() if g],
        output_warnings=warnings,
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_disk_usage(host: str, ctx: Context) -> DiskUsageResult:
    """`df -PTh` on the remote host, parsed into structured entries. POSIX-only."""
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_host_disk_usage", reason="uses `df -PTh`")
    conn = await pool.acquire(resolved)
    raw = await _run_capture(conn, ["df", "-PTh"])
    return DiskUsageResult(host=policy.hostname, entries=_parse_df(raw))


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_processes(host: str, ctx: Context, top: int = 20) -> ProcessListResult:
    """Top-N processes by CPU. `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu`, head -N.

    POSIX-only (uses `ps`). Windows targets raise `PlatformNotSupported`.
    """
    if not 1 <= top <= 200:
        raise ValueError("top must be between 1 and 200")
    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_host_processes", reason="uses POSIX `ps`")
    conn = await pool.acquire(resolved)
    raw = await _run_capture(conn, ["ps", "-eo", "pid,user,pcpu,pmem,comm", "--sort=-pcpu"])
    return ProcessListResult(
        host=policy.hostname,
        entries=_parse_ps(raw, top),
    )


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_alerts(host: str, ctx: Context) -> HostAlertsResult:
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
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    require_posix(resolved, tool="ssh_host_alerts", reason="reads /proc/loadavg, /proc/meminfo, df")
    conn = await pool.acquire(resolved)

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

    eval_result = evaluate(
        host=policy.hostname,
        policy=policy.alerts,
        disk_entries=disk_entries,
        load_1min=load_1min,
        mem_total_kb=mem_total_kb,
        mem_free_kb=mem_free_kb,
    )
    return HostAlertsResult(
        host=eval_result.host,
        breaches=[
            AlertBreach(
                metric=b.metric,
                threshold=b.threshold,
                current=b.current,
                severity=b.severity,
                detail=b.detail,
            )
            for b in eval_result.breaches
        ],
        metrics=eval_result.metrics,
    )


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
@audited(tier="read")
async def ssh_known_hosts_verify(host: str, ctx: Context) -> dict[str, Any]:
    """Verify the live server key matches known_hosts by attempting a real connect.

    Success means asyncssh's built-in verification passed (fingerprint matches).
    Failure returns the specific reason without auto-trusting anything.
    """
    pool = pool_from(ctx)
    kh = known_hosts_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    expected = kh.fingerprint_for(policy.hostname, policy.port)

    try:
        conn = await pool.acquire(resolved)
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
@audited(tier="read")
async def ssh_host_list(ctx: Context) -> HostListResult:
    """List all host aliases currently loaded in the running server.

    Returns sanitized metadata only — never exposes credentials (key paths,
    passwords, passphrases, proxy-jump credentials). The ``auth_method`` field
    names the method in use (``"agent"``, ``"key"``, or ``"password"``) but
    carries no secret value.

    Entries are sorted by alias for stable, predictable output.
    """
    hosts = hosts_from(ctx)
    settings = settings_from(ctx)
    notes_dir = settings.SSH_HOST_NOTES_DIR
    entries: list[HostListEntry] = [
        HostListEntry(
            alias=alias,
            hostname=policy.hostname,
            port=policy.port,
            platform=policy.platform,
            user=policy.user,
            auth_method=policy.auth.method,
            has_notes=either_notes_present(policy.notes, notes_dir, alias),
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


def _dedupe_warnings(*warning_lists: list[str]) -> list[str]:
    """Merge multiple sanitizer warning lists, preserving first-seen order.

    `output_sanitizer.scan()` returns a list of human-readable category
    strings. When several free-form fields (uname / uptime / os_release
    values) are scanned independently, the same category may appear in
    multiple lists (e.g. all carrying ANSI escapes). The LLM doesn't
    benefit from seeing "ANSI escape sequences ..." three times -- one
    instance per category is the useful signal.
    """
    seen: dict[str, None] = {}
    for warnings in warning_lists:
        for w in warnings:
            seen.setdefault(w, None)
    return list(seen)


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


def _parse_cpu_count(raw: str) -> int | None:
    """`nproc` returns a single integer line. Return None on parse failure
    so a busybox image without `nproc` doesn't fabricate a count."""
    s = raw.strip()
    if s.isdigit():
        return int(s)
    return None


def _parse_cpu_model(raw: str) -> str | None:
    """First `model name` line in /proc/cpuinfo. ARM uses `Model` /
    `Hardware`; AMD/Intel use `model name`. Try both, in that priority."""
    for needle in ("model name", "Model", "Hardware"):
        for line in raw.splitlines():
            if line.startswith(needle) and ":" in line:
                _, _, value = line.partition(":")
                v = value.strip()
                if v:
                    return v
    return None


def _parse_fqdn(raw: str) -> str | None:
    """`hostname -f` -- a single line. Empty / unset returns None so the
    field can be omitted from the result rather than carrying ''."""
    s = raw.strip()
    return s or None


def _parse_ip_json(raw: str) -> list[NetworkInterfaceEntry]:
    """Parse `ip -j addr show` output. Tolerate empty / malformed: hosts
    without iproute2 produce empty stdout, and we surface as `[]` so
    consumers can detect the gap and fall back to other tools."""
    s = raw.strip()
    if not s:
        return []
    try:
        items = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(items, list):
        return []

    out: list[NetworkInterfaceEntry] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        name = entry.get("ifname")
        if not isinstance(name, str):
            continue
        # `operstate` is the canonical link state from netlink. Older `ip`
        # builds may omit it; treat absence as UNKNOWN rather than UP.
        state = entry.get("operstate") or "UNKNOWN"
        mac = entry.get("address") if isinstance(entry.get("address"), str) else None
        addrs: list[NetworkInterfaceAddress] = []
        for a in entry.get("addr_info", []) or []:
            if not isinstance(a, dict):
                continue
            family = a.get("family")
            address = a.get("local")
            prefix = a.get("prefixlen")
            if not (isinstance(family, str) and isinstance(address, str) and isinstance(prefix, int)):
                continue
            addrs.append(NetworkInterfaceAddress(family=family, address=address, prefix_length=prefix))
        out.append(NetworkInterfaceEntry(name=name, state=state, mac=mac, addresses=addrs))
    return out


def _parse_passwd_line(raw: str) -> dict[str, Any] | None:
    """Parse one `getent passwd` line: `name:passwd:uid:gid:gecos:home:shell`.

    Returns None if the line is empty or malformed. `getent` may print
    nothing when the user doesn't exist (and exit non-zero), so empty
    stdout is the not-found signal here.
    """
    line = raw.strip()
    if not line:
        return None
    parts = line.split(":")
    if len(parts) < 7:
        return None
    try:
        return {
            "name": parts[0],
            "uid": int(parts[2]),
            "gid": int(parts[3]),
            "gecos": parts[4],
            "home": parts[5],
            "shell": parts[6],
        }
    except (ValueError, IndexError):
        return None
