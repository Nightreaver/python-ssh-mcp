"""Read-tier docker tools. All tagged ``{"safe", "read", "group:docker"}``.

Inspect / list / logs / events / volumes -- every tool here is read-only and
safe to expose by default. Mutating state lives in `lifecycle_tools`
(low-access) and `dangerous_tools` (dangerous).

INC-043: extracted from the original monolithic `docker_tools.py`.
"""
from __future__ import annotations

import json
import shlex
from typing import Any, Literal

from fastmcp import Context

from ...app import mcp_server
from ...services.audit import audited
from ...services.path_policy import (
    canonicalize_and_check,
    effective_allowlist,
)
from .._context import pool_from, resolve_host, settings_from
from ._helpers import (
    _DEFAULT_LOG_MAX_BYTES,
    _DOCKER_FILTER_RE,
    _DOCKER_TIME_RE,
    _parse_json_lines,
    _rewrite_stdout,
    _run_docker,
    _strip_noisy_fields,
    _validate_name,
)


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_ps(
    host: str,
    ctx: Context,
    all_: bool = False,
    include_labels: bool = False,
) -> dict[str, Any]:
    """List containers. Set ``all_=True`` to include stopped. Output is a list
    of JSON objects (one per container) parsed from ``docker ps --format '{{json .}}'``.

    ``include_labels`` defaults to False: the ``Labels`` field can run to
    hundreds of bytes per container on OCI-tagged images (ghcr, org.opencontainers.*)
    and 20+ containers quickly blow past the MCP output cap. Set True if you
    actually need them (e.g. filtering by label).
    """
    argv = ["ps", "--format", "{{json .}}", "--no-trunc"]
    if all_:
        argv.append("-a")
    result = await _run_docker(ctx, host, argv)
    containers = _parse_json_lines(result.get("stdout", ""))
    if not include_labels:
        _strip_noisy_fields(containers, ("Labels",))
        _rewrite_stdout(result, containers)
    return {**result, "containers": containers}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_logs(
    host: str,
    container: str,
    ctx: Context,
    tail: int = 50,
    since: str | None = None,
    timestamps: bool = False,
    max_bytes: int = _DEFAULT_LOG_MAX_BYTES,
) -> dict[str, Any]:
    """Read container logs with aggressive defaults to protect LLM context.

    Guards (all visible in the returned ExecResult):
      - ``tail`` defaults to 50 lines, capped at 10000.
      - ``since`` takes a time window (``"10m"``, ``"2h"``, RFC3339) -- prefer
        this over a large ``tail`` when you know roughly when something happened.
      - ``max_bytes`` truncates the returned ``stdout`` at ~64 KiB by default
        (~16k tokens). Raise when you genuinely need more; ``stdout_truncated``
        will be True if the cap is hit.
    """
    _validate_name("container", container)
    if not 1 <= tail <= 10000:
        raise ValueError("tail must be in 1..10000")
    if not 1024 <= max_bytes <= 10 * 1024 * 1024:
        raise ValueError("max_bytes must be in 1KiB..10MiB")
    argv = ["logs", f"--tail={tail}", "--"]
    if timestamps:
        argv.insert(2, "--timestamps")
    if since is not None:
        argv.insert(2, f"--since={since}")
    argv.append(container)
    return await _run_docker(ctx, host, argv, stdout_cap=max_bytes)


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_inspect(
    host: str,
    target: str,
    ctx: Context,
    kind: Literal["container", "image", "network", "volume"] = "container",
) -> dict[str, Any]:
    """Inspect a docker object. Returns the parsed JSON array under ``objects``."""
    _validate_name(kind, target)
    argv = ["inspect", "--type", kind, "--", target]
    result = await _run_docker(ctx, host, argv)
    objects: list[Any] = []
    if result.get("exit_code") == 0:
        try:
            objects = json.loads(result.get("stdout") or "[]")
        except json.JSONDecodeError:
            objects = []
    return {**result, "objects": objects}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_stats(host: str, ctx: Context) -> dict[str, Any]:
    """One-shot resource snapshot (no streaming). Parsed from
    ``docker stats --no-stream --format '{{json .}}'``.
    """
    argv = ["stats", "--no-stream", "--format", "{{json .}}"]
    result = await _run_docker(ctx, host, argv)
    return {**result, "containers": _parse_json_lines(result.get("stdout", ""))}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_top(
    host: str,
    container: str,
    ctx: Context,
    ps_options: str | None = None,
) -> dict[str, Any]:
    """`docker top <container>` -- list the container's running processes.

    The container name is argv-validated. Output is plain ``ps``-style text
    (Docker does not expose a JSON format for ``top``); it lands in ``stdout``
    unchanged for the caller to parse.

    ``ps_options`` is an OPTIONAL argv suffix passed verbatim to the
    container's ``ps`` (e.g. ``"-eo pid,user,comm"``). We ``shlex.split`` it
    and pass each token as its own argv element, so quoted values stay
    intact and there is no shell-interpolation path.

    Shell metacharacters (``|&;<>`$\\n``) are refused on the **raw** input
    BEFORE the split. Necessary because ``shlex.split`` treats ``\\n`` as
    whitespace -- a per-token check after splitting would silently accept a
    `\\n`-smuggled redirect.
    """
    _validate_name("container", container)
    argv = ["top", "--", container]
    if ps_options is not None:
        # Reject shell metacharacters in the RAW string first -- `shlex.split`
        # consumes `\n` as whitespace, so a per-token check after splitting
        # can't see it. Any of |&;<>`$\n in the input is refused whether or
        # not it would survive the split.
        if any(c in ps_options for c in "|&;<>`$\n"):
            raise ValueError(
                f"ps_options contains shell metacharacters: {ps_options!r}"
            )
        extra = shlex.split(ps_options)
        argv.extend(extra)
    return await _run_docker(ctx, host, argv)


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_events(
    host: str,
    ctx: Context,
    since: str = "1h",
    until: str = "now",
    filters: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch Docker daemon events over a bounded time window.

    Answers "what just happened to this container / image / volume / network?"
    -- OOM kill, restart, health transition, image pull, volume mount -- in
    one call. The runbook at `runbooks/ssh-docker-incident-response/SKILL.md`
    walks through reading the output.

    ``since`` defaults to ``"1h"`` so an operator paged part-way into an
    incident sees the triggering events without having to widen manually.

    Time anchors (`since`, `until`) accept:
      * relative (``10m``, ``2h``, ``24h30m``) -- Go ``time.ParseDuration``
        units only: ``s``, ``m``, ``h``. Days are NOT supported; use
        ``168h`` for 7 days, or an epoch / RFC3339 timestamp.
      * Unix epoch seconds (``1710000000``)
      * RFC3339 / ISO datetime (``2026-04-16T12:00:00Z``)
      * the literal ``now`` (only meaningful for ``until``)

    ``until`` defaults to ``now`` so the call is **bounded**. We never pass
    an unbounded `docker events` (which streams indefinitely); that would
    hang until `SSH_COMMAND_TIMEOUT`.

    ``filters`` is a list of ``KEY=VALUE`` strings, passed one-per-``--filter``
    argv element. Common keys: ``container=<name>``, ``event=die|start|oom``,
    ``type=container|image|volume|network``, ``label=foo``. Values must match
    a conservative regex; for anything exotic, drop to ``ssh_exec_run``.

    Output: newline-delimited JSON (same pattern as `ssh_docker_ps`); we
    parse it into ``events`` alongside the raw ``ExecResult``.
    """
    if not _DOCKER_TIME_RE.match(since):
        raise ValueError(
            f"`since` must be relative (10m), epoch (1710000000), RFC3339, "
            f"or 'now'; got {since!r}"
        )
    if not _DOCKER_TIME_RE.match(until):
        raise ValueError(
            f"`until` must be relative (10m), epoch (1710000000), RFC3339, "
            f"or 'now'; got {until!r}"
        )
    if filters:
        for f in filters:
            if not _DOCKER_FILTER_RE.match(f):
                raise ValueError(
                    f"filter {f!r} must match KEY=VALUE with alnum/path chars"
                )
    argv = [
        "events",
        f"--since={since}",
        f"--until={until}",
        "--format", "{{json .}}",
    ]
    if filters:
        for f in filters:
            argv.extend(["--filter", f])
    result = await _run_docker(ctx, host, argv)
    return {**result, "events": _parse_json_lines(result.get("stdout", ""))}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_volumes(
    host: str,
    ctx: Context,
    name: str | None = None,
) -> dict[str, Any]:
    """List Docker volumes (or inspect a single one by name).

    Without ``name``: runs ``docker volume ls --format '{{json .}}'`` and
    returns the parsed list under ``volumes``. Use this BEFORE deciding
    whether to run ``ssh_docker_prune(scope="volume")`` -- named volumes
    often carry application state (databases, uploaded files), and pruning
    without seeing what's there is how you lose data.

    With ``name``: runs ``docker volume inspect <name>`` and returns the
    parsed JSON array under ``volumes`` (same shape as `ssh_docker_inspect`).

    The volume name is argv-validated against the Docker naming rule.

    **Empty `volumes` semantics:** on any non-zero ``exit_code`` (volume
    missing, daemon error, parse failure), ``volumes`` is ``[]``. This is
    intentional parity with `ssh_docker_inspect`, but it means the caller
    MUST read ``exit_code`` and ``stderr`` to distinguish "no such volume"
    (non-zero exit, populated stderr) from a genuinely-empty result (zero
    exit, empty stdout -- only possible in list mode).
    """
    if name is not None:
        _validate_name("volume", name)
        argv = ["volume", "inspect", "--", name]
        result = await _run_docker(ctx, host, argv)
        volumes: list[Any] = []
        if result.get("exit_code") == 0:
            try:
                volumes = json.loads(result.get("stdout") or "[]")
            except json.JSONDecodeError:
                volumes = []
        return {**result, "volumes": volumes}
    argv = ["volume", "ls", "--format", "{{json .}}"]
    result = await _run_docker(ctx, host, argv)
    return {**result, "volumes": _parse_json_lines(result.get("stdout", ""))}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_images(
    host: str,
    ctx: Context,
    include_labels: bool = False,
) -> dict[str, Any]:
    """List local images, parsed from ``docker images --format '{{json .}}'``.

    ``include_labels`` defaults to False -- same rationale as ``ssh_docker_ps``.
    """
    argv = ["images", "--format", "{{json .}}"]
    result = await _run_docker(ctx, host, argv)
    images = _parse_json_lines(result.get("stdout", ""))
    if not include_labels:
        _strip_noisy_fields(images, ("Labels",))
        _rewrite_stdout(result, images)
    return {**result, "images": images}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_compose_ps(
    host: str,
    compose_file: str,
    ctx: Context,
    include_labels: bool = False,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """List services for a compose project. Parsed from ``compose ps --format json``.

    ``include_labels`` defaults to False -- same rationale as ``ssh_docker_ps``.
    Set ``compose_v1=True`` on hosts still running the legacy ``docker-compose``
    standalone binary; default is the v2 ``docker compose`` plugin.
    """
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn, compose_file, effective_allowlist(policy, settings),
        must_exist=True, platform=policy.platform,
    )
    argv = ["-f", canonical, "ps", "--format", "json"]
    result = await _run_docker(ctx, host, argv, compose=True, compose_v1=compose_v1)
    services = _parse_json_lines(result.get("stdout", ""))
    if not include_labels:
        _strip_noisy_fields(services, ("Labels",))
        _rewrite_stdout(result, services)
    return {**result, "services": services}


@mcp_server.tool(tags={"safe", "read", "group:docker"}, version="1.0")
@audited(tier="read")
async def ssh_docker_compose_logs(
    host: str,
    compose_file: str,
    ctx: Context,
    tail: int = 50,
    service: str | None = None,
    max_bytes: int = _DEFAULT_LOG_MAX_BYTES,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Read logs from a compose project. Same context-protection guards as
    `ssh_docker_logs`: default tail=50, default max_bytes=64 KiB. Prefer
    ``service=...`` to narrow scope when possible. Set ``compose_v1=True`` on
    hosts still running the legacy ``docker-compose`` standalone binary.
    """
    if not 1 <= tail <= 10000:
        raise ValueError("tail must be in 1..10000")
    if not 1024 <= max_bytes <= 10 * 1024 * 1024:
        raise ValueError("max_bytes must be in 1KiB..10MiB")
    if service is not None:
        _validate_name("service", service)
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn, compose_file, effective_allowlist(policy, settings),
        must_exist=True, platform=policy.platform,
    )
    argv = ["-f", canonical, "logs", f"--tail={tail}", "--no-color"]
    if service:
        argv.append(service)
    return await _run_docker(
        ctx, host, argv, compose=True, compose_v1=compose_v1, stdout_cap=max_bytes,
    )
