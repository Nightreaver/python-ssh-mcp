"""Low-access docker lifecycle tools. Tagged ``{"low-access", "group:docker"}``.

Bounded state changes: start / stop / restart containers, docker cp in either
direction, compose start / stop / restart. Mutating but additive -- no data
deletion here (that lives in `dangerous_tools`). Hidden unless
``ALLOW_LOW_ACCESS_TOOLS=true``.

INC-043: extracted from the original monolithic `docker_tools.py`.
"""
from __future__ import annotations

from typing import Any, Literal

from fastmcp import Context

from ...app import mcp_server
from ...services.audit import audited
from ...services.path_policy import (
    canonicalize_and_check,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
)
from .._context import pool_from, resolve_host, settings_from
from ._helpers import _compose_project_op, _run_docker, _validate_name


def _simple_container_op(subcommand: str) -> Any:
    """Factory for the repetitive start/stop/restart/pause/unpause pattern."""

    @mcp_server.tool(
        name=f"ssh_docker_{subcommand}",
        tags={"low-access", "group:docker"},
        version="1.0",
    )
    @audited(tier="low-access")
    async def _tool(host: str, container: str, ctx: Context) -> dict[str, Any]:
        _validate_name("container", container)
        return await _run_docker(ctx, host, [subcommand, "--", container])

    _tool.__doc__ = (
        f"`docker {subcommand} <container>`. Name is argv-validated; no shell."
    )
    return _tool


ssh_docker_start = _simple_container_op("start")
ssh_docker_stop = _simple_container_op("stop")
ssh_docker_restart = _simple_container_op("restart")


@mcp_server.tool(tags={"low-access", "group:docker"}, version="1.0")
@audited(tier="low-access")
async def ssh_docker_cp(
    host: str,
    container: str,
    container_path: str,
    host_path: str,
    direction: Literal["from_container", "to_container"],
    ctx: Context,
    timeout: int | None = None,
) -> dict[str, Any]:
    """`docker cp` in either direction, with host-side path confinement.

    The host-side path (``host_path``) is canonicalized on the remote and
    verified inside ``path_allowlist`` + ``restricted_paths`` -- same rules
    as ``ssh_cp`` / ``ssh_upload``. The container-side path (``container_path``)
    lives inside the container's filesystem and is NOT checked against any
    allowlist (we don't manage policy inside containers).

    Directions:
      - ``from_container``: copies ``container:<container_path>`` -> ``<host_path>``.
        ``host_path`` must be a writeable location (parent exists, path
        allowlisted). Use this to pull a file OUT of a running container
        (e.g. retrieve a generated report, an app-level state dump).
      - ``to_container``: copies ``<host_path>`` -> ``container:<container_path>``.
        ``host_path`` must exist and be allowlist-scoped.

    Container + image name conventions still apply: name argv-validated.
    Caveat: ``docker cp`` interacts with arbitrary container filesystems --
    a compromised container image could stage a symlink chain that surprises
    the host. This is why the tool sits in the low-access tier (operator
    opt-in) rather than read.
    """
    _validate_name("container", container)
    if direction not in ("from_container", "to_container"):
        raise ValueError(
            f"direction must be 'from_container' or 'to_container', got {direction!r}"
        )
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    # First acquire is for the canonicalize_and_check probe (`realpath -m`
    # over a fresh exec channel). `_run_docker` calls `pool.acquire(policy)`
    # again below; the keyed pool returns the SAME cached connection, so this
    # is one TCP/SSH session, two channels.
    conn = await pool.acquire(policy)

    allowlist = effective_allowlist(policy, settings)
    restricted = effective_restricted_paths(policy, settings)
    plat = policy.platform

    # `direction` is gated by the validator above, so the else-branch is
    # exhaustive. Using if/else (not if/elif/elif) means a future fourth
    # direction added without updating the validator fails fast at the
    # branch point instead of silently leaving `argv` unbound.
    if direction == "from_container":
        # Dest on host. Parent must be reachable; file itself may not exist yet.
        dst = await canonicalize_and_check(
            conn, host_path, allowlist, must_exist=False, platform=plat,
        )
        check_not_restricted(dst, restricted, plat)
        src = f"{container}:{container_path}"
    else:  # direction == "to_container"
        # Source on host. Must exist.
        src = await canonicalize_and_check(
            conn, host_path, allowlist, must_exist=True, platform=plat,
        )
        check_not_restricted(src, restricted, plat)
        dst = f"{container}:{container_path}"
    argv = ["cp", "--", src, dst]
    return await _run_docker(ctx, host, argv, timeout=timeout)


@mcp_server.tool(tags={"low-access", "group:docker"}, version="1.0")
@audited(tier="low-access")
async def ssh_docker_compose_start(
    host: str,
    compose_file: str,
    ctx: Context,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Start existing (stopped) services in a compose project. Set ``compose_v1=True``
    for hosts still running the legacy ``docker-compose`` standalone binary.
    """
    return await _compose_project_op(
        ctx, host, compose_file, "start", compose_v1=compose_v1,
    )


@mcp_server.tool(tags={"low-access", "group:docker"}, version="1.0")
@audited(tier="low-access")
async def ssh_docker_compose_stop(
    host: str,
    compose_file: str,
    ctx: Context,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Stop services in a compose project. Keeps containers; does not remove.
    Set ``compose_v1=True`` for hosts still running the legacy ``docker-compose``
    standalone binary.
    """
    return await _compose_project_op(
        ctx, host, compose_file, "stop", compose_v1=compose_v1,
    )


@mcp_server.tool(tags={"low-access", "group:docker"}, version="1.0")
@audited(tier="low-access")
async def ssh_docker_compose_restart(
    host: str,
    compose_file: str,
    ctx: Context,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Restart services in a compose project. Set ``compose_v1=True`` for hosts
    still running the legacy ``docker-compose`` standalone binary.
    """
    return await _compose_project_op(
        ctx, host, compose_file, "restart", compose_v1=compose_v1,
    )
