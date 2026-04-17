"""Dangerous-tier docker tools. Tagged ``{"dangerous", "group:docker"}``.

Arbitrary code inside containers (`exec`), state creation (`run`, `pull`,
`compose_up/pull`), destructive ops (`rm`, `rmi`, `prune`, `compose_down`).
Hidden unless ``ALLOW_DANGEROUS_TOOLS=true``.

INC-043: extracted from the original monolithic `docker_tools.py`.
"""
from __future__ import annotations

from typing import Any, Literal

from fastmcp import Context

from ...app import mcp_server
from ...services.audit import audited
from ...services.exec_policy import check_command
from ...services.path_policy import (
    canonicalize_and_check,
    effective_allowlist,
)
from .._context import pool_from, resolve_host, settings_from
from ._helpers import (
    _compose_project_op,
    _reject_escalation_flags,
    _run_docker,
    _validate_name,
)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_exec(
    host: str,
    container: str,
    command: str,
    ctx: Context,
    timeout: int | None = None,
    interactive: bool = False,
) -> dict[str, Any]:
    """Run a command inside a container. Command is allowlist-checked like
    ``ssh_exec_run``. The container name is argv-validated.
    """
    _validate_name("container", container)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    check_command(command, policy, settings)
    argv = ["exec"]
    if interactive:
        argv.append("-i")
    argv.extend(["--", container, "sh", "-c", command])
    return await _run_docker(ctx, host, argv, timeout=timeout)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_run(
    host: str,
    image: str,
    ctx: Context,
    args: list[str] | None = None,
    name: str | None = None,
    remove: bool = True,
    detached: bool = False,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Create and start a new container from an image. ``args`` is passed after
    the image name. ``remove=True`` sets ``--rm``. Use sparingly -- for long-
    running services prefer compose_up.

    **Capability-escalation surface:** ``args`` accepts any ``docker run``
    flag. Flags that grant the container root on the host (``--privileged``,
    ``--cap-add``, ``--security-opt``, ``--device``, ``--group-add``), flags
    that share host or another container's namespace (``--pid=host``,
    ``--network=host``, ``--pid=container:<id>``, both ``=`` and two-token
    forms), and host-root bind mounts in either ``-v /:`` or
    ``--mount source=/`` syntax are **rejected by default** even under
    ``ALLOW_DANGEROUS_TOOLS``. Set ``ALLOW_DOCKER_PRIVILEGED=true`` to
    permit them; that bypass is explicit and grep-able in env and audit logs.
    """
    _validate_name("image", image.split(":", 1)[0])
    if name is not None:
        _validate_name("container", name)
    settings = settings_from(ctx)
    if args and not settings.ALLOW_DOCKER_PRIVILEGED:
        _reject_escalation_flags(args)
    argv = ["run"]
    if remove:
        argv.append("--rm")
    if detached:
        argv.append("-d")
    if name:
        argv.extend(["--name", name])
    argv.append("--")
    argv.append(image)
    if args:
        argv.extend(args)
    return await _run_docker(ctx, host, argv, timeout=timeout)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_pull(
    host: str,
    image: str,
    ctx: Context,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Pull an image. Respects SSH_COMMAND_TIMEOUT; bump ``timeout`` for slow networks."""
    _validate_name("image", image.split(":", 1)[0])
    return await _run_docker(ctx, host, ["pull", "--", image], timeout=timeout)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_rm(
    host: str,
    container: str,
    ctx: Context,
    force: bool = False,
) -> dict[str, Any]:
    """Remove a container. ``force=True`` kills running containers first."""
    _validate_name("container", container)
    argv = ["rm"]
    if force:
        argv.append("-f")
    argv.extend(["--", container])
    return await _run_docker(ctx, host, argv)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_rmi(
    host: str,
    image: str,
    ctx: Context,
    force: bool = False,
) -> dict[str, Any]:
    """Remove an image. Force-delete with ``force=True`` (removes dependents)."""
    _validate_name("image", image.split(":", 1)[0])
    argv = ["rmi"]
    if force:
        argv.append("-f")
    argv.extend(["--", image])
    return await _run_docker(ctx, host, argv)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_prune(
    host: str,
    ctx: Context,
    scope: Literal["container", "image", "volume", "network", "system"] = "container",
    all_: bool = False,
) -> dict[str, Any]:
    """Prune unused docker resources. ``all_=True`` is more aggressive (e.g.
    ``image prune --all`` removes all unreferenced images, not just dangling).
    Always passes ``-f`` to skip the interactive prompt.
    """
    argv = [scope, "prune", "-f"]
    if all_ and scope in ("image", "system"):
        argv.append("--all")
    return await _run_docker(ctx, host, argv)


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_compose_up(
    host: str,
    compose_file: str,
    ctx: Context,
    detached: bool = True,
    build: bool = False,
    timeout: int | None = None,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Bring up a compose project. Defaults to ``-d`` (detached). Set
    ``compose_v1=True`` for hosts still running the legacy ``docker-compose``
    standalone binary.
    """
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn, compose_file, effective_allowlist(policy, settings),
        must_exist=True, platform=policy.platform,
    )
    argv = ["-f", canonical, "up"]
    if detached:
        argv.append("-d")
    if build:
        argv.append("--build")
    return await _run_docker(
        ctx, host, argv, compose=True, compose_v1=compose_v1, timeout=timeout,
    )


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_compose_down(
    host: str,
    compose_file: str,
    ctx: Context,
    volumes: bool = False,
    timeout: int | None = None,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Tear down a compose project. ``volumes=True`` also removes named volumes
    (**destructive** -- data loss). Set ``compose_v1=True`` for hosts still
    running the legacy ``docker-compose`` standalone binary.
    """
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn, compose_file, effective_allowlist(policy, settings),
        must_exist=True, platform=policy.platform,
    )
    argv = ["-f", canonical, "down"]
    if volumes:
        argv.append("-v")
    return await _run_docker(
        ctx, host, argv, compose=True, compose_v1=compose_v1, timeout=timeout,
    )


@mcp_server.tool(tags={"dangerous", "group:docker"}, version="1.0")
@audited(tier="dangerous")
async def ssh_docker_compose_pull(
    host: str,
    compose_file: str,
    ctx: Context,
    timeout: int | None = None,
    compose_v1: bool = False,
) -> dict[str, Any]:
    """Pull images for a compose project without starting services. Set
    ``compose_v1=True`` for hosts still running the legacy ``docker-compose``
    standalone binary.
    """
    return await _compose_project_op(
        ctx, host, compose_file, "pull", compose_v1=compose_v1, timeout=timeout,
    )
