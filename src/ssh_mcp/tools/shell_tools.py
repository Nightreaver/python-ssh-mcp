"""Persistent shell session tools. See services/shell_sessions.py for design.

Four tools:
  - ``ssh_shell_open``   {dangerous, group:shell}  -- register a session
  - ``ssh_shell_exec``   {dangerous, group:shell}  -- run a command; cwd persists
  - ``ssh_shell_close``  {low-access, group:shell} -- drop a session
  - ``ssh_shell_list``   {safe, read, group:shell} -- enumerate open sessions

The "session" is server-side state only -- we do not hold a real remote PTY.
Each ``ssh_shell_exec`` opens a fresh channel, prefixes the command with
``cd <cwd>``, and appends a sentinel that reports the new ``$PWD``. The
returned stdout has the sentinel line stripped.

Command allowlist (``check_command``) applies to ``ssh_shell_exec`` exactly
the same way it does to ``ssh_exec_run`` -- persistent state doesn't change
the risk model.
"""
from __future__ import annotations

from typing import Any

from fastmcp import Context

from ..app import mcp_server
from ..services.audit import audited
from ..services.exec_policy import check_command
from ..services.shell_sessions import SessionRegistry, strip_sentinel, wrap_command
from ..ssh.exec import run as exec_run
from ._context import pool_from, require_posix, resolve_host, settings_from


def _registry(ctx: Context) -> SessionRegistry:
    return ctx.lifespan_context["shell_sessions"]  # type: ignore[no-any-return]


@mcp_server.tool(tags={"dangerous", "group:shell", "persistent-session"}, version="1.0")
@audited(tier="dangerous")
async def ssh_shell_open(host: str, ctx: Context) -> dict[str, Any]:
    """Create a persistent shell session for this host. Returns a ``session_id``
    to pass to subsequent ``ssh_shell_exec`` calls. Default cwd is ``~``.

    Refuses if the host's ``persistent_session`` field in ``hosts.toml`` is
    ``false`` -- lets operators allow arbitrary exec but still deny stateful
    shells on specific hosts.
    """
    # Validate host resolves + is reachable via allow/block rules before opening.
    policy = resolve_host(ctx, host)
    require_posix(policy, tool="ssh_shell_open", reason="cwd sentinel relies on POSIX shell (`sh`, `$PWD`)")
    if not policy.persistent_session:
        raise ValueError(
            f"host {host!r} has persistent_session=false in hosts.toml; "
            f"use ssh_exec_run for stateless commands"
        )
    session = _registry(ctx).open(host)
    return {
        "session_id": session.id,
        "host": session.host,
        "cwd": session.cwd,
    }


@mcp_server.tool(tags={"dangerous", "group:shell", "persistent-session"}, version="1.0")
@audited(tier="dangerous")
async def ssh_shell_exec(
    session_id: str,
    command: str,
    ctx: Context,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Run a command inside a persistent session. The session's ``cwd`` is
    restored at the start and updated from the trailing sentinel before
    returning. ``command`` is allowlist-checked like ``ssh_exec_run``.
    """
    registry = _registry(ctx)
    session = registry.get(session_id)
    if session is None:
        raise ValueError(f"unknown session_id {session_id!r}")

    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, session.host)
    require_posix(policy, tool="ssh_shell_exec", reason="cwd sentinel relies on POSIX shell")
    check_command(command, policy, settings)
    conn = await pool.acquire(policy)

    # INC-047: `exec_scope()` owns the per-session lock that serializes
    # concurrent callers on the same session_id (INC-023) AND enables the
    # `set_cwd()` runtime assertion inside. All cwd updates must go through
    # `session.set_cwd(...)`; direct `session.cwd = ...` outside the scope
    # raises RuntimeError, so a future refactor that forgets the lock trips
    # loudly in the first test run instead of silently racing.
    async with session.exec_scope():
        wrapped = wrap_command(session, command)
        result = await exec_run(
            conn,
            wrapped,
            host=policy.hostname,
            timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
            stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
            stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        )
        payload = result.model_dump()
        clean_stdout, new_cwd = strip_sentinel(payload["stdout"])
        payload["stdout"] = clean_stdout
        if new_cwd is not None:
            session.set_cwd(new_cwd)
        registry.touch(session_id)
        payload["session_id"] = session.id
        payload["cwd"] = session.cwd
    return payload


@mcp_server.tool(tags={"low-access", "group:shell"}, version="1.0")
@audited(tier="low-access")
async def ssh_shell_close(session_id: str, ctx: Context) -> dict[str, Any]:
    """Close a persistent session. No-op if the id is already gone."""
    closed = _registry(ctx).close(session_id)
    return {"session_id": session_id, "closed": closed}


@mcp_server.tool(tags={"safe", "read", "group:shell"}, version="1.0")
async def ssh_shell_list(ctx: Context) -> dict[str, Any]:
    """List open persistent sessions with cwd + idle age."""
    registry = _registry(ctx)
    return {"sessions": registry.list(), "count": registry.size()}
