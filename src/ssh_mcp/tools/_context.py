"""Shared helpers for pulling pool + HostPolicy from the FastMCP Context.

The FastMCP ``Context`` type surfaces ``lifespan_context`` as a plain ``dict``.
We populate it in [lifespan.py](../lifespan.py) with a fixed set of keys. To
get mypy narrowing + IDE completion on the accessors -- and to drop the
``# type: ignore[no-any-return]`` that every accessor used to carry -- we
define the shape once as a ``TypedDict`` and cast the runtime dict into it.

INC-042: prior version had ``Any`` in-and-out; mypy couldn't help the caller
when they typoed a key, and refactors that added/removed keys only surfaced
at runtime.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict, cast

from ..services.host_policy import resolve as _resolve_host_policy
from ..ssh.errors import PlatformNotSupported

if TYPE_CHECKING:
    from fastmcp import Context

    from ..config import Settings
    from ..models.policy import HostPolicy
    from ..services.hooks import HookRegistry
    from ..services.shell_sessions import SessionRegistry
    from ..ssh.known_hosts import KnownHosts
    from ..ssh.pool import ConnectionPool


class LifespanContext(TypedDict):
    """Exact shape of ``ctx.lifespan_context`` throughout the ssh-mcp server.

    Keys are populated in ``ssh_lifespan`` (src/ssh_mcp/lifespan.py) before
    any tool runs. Tests build a stub Context whose ``lifespan_context`` must
    satisfy this TypedDict to pass mypy -- matches the real shape and catches
    drift. Add new entries here FIRST, then in the lifespan.

    Rationale for TypedDict over Protocol: we don't want duck typing, we want
    a fixed set of keys; TypedDict narrows to the exact value type per key on
    lookup, which is what the accessors below consume.
    """

    pool: ConnectionPool
    settings: Settings
    hosts: dict[str, HostPolicy]
    host_allowlist: list[str]
    known_hosts: KnownHosts
    shell_sessions: SessionRegistry
    hooks: HookRegistry


def _lifespan(ctx: Context) -> LifespanContext:
    """Narrow ``ctx.lifespan_context`` to our ``LifespanContext`` shape.

    FastMCP types it as ``dict[str, Any]``; we know it's our TypedDict after
    lifespan setup. One ``cast`` here beats a ``# type: ignore`` on every
    accessor below.
    """
    return cast("LifespanContext", ctx.lifespan_context)


def pool_from(ctx: Context) -> ConnectionPool:
    return _lifespan(ctx)["pool"]


def settings_from(ctx: Context) -> Settings:
    return _lifespan(ctx)["settings"]


def known_hosts_from(ctx: Context) -> KnownHosts:
    return _lifespan(ctx)["known_hosts"]


def hosts_from(ctx: Context) -> dict[str, HostPolicy]:
    """Return the live host registry dict. Callers that mutate it (e.g.
    ``ssh_host_reload``) get a direct reference to the in-memory dict so
    clear()+update() preserves object identity for other live references.
    """
    return _lifespan(ctx)["hosts"]


def resolve_host(ctx: Context, host: str) -> HostPolicy:
    """Resolve `host` via services/host_policy.resolve (blocklist + allowlist)."""
    hosts = _lifespan(ctx)["hosts"]
    return _resolve_host_policy(host, hosts, settings_from(ctx))


def require_posix(policy: HostPolicy, *, tool: str, reason: str) -> None:
    """Raise PlatformNotSupported if the target host is Windows.

    Use in tools that bake in POSIX assumptions (shell wrappers, ``/proc``
    reads, ``realpath`` probes, ``sudo``). The ``reason`` argument is the
    short "what's missing" string the error message surfaces to the LLM,
    e.g. ``"no /proc on Windows"`` or ``"relies on POSIX shell (sh)"``.
    """
    if policy.platform == "windows":
        raise PlatformNotSupported(
            f"{tool} is not available on host {policy.hostname!r} "
            f"(platform=windows): {reason}. "
            f"Use an SFTP-backed tool instead (ssh_sftp_*, ssh_upload, "
            f"ssh_edit, ssh_cp, ssh_mv, ssh_mkdir, ssh_delete)."
        )
