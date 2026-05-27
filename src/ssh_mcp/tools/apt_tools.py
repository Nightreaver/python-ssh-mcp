"""APT / apt-cache read tools over SSH. Safe tier -- no state mutation.

All three tools (``ssh_apt_list``, ``ssh_apt_search``, ``ssh_apt_show``)
carry the ``{"safe", "read", "group:pkg"}`` tagset and the
``@audited(tier="read")`` decorator.

Apt mutation operations (``apt-get install``, ``apt-get remove``,
``apt-get upgrade``) are intentionally NOT exposed here. They require
root and should be invoked via ``ssh_sudo_exec`` with both
``ALLOW_SUDO=true`` and ``ALLOW_DANGEROUS_TOOLS=true``.

Input safety
------------
Every user-supplied string is validated before reaching the shell.
Commands are built as ``list[str]`` and ``shlex.join`` quotes them
defensively -- there is no string interpolation of caller input.

Validators:

- ``_validate_pattern``: glob shape for ``apt list <pat>`` and
  ``apt-cache search <pat>``. Allows ``[A-Za-z0-9._*?+-]{1,128}``.
- ``validate_package_name`` / ``validate_packages``: live in
  :mod:`ssh_mcp.models.apt` -- they enforce the Debian package-name
  invariant shared by the read tier (``ssh_apt_show``) and the
  dangerous tier (install / remove / hold / unhold).

Platform gating
---------------
POSIX-only. Apt is Debian/Ubuntu/derivatives; Windows hosts raise
``PlatformNotSupported``. Non-Debian POSIX hosts (RHEL, Alpine, ...)
also raise ``PlatformNotSupported`` after a single ``command -v apt``
probe.

Output handling
---------------
``apt list --installed`` on a desktop can return ~10k packages.
``SSH_STDOUT_CAP_BYTES`` (default 1 MiB) trims runaway output -- we
parse the truncated stream and surface ``truncated=True`` so the LLM
knows to narrow with a pattern.
"""

from __future__ import annotations

import re
import shlex
import time
from typing import Literal

from fastmcp import Context

from ..app import mcp_server
from ..models.apt import (
    AptHoldsResult,
    AptListMode,
    AptListResult,
    AptMutationAction,
    AptMutationResult,
    AptSearchResult,
    AptShowResult,
    validate_package_name,
    validate_packages,
)
from ..services.apt_parser import (
    parse_apt_list,
    parse_apt_policy,
    parse_apt_search,
    parse_apt_show,
)
from ..services.audit import audited
from ..ssh.errors import PlatformNotSupported
from ..ssh.exec import run as exec_run
from ._context import pool_from, require_posix, resolve_host, settings_from

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Patterns accepted by ``apt list <pat>`` / ``apt-cache search <pat>``.
# Conservative: alphanumerics + the wildcard chars apt understands.
_PATTERN_RE = re.compile(r"^[A-Za-z0-9._*?+\-]{1,128}$")


def _validate_pattern(pattern: str) -> str:
    """Validate an apt glob pattern.

    Allows alphanumerics, dot, plus, hyphen, underscore, and the wildcard
    chars ``*`` and ``?``. Length capped at 128 to bound input shape.
    Rejects anything containing shell metacharacters.
    """
    if not pattern:
        raise ValueError("pattern must not be empty")
    if not _PATTERN_RE.match(pattern):
        raise ValueError(
            f"pattern {pattern!r} must match [A-Za-z0-9._*?+-]{{1,128}}; "
            "shell metacharacters are not allowed"
        )
    return pattern


# ---------------------------------------------------------------------------
# Probe + run helpers
# ---------------------------------------------------------------------------

# Map ssh_apt_list mode to the apt CLI flag. ``all`` uses no flag --
# apt then lists every package known to its caches.
_APT_MODE_FLAGS: dict[AptListMode, str | None] = {
    "installed": "--installed",
    "upgradable": "--upgradable",
    "all": None,
}


async def _probe_apt(ctx: Context, host: str) -> None:
    """Raise ``PlatformNotSupported`` if the host has no ``apt`` binary.

    A single fixed-argv probe (``command -v apt``) on the connection.
    Cheap (a few hundred bytes round-trip) and decisive: if apt isn't on
    PATH, neither ``apt list`` nor ``apt-cache`` will work.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    result = await exec_run(
        conn,
        shlex.join(["command", "-v", "apt"]),
        host=policy.hostname,
        timeout=float(settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=4096,
        stderr_cap=4096,
    )
    if result.exit_code != 0 or not result.stdout.strip():
        raise PlatformNotSupported(
            f"apt not available on host {policy.hostname!r}; "
            "non-Debian-family distro? (probed via `command -v apt`)"
        )


async def _run_apt(
    ctx: Context,
    host: str,
    argv: list[str],
    *,
    timeout: int | None = None,
) -> tuple[str, str, int, list[str], bool]:
    """Execute an apt argv on the remote host.

    Returns ``(stdout, stderr, exit_code, output_warnings, stdout_truncated)``.
    ``output_warnings`` (INC-058) is propagated up to every Result model
    so the LLM sees ANSI / suspicious-pattern flags raised by the
    sanitiser. ``stdout_truncated`` mirrors :attr:`ExecResult.stdout_truncated`
    so callers can surface the cap-hit flag without re-deriving it from a
    byte-length comparison (which false-positives at exactly the cap size).

    ``timeout`` (seconds) is the per-call override consumed by the mutation
    tools where the operator may need a longer window than the global
    ``SSH_COMMAND_TIMEOUT`` for a chunky ``apt-get install``. Read-tier
    callers omit it and inherit the global default.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    result = await exec_run(
        conn,
        shlex.join(argv),
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
    )
    return (
        result.stdout,
        result.stderr,
        result.exit_code,
        result.output_warnings,
        result.stdout_truncated,
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp_server.tool(tags={"safe", "read", "group:pkg"}, version="1.0")
@audited(tier="read")
async def ssh_apt_list(
    host: str,
    mode: AptListMode,
    ctx: Context,
    pattern: str | None = None,
) -> dict[str, object]:
    """List packages via ``apt list`` filtered by ``mode`` and optional ``pattern``.

    POSIX + apt only; non-Debian / Windows hosts raise ``PlatformNotSupported``.
    Output is capped at ``SSH_STDOUT_CAP_BYTES`` (default 1 MiB); see the
    ``truncated`` field. See SKILL for modes and parse shape.
    """
    if mode not in _APT_MODE_FLAGS:
        raise ValueError(f"mode {mode!r} must be one of: installed, upgradable, all")
    if pattern is not None:
        _validate_pattern(pattern)

    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_apt_list", reason="apt is POSIX-only")
    await _probe_apt(ctx, host)

    argv: list[str] = ["apt", "list"]
    flag = _APT_MODE_FLAGS[mode]
    if flag is not None:
        argv.append(flag)
    if pattern is not None:
        argv.append("--")
        argv.append(pattern)

    stdout, _stderr, _exit_code, output_warnings, stdout_truncated = await _run_apt(ctx, host, argv)
    packages = parse_apt_list(stdout)

    return AptListResult(
        host=resolved.hostname,
        mode=mode,
        packages=packages,
        total=len(packages),
        truncated=stdout_truncated,
        output_warnings=output_warnings,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:pkg"}, version="1.0")
@audited(tier="read")
async def ssh_apt_search(
    host: str,
    pattern: str,
    ctx: Context,
) -> dict[str, object]:
    """Search apt's package descriptions via ``apt-cache search <pattern>``.

    Searches names AND short descriptions -- broader than ``ssh_apt_list``.
    POSIX + apt only. See SKILL for when to choose this over ssh_apt_list.
    """
    _validate_pattern(pattern)

    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_apt_search", reason="apt-cache is POSIX-only")
    await _probe_apt(ctx, host)

    argv = ["apt-cache", "search", "--", pattern]
    stdout, _stderr, _exit_code, output_warnings, _trunc = await _run_apt(ctx, host, argv)
    results = parse_apt_search(stdout)

    return AptSearchResult(
        host=resolved.hostname,
        pattern=pattern,
        results=results,
        output_warnings=output_warnings,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:pkg"}, version="1.0")
@audited(tier="read")
async def ssh_apt_show(
    host: str,
    package: str,
    ctx: Context,
) -> dict[str, object]:
    """Combined ``apt-cache show`` + ``apt-cache policy`` for one package.

    Two probes merged into one LLM-friendly result: descriptions and
    dependencies from ``show``; installed/candidate version + repo
    sources from ``policy``. POSIX + apt only. See SKILL for the merged shape.
    """
    validate_package_name(package)

    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_apt_show", reason="apt-cache is POSIX-only")
    await _probe_apt(ctx, host)

    show_argv = ["apt-cache", "show", "--", package]
    policy_argv = ["apt-cache", "policy", "--", package]

    show_stdout, _show_stderr, _show_exit, show_warnings, _show_trunc = await _run_apt(ctx, host, show_argv)
    policy_stdout, _pol_stderr, _pol_exit, policy_warnings, _pol_trunc = await _run_apt(
        ctx, host, policy_argv
    )

    show_parsed = parse_apt_show(show_stdout)
    policy_parsed = parse_apt_policy(policy_stdout)

    # Merge dedup the warnings -- "ANSI escape sequences stripped" should
    # appear once even if both probes produced it.
    merged_warnings = list(dict.fromkeys([*show_warnings, *policy_warnings]))

    return AptShowResult(
        host=resolved.hostname,
        package=package,
        installed_version=policy_parsed["installed_version"],
        candidate_version=policy_parsed["candidate_version"],
        repos=policy_parsed["repos"],
        description=show_parsed["description"],
        depends=show_parsed["depends"],
        recommends=show_parsed["recommends"],
        suggests=show_parsed["suggests"],
        conflicts=show_parsed["conflicts"],
        breaks=show_parsed["breaks"],
        replaces=show_parsed["replaces"],
        output_warnings=merged_warnings,
    ).model_dump()


# ---------------------------------------------------------------------------
# Mutation tools (dangerous tier)
#
# Five tools sharing one ``_run_apt_mutation`` dispatcher, in the same shape
# as ``systemctl_tools._run_unit_action`` (C1). All carry the
# ``{"dangerous", "group:pkg"}`` tagset and ``@audited(tier="dangerous")``.
# Sudo is NOT auto-prepended -- matching the read-tier convention and the
# systemctl tier. Each tool builds its argv list-style and ``shlex.join``
# quotes the tokens, so package names can never reach a shell as anything
# but single literal tokens. Non-zero exit codes are returned as data; only
# transport failures escape the tool.
# ---------------------------------------------------------------------------


# Verbs accepted by the shared mutation runner. Derived from the
# ``AptMutationAction`` Literal so the result-model literal is the single
# source of truth -- mypy already enforces the per-call-site verb at compile
# time; this frozenset is the runtime tripwire for any non-typed caller.
_MUTATION_ACTIONS: frozenset[str] = frozenset(
    {"install", "upgrade", "remove", "purge", "autoremove", "hold", "unhold"}
)

# Mutation verbs accepted by ``ssh_apt_mark``. The read-only ``showhold``
# verb has its own dedicated read-tier tool (``ssh_apt_show_holds``) so
# this literal stays mutation-only and the tool's tag set stays consistent
# with its actual blast radius.
AptMarkAction = Literal["hold", "unhold"]


async def _run_apt_mutation(
    ctx: Context,
    host: str,
    *,
    action: AptMutationAction,
    argv: list[str],
    packages: list[str],
    timeout: int | None,
) -> dict[str, object]:
    """Validate ``action``, run ``argv`` on ``host``, and return an
    ``AptMutationResult`` as a plain dict.

    Shared body for the four mutation tools whose result shape is
    ``AptMutationResult`` (``install`` / ``upgrade`` / ``remove`` / ``purge`` /
    ``autoremove`` / ``hold`` / ``unhold``). ``ssh_apt_mark(action="showhold")``
    has its own ``AptHoldsResult`` shape and bypasses this helper.
    """
    if action not in _MUTATION_ACTIONS:
        # Defensive: caller bug, not user input. Surface as ValueError so
        # tests catch a typo before it reaches the wire.
        raise ValueError(f"unsupported apt mutation action: {action!r}")

    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_apt_mutation", reason="apt is POSIX-only")
    await _probe_apt(ctx, host)

    start = time.monotonic()
    stdout, stderr, exit_code, output_warnings, stdout_truncated = await _run_apt(
        ctx,
        host,
        argv,
        timeout=timeout,
    )
    duration_ms = int((time.monotonic() - start) * 1000)

    return AptMutationResult(
        host=resolved.hostname,
        action=action,
        packages=packages,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        stdout_truncated=stdout_truncated,
        output_warnings=output_warnings,
    ).model_dump()


@mcp_server.tool(tags={"dangerous", "group:pkg"}, version="1.0")
@audited(tier="dangerous")
async def ssh_apt_install(
    host: str,
    packages: list[str],
    ctx: Context,
    *,
    update_first: bool = False,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-get -y install -- <packages...>`` on the host. Requires root
    (use a sudoers-enabled SSH account or ``ssh_sudo_exec``). Optionally runs
    ``apt-get update`` first. See SKILL for details."""
    validate_packages(packages, action="install")
    if update_first:
        # Probe BEFORE attempting ``apt-get update`` so non-Debian hosts get
        # a clean ``PlatformNotSupported`` instead of a raw ``apt-get: not
        # found`` exec failure. ``_run_apt_mutation`` re-probes shortly after
        # -- the duplicate is one cheap ``command -v apt`` exec on the same
        # cached connection and avoids carrying probe-state across the call.
        resolved = resolve_host(ctx, host)
        require_posix(resolved, tool="ssh_apt_install", reason="apt is POSIX-only")
        await _probe_apt(ctx, host)
        # Run ``apt-get update`` as a discrete exec so its exit / stderr are
        # observable in the audit stream. The result we surface is the
        # install's; if update failed, install will surface the cascade.
        await _run_apt(ctx, host, ["apt-get", "update"], timeout=timeout)
    argv = ["apt-get", "-y", "install", "--", *packages]
    return await _run_apt_mutation(
        ctx,
        host,
        action="install",
        argv=argv,
        packages=packages,
        timeout=timeout,
    )


@mcp_server.tool(tags={"dangerous", "group:pkg"}, version="1.0")
@audited(tier="dangerous")
async def ssh_apt_upgrade(
    host: str,
    ctx: Context,
    *,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-get -y upgrade`` on the host. Requires root. Caller should
    typically run ``ssh_apt_install([], update_first=True)`` or ``ssh_exec_run
    'apt-get update'`` first -- see SKILL for the upgrade workflow and why
    this tool deliberately does NOT cover ``do-release-upgrade``."""
    argv = ["apt-get", "-y", "upgrade"]
    return await _run_apt_mutation(
        ctx,
        host,
        action="upgrade",
        argv=argv,
        packages=[],
        timeout=timeout,
    )


@mcp_server.tool(tags={"dangerous", "group:pkg"}, version="1.0")
@audited(tier="dangerous")
async def ssh_apt_remove(
    host: str,
    packages: list[str],
    ctx: Context,
    *,
    purge: bool = False,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-get -y remove -- <packages...>`` (or ``purge`` when
    ``purge=True``) on the host. Requires root. ``purge`` also removes the
    package's config files. See SKILL for details."""
    validate_packages(packages, action="purge" if purge else "remove")
    verb = "purge" if purge else "remove"
    action: AptMutationAction = "purge" if purge else "remove"
    argv = ["apt-get", "-y", verb, "--", *packages]
    return await _run_apt_mutation(
        ctx,
        host,
        action=action,
        argv=argv,
        packages=packages,
        timeout=timeout,
    )


@mcp_server.tool(tags={"dangerous", "group:pkg"}, version="1.0")
@audited(tier="dangerous")
async def ssh_apt_autoremove(
    host: str,
    ctx: Context,
    *,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-get -y autoremove`` on the host. Requires root. Removes
    packages installed as dependencies that are no longer needed. See SKILL
    for details."""
    argv = ["apt-get", "-y", "autoremove"]
    return await _run_apt_mutation(
        ctx,
        host,
        action="autoremove",
        argv=argv,
        packages=[],
        timeout=timeout,
    )


@mcp_server.tool(tags={"safe", "read", "group:pkg"}, version="1.0")
@audited(tier="read")
async def ssh_apt_show_holds(
    host: str,
    ctx: Context,
    *,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-mark showhold`` on the host. Read-only -- no root required.

    Returns ``AptHoldsResult`` with a parsed ``held`` list so callers don't
    re-split stdout. See SKILL for details."""
    resolved = resolve_host(ctx, host)
    require_posix(resolved, tool="ssh_apt_show_holds", reason="apt-mark is POSIX-only")
    await _probe_apt(ctx, host)

    start = time.monotonic()
    stdout, stderr, exit_code, output_warnings, stdout_truncated = await _run_apt(
        ctx,
        host,
        ["apt-mark", "showhold"],
        timeout=timeout,
    )
    duration_ms = int((time.monotonic() - start) * 1000)
    held = [line.strip() for line in stdout.splitlines() if line.strip()]
    return AptHoldsResult(
        host=resolved.hostname,
        held=held,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout_truncated=stdout_truncated,
        output_warnings=output_warnings,
    ).model_dump()


@mcp_server.tool(tags={"dangerous", "group:pkg"}, version="1.0")
@audited(tier="dangerous")
async def ssh_apt_mark(
    host: str,
    action: AptMarkAction,
    packages: list[str],
    ctx: Context,
    *,
    timeout: int | None = None,
) -> dict[str, object]:
    """Run ``apt-mark hold|unhold -- <packages...>`` on the host. Requires
    root. Use ``ssh_apt_show_holds`` for the read-only ``showhold`` variant.

    ``action`` is ``hold`` or ``unhold``; ``packages`` must be non-empty.
    See SKILL for details."""
    validate_packages(packages, action=action)
    argv = ["apt-mark", action, "--", *packages]
    return await _run_apt_mutation(
        ctx,
        host,
        action=action,
        argv=argv,
        packages=packages,
        timeout=timeout,
    )
