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
- ``_validate_package_name``: Debian package-name shape. Lowercase
  only by convention; matches ``^[a-z0-9][a-z0-9.+-]{0,127}$``.

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

from fastmcp import Context

from ..app import mcp_server
from ..models.apt import (
    AptListMode,
    AptListResult,
    AptSearchResult,
    AptShowResult,
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

# Debian package-name shape (subset of policy-manual §5.6.7). Lowercase
# only by convention -- apt is case-insensitive on lookup but accepting
# lowercase keeps the regex tight and the audit trail unambiguous.
_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.+\-]{0,127}$")


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


def _validate_package_name(name: str) -> str:
    """Validate a Debian package name.

    Returns the validated name unchanged. Rejects empty strings, names
    containing uppercase, slashes, or shell metacharacters.
    """
    if not name:
        raise ValueError("package name must not be empty")
    if not _PACKAGE_NAME_RE.match(name):
        raise ValueError(
            f"package name {name!r} must match [a-z0-9][a-z0-9.+-]{{0,127}} "
            "(Debian package name shape, lowercase only)"
        )
    return name


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
) -> tuple[str, str, int, list[str], bool]:
    """Execute an apt argv on the remote host.

    Returns ``(stdout, stderr, exit_code, output_warnings, stdout_truncated)``.
    ``output_warnings`` (INC-058) is propagated up to every Result model
    so the LLM sees ANSI / suspicious-pattern flags raised by the
    sanitiser. ``stdout_truncated`` mirrors :attr:`ExecResult.stdout_truncated`
    so callers can surface the cap-hit flag without re-deriving it from a
    byte-length comparison (which false-positives at exactly the cap size).
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
        timeout=float(settings.SSH_COMMAND_TIMEOUT),
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
    _validate_package_name(package)

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
