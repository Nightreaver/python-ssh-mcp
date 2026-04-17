"""Systemctl / journalctl read tools over SSH. Safe tier — no mutations.

All tools are tagged ``{"safe", "read", "group:systemctl"}`` and work
without sudo on any stock Linux host running systemd.

Lifecycle operations (start / stop / restart / reload / enable / disable /
daemon-reload) intentionally have no dedicated tools here. They require root
and should be invoked via ``ssh_sudo_exec systemctl <cmd>`` with
``ALLOW_SUDO=true`` + ``ALLOW_DANGEROUS_TOOLS=true``. The operator runbook at
``runbooks/ssh-systemd-diagnostics/SKILL.md`` has worked examples.

Input safety
------------
All user-supplied strings are validated before they touch any shell command.
Commands are built as ``list[str]`` and passed through ``shlex.join`` —
there is no string interpolation of caller input into shell commands.

Validation helpers
~~~~~~~~~~~~~~~~~~
- ``_validate_systemd_unit_name`` — units / service names.
- ``_validate_pattern`` — glob patterns for ``list-units``.
- ``_validate_property_names`` — property name list for ``systemctl show``.
- ``_validate_time_anchor`` — ``--since`` / ``--until`` arguments.
- ``_validate_grep`` — ``journalctl --grep`` argument.
"""

from __future__ import annotations

import re
import shlex
from typing import cast

from fastmcp import Context

from ..app import mcp_server
from ..models.systemctl import (
    IsActiveState,
    IsEnabledState,
    JournalctlResult,
    SystemctlCatResult,
    SystemctlIsActiveResult,
    SystemctlIsEnabledResult,
    SystemctlIsFailedResult,
    SystemctlListUnitsResult,
    SystemctlShowResult,
    SystemctlStatusResult,
    SystemctlUnitEntry,
)
from ..services.audit import audited
from ..ssh.exec import run as exec_run
from ._context import pool_from, resolve_host, settings_from

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

# Known unit-type suffixes from systemd.unit(5).
_UNIT_SUFFIXES = frozenset(
    {
        "service",
        "socket",
        "target",
        "timer",
        "path",
        "mount",
        "automount",
        "swap",
        "slice",
        "scope",
        "device",
    }
)

# Base name characters (no slash, no metachar). Dots are allowed inside names
# (e.g. proc-sys-fs-binfmt_misc.automount) — suffix validation is done
# separately by inspecting the last dot-delimited component.
_UNIT_BASE_RE = re.compile(r"^[A-Za-z0-9@._\-]+$")

# Shell metacharacters we always deny, regardless of context.
_SHELL_METACHARS = frozenset(";& |`$\n\r\x00()<>")


def _validate_systemd_unit_name(name: str) -> str:
    """Validate a systemd unit name.

    Accepts bare names (e.g. ``nginx``) and names with a known unit-type
    suffix (e.g. ``nginx.service``, ``foo@bar.socket``). Rejects any
    string containing shell metacharacters, slashes, empty strings, or
    characters outside the documented systemd naming alphabet.

    Returns the validated name unchanged.
    """
    if not name:
        raise ValueError("unit name must not be empty")
    if any(c in name for c in _SHELL_METACHARS):
        raise ValueError(
            f"unit name {name!r} contains shell metacharacters; "
            "use only [A-Za-z0-9@._-] with an optional unit-type suffix"
        )
    if "/" in name:
        raise ValueError(f"unit name {name!r} contains a slash; unit names must not be paths")
    if not _UNIT_BASE_RE.match(name):
        raise ValueError(
            f"invalid unit name {name!r}: must match "
            r"[A-Za-z0-9@._-]+(.<type>)? where <type> is one of "
            "service|socket|target|timer|path|mount|automount|swap|slice|scope|device"
        )
    # If the name contains a dot, the last component must be a known unit type.
    # This rejects names like "nginx.notaunit" while allowing bare names ("nginx")
    # and names with internal dots ("proc-sys-fs-binfmt_misc.automount").
    if "." in name:
        suffix = name.rsplit(".", 1)[1]
        if suffix not in _UNIT_SUFFIXES:
            raise ValueError(
                f"unit name {name!r} has unknown suffix {suffix!r}; "
                f"known unit types: {', '.join(sorted(_UNIT_SUFFIXES))}"
            )
    return name


def _validate_pattern(pattern: str) -> str:
    """Validate a glob pattern for ``systemctl list-units``.

    Allows the same characters as unit names plus ``*`` and ``?`` wildcards.
    Rejects shell metacharacters.
    """
    if not pattern:
        raise ValueError("pattern must not be empty")
    if any(c in pattern for c in _SHELL_METACHARS):
        raise ValueError(f"pattern {pattern!r} contains shell metacharacters")
    if "/" in pattern:
        raise ValueError(f"pattern {pattern!r} contains a slash; patterns must not be paths")
    # Allow everything that unit names allow plus wildcards.
    allowed = re.compile(r"^[A-Za-z0-9@._\-\*\?]+$")
    if not allowed.match(pattern):
        raise ValueError(f"pattern {pattern!r} contains characters not allowed in unit glob patterns")
    return pattern


def _validate_property_names(props: list[str]) -> list[str]:
    """Validate a list of ``systemctl show --property`` names.

    Each name must start with an uppercase letter and contain only letters
    and digits (e.g. ``ActiveState``, ``ExecMainPID``, ``NRestarts``).
    """
    for name in props:
        if not _PROP_RE.match(name):
            raise ValueError(
                f"property name {name!r} is invalid; must match [A-Z][A-Za-z0-9]* "
                "(e.g. ActiveState, ExecMainPID)"
            )
    return props


# Time-anchor formats accepted by journalctl --since / --until.
# Matches:
#   - relative: "10min", "2h", "24h30m", "1s", "yesterday", "today",
#     "now" — journalctl uses its own time parser that accepts more than
#     Go's time.ParseDuration.
#   - Unix epoch: "1710000000" or "1710000000.123456"
#   - RFC3339 / ISO datetime: "2026-04-16T12:00:00Z" / "+HH:MM" / fractional
#   - Short dates: "2026-04-16" / "2026-04-16 12:00:00"
#   - Relative keywords: "yesterday", "today", "now", "tomorrow"
# Unlike docker's time regex (Go's time.ParseDuration — s/m/h only), journalctl
# delegates to systemd's own systemd.time(7) parser which accepts s/m/h/d/w/M/y.
# We allow the full systemd unit set here.
_JOURNALCTL_TIME_RE = re.compile(
    r"^(?:"
    r"\d+(?:\.\d+)?"  # epoch (int or float)
    r"|(?:\d+[smhdwMy])+"  # relative (e.g. 10m, 2h, 30d, 1w, 6M, 1y, 24h30m)
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # ISO datetime
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"  # optional fractional + tz
    r"|\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}(?::\d{2})?)?"  # short date (optional time)
    r"|yesterday|today|now|tomorrow"
    r")$",
)


def _validate_time_anchor(value: str, *, param: str) -> str:
    """Validate a journalctl time anchor (``--since`` / ``--until``).

    Accepts relative durations, Unix epoch, RFC3339, short dates, and the
    special keywords ``yesterday``, ``today``, ``now``, ``tomorrow``.
    Raises ``ValueError`` with the parameter name in the message.
    """
    if not value:
        raise ValueError(f"{param} must not be empty")
    if not _JOURNALCTL_TIME_RE.match(value):
        raise ValueError(
            f"`{param}` must be relative (10m, 2h, 30d, 1w, 6M, 1y), epoch (1710000000), "
            f"RFC3339 (2026-04-16T12:00:00Z), short date (2026-04-16), "
            f"or a keyword (yesterday, today, now, tomorrow); got {value!r}"
        )
    return value


# Property name pattern: PascalCase identifiers (e.g. ActiveState, ExecMainPID).
_PROP_RE = re.compile(r"^[A-Z][A-Za-z0-9]*$")

# Conservative grep pattern: alphanumerics plus a modest set of safe chars.
_GREP_RE = re.compile(r"^[A-Za-z0-9 _\-.:/@]{1,200}$")


def _validate_grep(grep: str) -> str:
    """Validate a ``journalctl --grep`` argument.

    Accepts letters, digits, spaces, and a small set of punctuation safe for
    log-matching. Rejects shell metacharacters and strings longer than 200
    characters.
    """
    if not grep:
        raise ValueError("grep must not be empty")
    if not _GREP_RE.match(grep):
        raise ValueError(
            f"grep {grep!r} must match [A-Za-z0-9 _\\-.:/@]{{1,200}}; shell metacharacters are not allowed"
        )
    return grep


# Recognised ``systemctl is-active`` state words.
_IS_ACTIVE_STATES: frozenset[str] = frozenset(
    {
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
    }
)

# Recognised ``systemctl is-enabled`` state words.
_IS_ENABLED_STATES: frozenset[str] = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "linked",
        "linked-runtime",
        "alias",
        "masked",
        "masked-runtime",
        "static",
        "indirect",
        "disabled",
        "generated",
        "transient",
        "bad",
        "not-found",
    }
)


# ---------------------------------------------------------------------------
# Shared runner
# ---------------------------------------------------------------------------


async def _run_systemctl(
    ctx: Context,
    host: str,
    argv: list[str],
    *,
    timeout: int | None = None,
) -> tuple[str, str, int]:
    """Execute an argv list on the remote host and return (stdout, stderr, exit_code)."""
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    result = await exec_run(
        conn,
        shlex.join(argv),
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
    )
    return result.stdout, result.stderr, result.exit_code


# ---------------------------------------------------------------------------
# Parse helpers
# ---------------------------------------------------------------------------


def _parse_active_state(stdout: str) -> str | None:
    """Extract the state token from the ``Active:`` line in ``systemctl status`` output.

    Returns the first whitespace-delimited token on the ``Active:`` line
    (e.g. ``"active"``, ``"inactive"``, ``"failed"``), or ``None`` when the
    line is absent. The parenthesised qualifier (e.g. ``(running)``) is not
    included.
    """
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Active:"):
            rest = stripped[len("Active:") :].strip()
            # The line looks like: "active (running) since ..."
            # We want only the first token.
            token = rest.split()[0] if rest.split() else None
            return token
    return None


def _parse_is_active_state(stdout: str, exit_code: int) -> IsActiveState:
    """Map ``systemctl is-active`` stdout + exit code to an ``IsActiveState``.

    ``systemctl is-active`` prints exactly one word. Exit code 4 means "no
    such unit"; we normalise that to ``"unknown"`` regardless of stdout.
    For all other exit codes, if the word is not a recognised state we also
    fall back to ``"unknown"``.
    """
    if exit_code == 4:
        return "unknown"
    word = stdout.strip()
    if word in _IS_ACTIVE_STATES:
        return cast(IsActiveState, word)
    return "unknown"


def _parse_is_enabled_state(stdout: str) -> IsEnabledState:
    """Map ``systemctl is-enabled`` stdout to an ``IsEnabledState``.

    The exit code carries no information beyond what the stdout word already
    encodes (enabled→0, disabled→1, etc.), so it is not accepted here.
    Unrecognised words fall back to ``"unknown"``.
    """
    word = stdout.strip()
    if word in _IS_ENABLED_STATES:
        return cast(IsEnabledState, word)
    return "unknown"


def _parse_show_properties(stdout: str) -> dict[str, str]:
    """Parse ``systemctl show`` output into a ``{key: value}`` dict.

    Each line has the form ``Key=value``. Multi-line values (not standard for
    ``systemctl show``) are handled by last-write-wins: if the same key appears
    more than once, the last value is kept. Empty values (``Key=``) are
    retained as empty strings.
    """
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            result[key] = value  # last-write-wins for duplicate keys
    return result


def _parse_list_units(stdout: str) -> list[SystemctlUnitEntry]:
    """Parse ``systemctl list-units --no-legend`` text into ``SystemctlUnitEntry`` rows.

    The columns are fixed-width fields: UNIT, LOAD, ACTIVE, SUB, DESCRIPTION.
    The first four are single words; DESCRIPTION is the remainder of the line.
    We split on whitespace with a max-split of 4 to avoid fragmenting the
    description.
    """
    entries: list[SystemctlUnitEntry] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # ``systemctl list-units`` can prefix continuation/legend lines with
        # whitespace-only or bullet-like markers -- skip them.
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        load = parts[1]
        active = parts[2]
        sub = parts[3]
        description = parts[4].strip() if len(parts) > 4 else ""
        entries.append(
            SystemctlUnitEntry(
                unit=unit,
                load=load,
                active=active,
                sub=sub,
                description=description,
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_status(
    host: str,
    unit: str,
    ctx: Context,
) -> dict[str, object]:
    """Run ``systemctl status <unit> --no-pager`` and return structured output.

    Exit code 3 (unit inactive/dead) is treated as data, not an error.
    ``active_state`` is parsed from the ``Active:`` line; it is ``None``
    when the line is absent (e.g. unit not found).

    Returns ``{host, unit, stdout, exit_code, active_state}``.
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "status", "--no-pager", "--", unit]
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    active_state = _parse_active_state(stdout)
    policy = resolve_host(ctx, host)
    return SystemctlStatusResult(
        host=policy.hostname,
        unit=unit,
        stdout=stdout,
        exit_code=exit_code,
        active_state=active_state,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_is_active(
    host: str,
    unit: str,
    ctx: Context,
) -> dict[str, object]:
    """Run ``systemctl is-active <unit>``.

    Non-zero exit is normal (unit inactive or failed). Returns
    ``{host, unit, state, exit_code}`` where ``state`` is one of
    ``active | inactive | failed | activating | deactivating | reloading | unknown``.
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "is-active", "--", unit]
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    state = _parse_is_active_state(stdout, exit_code)
    policy = resolve_host(ctx, host)
    return SystemctlIsActiveResult(
        host=policy.hostname,
        unit=unit,
        state=state,
        exit_code=exit_code,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_is_enabled(
    host: str,
    unit: str,
    ctx: Context,
) -> dict[str, object]:
    """Run ``systemctl is-enabled <unit>``.

    Returns ``{host, unit, state, exit_code}`` where ``state`` is one of
    the standard ``systemctl is-enabled`` states (enabled, disabled, masked,
    static, indirect, etc.) or ``unknown`` for unrecognised output.
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "is-enabled", "--", unit]
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    state = _parse_is_enabled_state(stdout)
    policy = resolve_host(ctx, host)
    return SystemctlIsEnabledResult(
        host=policy.hostname,
        unit=unit,
        state=state,
        exit_code=exit_code,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_is_failed(
    host: str,
    unit: str,
    ctx: Context,
) -> dict[str, object]:
    """Run ``systemctl is-failed <unit>``.

    Returns ``{host, unit, failed, state, exit_code}``. ``failed`` is ``True``
    when the exit code is 0 (i.e. the unit IS in a failed state — consistent
    with what ``systemctl is-failed`` signals).
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "is-failed", "--", unit]
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    state = stdout.strip()
    failed = exit_code == 0
    policy = resolve_host(ctx, host)
    return SystemctlIsFailedResult(
        host=policy.hostname,
        unit=unit,
        failed=failed,
        state=state,
        exit_code=exit_code,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_list_units(
    host: str,
    ctx: Context,
    pattern: str | None = None,
    state: str | None = None,
    unit_type: str = "service",
) -> dict[str, object]:
    """Run ``systemctl list-units`` and return parsed rows.

    Args:
        host: Target host.
        pattern: Optional glob filter (e.g. ``"nginx*"``).
        state: Optional ``--state`` filter (e.g. ``"failed"``, ``"running"``).
        unit_type: Unit type passed to ``--type`` (default ``"service"``).

    Returns ``{host, units, exit_code}`` where ``units`` is a list of
    ``{unit, load, active, sub, description}`` dicts.

    Simple text parse — does not gate on systemd version.
    """
    if pattern is not None:
        _validate_pattern(pattern)
    # unit_type comes from us but we still validate it to avoid surprises.
    _validate_pattern(unit_type)
    if state is not None:
        # State values are simple words; reject metacharacters.
        if any(c in state for c in _SHELL_METACHARS) or "/" in state:
            raise ValueError(f"state {state!r} contains invalid characters")
        if not re.match(r"^[A-Za-z0-9\-]+$", state):
            raise ValueError(f"state {state!r} must match [A-Za-z0-9-]+ (e.g. 'failed', 'running')")

    argv = [
        "systemctl",
        "list-units",
        "--no-pager",
        "--no-legend",
        f"--type={unit_type}",
    ]
    if state is not None:
        argv.append(f"--state={state}")
    if pattern is not None:
        argv.append("--")
        argv.append(pattern)
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    units = _parse_list_units(stdout)
    policy = resolve_host(ctx, host)
    return SystemctlListUnitsResult(
        host=policy.hostname,
        units=units,
        exit_code=exit_code,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_show(
    host: str,
    unit: str,
    ctx: Context,
    properties: list[str] | None = None,
) -> dict[str, object]:
    """Run ``systemctl show <unit> [--property=P1,P2,...]``.

    ``properties`` is an optional list of property names to retrieve
    (e.g. ``["ActiveState", "ExecMainPID", "NRestarts"]``). When omitted,
    all properties are returned.

    Returns ``{host, unit, properties, exit_code}`` where ``properties`` is a
    ``dict[str, str]``. Duplicate keys in the output are handled by
    last-write-wins.
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "show"]
    if properties is not None:
        _validate_property_names(properties)
        argv.append(f"--property={','.join(properties)}")
    argv.extend(["--", unit])
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    props = _parse_show_properties(stdout)
    policy = resolve_host(ctx, host)
    return SystemctlShowResult(
        host=policy.hostname,
        unit=unit,
        properties=props,
        exit_code=exit_code,
    ).model_dump()


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_systemctl_cat(
    host: str,
    unit: str,
    ctx: Context,
) -> dict[str, object]:
    """Run ``systemctl cat <unit>`` and return the unit file content.

    Returns ``{host, unit, stdout, exit_code}``. The raw unit file content
    (including overrides) is in ``stdout``.
    """
    _validate_systemd_unit_name(unit)
    argv = ["systemctl", "cat", "--", unit]
    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    policy = resolve_host(ctx, host)
    return SystemctlCatResult(
        host=policy.hostname,
        unit=unit,
        stdout=stdout,
        exit_code=exit_code,
    ).model_dump()


# Maximum number of log lines to return in a single journalctl call.
_JOURNALCTL_MAX_LINES = 1000


@mcp_server.tool(tags={"safe", "read", "group:systemctl"}, version="1.0")
@audited(tier="read")
async def ssh_journalctl(
    host: str,
    unit: str,
    ctx: Context,
    since: str | None = None,
    until: str | None = None,
    lines: int = 200,
    grep: str | None = None,
) -> dict[str, object]:
    """Run ``journalctl -u <unit> --no-pager -n <lines>`` and return log output.

    Args:
        host: Target host.
        unit: Systemd unit name (e.g. ``"nginx.service"``).
        since: Time anchor for ``--since`` (e.g. ``"15m"``, ``"2026-04-16T12:00:00Z"``).
        until: Time anchor for ``--until``.
        lines: Maximum lines to return. Capped at 1000; raises ``ValueError`` above.
        grep: Filter log lines by regex. Conservative: alphanumerics + ``_-.:/@ ``.

    Returns ``{host, unit, stdout, lines_returned, exit_code}``.

    Note: ``journalctl -u <unit>`` requires the SSH user to be in the
    ``systemd-journal`` or ``adm`` group, or to run as root. If permission
    is denied, ``exit_code`` will be non-zero and ``stderr`` will explain.
    """
    _validate_systemd_unit_name(unit)
    if lines > _JOURNALCTL_MAX_LINES:
        raise ValueError(
            f"lines={lines} exceeds the maximum of {_JOURNALCTL_MAX_LINES}; "
            f"use a tighter time window (since=) instead of a large line count"
        )
    if lines < 1:
        raise ValueError("lines must be >= 1")
    if since is not None:
        _validate_time_anchor(since, param="since")
    if until is not None:
        _validate_time_anchor(until, param="until")
    if grep is not None:
        _validate_grep(grep)

    argv = ["journalctl", "-u", unit, "--no-pager", "-n", str(lines)]
    if since is not None:
        argv.extend(["--since", since])
    if until is not None:
        argv.extend(["--until", until])
    if grep is not None:
        argv.extend(["--grep", grep])

    stdout, _stderr, exit_code = await _run_systemctl(ctx, host, argv)
    lines_returned = len([ln for ln in stdout.splitlines() if ln])
    policy = resolve_host(ctx, host)
    return JournalctlResult(
        host=policy.hostname,
        unit=unit,
        stdout=stdout,
        lines_returned=lines_returned,
        exit_code=exit_code,
    ).model_dump()
