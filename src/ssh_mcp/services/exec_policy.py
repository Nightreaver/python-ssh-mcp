"""Command-allowlist enforcement for the exec tier. See DESIGN.md §5.7, §PI-2."""
from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

from ..ssh.errors import SSHMCPError

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import HostPolicy


class CommandNotAllowed(SSHMCPError):
    """First token of the command is not in the allowlist."""


def effective_command_allowlist(policy: HostPolicy, settings: Settings) -> list[str]:
    """Per-host + env command allowlist unioned, order preserved, deduped."""
    merged: list[str] = []
    seen: set[str] = set()
    for token in (*policy.command_allowlist, *settings.SSH_COMMAND_ALLOWLIST):
        if token not in seen:
            seen.add(token)
            merged.append(token)
    return merged


def check_command(
    command: str,
    policy: HostPolicy,
    settings: Settings,
) -> None:
    """Reject the command if the first token isn't on the allowlist.

    Empty allowlist **denies every command** unless `ALLOW_ANY_COMMAND=true`
    is set. This fails-closed: operators reading "empty allowlist" naturally
    expect "nothing allowed." To permit arbitrary commands, the flag must be
    set explicitly (see ADR-0018).

    The first token is extracted via `shlex.split`, so quoted arguments don't
    bypass the check. On parse failure we refuse -- malformed shell syntax is a
    red flag on its own.
    """
    allowlist = effective_command_allowlist(policy, settings)
    if not allowlist:
        if settings.ALLOW_ANY_COMMAND:
            return
        raise CommandNotAllowed(
            "no command_allowlist configured for this host; "
            "set ALLOW_ANY_COMMAND=true to permit any command"
        )
    # Per-host "allow everything" sentinel -- mirror of path_allowlist=["*"].
    # Startup logs a WARNING (see hosts.py::_warn_on_risky_config).
    if "*" in allowlist:
        return
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise CommandNotAllowed(f"command failed to parse: {exc}") from exc
    if not tokens:
        raise CommandNotAllowed("command is empty")
    program = tokens[0]
    # Match rules (INC-012):
    #   - Exact match always wins -- bare entry matches bare program,
    #     absolute entry matches absolute program.
    #   - If the program is absolute AND the allowlist entry is BARE, match by
    #     basename so `["systemctl"]` permits `/usr/bin/systemctl`.
    #   - Absolute allowlist entries (`/usr/bin/systemctl`) require exact
    #     match -- they do NOT match `/opt/rogue/systemctl`, closing the
    #     shadow-binary risk for operators who want a strict policy.
    if program in allowlist:
        return
    if "/" in program:
        basename = program.rsplit("/", 1)[-1]
        bare_entries = {e for e in allowlist if "/" not in e}
        if basename in bare_entries:
            return
    raise CommandNotAllowed(
        f"command {program!r} is not in the command_allowlist. "
        f"Allowed tokens: {sorted(allowlist)!r}. Remediation: pick one of "
        f"those, or ask the operator to add {program!r} to command_allowlist "
        f"(per-host in hosts.toml or env SSH_COMMAND_ALLOWLIST)."
    )
