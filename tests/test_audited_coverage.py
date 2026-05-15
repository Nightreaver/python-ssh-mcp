"""Coverage test: every tool the project advertises at a given tier MUST be
wrapped with ``@audited(tier=...)``.

Locks in the user's locked Option B decision (read tier fully audited) so a
future tool author can't quietly land a read-tier ``ssh_*`` tool without the
decorator. Sprint 3 added the missing decorators (ssh_sftp_*, ssh_find,
ssh_session_list, ssh_shell_list, the ssh_host_* read tools,
ssh_known_hosts_verify); the parametrized table below is the gate that
keeps them in.

Detection strategy: ``audited`` uses ``functools.wraps`` on the inner
``async def wrapper(*args, **kwargs)``, so the decorated symbol always
exposes ``__wrapped__``. The captured ``tier`` argument lives in the
wrapper's closure cells -- we walk those to confirm the tier matches.
That gives a structural assertion (no need to invoke the tool with a
live Context) that fails loudly if a future refactor swaps the
decorator chain order or drops it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

# Read-tier tools currently expected to carry @audited(tier="read"). Listed
# as (module-path, attribute-name) so the test imports lazily and the
# parametrize id stays the tool name rather than a function repr.
READ_TIER_TOOLS: list[tuple[str, str]] = [
    # SFTP read
    ("ssh_mcp.tools.sftp_read_tools", "ssh_sftp_list"),
    ("ssh_mcp.tools.sftp_read_tools", "ssh_sftp_stat"),
    ("ssh_mcp.tools.sftp_read_tools", "ssh_sftp_download"),
    ("ssh_mcp.tools.sftp_read_tools", "ssh_find"),
    ("ssh_mcp.tools.sftp_read_tools", "ssh_file_hash"),
    # Session / shell inspection (Sprint 5: ssh_session_list moved into
    # shell_tools alongside ssh_shell_list -- both are "enumerate open
    # server-side state" reads).
    ("ssh_mcp.tools.shell_tools", "ssh_session_list"),
    ("ssh_mcp.tools.shell_tools", "ssh_shell_list"),
    # Host read tools
    ("ssh_mcp.tools.host_tools", "ssh_host_ping"),
    ("ssh_mcp.tools.host_tools", "ssh_host_info"),
    ("ssh_mcp.tools.host_tools", "ssh_host_list"),
    ("ssh_mcp.tools.host_tools", "ssh_host_alerts"),
    ("ssh_mcp.tools.host_tools", "ssh_host_disk_usage"),
    ("ssh_mcp.tools.host_tools", "ssh_host_processes"),
    ("ssh_mcp.tools.host_tools", "ssh_host_network"),
    ("ssh_mcp.tools.host_notes_tools", "ssh_host_notes"),
    ("ssh_mcp.tools.host_tools", "ssh_user_info"),
    ("ssh_mcp.tools.host_tools", "ssh_known_hosts_verify"),
    # systemctl read tools (already decorated; locked in here so a future
    # refactor can't quietly drop them either).
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_status"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_cat"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_is_active"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_is_enabled"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_is_failed"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_list_units"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_systemctl_show"),
    ("ssh_mcp.tools.systemctl_tools", "ssh_journalctl"),
    # APT / apt-cache read tools (Sprint 6).
    ("ssh_mcp.tools.apt_tools", "ssh_apt_list"),
    ("ssh_mcp.tools.apt_tools", "ssh_apt_search"),
    ("ssh_mcp.tools.apt_tools", "ssh_apt_show"),
]

#: All tier strings the project currently uses. ``audited`` stores the tier
#: in the wrapper's closure as a plain string; we match against this set
#: so an unknown value (typo, drift) is also caught.
KNOWN_TIERS = frozenset({"read", "low-access", "exec", "dangerous"})


def _resolve(module_path: str, attr: str) -> Callable[..., Any]:
    import importlib

    mod = importlib.import_module(module_path)
    return getattr(mod, attr)  # type: ignore[no-any-return]


def _captured_tier(fn: Callable[..., Any]) -> str | None:
    """Walk a wrapped function's closure to find the captured ``tier`` string.

    Returns the tier (e.g. ``"read"``) if found, else ``None``. We require the
    string to be in :data:`KNOWN_TIERS` so an unrelated string captured in
    the same closure (function name, etc.) doesn't masquerade as a tier.
    """
    closure = getattr(fn, "__closure__", None)
    if not closure:
        return None
    for cell in closure:
        try:
            value = cell.cell_contents
        except ValueError:  # empty cell
            continue
        if isinstance(value, str) and value in KNOWN_TIERS:
            return value
    return None


@pytest.mark.parametrize(
    ("module_path", "tool_name"),
    READ_TIER_TOOLS,
    ids=[name for _, name in READ_TIER_TOOLS],
)
def test_read_tier_tool_is_audited(module_path: str, tool_name: str) -> None:
    """Every read-tier tool must be wrapped with ``@audited(tier="read")``."""
    tool = _resolve(module_path, tool_name)
    assert hasattr(tool, "__wrapped__"), (
        f"{tool_name} is not wrapped -- missing @audited decorator? "
        "Place it BELOW @mcp_server.tool(...) and ABOVE the async def line."
    )
    tier = _captured_tier(tool)
    assert tier == "read", f"{tool_name} is wrapped but the captured audit tier is {tier!r}; expected 'read'."
