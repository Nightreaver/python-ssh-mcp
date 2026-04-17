"""Return-shape models for systemctl tools.

These models define the structured output for every tool in
``tools/systemctl_tools.py``. Literal types enforce that only the
values systemd actually emits end up in serialised output.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# ssh_systemctl_status
# ---------------------------------------------------------------------------


class SystemctlStatusResult(BaseModel):
    """Result of ``systemctl status <unit> --no-pager``."""

    host: str
    unit: str
    stdout: str
    exit_code: int
    # Parsed from the ``Active:`` line; None when not present in output.
    active_state: str | None = None


# ---------------------------------------------------------------------------
# ssh_systemctl_is_active
# ---------------------------------------------------------------------------

#: Exhaustive set of states ``systemctl is-active`` can print.
IsActiveState = Literal[
    "active",
    "inactive",
    "failed",
    "activating",
    "deactivating",
    "reloading",
    "unknown",
]


class SystemctlIsActiveResult(BaseModel):
    """Result of ``systemctl is-active <unit>``."""

    host: str
    unit: str
    state: IsActiveState
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_is_enabled
# ---------------------------------------------------------------------------

#: Exhaustive set of states ``systemctl is-enabled`` can print.
IsEnabledState = Literal[
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
    "unknown",
]


class SystemctlIsEnabledResult(BaseModel):
    """Result of ``systemctl is-enabled <unit>``."""

    host: str
    unit: str
    state: IsEnabledState
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_is_failed
# ---------------------------------------------------------------------------


class SystemctlIsFailedResult(BaseModel):
    """Result of ``systemctl is-failed <unit>``."""

    host: str
    unit: str
    failed: bool
    state: str
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_list_units
# ---------------------------------------------------------------------------


class SystemctlUnitEntry(BaseModel):
    """One row from ``systemctl list-units --no-legend --no-pager``."""

    unit: str
    load: str
    active: str
    sub: str
    description: str


class SystemctlListUnitsResult(BaseModel):
    """Result of ``systemctl list-units``."""

    host: str
    units: list[SystemctlUnitEntry]
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_show
# ---------------------------------------------------------------------------


class SystemctlShowResult(BaseModel):
    """Result of ``systemctl show <unit>``."""

    host: str
    unit: str
    # Key-value pairs from ``key=value\n`` output.
    properties: dict[str, str]
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_cat
# ---------------------------------------------------------------------------


class SystemctlCatResult(BaseModel):
    """Result of ``systemctl cat <unit>``."""

    host: str
    unit: str
    stdout: str
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_journalctl
# ---------------------------------------------------------------------------


class JournalctlResult(BaseModel):
    """Result of ``journalctl -u <unit>``."""

    host: str
    unit: str
    stdout: str
    lines_returned: int
    exit_code: int
