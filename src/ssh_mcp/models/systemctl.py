"""Return-shape models for systemctl tools.

These models define the structured output for every tool in
``tools/systemctl_tools.py``. Literal types enforce that only the
values systemd actually emits end up in serialised output.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

# Mirror models/results.py (INC-046): every result model forbids extras so a
# typo at construction surfaces immediately instead of producing incomplete
# output the LLM then trusts.
_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")

# ---------------------------------------------------------------------------
# ssh_systemctl_status
# ---------------------------------------------------------------------------


class SystemctlStatusResult(BaseModel):
    """Result of ``systemctl status <unit> --no-pager``."""

    model_config = _RESULT_MODEL_CONFIG

    host: str
    unit: str
    stdout: str
    exit_code: int
    # Parsed from the ``Active:`` line; None when not present in output.
    active_state: str | None = None
    # INC-058: output_sanitizer warnings about `stdout`. Empty for clean
    # output. ANSI / NUL stripped from stdout already; warnings flag the
    # strip + any non-stripped suspicious patterns (bidi, zero-width,
    # LLM markers, fake conversation turns).
    output_warnings: list[str] = []


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

    model_config = _RESULT_MODEL_CONFIG

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

    model_config = _RESULT_MODEL_CONFIG

    host: str
    unit: str
    state: IsEnabledState
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_is_failed
# ---------------------------------------------------------------------------


class SystemctlIsFailedResult(BaseModel):
    """Result of ``systemctl is-failed <unit>``."""

    model_config = _RESULT_MODEL_CONFIG

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

    model_config = _RESULT_MODEL_CONFIG

    unit: str
    load: str
    active: str
    sub: str
    description: str


class SystemctlListUnitsResult(BaseModel):
    """Result of ``systemctl list-units``."""

    model_config = _RESULT_MODEL_CONFIG

    host: str
    units: list[SystemctlUnitEntry]
    exit_code: int


# ---------------------------------------------------------------------------
# ssh_systemctl_show
# ---------------------------------------------------------------------------


class SystemctlShowResult(BaseModel):
    """Result of ``systemctl show <unit>``."""

    model_config = _RESULT_MODEL_CONFIG

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

    model_config = _RESULT_MODEL_CONFIG

    host: str
    unit: str
    stdout: str
    exit_code: int
    # INC-058: output_sanitizer warnings about `stdout` (the unit file
    # contents). Empty for clean unit files.
    output_warnings: list[str] = []


# ---------------------------------------------------------------------------
# ssh_journalctl
# ---------------------------------------------------------------------------


class JournalctlResult(BaseModel):
    """Result of ``journalctl -u <unit>``."""

    model_config = _RESULT_MODEL_CONFIG

    host: str
    unit: str
    stdout: str
    lines_returned: int
    exit_code: int
    # INC-058: output_sanitizer warnings about `stdout`. Log lines are
    # the most common prompt-injection vector (anything that ends up
    # in the journal: motd, sshd auth lines, application crash dumps).
    output_warnings: list[str] = []
