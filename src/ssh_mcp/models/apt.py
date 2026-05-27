"""Return-shape models for APT / apt-cache read tools.

Mirrors the systemctl pattern: every result model forbids extras (INC-046)
so a typo at construction site surfaces as a Pydantic ValidationError
instead of silently producing an incomplete result the LLM then trusts.

Tools live in :mod:`ssh_mcp.tools.apt_tools`; parsers in
:mod:`ssh_mcp.services.apt_parser`.

Package-name validators (``validate_package_name`` / ``validate_packages``)
also live here -- they are part of the model contract, not the tool layer,
and the same regex is consulted from multiple call sites in the dangerous
tier.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict

# Mirror models/results.py + models/systemctl.py (INC-046).
_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Validators (model invariants -- shared between read + mutation tools)
# ---------------------------------------------------------------------------

# Debian package-name shape (subset of policy-manual §5.6.7). Lowercase
# only by convention -- apt is case-insensitive on lookup but accepting
# lowercase keeps the regex tight and the audit trail unambiguous.
_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.+\-]{0,127}$")


def validate_package_name(name: str) -> str:
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


def validate_packages(packages: list[str], *, action: str) -> list[str]:
    """Validate every package name in ``packages``.

    Returns the same list (post-validation). Empty lists are rejected here
    for the actions that require at least one target -- the per-tool callers
    rely on this to keep the empty-list policy in one place.
    """
    if not packages:
        raise ValueError(f"packages must be non-empty for action={action!r}")
    for pkg in packages:
        validate_package_name(pkg)
    return packages


# ---------------------------------------------------------------------------
# ssh_apt_list
# ---------------------------------------------------------------------------

#: Modes accepted by ``ssh_apt_list`` -- map onto apt's flag set.
#: ``installed`` -> ``--installed``;
#: ``upgradable`` -> ``--upgradable`` (apt's spelling, no "e");
#: ``all`` -> no flag (lists every package known to apt's caches).
AptListMode = Literal["installed", "upgradable", "all"]

#: State words apt prints in square brackets after the package version.
#: Real-world apt emits these as comma-joined sets (e.g.
#: ``[installed,automatic]``); the parser splits and we keep the most
#: meaningful single state token. ``unknown`` is the fallback for anything
#: not in the recognised set.
AptPackageState = Literal[
    "installed",
    "installed,automatic",
    "installed,local",
    "upgradable",
    "residual-config",
    "unknown",
]


class AptPackage(BaseModel):
    """One row from ``apt list``.

    ``apt list`` columns (post the ``Listing...`` header and after stripping
    the ``Listing...`` marker) look like::

        nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 amd64 [installed]

    Fields parsed:

    - ``name``: package name (left of the first ``/``)
    - ``version``: version string (token after the repo list)
    - ``architecture``: arch (``amd64``, ``arm64``, ``all``, ...)
    - ``state``: bracketed state token, joined with commas if multi-valued
    """

    model_config = _RESULT_MODEL_CONFIG

    name: str
    version: str
    architecture: str
    # Free string rather than the Literal: apt can mix states arbitrarily
    # and we don't want a parser surprise to crash construction. The
    # AptPackageState alias above documents the common values.
    state: str


class AptListResult(BaseModel):
    """Result of ``ssh_apt_list``."""

    model_config = _RESULT_MODEL_CONFIG

    host: str
    mode: AptListMode
    packages: list[AptPackage]
    total: int
    # ``apt list --installed`` on a desktop can run to ~10k entries; output
    # cap (SSH_STDOUT_CAP_BYTES, default 1 MiB) may trim before we parse.
    # When True, ``packages`` is the parse of as-much-as-we-saw and ``total``
    # reflects the parsed rows -- the truth on disk may be larger.
    truncated: bool = False
    # INC-058 propagation: any sanitiser warnings from the raw stdout
    # (ANSI / NUL / suspicious patterns). apt output is usually clean
    # but apt's CNF / esm hooks have shipped escape sequences before.
    output_warnings: list[str] = []


# ---------------------------------------------------------------------------
# ssh_apt_search
# ---------------------------------------------------------------------------


class AptSearchHit(BaseModel):
    """One row from ``apt-cache search <pattern>``.

    Output format: ``<name> - <short description>``. We split on the first
    " - " (space-dash-space); descriptions may contain ' - ' internally
    so over-splitting would be wrong.
    """

    model_config = _RESULT_MODEL_CONFIG

    name: str
    short_description: str


class AptSearchResult(BaseModel):
    """Result of ``ssh_apt_search``."""

    model_config = _RESULT_MODEL_CONFIG

    host: str
    pattern: str
    results: list[AptSearchHit]
    output_warnings: list[str] = []


# ---------------------------------------------------------------------------
# ssh_apt_show
# ---------------------------------------------------------------------------


class AptShowResult(BaseModel):
    """Combined ``apt-cache show`` + ``apt-cache policy`` for one package.

    All optional fields default to ``None`` / ``[]`` so a partial parse
    (e.g. package not in any policy repo) still constructs cleanly. The
    LLM gets ``installed_version=None`` rather than a ValidationError.

    Field provenance:

    - ``installed_version`` / ``candidate_version`` / ``repos`` come from
      ``apt-cache policy <pkg>``.
    - ``description`` / ``depends`` / ``recommends`` / ``suggests`` /
      ``conflicts`` / ``breaks`` / ``replaces`` come from
      ``apt-cache show <pkg>``.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    package: str
    installed_version: str | None = None
    candidate_version: str | None = None
    repos: list[str] = []
    description: str | None = None
    depends: list[str] = []
    recommends: list[str] = []
    suggests: list[str] = []
    conflicts: list[str] = []
    breaks: list[str] = []
    replaces: list[str] = []
    output_warnings: list[str] = []


# ---------------------------------------------------------------------------
# ssh_apt_install / ssh_apt_upgrade / ssh_apt_remove / ssh_apt_autoremove /
# ssh_apt_mark  (dangerous-tier mutation tools)
# ---------------------------------------------------------------------------


#: The verb that ended up running on the remote box. ``purge`` is distinct
#: from ``remove`` so the LLM (and audit consumers) can tell whether config
#: files were also removed. ``hold`` / ``unhold`` come from ``apt-mark``;
#: ``showhold`` has its own result model.
AptMutationAction = Literal[
    "install",
    "upgrade",
    "remove",
    "purge",
    "autoremove",
    "hold",
    "unhold",
]


class AptMutationResult(BaseModel):
    """Shared shape for install / upgrade / remove / autoremove / mark mutations.

    Non-zero exit codes are returned as data in ``exit_code`` (apt-get's exit
    codes are informative -- 100 means the package list could not be parsed,
    1 means "nothing to do or held back", etc.); only transport failures
    escape the tool.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    action: AptMutationAction
    # Input packages, post-validation. Empty list for verbs that take no
    # package argument (``upgrade``, ``autoremove``).
    packages: list[str] = []
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    # Mirrors ``ExecResult.stdout_truncated`` -- True when stdout reached the
    # ``SSH_STDOUT_CAP_BYTES`` cap and was trimmed before we returned it.
    stdout_truncated: bool = False
    # INC-058: output_sanitizer warnings about stdout/stderr. apt's free-form
    # progress/dialog text is a moderate prompt-injection vector (DEBCONF,
    # apt-listchanges, esm hooks have all shipped escape sequences before).
    output_warnings: list[str] = []


class AptHoldsResult(BaseModel):
    """Result of ``apt-mark showhold`` -- parsed list of currently-held packages.

    Distinct from ``AptMutationResult`` because the value the LLM cares about
    is the parsed ``held`` list, not a free-form stdout chunk. We still carry
    the raw stdout/stderr/exit_code so callers debugging apt's output can see
    what came back.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    held: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    stdout_truncated: bool = False
    output_warnings: list[str] = []
