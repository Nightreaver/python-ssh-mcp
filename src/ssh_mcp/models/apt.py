"""Return-shape models for APT / apt-cache read tools.

Mirrors the systemctl pattern: every result model forbids extras (INC-046)
so a typo at construction site surfaces as a Pydantic ValidationError
instead of silently producing an incomplete result the LLM then trusts.

Tools live in :mod:`ssh_mcp.tools.apt_tools`; parsers in
:mod:`ssh_mcp.services.apt_parser`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

# Mirror models/results.py + models/systemctl.py (INC-046).
_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")


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
