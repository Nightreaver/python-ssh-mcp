"""Parsers for APT / apt-cache output.

Pure text -> structured-data helpers. No SSH, no I/O -- consumed by
:mod:`ssh_mcp.tools.apt_tools`.

The names ``apt_parser`` / module path is deliberate: a future ``dnf``
or ``rpm`` family lands as ``services/dnf_parser.py`` next door without
forcing a rename here. Don't fold the parsing into the tools module.
"""

from __future__ import annotations

import re
from typing import TypedDict

from ..models.apt import AptPackage, AptSearchHit


class AptShowParsed(TypedDict):
    """Typed return shape for :func:`parse_apt_show`.

    Each key matches a kwarg on :class:`ssh_mcp.models.apt.AptShowResult`
    so callers can unpack ``**parsed`` without per-field ``# type: ignore``.
    """

    description: str | None
    depends: list[str]
    recommends: list[str]
    suggests: list[str]
    conflicts: list[str]
    breaks: list[str]
    replaces: list[str]


class AptPolicyParsed(TypedDict):
    """Typed return shape for :func:`parse_apt_policy`."""

    installed_version: str | None
    candidate_version: str | None
    repos: list[str]


# ---------------------------------------------------------------------------
# apt list
# ---------------------------------------------------------------------------

# Header lines apt prints before / between rows. We skip them because
# they don't represent packages.
_APT_LIST_HEADERS: frozenset[str] = frozenset(
    {
        "Listing...",
        "Listing... Done",
        "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.",
    }
)

# A row from ``apt list``:
#   <name>/<repos> <version> <architecture> [<state>[,<state>...]]
# Examples (real outputs):
#   nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 amd64 [installed]
#   curl/now 7.81.0-1ubuntu1.16 amd64 [installed,local]
#   libfoo/jammy 1.2.3 amd64
# The state bracket is optional ("apt list" without any flag elides it for
# non-installed entries on some apt versions).
_APT_LIST_ROW_RE = re.compile(
    r"""
    ^
    (?P<name>[A-Za-z0-9][A-Za-z0-9.+\-]*)   # package name
    /                                        # name/repo separator
    (?P<repos>\S+)                           # repo list (we discard)
    \s+
    (?P<version>\S+)                         # version
    \s+
    (?P<arch>\S+)                            # architecture
    (?:\s+\[(?P<state>[^\]]+)\])?            # optional [state[,state]] bracket
    \s*$
    """,
    re.VERBOSE,
)


def parse_apt_list(stdout: str) -> list[AptPackage]:
    """Parse ``apt list`` output into ``AptPackage`` rows.

    Lines that don't match the apt row shape (header banners, blanks,
    indented continuation text) are silently skipped. The parser is
    forgiving by design: apt's CLI is documented as not stable, and
    we'd rather drop oddities than crash construction.
    """
    packages: list[AptPackage] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line in _APT_LIST_HEADERS:
            continue
        if line.startswith("WARNING:"):
            # apt's stderr-on-stdout banner; skip even when we see it
            # despite redirecting 2>/dev/null (some hooks bypass that).
            continue
        m = _APT_LIST_ROW_RE.match(line)
        if not m:
            continue
        state = m.group("state") or ""
        packages.append(
            AptPackage(
                name=m.group("name"),
                version=m.group("version"),
                architecture=m.group("arch"),
                state=state,
            )
        )
    return packages


# ---------------------------------------------------------------------------
# apt-cache search
# ---------------------------------------------------------------------------

# Each result line from ``apt-cache search`` is::
#   <name> - <short description>
# Descriptions may contain " - " internally; we split on the FIRST
# occurrence only to keep the description intact.
_APT_SEARCH_SEP = " - "


def parse_apt_search(stdout: str) -> list[AptSearchHit]:
    """Parse ``apt-cache search <pattern>`` output into ``AptSearchHit`` rows.

    Lines without the ``" - "`` separator are skipped. apt-cache normally
    emits one result per line, but very-long descriptions sometimes wrap;
    we don't try to rejoin -- the wrapped continuation just gets dropped.
    """
    hits: list[AptSearchHit] = []
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        sep_index = line.find(_APT_SEARCH_SEP)
        if sep_index < 0:
            continue
        name = line[:sep_index].strip()
        desc = line[sep_index + len(_APT_SEARCH_SEP) :].strip()
        if not name:
            continue
        hits.append(AptSearchHit(name=name, short_description=desc))
    return hits


# ---------------------------------------------------------------------------
# apt-cache show
# ---------------------------------------------------------------------------

# ``apt-cache show`` emits paragraph-style records:
#   Package: nginx
#   Version: 1.18.0-6ubuntu14.4
#   ...
#   Description: A high performance web server
#    nginx is a fast and lightweight web server...
# Continuation lines (description body, multi-line fields) are indented.
# Multiple stanzas (one per available version) are separated by a blank line.
# We consume the FIRST stanza only -- that's the candidate version's record.


# Comma-separated dependency-style fields. Values look like::
#   libc6 (>= 2.34), libcrypt1 (>= 1:4.4.10-10ubuntu4) | libcrypt1-udeb
# We split on commas, strip whitespace, and keep the entries verbatim
# (with the version constraint and alternation intact) so the LLM sees
# what apt would resolve.
def _split_csv_field(value: str) -> list[str]:
    """Split a comma-delimited apt field value, preserving inner whitespace.

    Handles the trailing-newline / multi-line-folded cases that apt-cache
    occasionally emits by the time it reaches us.
    """
    parts = [p.strip() for p in value.split(",")]
    return [p for p in parts if p]


# Single-line scalar fields we extract verbatim.
_SHOW_SCALAR_FIELDS = {"Package", "Version"}
# CSV-list fields.
_SHOW_LIST_FIELDS = {"Depends", "Recommends", "Suggests", "Conflicts", "Breaks", "Replaces"}


def parse_apt_show(stdout: str) -> AptShowParsed:
    """Parse ``apt-cache show <pkg>`` output into a typed dict.

    Returns an :class:`AptShowParsed` with:
        ``description: str | None``,
        ``depends|recommends|suggests|conflicts|breaks|replaces: list[str]``.

    Only the FIRST stanza is consumed. ``Description`` aggregates the
    header line + every following indented continuation line, with the
    sentinel single-dot lines apt uses for paragraph breaks rendered
    as blank lines (apt's RFC822-style convention).
    """
    # ``raw_fields`` is a parser-internal scratchpad: we accumulate scalar
    # field values to read out the dependency-style fields below. Not part
    # of the return shape -- consumers only need the structured outputs.
    raw_fields: dict[str, str] = {}
    description_lines: list[str] = []
    current_field: str | None = None
    in_description = False
    seen_blank = False

    for line in stdout.splitlines():
        # Stanza separator: first blank line ends the stanza we care about.
        if not line.strip():
            if seen_blank or raw_fields:
                seen_blank = True
                # Stop after the first stanza completes.
                if raw_fields and current_field is not None:
                    break
                continue
            continue

        # Continuation line (starts with whitespace).
        if line.startswith((" ", "\t")):
            if in_description:
                # apt uses " ." to render an explicit blank paragraph break.
                stripped = line.strip()
                if stripped == ".":
                    description_lines.append("")
                else:
                    description_lines.append(stripped)
            elif current_field is not None:
                # Continuation of a non-description field (rare for apt-cache
                # show, but defensive).
                raw_fields[current_field] = raw_fields[current_field] + " " + line.strip()
            continue

        # New field header: "Key: value".
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        current_field = key
        if key == "Description":
            in_description = True
            description_lines = [value] if value else []
        else:
            in_description = False
            raw_fields[key] = value

    description: str | None
    if description_lines:
        # Strip trailing blanks but keep internal paragraph breaks.
        while description_lines and not description_lines[-1]:
            description_lines.pop()
        description = "\n".join(description_lines) if description_lines else None
    else:
        description = None

    return AptShowParsed(
        description=description,
        depends=_split_csv_field(raw_fields.get("Depends", "")),
        recommends=_split_csv_field(raw_fields.get("Recommends", "")),
        suggests=_split_csv_field(raw_fields.get("Suggests", "")),
        conflicts=_split_csv_field(raw_fields.get("Conflicts", "")),
        breaks=_split_csv_field(raw_fields.get("Breaks", "")),
        replaces=_split_csv_field(raw_fields.get("Replaces", "")),
    )


# ---------------------------------------------------------------------------
# apt-cache policy
# ---------------------------------------------------------------------------

# ``apt-cache policy <pkg>`` output:
#
#   nginx:
#     Installed: 1.18.0-6ubuntu14.4
#     Candidate: 1.18.0-6ubuntu14.4
#     Version table:
#    *** 1.18.0-6ubuntu14.4 500
#           500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
#           500 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages
#           100 /var/lib/dpkg/status
#
# When the package is not installed, ``Installed:`` reads ``(none)``.
# When apt knows nothing about the package, the policy may be empty.

_INSTALLED_RE = re.compile(r"^\s*Installed:\s*(.+?)\s*$")
_CANDIDATE_RE = re.compile(r"^\s*Candidate:\s*(.+?)\s*$")
# Repo lines look like "       500 http://... jammy/main amd64 Packages".
# The pin priority is the leading integer; we keep the URL component for the
# repos list. Lines pointing to the dpkg status DB are dropped (they're
# the local installed state, not a remote repo).
_REPO_LINE_RE = re.compile(r"^\s*\d+\s+(http[s]?://\S+|file:\S+|cdrom:\S+|copy:\S+)\s+(.+)$")


def parse_apt_policy(stdout: str) -> AptPolicyParsed:
    """Parse ``apt-cache policy <pkg>`` output.

    Returns an :class:`AptPolicyParsed` with:
        ``installed_version`` -- ``None`` when apt reports ``(none)`` or
        the line is absent.
        ``candidate_version`` -- ``None`` when absent (rare; usually means
        no apt cache for the package).
        ``repos`` -- deduplicated while preserving order; entries are
        ``"<url> <suite>/<component> <arch>"`` strings, mirroring what apt
        prints, so the LLM sees the same identifier shown in apt's UI.
    """
    installed: str | None = None
    candidate: str | None = None
    repos: list[str] = []
    seen_repos: set[str] = set()

    for line in stdout.splitlines():
        m_inst = _INSTALLED_RE.match(line)
        if m_inst:
            value = m_inst.group(1)
            installed = None if value == "(none)" else value
            continue
        m_cand = _CANDIDATE_RE.match(line)
        if m_cand:
            value = m_cand.group(1)
            candidate = None if value == "(none)" else value
            continue
        m_repo = _REPO_LINE_RE.match(line)
        if m_repo:
            entry = f"{m_repo.group(1)} {m_repo.group(2).strip()}"
            if entry not in seen_repos:
                seen_repos.add(entry)
                repos.append(entry)

    return AptPolicyParsed(
        installed_version=installed,
        candidate_version=candidate,
        repos=repos,
    )
