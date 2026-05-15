"""Pure-Python helpers for the per-host agent-notes sidecar layer.

The sidecar is a markdown file at ``<notes_dir>/<alias>.md`` that the LLM
reads through ``ssh_host_notes`` and writes through ``ssh_host_notes_append``
/ ``ssh_host_notes_set``. This module owns the filesystem mechanics --
filename validation, atomic writes, presence checks -- so the tool layer
stays a thin wrapper around Pydantic models + audit decorators.

Layer boundary: nothing here imports from ``..tools`` or pulls a Settings
object. The size cap (``SSH_HOST_NOTES_MAX_BYTES``) is a parameter on the
write call sites, supplied by the caller. This keeps the helpers reusable
from non-tool contexts (tests, future CLI inspection, etc.) and makes the
unit tests trivially independent of pydantic-settings loading.

Defensive note: ``HOST_NOTES_ALIAS_RE`` is the second line of defense
against path traversal in the sidecar filename. Aliases reach these
helpers via ``resolve_host`` which only accepts known registry keys, but
any future code path that bypasses resolution still cannot escape the
notes directory because the regex rejects ``..``, ``/``, ``\\``, NUL, etc.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


HOST_NOTES_ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]+$")
"""Whitelist of characters legal in a sidecar filename stem.

Matches the alias format documented in ``hosts.toml``. Anything outside
this set (slash, backslash, dot-dot, NUL, whitespace, ...) is rejected
to keep ``<notes_dir>/<alias>.md`` strictly inside the notes directory.
"""


def either_notes_present(operator_notes: str | None, notes_dir: Path | None, alias: str) -> bool:
    """True when EITHER the operator field or the agent sidecar has content.

    Cheap: one stat call per host on the local FS. The sidecar path is
    constructed only after :data:`HOST_NOTES_ALIAS_RE` validates the
    alias -- callers go through ``resolve_host`` first, but the regex
    is defense in depth against any future code path that bypasses
    resolution.
    """
    if operator_notes and operator_notes.strip():
        return True
    if notes_dir is None:
        return False
    if not HOST_NOTES_ALIAS_RE.match(alias):
        return False
    sidecar = notes_dir.expanduser() / f"{alias}.md"
    try:
        return sidecar.is_file() and sidecar.stat().st_size > 0
    except OSError:
        return False


def resolve_sidecar_path(notes_dir: Path | None, alias: str) -> Path:
    """Locate ``<notes_dir>/<alias>.md``.

    Raises ``ValueError`` when the agent notes directory is unset
    (operator opted out) or the alias contains characters that could
    escape the directory.
    """
    if notes_dir is None:
        raise ValueError(
            "SSH_HOST_NOTES_DIR is unset; agent-side notes are disabled. "
            "Set the env var (or the field in your launcher config) to "
            "an absolute or CWD-relative directory to enable."
        )
    if not HOST_NOTES_ALIAS_RE.match(alias):
        # Defensive: aliases come through resolve_host (which only accepts
        # known keys), but if a future tool path bypasses that, never let
        # the alias build a sidecar path that escapes the directory.
        raise ValueError(
            f"alias {alias!r} contains characters not allowed in a notes "
            f"sidecar filename ([A-Za-z0-9._-] only)"
        )
    return notes_dir.expanduser() / f"{alias}.md"


def try_resolve_sidecar_path(notes_dir: Path | None, alias: str) -> Path | None:
    """Silent variant of :func:`resolve_sidecar_path`.

    Returns ``None`` when the notes directory is unset OR the alias fails
    the :data:`HOST_NOTES_ALIAS_RE` whitelist; returns the resolved
    ``<notes_dir>/<alias>.md`` path otherwise.

    Use this on read paths (``ssh_host_ping`` agent-notes auto-injection,
    ``ssh_host_notes`` read) where "no sidecar configured / alias rejected"
    is a normal degraded state. The strict :func:`resolve_sidecar_path`
    that raises stays for the write tools (``_append`` / ``_set``) where
    a misconfiguration must surface to the caller.
    """
    if notes_dir is None:
        return None
    if not HOST_NOTES_ALIAS_RE.match(alias):
        return None
    return notes_dir.expanduser() / f"{alias}.md"


def read_sidecar(path: Path) -> str | None:
    """Read sidecar contents. Returns ``None`` for missing / unreadable /
    empty files so callers can treat 'no notes' uniformly."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return None
    return text or None


def atomic_write_sidecar(path: Path, content: str) -> None:
    """Atomic write via temp + ``os.replace``. Creates the parent dir if
    missing. Cleans up the temp file on failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{secrets.token_hex(4)}")
    try:
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
