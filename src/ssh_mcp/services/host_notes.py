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
from dataclasses import dataclass
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


# --- optimistic CAS for concurrent-writer safety (INC-065, v1.4.1) -------
#
# Two MCP server processes that both write to the same sidecar via
# ``ssh_host_notes_append`` race: each reads the file, builds new content
# from THEIR snapshot of existing, then writes. The second writer
# silently clobbers the first's entry. ``atomic_write_sidecar`` is atomic
# at the FS level (no torn write) but is not a logical CAS.
#
# Fix: capture (mtime_ns, size) at read time; re-stat immediately before
# rename and bail out if the file changed since. Caller retries with a
# fresh snapshot. Lock-free, portable across POSIX + Windows. There is a
# tiny TOCTOU window between the final stat and the os.replace -- for our
# contention level (a handful of agent sessions sharing a notes file) this
# is statistically negligible; for stricter guarantees use a real flock.


@dataclass(frozen=True)
class SidecarSnapshot:
    """Captured state of a sidecar at one point in time, used as the
    basis for an optimistic CAS write.

    ``text`` is the file contents (or ``None`` for missing files).
    ``mtime_ns`` and ``size`` together form the version tag the CAS
    compares against. Both ``None`` when the file did not exist at
    capture time -- a later writer can still distinguish "I expected
    no file" from "I expected file X" via the equality of the whole
    snapshot.
    """

    text: str | None
    mtime_ns: int | None
    size: int | None


def read_sidecar_with_snapshot(path: Path) -> SidecarSnapshot:
    """Read sidecar contents AND capture the (mtime_ns, size) version tag
    for a later CAS write. Missing file yields ``(None, None, None)``."""
    try:
        st = path.stat()
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return SidecarSnapshot(text=None, mtime_ns=None, size=None)
    except OSError:
        # Same degraded-read semantics as ``read_sidecar``: unreadable
        # file is treated as "no content"; we cannot CAS against a state
        # we could not capture, so signal that with all-None too.
        return SidecarSnapshot(text=None, mtime_ns=None, size=None)
    return SidecarSnapshot(text=text or None, mtime_ns=st.st_mtime_ns, size=st.st_size)


def atomic_write_sidecar_if_unchanged(
    path: Path,
    content: str,
    *,
    expected_mtime_ns: int | None,
    expected_size: int | None,
) -> bool:
    """Write ``content`` to ``path`` ONLY if the file's current
    (mtime_ns, size) matches the expected snapshot. Returns ``True`` on
    successful write, ``False`` when a concurrent writer beat us between
    snapshot capture and this call. Caller retries by re-snapshotting,
    rebuilding content, and calling again.

    When ``expected_mtime_ns`` and ``expected_size`` are both ``None``
    the caller is asserting the file did NOT exist at snapshot time;
    write proceeds only if the file still does not exist.

    NOT a real OS-level CAS: the window between our stat check and the
    rename is a few microseconds. For our actual contention (small
    number of agent sessions hitting the same notes file) this is fine;
    high-contention scenarios need a real lock (``fcntl.flock`` on
    POSIX). Documented in INC-065.
    """
    try:
        st = path.stat()
        actual_mtime_ns: int | None = st.st_mtime_ns
        actual_size: int | None = st.st_size
    except FileNotFoundError:
        actual_mtime_ns = None
        actual_size = None
    except OSError:
        # Couldn't even stat -- be conservative and refuse the write.
        # Caller's retry will reach the same conclusion and surface the
        # OSError up the stack via read_sidecar_with_snapshot.
        return False
    if actual_mtime_ns != expected_mtime_ns or actual_size != expected_size:
        return False
    atomic_write_sidecar(path, content)
    return True
