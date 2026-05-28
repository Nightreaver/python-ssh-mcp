"""MCP-host local-filesystem canonicalization + allowlist enforcement.

Parallel to :mod:`ssh_mcp.services.path_policy` (which guards REMOTE paths via
``realpath`` on the SSH channel), but for the MCP server's OWN filesystem.
Used by the ``local_path=`` mode of ``ssh_upload`` / ``ssh_deploy`` /
``ssh_sftp_download`` (v1.3.0), where the bytestream is read from or written
to local disk directly instead of being routed through the MCP JSON channel
as base64.

Allowlist source: the env-level ``SSH_LOCAL_TRANSFER_ROOTS`` setting. Empty
list ⇒ the entire ``local_path`` mode is disabled and every call raises
:class:`LocalPathPolicyError` naming the setting. No per-host overlay -- this
is a property of the MCP host itself, not of any one remote target.

Canonicalization uses :meth:`pathlib.Path.resolve(strict=False)`. We do NOT
pre-validate that the roots themselves exist at startup -- mounted volumes,
removable media, or network shares may be transiently missing without that
being a config error. The check happens lazily at each call.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..ssh.errors import LocalPathPolicyError

if TYPE_CHECKING:
    from ..config import Settings

Mode = Literal["read", "write"]

# Shared chunk size for `local_path` streaming on both the upload-from-local
# (low_access_tools._atomic_write_stream) and download-to-local
# (sftp_read_tools._sftp_download_to_local) paths. 256 KiB matches asyncssh's
# window-based flow control sweet spot: larger chunks do not improve
# throughput once the window is full; smaller ones add per-request overhead.
LOCAL_STREAM_CHUNK_BYTES = 256 * 1024


def _resolve_roots(roots: list[str]) -> list[Path]:
    """Canonicalize the configured roots.

    Each root is run through ``Path.resolve(strict=False)`` so the symlink-
    safe ``is_relative_to`` check below operates in a single normalized
    representation regardless of whether the operator passed the realpath
    or a symlinked alias in the env. Non-existing roots are kept as the
    operator wrote them (lazy validation -- see module docstring).
    """
    out: list[Path] = []
    for raw in roots:
        if not raw or not raw.strip():
            continue
        try:
            resolved = Path(raw).resolve(strict=False)
        except OSError:
            # A genuinely broken entry (e.g. malformed UNC, drive that
            # threw on resolve) -- skip it and let the no-match branch
            # below produce a clear "not in any root" error. Surfacing the
            # OSError here would hide the actual root cause behind a
            # filesystem hiccup.
            continue
        out.append(resolved)
    return out


def resolve_local_path(
    path: str,
    settings: Settings,
    *,
    mode: Mode,
) -> Path:
    """Canonicalize ``path`` on the MCP-host filesystem and enforce the
    ``SSH_LOCAL_TRANSFER_ROOTS`` allowlist.

    Symlink semantics:

    - ``mode="read"`` resolves with ``strict=True`` so the call fails fast
      if the file does not exist (the upload path needs real bytes to
      read). The strict resolve also follows symlinks all the way through,
      so a symlink pointing outside the allowlist is rejected by the
      ``is_relative_to`` check on the RESOLVED target -- not on the
      symlink's apparent location.
    - ``mode="write"`` resolves with ``strict=False`` (the target may not
      exist yet -- it's about to be created or overwritten). The PARENT
      directory must exist, however; resolving the parent strictly makes
      that check explicit and produces a clean error rather than letting
      ``os.replace`` later fail with a less actionable ENOENT.

    Returns the canonical :class:`pathlib.Path` (always absolute, always
    inside one of the configured roots). Raises :class:`LocalPathPolicyError`
    on any policy failure -- caller may surface the message verbatim to the
    LLM (no secrets, references the env knob).
    """
    if not isinstance(path, str) or not path:
        raise LocalPathPolicyError("local_path must be a non-empty string")
    if "\x00" in path:
        raise LocalPathPolicyError("local_path contains NUL byte")

    roots = _resolve_roots(settings.SSH_LOCAL_TRANSFER_ROOTS)
    if not roots:
        raise LocalPathPolicyError(
            "local_path mode is disabled: SSH_LOCAL_TRANSFER_ROOTS is empty. "
            "Ask the operator to set SSH_LOCAL_TRANSFER_ROOTS to a "
            "comma-separated list of absolute directories the MCP server "
            "may read/write from."
        )

    candidate = Path(path)
    if mode == "read":
        try:
            canonical = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise LocalPathPolicyError(f"local_path {path!r} does not exist (mode=read)") from exc
        except OSError as exc:
            raise LocalPathPolicyError(f"local_path {path!r} could not be resolved: {exc}") from exc
        if not canonical.is_file():
            raise LocalPathPolicyError(
                f"local_path {path!r} resolves to {canonical!s} which is not a "
                f"regular file (mode=read requires a regular file)"
            )
    else:  # mode == "write"
        # Resolve loosely so a not-yet-existing target is allowed. Symlink
        # resolution stops at the first missing segment, which is fine here:
        # we only care that the eventual location lies inside an allowlisted
        # root.
        try:
            canonical = candidate.resolve(strict=False)
        except OSError as exc:
            raise LocalPathPolicyError(f"local_path {path!r} could not be resolved: {exc}") from exc
        parent = canonical.parent
        try:
            resolved_parent = parent.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise LocalPathPolicyError(
                f"local_path {path!r}: parent directory {parent!s} does not exist "
                f"(mode=write requires the parent dir to exist; create it first)"
            ) from exc
        if not resolved_parent.is_dir():
            raise LocalPathPolicyError(f"local_path {path!r}: parent {resolved_parent!s} is not a directory")
        # Rebuild the canonical path on top of the strictly-resolved parent
        # so symlinks ABOVE the target are followed even when the target
        # itself doesn't exist. Without this step a symlinked parent could
        # smuggle the eventual write outside an allowlisted root.
        canonical = resolved_parent / canonical.name

    for root in roots:
        # `is_relative_to` (Python 3.9+) is the symlink-safe form: it operates
        # on the already-resolved path, so a symlink-escape attempt has been
        # collapsed by `.resolve()` above before we get here.
        if canonical == root or canonical.is_relative_to(root):
            return canonical

    roots_display = ", ".join(str(r) for r in roots)
    raise LocalPathPolicyError(
        f"local_path {path!r} resolves to {canonical!s} which is outside the "
        f"configured SSH_LOCAL_TRANSFER_ROOTS ({roots_display}). Remediation: "
        f"pick a path inside one of the configured roots, or ask the operator "
        f"to add the needed root to SSH_LOCAL_TRANSFER_ROOTS."
    )
