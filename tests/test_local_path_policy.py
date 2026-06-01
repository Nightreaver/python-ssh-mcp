"""services/local_path_policy -- MCP-host filesystem allowlist for the
v1.10.0 ``local_path`` upload/download mode.

Covers the contract in :func:`ssh_mcp.services.local_path_policy.resolve_local_path`:

- Empty SSH_LOCAL_TRANSFER_ROOTS ⇒ mode disabled, error names the setting.
- Path outside the allowlist rejected (with the canonical form in the msg).
- Symlink escape attempt rejected (resolve follows the symlink, then
  is_relative_to fails on the RESOLVED target).
- Read mode: missing file ⇒ error; non-regular target ⇒ error.
- Write mode: missing parent dir ⇒ error; target may not exist (overwrite
  semantics).
- Happy paths: read existing file, write new-or-existing file inside an
  allowlisted root.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.services.local_path_policy import resolve_local_path
from ssh_mcp.ssh.errors import LocalPathPolicyError

if TYPE_CHECKING:
    from pathlib import Path


def _settings_with_roots(*roots: Path) -> Settings:
    """Build a fresh Settings with `SSH_LOCAL_TRANSFER_ROOTS` set."""
    return Settings(SSH_LOCAL_TRANSFER_ROOTS=[str(r) for r in roots])


def test_empty_allowlist_rejects_with_setting_name(tmp_path: Path) -> None:
    """Default deny: empty SSH_LOCAL_TRANSFER_ROOTS ⇒ mode disabled.

    The message MUST name the env var so the operator can find the knob
    without grep'ing the codebase.
    """
    f = tmp_path / "a.txt"
    f.write_text("x")
    with pytest.raises(LocalPathPolicyError, match="SSH_LOCAL_TRANSFER_ROOTS"):
        resolve_local_path(str(f), Settings(), mode="read")


def test_path_outside_roots_rejected(tmp_path: Path) -> None:
    """Path that exists but lies outside any allowlisted root ⇒ reject."""
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    target = outside / "secret.txt"
    target.write_text("classified")

    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="outside the configured"):
        resolve_local_path(str(target), settings, mode="read")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_symlink_escape_attempt_rejected(tmp_path: Path) -> None:
    """A symlink inside the allowlist pointing OUTSIDE must be rejected.

    Resolve follows the link; is_relative_to then runs against the
    RESOLVED target, which lies outside any root.
    """
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "secret_dir"
    outside.mkdir()
    real_secret = outside / "secret.txt"
    real_secret.write_text("classified")

    trap = inside / "looks_innocent.txt"
    trap.symlink_to(real_secret)

    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="outside the configured"):
        resolve_local_path(str(trap), settings, mode="read")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_write_mode_symlinked_parent_escape_rejected(tmp_path: Path) -> None:
    """Write-mode: a symlinked PARENT directory that escapes the allowlist
    must be rejected even when the target file does not yet exist.

    Pins the docstring claim in `resolve_local_path` (mode="write"):
    rebuilding canonical on top of the strictly-resolved parent is what
    prevents a parent-symlink from smuggling a write outside an
    allowlisted root.
    """
    inside = tmp_path / "allowed"
    inside.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    # Trap: a symlink under the allowlist whose target is OUTSIDE.
    trap_parent = inside / "looks_local"
    trap_parent.symlink_to(outside)

    settings = _settings_with_roots(inside)
    target = trap_parent / "new.bin"  # target doesn't exist yet
    with pytest.raises(LocalPathPolicyError, match="outside the configured"):
        resolve_local_path(str(target), settings, mode="write")


def test_read_mode_missing_file_rejected(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="does not exist"):
        resolve_local_path(str(inside / "ghost.bin"), settings, mode="read")


def test_read_mode_directory_rejected(tmp_path: Path) -> None:
    """Read requires a REGULAR file; pointing at a directory must fail."""
    inside = tmp_path / "allowed"
    inside.mkdir()
    subdir = inside / "subdir"
    subdir.mkdir()
    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="not a regular file"):
        resolve_local_path(str(subdir), settings, mode="read")


def test_write_mode_missing_parent_rejected(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    settings = _settings_with_roots(inside)
    target = inside / "no_such_dir" / "out.bin"
    with pytest.raises(LocalPathPolicyError, match="parent directory"):
        resolve_local_path(str(target), settings, mode="write")


def test_write_mode_overwrites_existing_target(tmp_path: Path) -> None:
    """Write mode is fine with an EXISTING target -- matches the
    remote-side overwrite semantics for ssh_upload / ssh_deploy."""
    inside = tmp_path / "allowed"
    inside.mkdir()
    existing = inside / "rotated.log"
    existing.write_text("old contents")
    settings = _settings_with_roots(inside)
    out = resolve_local_path(str(existing), settings, mode="write")
    assert out == existing.resolve()


def test_read_mode_happy_path(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    f = inside / "in.bin"
    f.write_bytes(b"\x00\x01\x02")
    settings = _settings_with_roots(inside)
    out = resolve_local_path(str(f), settings, mode="read")
    assert out == f.resolve()


def test_write_mode_new_file_in_allowlisted_dir(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    settings = _settings_with_roots(inside)
    new_target = inside / "new.bin"
    out = resolve_local_path(str(new_target), settings, mode="write")
    # Path may or may not equal resolve() depending on whether tmp_path
    # itself is a symlinked location (varies by platform / runner). What
    # matters is that the result is inside the resolved root.
    assert out.is_relative_to(inside.resolve())


def test_empty_string_rejected(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="non-empty string"):
        resolve_local_path("", settings, mode="read")


def test_nul_byte_rejected(tmp_path: Path) -> None:
    inside = tmp_path / "allowed"
    inside.mkdir()
    settings = _settings_with_roots(inside)
    with pytest.raises(LocalPathPolicyError, match="NUL byte"):
        resolve_local_path("foo\x00bar", settings, mode="read")


def test_multiple_roots_first_match_wins(tmp_path: Path) -> None:
    """Multiple allowlisted roots are tried in order -- one matching root
    is enough for the call to succeed."""
    root_a = tmp_path / "a"
    root_a.mkdir()
    root_b = tmp_path / "b"
    root_b.mkdir()
    target = root_b / "file.bin"
    target.write_bytes(b"hi")
    settings = _settings_with_roots(root_a, root_b)
    out = resolve_local_path(str(target), settings, mode="read")
    assert out == target.resolve()
