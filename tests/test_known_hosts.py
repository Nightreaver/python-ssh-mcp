"""known_hosts loader behavior: missing file → empty (warn), present → lookup works."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ssh_mcp.ssh.known_hosts import KnownHosts

if TYPE_CHECKING:
    from pathlib import Path


def test_missing_file_yields_empty_kh(tmp_path: Path, caplog) -> None:
    caplog.set_level("WARNING", logger="ssh_mcp.ssh.known_hosts")
    kh = KnownHosts(tmp_path / "nope")
    assert kh.fingerprint_for("web01.internal") is None
    assert any("does not exist" in r.message for r in caplog.records)


def test_fingerprint_for_missing_host(tmp_path: Path) -> None:
    # Write an empty but valid known_hosts; lookup for unknown host returns None.
    (tmp_path / "kh").write_text("", encoding="utf-8")
    kh = KnownHosts(tmp_path / "kh")
    assert kh.fingerprint_for("never-seen.example") is None


def test_malformed_known_hosts_yields_none(tmp_path: Path) -> None:
    p = tmp_path / "kh"
    p.write_text("nonsense line that is not a valid entry\n", encoding="utf-8")
    kh = KnownHosts(p)
    # Should not raise; lookup returns None for anything.
    assert kh.fingerprint_for("anything") is None


def test_reload_picks_up_file_edits(tmp_path: Path) -> None:
    # Operator edits known_hosts mid-session (README three-step pin flow).
    # fingerprint_for() on the same KnownHosts instance must see the new entry
    # without a server restart.
    import asyncssh

    key_a = asyncssh.generate_private_key("ssh-ed25519")
    key_b = asyncssh.generate_private_key("ssh-ed25519")
    pub_a = key_a.export_public_key().decode("ascii").strip()
    pub_b = key_b.export_public_key().decode("ascii").strip()

    p = tmp_path / "kh"
    p.write_text(f"[host-a.internal]:22 {pub_a}\n", encoding="utf-8")

    kh = KnownHosts(p)
    assert kh.fingerprint_for("host-a.internal", 22) == key_a.get_fingerprint("sha256")
    assert kh.fingerprint_for("host-b.internal", 22) is None  # not pinned yet

    # Append the second host. Make the mtime change observable (fs resolution).
    import time

    time.sleep(0.01)
    with p.open("a", encoding="utf-8") as f:
        f.write(f"[host-b.internal]:22 {pub_b}\n")
    import os

    new_mtime = time.time() + 1
    os.utime(p, (new_mtime, new_mtime))

    # Without a restart, the new entry is visible.
    assert kh.fingerprint_for("host-b.internal", 22) == key_b.get_fingerprint("sha256")
    # And the original entry is still there.
    assert kh.fingerprint_for("host-a.internal", 22) == key_a.get_fingerprint("sha256")


def test_reload_keeps_previous_state_on_missing_file(tmp_path: Path, caplog) -> None:
    # If the file is removed after startup, keep the last-known parse rather
    # than falling back to empty-and-reject-everything.
    import os
    import time

    import asyncssh

    key = asyncssh.generate_private_key("ssh-ed25519")
    pub = key.export_public_key().decode("ascii").strip()

    p = tmp_path / "kh"
    p.write_text(f"[web01]:22 {pub}\n", encoding="utf-8")

    kh = KnownHosts(p)
    assert kh.fingerprint_for("web01", 22) is not None

    # Remove the file. The next lookup should not crash and should keep
    # returning the cached fingerprint.
    p.unlink()
    assert kh.fingerprint_for("web01", 22) is not None

    # Re-create the file; the reload kicks back in.
    p.write_text(f"[web01]:22 {pub}\n", encoding="utf-8")
    new_mtime = time.time() + 2
    os.utime(p, (new_mtime, new_mtime))
    assert kh.fingerprint_for("web01", 22) is not None


def test_fingerprint_for_resolves_real_entry(tmp_path: Path) -> None:
    # Regression guard for the silently-returning-None bug: an earlier version
    # unpacked 3 values from asyncssh's 7-tuple match() return and caught
    # ValueError, so fingerprint_for() returned None for *every* lookup.
    # We generate a real ed25519 keypair here so the whole match path is
    # exercised end-to-end against a key asyncssh actually accepts.
    import asyncssh

    key = asyncssh.generate_private_key("ssh-ed25519")
    pubkey_line = key.export_public_key().decode("ascii").strip()
    _algo, _pubkey_b64 = pubkey_line.split(None, 1)[0], pubkey_line.split(None, 1)[1]

    p = tmp_path / "kh"
    p.write_text(f"[example.internal]:2222 {pubkey_line}\n", encoding="utf-8")

    kh = KnownHosts(p)
    fp = kh.fingerprint_for("example.internal", 2222)
    assert fp is not None, (
        "fingerprint_for returned None for an entry that is literally in the file"
    )
    assert fp.startswith("SHA256:")
    # The fingerprint we derive matches the one asyncssh reports for the same key.
    assert fp == key.get_fingerprint("sha256")
    # Wrong host -> no match.
    assert kh.fingerprint_for("other.internal", 2222) is None
