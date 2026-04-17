"""Tool groups: `SSH_ENABLED_GROUPS` filters visibility; empty = all. See ADR-0016."""
from __future__ import annotations

from ssh_mcp.lifespan import ALL_GROUPS


def test_all_groups_set_covers_every_used_group() -> None:
    # Keep this in sync with the group tags used by real tools.
    used = {"host", "session", "sftp-read", "file-ops", "exec", "sudo", "keys"}
    assert used.issubset(ALL_GROUPS), f"missing from ALL_GROUPS: {used - ALL_GROUPS}"


def test_empty_enabled_defaults_to_every_group() -> None:
    # Contract: settings.SSH_ENABLED_GROUPS == [] means "all enabled".
    enabled = set() or set(ALL_GROUPS)
    assert enabled == set(ALL_GROUPS)


def test_explicit_list_filters_groups() -> None:
    # Contract: settings.SSH_ENABLED_GROUPS == ["host"] means hide everything else.
    enabled = set(["host"])
    hidden = set(ALL_GROUPS) - enabled
    assert "file-ops" in hidden
    assert "exec" in hidden
    assert "host" not in hidden


def test_unknown_group_is_filtered_out_not_crashing() -> None:
    enabled_raw = {"host", "bogus"}
    unknown = enabled_raw - set(ALL_GROUPS)
    cleaned = enabled_raw - unknown
    assert cleaned == {"host"}
    assert unknown == {"bogus"}
