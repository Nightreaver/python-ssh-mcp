"""services/path_policy -- restricted_globs (v1.5.0).

Covers:

- glob matches / misses
- combined prefix + glob deny (both lists hit, both should refuse)
- POSIX vs Windows platform handling
"""

from __future__ import annotations

import pytest

from ssh_mcp.services.path_policy import check_not_restricted
from ssh_mcp.ssh.errors import PathRestricted


def test_glob_match_rejects() -> None:
    with pytest.raises(PathRestricted, match="restricted glob"):
        check_not_restricted(
            "/opt/app/.env",
            restricted=[],
            restricted_globs=["**/.env"],
        )


def test_glob_miss_allows() -> None:
    # Not a match -- function should not raise.
    check_not_restricted(
        "/opt/app/main.py",
        restricted=[],
        restricted_globs=["**/.env"],
    )


def test_glob_secrets_dir() -> None:
    with pytest.raises(PathRestricted):
        check_not_restricted(
            "/opt/app/secrets/token.txt",
            restricted=[],
            restricted_globs=["**/secrets/*"],
        )


def test_prefix_still_applies_alongside_glob() -> None:
    # Prefix hits first -- the prefix message must surface, not the glob one.
    with pytest.raises(PathRestricted, match="restricted zone"):
        check_not_restricted(
            "/mnt/shared/data.csv",
            restricted=["/mnt/shared"],
            restricted_globs=["**/secrets/*"],
        )


def test_glob_hits_when_prefix_misses() -> None:
    with pytest.raises(PathRestricted, match="restricted glob"):
        check_not_restricted(
            "/opt/app/.env",
            restricted=["/mnt/shared"],  # prefix doesn't match
            restricted_globs=["**/.env"],  # glob does
        )


def test_empty_globs_list_is_noop() -> None:
    # restricted_globs=None and restricted_globs=[] are both no-ops.
    check_not_restricted("/opt/app/file", restricted=[], restricted_globs=None)
    check_not_restricted("/opt/app/file", restricted=[], restricted_globs=[])


def test_windows_platform_glob_match() -> None:
    with pytest.raises(PathRestricted):
        check_not_restricted(
            "C:\\opt\\app\\.env",
            restricted=[],
            platform="windows",
            restricted_globs=["**/.env"],
        )


def test_windows_platform_glob_miss() -> None:
    check_not_restricted(
        "C:\\opt\\app\\main.py",
        restricted=[],
        platform="windows",
        restricted_globs=["**/.env"],
    )


def test_multiple_globs_first_match_wins() -> None:
    # We don't care which glob's name is in the message; just that it raises.
    with pytest.raises(PathRestricted):
        check_not_restricted(
            "/opt/private_data",
            restricted=[],
            restricted_globs=["**/.env", "**/private*"],
        )
