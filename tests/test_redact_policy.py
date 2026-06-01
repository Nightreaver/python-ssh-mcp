"""services/redact_policy -- settings resolution + glob matching.

Covers:

- ``redact_keys_add`` vs ``redact_keys_replace`` mutex (env + per-host)
- per-host override of every redact knob
- defaults round-trip
- glob matching (POSIX + Windows)
- bypass-mode resolution
"""

from __future__ import annotations

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.redact_policy import (
    check_redact_bypass,
    default_redact_keys,
    path_matches_redact_globs,
    resolve_bypass_policy,
    resolve_entropy_detection,
    resolve_hint_chars,
    resolve_redact_keys,
    resolve_redact_paths_globs,
    resolve_restricted_globs,
    resolve_salt,
    should_block_redact_bypass,
)


def _settings(**kwargs: object) -> Settings:
    base: dict[str, object] = {"SSH_HOSTS_ALLOWLIST": ["h"]}
    base.update(kwargs)
    return Settings(**base)  # type: ignore[arg-type]


def _policy(**kwargs: object) -> HostPolicy:
    base: dict[str, object] = {"hostname": "h", "user": "u", "auth": AuthPolicy(method="agent")}
    base.update(kwargs)
    return HostPolicy(**base)  # type: ignore[arg-type]


# --- defaults ------------------------------------------------------------


def test_defaults_alone_yield_builtin_set() -> None:
    settings = _settings()
    policy = _policy()
    keys = resolve_redact_keys(policy, settings)
    assert keys == default_redact_keys()
    # Sanity: a couple of well-known tokens must be present.
    assert "PASSWORD" in keys
    assert "API_KEY" in keys
    assert "JWT" in keys


# --- add (per-host + env) -----------------------------------------------


def test_env_add_appends_to_defaults() -> None:
    settings = _settings(SSH_REDACT_KEYS_ADD=["MY_TOKEN"])
    policy = _policy()
    keys = resolve_redact_keys(policy, settings)
    assert "MY_TOKEN" in keys
    # Defaults still present.
    assert "PASSWORD" in keys


def test_host_add_appends_to_env_add_and_defaults() -> None:
    settings = _settings(SSH_REDACT_KEYS_ADD=["ENV_ONE"])
    policy = _policy(redact_keys_add=["HOST_ONE"])
    keys = resolve_redact_keys(policy, settings)
    assert "ENV_ONE" in keys
    assert "HOST_ONE" in keys
    assert "PASSWORD" in keys


# --- replace -------------------------------------------------------------


def test_env_replace_swaps_out_defaults() -> None:
    settings = _settings(SSH_REDACT_KEYS_REPLACE=["ONLY_THIS"])
    policy = _policy()
    keys = resolve_redact_keys(policy, settings)
    assert keys == frozenset({"ONLY_THIS"})


def test_host_replace_wins_over_env() -> None:
    settings = _settings(SSH_REDACT_KEYS_ADD=["WOULD_APPEND"])
    policy = _policy(redact_keys_replace=["HOST_ONLY"])
    keys = resolve_redact_keys(policy, settings)
    # host REPLACE wins outright; env ADD ignored, defaults dropped
    assert keys == frozenset({"HOST_ONLY"})


def test_host_replace_normalizes_case() -> None:
    settings = _settings()
    policy = _policy(redact_keys_replace=["lowercase_secret"])
    keys = resolve_redact_keys(policy, settings)
    assert keys == frozenset({"LOWERCASE_SECRET"})


# --- mutex (env) ---------------------------------------------------------


def test_env_keys_add_and_replace_mutex() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        Settings(  # type: ignore[call-arg]
            SSH_HOSTS_ALLOWLIST=["h"],
            SSH_REDACT_KEYS_ADD=["A"],
            SSH_REDACT_KEYS_REPLACE=["B"],
        )


def test_env_salt_minimum_length() -> None:
    with pytest.raises(ValueError, match="at least 32 chars"):
        Settings(  # type: ignore[call-arg]
            SSH_HOSTS_ALLOWLIST=["h"],
            SSH_REDACT_SALT="too short",
        )


def test_env_salt_exactly_32_accepted() -> None:
    # 32 chars is the lower bound. Accept it.
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_ALLOWLIST=["h"],
        SSH_REDACT_SALT="a" * 32,
    )
    assert resolve_salt(settings) == "a" * 32


def test_env_hint_chars_out_of_range_rejected() -> None:
    with pytest.raises(ValueError, match=r"\[0, 4\]"):
        Settings(  # type: ignore[call-arg]
            SSH_HOSTS_ALLOWLIST=["h"],
            SSH_REDACT_HINT_CHARS=5,
        )
    with pytest.raises(ValueError, match=r"\[0, 4\]"):
        Settings(  # type: ignore[call-arg]
            SSH_HOSTS_ALLOWLIST=["h"],
            SSH_REDACT_HINT_CHARS=-1,
        )


# --- mutex (per-host) ----------------------------------------------------


def test_host_keys_add_and_replace_mutex() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="mutually exclusive"):
        HostPolicy(
            hostname="h",
            user="u",
            auth=AuthPolicy(method="agent"),
            redact_keys_add=["A"],
            redact_keys_replace=["B"],
        )


def test_host_hint_chars_out_of_range_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=r"\[0, 4\]"):
        HostPolicy(
            hostname="h",
            user="u",
            auth=AuthPolicy(method="agent"),
            redact_hint_chars=5,
        )


# --- per-host override of every knob -------------------------------------


def test_host_bypass_policy_overrides_env() -> None:
    settings = _settings(SSH_REDACT_BYPASS_POLICY="block")
    policy = _policy(redact_bypass_policy="warn")
    assert resolve_bypass_policy(policy, settings) == "warn"


def test_host_bypass_policy_none_inherits_env() -> None:
    settings = _settings(SSH_REDACT_BYPASS_POLICY="block")
    policy = _policy()
    assert resolve_bypass_policy(policy, settings) == "block"


def test_host_entropy_detection_overrides_env() -> None:
    settings = _settings(SSH_REDACT_ENTROPY_DETECTION=True)
    policy = _policy(redact_entropy_detection=False)
    assert resolve_entropy_detection(policy, settings) is False


def test_host_entropy_detection_none_inherits_env() -> None:
    settings = _settings(SSH_REDACT_ENTROPY_DETECTION=False)
    policy = _policy()
    assert resolve_entropy_detection(policy, settings) is False


def test_host_hint_chars_overrides_env_and_clamps() -> None:
    settings = _settings(SSH_REDACT_HINT_CHARS=1)
    policy = _policy(redact_hint_chars=3)
    assert resolve_hint_chars(policy, settings) == 3


def test_host_hint_chars_none_inherits_env() -> None:
    settings = _settings(SSH_REDACT_HINT_CHARS=2)
    policy = _policy()
    assert resolve_hint_chars(policy, settings) == 2


def test_redact_paths_globs_union() -> None:
    settings = _settings(SSH_REDACT_PATHS_GLOBS=["**/.env"])
    policy = _policy(redact_paths_globs=["/opt/app/*.secret"])
    merged = resolve_redact_paths_globs(policy, settings)
    assert "/opt/app/*.secret" in merged
    assert "**/.env" in merged
    # host-first order
    assert merged.index("/opt/app/*.secret") < merged.index("**/.env")


def test_restricted_globs_union() -> None:
    settings = _settings(SSH_RESTRICTED_GLOBS=["**/private*"])
    policy = _policy(restricted_globs=["/mnt/secret/**"])
    merged = resolve_restricted_globs(policy, settings)
    assert "/mnt/secret/**" in merged
    assert "**/private*" in merged


# --- glob matching -------------------------------------------------------


def test_glob_matches_env_file_anywhere() -> None:
    assert path_matches_redact_globs("/opt/app/.env", ["**/.env"])
    assert path_matches_redact_globs("/etc/.env", ["**/.env"])


def test_glob_does_not_match_unrelated_file() -> None:
    assert not path_matches_redact_globs("/opt/app/main.py", ["**/.env"])


def test_glob_empty_list_returns_false() -> None:
    assert not path_matches_redact_globs("/anything", [])


def test_glob_windows_platform() -> None:
    assert path_matches_redact_globs(
        "C:\\opt\\app\\.env",
        ["**/.env"],
        platform="windows",
    )


# --- bypass resolution ---------------------------------------------------


def test_should_block_only_when_block_mode() -> None:
    settings = _settings(
        SSH_REDACT_PATHS_GLOBS=["**/.env"],
        SSH_REDACT_BYPASS_POLICY="warn",
    )
    policy = _policy()
    # warn mode → block returns False even on a matching path
    assert should_block_redact_bypass("/opt/app/.env", policy, settings) is False

    settings = _settings(
        SSH_REDACT_PATHS_GLOBS=["**/.env"],
        SSH_REDACT_BYPASS_POLICY="block",
    )
    assert should_block_redact_bypass("/opt/app/.env", policy, settings) is True
    # Non-matching path: still False even in block mode
    assert should_block_redact_bypass("/opt/app/main.py", policy, settings) is False


def test_check_redact_bypass_returns_mode_or_none() -> None:
    settings = _settings(
        SSH_REDACT_PATHS_GLOBS=["**/.env"],
        SSH_REDACT_BYPASS_POLICY="warn",
    )
    policy = _policy()
    assert check_redact_bypass("/opt/app/.env", policy, settings) == "warn"
    assert check_redact_bypass("/opt/app/main.py", policy, settings) is None
