"""services/host_policy.resolve — blocklist wins, allowlist required."""
from __future__ import annotations

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.host_policy import check_policy, resolve
from ssh_mcp.ssh.errors import HostBlocked, HostNotAllowed


def _policy(name: str = "web01.internal", user: str = "deploy") -> HostPolicy:
    return HostPolicy(hostname=name, user=user, port=22, auth=AuthPolicy(method="agent"))


def _settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "SSH_HOSTS_ALLOWLIST": [],
        "SSH_HOSTS_BLOCKLIST": [],
        "SSH_HOSTS_FILE": None,
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


# --- allowlist path ---


def test_resolve_from_hosts_toml_by_alias() -> None:
    hosts = {"web": _policy("web01.internal")}
    assert resolve("web", hosts, _settings()).hostname == "web01.internal"


def test_resolve_from_hosts_toml_by_hostname() -> None:
    hosts = {"web": _policy("web01.internal")}
    assert resolve("web01.internal", hosts, _settings()).hostname == "web01.internal"


def test_resolve_from_env_allowlist_builds_minimal_policy() -> None:
    s = _settings(SSH_HOSTS_ALLOWLIST=["web01.internal"], SSH_DEFAULT_USER="deploy")
    policy = resolve("web01.internal", {}, s)
    assert policy.hostname == "web01.internal"
    assert policy.user == "deploy"
    assert policy.auth.method == "agent"


def test_unknown_host_raises_not_allowed() -> None:
    with pytest.raises(HostNotAllowed, match="ghost"):
        resolve("ghost.example", {"web": _policy()}, _settings())


def test_empty_registry_and_empty_allowlist_is_default_deny() -> None:
    with pytest.raises(HostNotAllowed, match="no hosts configured"):
        resolve("anywhere", {}, _settings())


# --- blocklist wins ---


def test_blocklist_on_alias_is_IGNORED_use_hostname() -> None:
    # ADR-0019: blocklist evaluates on canonical hostname only.
    # The alias is just a lookup key; putting the alias in the blocklist does nothing.
    hosts = {"prod-db": _policy("prod-db.internal")}
    s = _settings(SSH_HOSTS_BLOCKLIST=["prod-db"])  # alias, not hostname
    # Resolution succeeds because the CANONICAL hostname is not blocked.
    result = resolve("prod-db", hosts, s)
    assert result.hostname == "prod-db.internal"


def test_blocklist_by_hostname_after_alias_lookup() -> None:
    hosts = {"db": _policy("prod-db.internal")}
    s = _settings(SSH_HOSTS_BLOCKLIST=["prod-db.internal"])
    with pytest.raises(HostBlocked, match="prod-db.internal"):
        resolve("db", hosts, s)


def test_blocklist_wins_over_env_allowlist() -> None:
    s = _settings(
        SSH_HOSTS_ALLOWLIST=["prod-db.internal"],
        SSH_HOSTS_BLOCKLIST=["prod-db.internal"],
    )
    with pytest.raises(HostBlocked):
        resolve("prod-db.internal", {}, s)


def test_unknown_blocked_host_reports_NotAllowed_not_Blocked() -> None:
    # ADR-0019: blocklist is evaluated AFTER resolution. An unknown host can
    # never pass resolution, so it surfaces as HostNotAllowed regardless of
    # whether it also appears on the blocklist.
    s = _settings(SSH_HOSTS_BLOCKLIST=["ghost.example"])
    with pytest.raises(HostNotAllowed):
        resolve("ghost.example", {}, s)


# --- check_policy (defense-in-depth) ---


def test_check_policy_raises_for_blocked_hostname() -> None:
    s = _settings(SSH_HOSTS_BLOCKLIST=["prod-db.internal"])
    with pytest.raises(HostBlocked):
        check_policy(_policy("prod-db.internal"), s)


def test_check_policy_allows_unblocked() -> None:
    check_policy(_policy("web01.internal"), _settings())


# --- config CSV parsing ---


def test_csv_env_string_splits_to_list() -> None:
    s = Settings(SSH_HOSTS_ALLOWLIST="a,b, c ,", SSH_HOSTS_BLOCKLIST="x")  # type: ignore[arg-type]
    assert s.SSH_HOSTS_ALLOWLIST == ["a", "b", "c"]
    assert s.SSH_HOSTS_BLOCKLIST == ["x"]


def test_empty_csv_yields_empty_list() -> None:
    s = Settings(SSH_HOSTS_ALLOWLIST="", SSH_HOSTS_BLOCKLIST="  ")  # type: ignore[arg-type]
    assert s.SSH_HOSTS_ALLOWLIST == []
    assert s.SSH_HOSTS_BLOCKLIST == []


def test_json_array_still_parses() -> None:
    s = Settings(SSH_HOSTS_ALLOWLIST='["a","b"]')  # type: ignore[arg-type]
    assert s.SSH_HOSTS_ALLOWLIST == ["a", "b"]
