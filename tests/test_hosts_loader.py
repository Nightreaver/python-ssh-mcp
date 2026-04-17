"""hosts.toml loader tests — see DESIGN.md §5.7 and ADR-0003/0004."""
from __future__ import annotations

from textwrap import dedent
from typing import TYPE_CHECKING

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.hosts import HostsConfigError, load_hosts, merged_host_allowlist

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "hosts.toml"
    p.write_text(dedent(body), encoding="utf-8")
    return p


def _settings(**overrides: object) -> Settings:
    defaults = {
        "SSH_DEFAULT_USER": "deploy",
        "SSH_HOSTS_ALLOWLIST": [],
        "ALLOW_DANGEROUS_TOOLS": False,
        "ALLOW_PASSWORD_AUTH": False,
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_hosts(tmp_path / "nope.toml", _settings()) == {}


def test_none_path_returns_empty() -> None:
    assert load_hosts(None, _settings()) == {}


def test_minimal_host_applies_defaults(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [defaults]
        user = "deploy"
        port = 2222

        [hosts.web01]
        hostname = "web01.internal"
        """,
    )
    hosts = load_hosts(path, _settings())
    assert set(hosts) == {"web01"}
    assert hosts["web01"].user == "deploy"
    assert hosts["web01"].port == 2222
    assert hosts["web01"].auth.method == "agent"


def test_per_host_overrides_defaults(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [defaults]
        user = "deploy"

        [hosts.db01]
        hostname = "db01.internal"
        user = "dbadmin"

        [hosts.db01.auth]
        method = "agent"
        identity_fingerprint = "SHA256:abcdefghij1234567890"
        identities_only = true
        """,
    )
    hosts = load_hosts(path, _settings())
    assert hosts["db01"].user == "dbadmin"
    assert hosts["db01"].auth.identity_fingerprint == "SHA256:abcdefghij1234567890"
    assert hosts["db01"].auth.identities_only is True


def test_unknown_proxy_jump_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "deploy"
        proxy_jump = "ghost"
        """,
    )
    with pytest.raises(HostsConfigError, match="unknown host 'ghost'"):
        load_hosts(path, _settings())


def test_circular_proxy_chain_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.a]
        hostname = "a.internal"
        user = "x"
        proxy_jump = "b"

        [hosts.b]
        hostname = "b.internal"
        user = "x"
        proxy_jump = "a"
        """,
    )
    with pytest.raises(HostsConfigError, match="circular"):
        load_hosts(path, _settings())


def test_relative_path_in_allowlist_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "deploy"
        path_allowlist = ["relative/path"]
        """,
    )
    with pytest.raises(HostsConfigError, match="absolute"):
        load_hosts(path, _settings())


def test_password_auth_refused_by_default(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.legacy]
        hostname = "legacy.internal"
        user = "root"

        [hosts.legacy.auth]
        method = "password"
        password_cmd = "echo hunter2"
        """,
    )
    with pytest.raises(HostsConfigError, match="ALLOW_PASSWORD_AUTH=false"):
        load_hosts(path, _settings())


def test_password_auth_allowed_when_flag_set(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.legacy]
        hostname = "legacy.internal"
        user = "root"

        [hosts.legacy.auth]
        method = "password"
        password_cmd = "echo hunter2"
        """,
    )
    hosts = load_hosts(path, _settings(ALLOW_PASSWORD_AUTH=True))
    assert hosts["legacy"].auth.method == "password"


def test_fingerprint_shape_validated(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.db01]
        hostname = "db01.internal"
        user = "x"

        [hosts.db01.auth]
        method = "agent"
        identity_fingerprint = "MD5:abc"
        """,
    )
    with pytest.raises(HostsConfigError, match="SHA256"):
        load_hosts(path, _settings())


def test_bad_toml_surfaces_helpful_error(tmp_path: Path) -> None:
    p = tmp_path / "hosts.toml"
    p.write_text("[hosts.web01\nhostname = bad", encoding="utf-8")
    with pytest.raises(HostsConfigError):
        load_hosts(p, _settings())


def test_merged_allowlist_union(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.a]
        hostname = "a.internal"
        user = "x"

        [hosts.b]
        hostname = "b.internal"
        user = "x"
        """,
    )
    hosts = load_hosts(path, _settings(SSH_HOSTS_ALLOWLIST=["c", "d"]))
    merged = merged_host_allowlist(hosts, _settings(SSH_HOSTS_ALLOWLIST=["c", "d"]))
    assert merged == {"a", "b", "c", "d"}


def test_proxy_jump_list_accepted(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [hosts.bastion1]
        hostname = "b1.internal"
        user = "x"

        [hosts.bastion2]
        hostname = "b2.internal"
        user = "x"

        [hosts.target]
        hostname = "t.internal"
        user = "x"
        proxy_jump = ["bastion1", "bastion2"]
        """,
    )
    hosts = load_hosts(path, _settings())
    assert hosts["target"].proxy_chain() == ["bastion1", "bastion2"]


def test_warns_on_wildcard_command_allowlist(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    # After INC-012 + the wildcard sentinel: empty command_allowlist is
    # fail-closed and needs no warning. But `command_allowlist = ["*"]` (or
    # empty + ALLOW_ANY_COMMAND=true) widens scope to every command and SHOULD
    # log a warning so the decision is grep-able in operator logs.
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "x"
        command_allowlist = ["*"]
        """,
    )
    caplog.set_level("WARNING", logger="ssh_mcp.hosts")
    load_hosts(path, _settings(ALLOW_DANGEROUS_TOOLS=True))
    assert any("wildcard command_allowlist" in r.message for r in caplog.records)


def test_warns_on_wildcard_path_without_restricted_paths(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Wildcard path_allowlist + no restricted_paths covering /etc/shadow,
    /etc/sudoers, /etc/ssh, ~/.ssh -> remind operator (mcp-ssh-manager#13)."""
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "x"
        path_allowlist = ["*"]
        """,
    )
    caplog.set_level("WARNING", logger="ssh_mcp.hosts")
    load_hosts(path, _settings())
    msgs = [r.message for r in caplog.records]
    assert any("wildcard path_allowlist" in m for m in msgs)
    assert any("restricted_paths" in m and "/etc/shadow" in m for m in msgs)


def test_no_restricted_paths_hint_when_operator_set_them(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """When the operator already covers the recommended zones, don't nag."""
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "x"
        path_allowlist = ["*"]
        restricted_paths = ["/etc/shadow", "/etc/sudoers", "/etc/ssh"]
        """,
    )
    caplog.set_level("WARNING", logger="ssh_mcp.hosts")
    load_hosts(path, _settings())
    msgs = [r.message for r in caplog.records]
    # Wildcard warning still fires (intentional), but the restricted_paths
    # nag must NOT appear.
    assert any("wildcard path_allowlist" in m for m in msgs)
    assert not any("restricted_paths" in m and "/etc/shadow" in m for m in msgs)


def test_empty_command_allowlist_is_silent_when_failclosed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Empty + ALLOW_ANY_COMMAND=false = every call rejected by check_command.
    # No warning: the fail-closed state is the safe default, not a risky config.
    path = _write(
        tmp_path,
        """
        [hosts.web01]
        hostname = "web01.internal"
        user = "x"
        """,
    )
    caplog.set_level("WARNING", logger="ssh_mcp.hosts")
    load_hosts(path, _settings(ALLOW_DANGEROUS_TOOLS=True))  # ALLOW_ANY_COMMAND default = false
    assert not any("command_allowlist" in r.message for r in caplog.records)
