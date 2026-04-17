"""services/exec_policy — command allowlist enforcement."""
from __future__ import annotations

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.exec_policy import (
    CommandNotAllowed,
    check_command,
    effective_command_allowlist,
)


def _policy(cmds: list[str] | None = None) -> HostPolicy:
    return HostPolicy(
        hostname="web01.internal",
        user="deploy",
        port=22,
        command_allowlist=cmds or [],
        auth=AuthPolicy(method="agent"),
    )


def _settings(cmds: list[str] | None = None, allow_any: bool = False) -> Settings:
    return Settings(  # type: ignore[call-arg]
        SSH_HOSTS_ALLOWLIST=["web01.internal"],
        SSH_COMMAND_ALLOWLIST=cmds or [],
        ALLOW_ANY_COMMAND=allow_any,
    )


def test_empty_allowlist_denies_by_default() -> None:
    # ADR-0018: empty allowlist is fail-closed.
    with pytest.raises(CommandNotAllowed, match="no command_allowlist"):
        check_command("ls /", _policy(), _settings())


def test_empty_allowlist_allows_with_explicit_opt_in() -> None:
    check_command("rm -rf /", _policy(), _settings(allow_any=True))  # does not raise


def test_bare_program_match() -> None:
    check_command("systemctl reload nginx", _policy(["systemctl"]), _settings())


def test_absolute_path_matches_by_basename() -> None:
    check_command("/usr/bin/systemctl status nginx", _policy(["systemctl"]), _settings())


def test_wildcard_sentinel_allows_any_command() -> None:
    # Symmetric with path_allowlist = ["*"]. Per-host opt-in; startup warns.
    check_command("curl https://evil", _policy(["*"]), _settings())
    check_command("rm -rf /", _policy(["*"]), _settings())
    check_command("/opt/rogue/anything", _policy(["*"]), _settings())


def test_wildcard_sentinel_via_env_allowlist() -> None:
    # Env-level SSH_COMMAND_ALLOWLIST=["*"] has the same effect across every host.
    check_command("anything", _policy(), _settings(["*"]))


def test_absolute_allowlist_entry_requires_exact_match() -> None:
    # INC-012: when the allowlist entry is fully qualified, basename matching
    # is disabled so a rogue /opt/evil/systemctl cannot sneak in.
    check_command("/usr/bin/systemctl status nginx", _policy(["/usr/bin/systemctl"]), _settings())
    with pytest.raises(CommandNotAllowed):
        check_command("/opt/evil/systemctl status nginx", _policy(["/usr/bin/systemctl"]), _settings())


def test_program_not_in_allowlist_rejected() -> None:
    with pytest.raises(CommandNotAllowed, match="'curl'"):
        check_command("curl https://evil", _policy(["systemctl", "nginx"]), _settings())


def test_quoted_argument_does_not_bypass_check() -> None:
    # `"systemctl" status` parses via shlex; first token is `systemctl`.
    check_command('"systemctl" status nginx', _policy(["systemctl"]), _settings())


def test_env_and_host_allowlists_union() -> None:
    merged = effective_command_allowlist(_policy(["systemctl"]), _settings(["nginx", "systemctl"]))
    assert merged == ["systemctl", "nginx"]  # order preserved, deduped


def test_empty_command_rejected() -> None:
    with pytest.raises(CommandNotAllowed, match="empty"):
        check_command("   ", _policy(["ls"]), _settings())


def test_malformed_shell_syntax_rejected() -> None:
    with pytest.raises(CommandNotAllowed, match="failed to parse"):
        check_command('"unclosed', _policy(["ls"]), _settings())
