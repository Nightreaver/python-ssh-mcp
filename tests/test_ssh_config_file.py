"""SSH_CONFIG_FILE wiring (INC-051 / classfang/ssh-mcp-server#22).

Pins the contract: when the operator sets `SSH_CONFIG_FILE`, the path is
expanded and forwarded to `asyncssh.connect(config=[...])`. When unset, no
`config` kwarg is passed (asyncssh then ignores the OpenSSH client config
entirely, which matches our pre-INC-051 behavior).

Empty-string env values (`SSH_CONFIG_FILE=` in `.env`) are normalized to
None by the field validator, so they don't smuggle a `Path("")` through.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.ssh.connection import _open_single
from ssh_mcp.ssh.known_hosts import KnownHosts


class _StopHere(RuntimeError):
    """Raised by the fake asyncssh.connect to abort before networking."""


def _capture_connect_kwargs(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    async def fake_connect(**kwargs: Any) -> None:
        captured.update(kwargs)
        raise _StopHere

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    return captured


def _policy() -> HostPolicy:
    return HostPolicy(hostname="example", user="root", auth=AuthPolicy(method="agent"))


@pytest.mark.asyncio
async def test_open_single_passes_config_when_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config_file = tmp_path / "ssh_config"
    config_file.write_text("Host example\n  HostName real.example.com\n", encoding="utf-8")

    captured = _capture_connect_kwargs(monkeypatch)
    settings = Settings(SSH_CONFIG_FILE=config_file)  # type: ignore[arg-type]
    known_hosts = KnownHosts(tmp_path / "missing_known_hosts")

    with pytest.raises(_StopHere):
        await _open_single(_policy(), settings, known_hosts, tunnel=None)

    assert captured["config"] == [str(config_file)]


@pytest.mark.asyncio
async def test_open_single_omits_config_when_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _capture_connect_kwargs(monkeypatch)
    settings = Settings()  # SSH_CONFIG_FILE defaults to None
    known_hosts = KnownHosts(tmp_path / "missing_known_hosts")

    with pytest.raises(_StopHere):
        await _open_single(_policy(), settings, known_hosts, tunnel=None)

    assert "config" not in captured


@pytest.mark.asyncio
async def test_open_single_expands_tilde_in_config_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """asyncssh would also expand `~`, but pydantic's Path coercion does not.

    We must call `.expanduser()` ourselves before stringifying so the path
    that reaches asyncssh is absolute. Using HOME=tmp_path gives a stable
    expansion target on every OS without touching the operator's real $HOME.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows fallback

    captured = _capture_connect_kwargs(monkeypatch)
    settings = Settings(SSH_CONFIG_FILE=Path("~/ssh_config"))  # type: ignore[arg-type]
    known_hosts = KnownHosts(tmp_path / "missing_known_hosts")

    with pytest.raises(_StopHere):
        await _open_single(_policy(), settings, known_hosts, tunnel=None)

    expanded = str(tmp_path / "ssh_config")
    assert captured["config"] == [expanded]


def test_empty_env_string_normalizes_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """`.env.example` ships `SSH_CONFIG_FILE=` (blank). Without the validator,
    pydantic would coerce that to `Path('')` (truthy, points at CWD), and
    every connection would smuggle a bogus config path into asyncssh."""
    monkeypatch.setenv("SSH_CONFIG_FILE", "")
    settings = Settings()
    assert settings.SSH_CONFIG_FILE is None


def test_whitespace_only_env_string_normalizes_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_CONFIG_FILE", "   ")
    settings = Settings()
    assert settings.SSH_CONFIG_FILE is None
