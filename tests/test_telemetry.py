"""telemetry.redact_argv + span() noop behavior + wiring regression."""
from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

from ssh_mcp.telemetry import redact_argv, redact_command_string, span

if TYPE_CHECKING:
    import pytest


def test_redact_password_flag_preserves_length() -> None:
    argv = ["curl", "--password=hunter2", "https://example"]
    out = redact_argv(argv)
    assert out == ["curl", "--password=<redacted:7>", "https://example"]


def test_redact_token_bare_flag() -> None:
    argv = ["myapp", "token=abc123"]
    assert redact_argv(argv) == ["myapp", "token=<redacted:6>"]


def test_redact_case_insensitive() -> None:
    argv = ["x", "--API_KEY=deadbeef"]
    assert redact_argv(argv) == ["x", "--API_KEY=<redacted:8>"]


def test_non_secret_args_untouched() -> None:
    argv = ["ls", "-la", "/opt/app"]
    assert redact_argv(argv) == argv


def test_empty_secret_value_still_redacted() -> None:
    assert redact_argv(["--token="]) == ["--token=<redacted:0>"]


# --- redact_command_string (raw-string commands) -----------------------------


def test_redact_command_string_password() -> None:
    cmd = "mysql -uroot --password=hunter2 -e SELECT 1"
    out = redact_command_string(cmd)
    assert out == "mysql -uroot --password=<redacted:7> -e SELECT 1"


def test_redact_command_string_token_in_pipeline() -> None:
    cmd = "curl -H X --token=abc123 https://example | jq ."
    out = redact_command_string(cmd)
    assert out == "curl -H X --token=<redacted:6> https://example | jq ."


def test_redact_command_string_multiple_secrets() -> None:
    cmd = "myapp --api-key=k1234 --secret=ssss"
    out = redact_command_string(cmd)
    assert out == "myapp --api-key=<redacted:5> --secret=<redacted:4>"


def test_redact_command_string_non_secret_untouched() -> None:
    cmd = "git log --oneline --since=2026-01-01 --author=alice"
    assert redact_command_string(cmd) == cmd


def test_redact_command_string_substring_not_matched() -> None:
    # `--no-password` and `xpassword=foo` should NOT match -- they're not the
    # secret-flag we're looking for.
    cmd = "tool --no-password xpassword=foo"
    assert redact_command_string(cmd) == cmd


def test_span_noop_accepts_set_attribute() -> None:
    # Without OTel installed, span() returns a noop that tolerates set_attribute.
    with span("ssh.exec", host="web01.internal") as s:
        s.set_attribute("ssh.exit_code", 0)
        s.set_attribute("ssh.duration_ms", 42)
        s.record_exception(ValueError("boom"))


# --- Wiring regression -------------------------------------------------------
# These tests assert each module that should open a span actually does. They
# guard the BACKLOG Phase 5 wiring item -- a refactor that drops the `with
# span(...)` block here would let traces silently disappear in production.


class _SpyContext:
    """Replacement for span(): records (name, attrs) without doing OTel work."""

    def __init__(self, name: str, attrs: dict[str, Any]) -> None:
        self.name = name
        self.attrs = attrs
        self.set_attrs: dict[str, Any] = {}

    def __enter__(self) -> _SpyContext:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def set_attribute(self, key: str, value: Any) -> None:
        self.set_attrs[key] = value

    def record_exception(self, _exc: BaseException) -> None:
        return None


def _make_spy(records: list[_SpyContext]) -> Any:
    @contextlib.contextmanager
    def fake_span(name: str, **attrs: Any):  # type: ignore[no-untyped-def]
        ctx = _SpyContext(name, attrs)
        records.append(ctx)
        yield ctx
    return fake_span


def test_exec_run_opens_ssh_exec_span(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_mcp.ssh import exec as exec_mod

    records: list[_SpyContext] = []
    monkeypatch.setattr(exec_mod, "span", _make_spy(records))

    fake_result = MagicMock(stdout="ok\n", stderr="", exit_status=0, signal=None)

    class _Conn:
        async def run(self, *_a: Any, **_k: Any) -> Any:
            return fake_result

    import asyncio
    asyncio.run(exec_mod.run(
        _Conn(),  # type: ignore[arg-type]
        "echo ok",
        host="web01.internal",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
    ))

    assert len(records) == 1
    rec = records[0]
    assert rec.name == "ssh.exec"
    assert rec.attrs["ssh.host"] == "web01.internal"
    assert rec.attrs["ssh.argv_len"] == len("echo ok")
    assert rec.set_attrs["ssh.exit_code"] == 0
    assert rec.set_attrs["ssh.timed_out"] is False
    # Argv content must NEVER appear as an attribute (redaction posture).
    for v in (*rec.attrs.values(), *rec.set_attrs.values()):
        assert v != "echo ok"


def test_path_policy_opens_canonicalize_span(monkeypatch: pytest.MonkeyPatch) -> None:
    from ssh_mcp.services import path_policy

    records: list[_SpyContext] = []
    monkeypatch.setattr(path_policy, "span", _make_spy(records))

    async def fake_canonicalize(_conn: Any, path: str, **_kw: Any) -> str:
        return path  # already canonical for the test

    monkeypatch.setattr(path_policy, "canonicalize", fake_canonicalize)

    import asyncio
    asyncio.run(path_policy.canonicalize_and_check(
        conn=None,  # type: ignore[arg-type]
        path="/opt/app/cfg.toml",
        allowlist=["/opt/app"],
        must_exist=True,
        platform="posix",
    ))

    assert len(records) == 1
    rec = records[0]
    assert rec.name == "path.canonicalize"
    # Path content itself must NOT appear -- only length.
    assert rec.attrs["path.len"] == len("/opt/app/cfg.toml")
    assert rec.attrs["ssh.platform"] == "posix"
    assert rec.attrs["path.allowlist_len"] == 1
    for v in (*rec.attrs.values(), *rec.set_attrs.values()):
        assert v != "/opt/app/cfg.toml"


def test_connection_module_imports_span() -> None:
    # The connection.open_connection path requires a live asyncssh handshake to
    # exercise end-to-end, so we settle for a lightweight wiring assertion: the
    # module must hold a reference to telemetry.span at import time.
    from ssh_mcp import telemetry as telemetry_mod
    from ssh_mcp.ssh import connection
    assert connection.span is telemetry_mod.span
