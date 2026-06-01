"""Pipeline-level tests for the v1.4.1 sudo file ops helpers.

Covers (with mocked SSH conn):

- ``sudo_read_bytes`` happy path returns raw bytes.
- Cap exceeded raises ``SudoFileOpError``.
- Non-zero sudo / cat exit raises ``SudoFileOpError``.
- ``sudo_stat_owner`` returns ``None`` for missing file (exit 1 + ENOENT
  stderr) and ``(user, group)`` for an existing file.
- ``sudo_stat_owner`` exit 1 without ENOENT stderr raises.
- ``sudo_atomic_write`` happy path with explicit chown.
- ``sudo_atomic_write`` non-zero exit raises with stage name in message.
- ``sudo_ls_parsed`` parses a GNU ls --time-style=full-iso block.
- ``sudo_ls_parsed`` empty directory returns ``[]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.services import sudo_file_ops
from ssh_mcp.ssh.errors import SudoFileOpError


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "SSH_HOSTS_FILE": None,
        "SSH_HOSTS_ALLOWLIST": [],
        "SSH_PATH_ALLOWLIST": ["/"],
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@dataclass
class _FakeProc:
    """Stand-in for asyncssh's SSHCompletedProcess."""

    exit_status: int
    stdout: bytes = b""
    stderr: bytes = b""


def _conn_with(proc: _FakeProc) -> Any:
    """Mock conn whose .run returns ``proc``."""
    conn = MagicMock()
    conn.run = AsyncMock(return_value=proc)
    return conn


@pytest.fixture(autouse=True)
def _no_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force passwordless sudo so tests don't read the operator's keychain."""
    import ssh_mcp.ssh.sudo as sudo_module

    monkeypatch.setattr(sudo_module, "_keyring", None)


# --- sudo_read_bytes -------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_read_bytes_happy_path() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=b"secrets-here\n"))
    data = await sudo_file_ops.sudo_read_bytes(conn, "/etc/foo", alias="web01", settings=_settings())
    assert data == b"secrets-here\n"
    # The argv should be `sudo -n -- sh -c '<quoted inner>'` (passwordless mode).
    args, kwargs = conn.run.call_args
    argv: str = args[0]
    assert "sudo -n -- sh -c" in argv
    assert "cat -- /etc/foo" in argv
    # encoding=None means asyncssh returns raw bytes.
    assert kwargs["encoding"] is None


@pytest.mark.asyncio
async def test_sudo_read_bytes_cap_exceeded_raises() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=b"x" * 1024))
    with pytest.raises(SudoFileOpError, match="exceeds cap"):
        await sudo_file_ops.sudo_read_bytes(
            conn,
            "/etc/foo",
            alias="web01",
            settings=_settings(),
            cap=100,
        )


@pytest.mark.asyncio
async def test_sudo_read_bytes_nonzero_exit_raises() -> None:
    conn = _conn_with(_FakeProc(exit_status=1, stderr=b"cat: /etc/foo: Permission denied\n"))
    with pytest.raises(SudoFileOpError, match="exited 1"):
        await sudo_file_ops.sudo_read_bytes(conn, "/etc/foo", alias="web01", settings=_settings())


# --- sudo_stat_owner -------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_stat_owner_returns_tuple_for_existing() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=b"root:root\n"))
    owner = await sudo_file_ops.sudo_stat_owner(conn, "/etc/foo", alias="web01", settings=_settings())
    assert owner == ("root", "root")


@pytest.mark.asyncio
async def test_sudo_stat_owner_returns_none_for_missing() -> None:
    conn = _conn_with(
        _FakeProc(
            exit_status=1,
            stderr=b"stat: cannot stat '/etc/nonexistent': No such file or directory\n",
        )
    )
    owner = await sudo_file_ops.sudo_stat_owner(conn, "/etc/nonexistent", alias="web01", settings=_settings())
    assert owner is None


@pytest.mark.asyncio
async def test_sudo_stat_owner_exit1_without_enoent_raises() -> None:
    conn = _conn_with(_FakeProc(exit_status=1, stderr=b"some other failure\n"))
    with pytest.raises(SudoFileOpError, match="did not look like ENOENT"):
        await sudo_file_ops.sudo_stat_owner(conn, "/etc/foo", alias="web01", settings=_settings())


@pytest.mark.asyncio
async def test_sudo_stat_owner_unparseable_raises() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=b"garbage without colon\n"))
    with pytest.raises(SudoFileOpError, match="unparseable owner"):
        await sudo_file_ops.sudo_stat_owner(conn, "/etc/foo", alias="web01", settings=_settings())


# --- sudo_atomic_write -----------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_atomic_write_happy_path_uses_stdin() -> None:
    conn = _conn_with(_FakeProc(exit_status=0))
    await sudo_file_ops.sudo_atomic_write(
        conn,
        "/etc/foo",
        b"new content",
        alias="web01",
        settings=_settings(),
        mode=0o600,
        chown_user="root",
        chown_group="root",
    )
    args, kwargs = conn.run.call_args
    argv: str = args[0]
    assert "mktemp" in argv
    assert "/etc/foo" in argv
    assert "root:root" in argv
    # mode rendered as octal '600' (no leading zero).
    assert "600" in argv
    # Passwordless mode: stdin is exactly the file bytes (no password prefix).
    assert kwargs["input"] == b"new content"


@pytest.mark.asyncio
async def test_sudo_atomic_write_inner_command_has_no_trailing_positional_args() -> None:
    """Regression guard for the v1.4.1 cat>tmp parse bug.

    Live-discovered on iruelg4: the original implementation appended
    ``_ <path> <mode> <owner>`` after the script body assuming
    ``_run_sudo_bytes`` would forward those as positional args. It does
    NOT -- it does ``sudo ... sh -c '<inner>'`` where the entire inner
    becomes the script body, and trailing ``_ ...`` tokens parse as
    statements after the brace group, producing ``sh: 1: Syntax error:
    word unexpected`` at stage cat>tmp. Fix inlines the three values
    as shell variables (dest=, mode=, owner=) at the top of the script.
    This test pins the fix: the constructed inner_command MUST assign
    the variables AND MUST NOT carry the trailing-positional-args form
    after ``mv -- ... "$dest" || { ...; exit 5; }``.
    """
    conn = _conn_with(_FakeProc(exit_status=0))
    await sudo_file_ops.sudo_atomic_write(
        conn,
        "/etc/myapp/secret.env",
        b"x",
        alias="web01",
        settings=_settings(),
        mode=0o600,
        chown_user="appuser",
        chown_group="appgrp",
    )
    args, _kwargs = conn.run.call_args
    argv: str = args[0]
    # The three operator-supplied values must be present as shell var
    # assignments AT THE TOP of the script body.
    assert "dest=" in argv
    assert "mode=" in argv
    assert "owner=" in argv
    # The bug pattern: trailing ``_ /path 600 user:group`` AFTER the
    # script's last statement. We assert the inner doesn't end with that
    # form by checking the last `mv` is followed by the exit-5 brace
    # group close and NOTHING after the closing quote of the outer
    # sh -c argument (modulo whitespace).
    assert "}; _ " not in argv, "trailing positional-args form must not return"
    assert "; _ /" not in argv


@pytest.mark.asyncio
async def test_sudo_atomic_write_nonzero_exit_names_stage() -> None:
    # exit code 3 -> chmod stage per the script's exit table.
    conn = _conn_with(_FakeProc(exit_status=3, stderr=b"chmod: bad mode\n"))
    with pytest.raises(SudoFileOpError, match="stage chmod"):
        await sudo_file_ops.sudo_atomic_write(
            conn,
            "/etc/foo",
            b"x",
            alias="web01",
            settings=_settings(),
            chown_user="root",
            chown_group="root",
        )


# --- sudo_ls_parsed --------------------------------------------------------


_GNU_LS_OUTPUT = (
    b"total 12\n"
    b"drwxr-xr-x 2 root root 4096 2026-05-30 12:34:56.000000000 +0000 .\n"
    b"drwxr-xr-x 3 root root 4096 2026-05-29 11:22:33.000000000 +0000 ..\n"
    b"-rw-r--r-- 1 root root  240 2026-05-30 12:34:56.000000000 +0000 .env\n"
    b"drwxr-xr-x 2 root root 4096 2026-05-29 09:00:00.000000000 +0000 secrets\n"
    b"lrwxrwxrwx 1 root root   12 2026-05-29 09:00:00.000000000 +0000 link -> /etc/foo\n"
)


@pytest.mark.asyncio
async def test_sudo_ls_parsed_gnu_output() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=_GNU_LS_OUTPUT))
    entries = await sudo_file_ops.sudo_ls_parsed(conn, "/etc/myapp", alias="web01", settings=_settings())
    # ``.`` and ``..`` skipped.
    names = sorted(e.name for e in entries)
    assert names == [".env", "link", "secrets"]
    by_name = {e.name: e for e in entries}
    assert by_name[".env"].kind == "file"
    assert by_name[".env"].size == 240
    assert by_name["secrets"].kind == "dir"
    assert by_name["link"].kind == "symlink"
    assert by_name["link"].symlink_target == "/etc/foo"


@pytest.mark.asyncio
async def test_sudo_ls_parsed_empty_dir_returns_nothing() -> None:
    conn = _conn_with(_FakeProc(exit_status=0, stdout=b"total 0\n"))
    entries = await sudo_file_ops.sudo_ls_parsed(conn, "/empty", alias="web01", settings=_settings())
    assert entries == []


@pytest.mark.asyncio
async def test_sudo_ls_parsed_unparseable_rows_skipped() -> None:
    """BusyBox-style ls without --time-style=full-iso is documented to skip."""
    conn = _conn_with(
        _FakeProc(
            exit_status=0,
            stdout=(
                b"total 0\n" b"-rw-r--r-- 1 root root 240 May 30 12:34 .env\n"  # no full-iso
            ),
        )
    )
    entries = await sudo_file_ops.sudo_ls_parsed(conn, "/etc", alias="web01", settings=_settings())
    assert entries == []


@pytest.mark.asyncio
async def test_sudo_ls_parsed_nonzero_exit_raises() -> None:
    conn = _conn_with(_FakeProc(exit_status=2, stderr=b"ls: cannot access\n"))
    with pytest.raises(SudoFileOpError, match="exited 2"):
        await sudo_file_ops.sudo_ls_parsed(conn, "/etc", alias="web01", settings=_settings())


# --- with-password mode prefixes stdin -------------------------------------


@pytest.mark.asyncio
async def test_password_mode_prefixes_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    """When fetch_sudo_password returns a non-None value, the helper uses
    ``sudo -S`` and prefixes the password before any ``stdin_extra``."""
    monkeypatch.setattr(sudo_file_ops, "fetch_sudo_password", lambda _s, _a: "hunter2")
    conn = _conn_with(_FakeProc(exit_status=0))
    await sudo_file_ops.sudo_atomic_write(
        conn,
        "/etc/foo",
        b"body",
        alias="web01",
        settings=_settings(),
        chown_user="root",
        chown_group="root",
    )
    args, kwargs = conn.run.call_args
    assert "sudo -S -p ''" in args[0]
    # Password line + file body.
    assert kwargs["input"] == b"hunter2\nbody"
