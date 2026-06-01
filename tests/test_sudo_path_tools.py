"""Tool-surface tests for the v1.4.0 sudo path-bearing tools.

Combines ``ssh_sudo_read`` / ``ssh_sudo_read_redacted`` / ``ssh_sudo_write``
/ ``ssh_sudo_edit`` / ``ssh_sudo_sftp_list`` so the shared mocking
infrastructure (fake conn / pool / canonicalize patch / sudo helper
monkeypatch) is set up once.

We mock the sudo_file_ops helpers at the tool-module level (not at the
service module) because the tool body does ``from ..services.sudo_file_ops
import ...`` -- monkeypatching the service module would not rebind the
tool's local symbol.
"""

from __future__ import annotations

import base64
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.models.results import SftpEntry
from ssh_mcp.services import path_policy
from ssh_mcp.ssh.errors import PathRestricted, RedactBypassBlocked, SudoFileOpError
from ssh_mcp.tools import sudo_tools


def _ctx(
    *,
    redact_globs: list[str] | None = None,
    restricted: list[str] | None = None,
    restricted_globs: list[str] | None = None,
    redact_bypass_policy: str | None = None,
    upload_cap: int = 256 << 20,
    edit_cap: int = 10 << 20,
) -> Any:
    conn = MagicMock(name="conn")
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    policy = HostPolicy(
        hostname="h.example.com",
        user="deploy",
        port=22,
        platform="posix",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/"],
        restricted_paths=restricted or [],
        restricted_globs=restricted_globs or [],
        redact_paths_globs=redact_globs or [],
        redact_bypass_policy=redact_bypass_policy,  # type: ignore[arg-type]
    )
    hosts = {"h": policy}
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_PATH_ALLOWLIST=["/"],
        SSH_UPLOAD_MAX_FILE_BYTES=upload_cap,
        SSH_EDIT_MAX_FILE_BYTES=edit_cap,
    )

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": hosts,
            "host_allowlist": ["h"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


@pytest.fixture(autouse=True)
def _patch_canonicalize(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(path_policy, "canonicalize", _fake_canon)


# ---------------------------------------------------------------------------
# ssh_sudo_read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_read_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"PRIVATE_KEY=hunter2\n"

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_read(host="h", path="/etc/foo", ctx=ctx)
    assert result.host == "h.example.com"
    assert result.path == "/etc/foo"
    assert base64.b64decode(result.content_base64) == b"PRIVATE_KEY=hunter2\n"
    assert result.truncated is False


@pytest.mark.asyncio
async def test_sudo_read_respects_redact_bypass_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A path on the redact list with bypass='block' raises before sudo runs."""
    called = False

    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        nonlocal called
        called = True
        return b""

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx(redact_globs=["**/.env"], redact_bypass_policy="block")
    with pytest.raises(RedactBypassBlocked):
        await sudo_tools.ssh_sudo_read(host="h", path="/opt/app/.env", ctx=ctx)
    assert called is False, "sudo_read_bytes must not run when redact-block fires"


@pytest.mark.asyncio
async def test_sudo_read_respects_restricted_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b""

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx(restricted=["/mnt/shared"])
    with pytest.raises(PathRestricted):
        await sudo_tools.ssh_sudo_read(host="h", path="/mnt/shared/x", ctx=ctx)


# ---------------------------------------------------------------------------
# ssh_sudo_read_redacted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_read_redacted_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"DB_PASSWORD=hunter2\nNAME=app\n"

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx(redact_globs=["**/.env"])
    result = await sudo_tools.ssh_sudo_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    assert result.format_detected == "env"
    assert "hunter2" not in result.content
    assert "NAME=app" in result.content
    assert any(r["key"] == "DB_PASSWORD" for r in result.redactions)


@pytest.mark.asyncio
async def test_sudo_read_redacted_exempt_from_bypass_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """redact_bypass_policy=block does NOT fire on this tool -- it IS the
    operator-blessed alternative."""

    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"DB_PASSWORD=hunter2\n"

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx(redact_globs=["**/.env"], redact_bypass_policy="block")
    result = await sudo_tools.ssh_sudo_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    assert "hunter2" not in result.content


@pytest.mark.asyncio
async def test_sudo_read_redacted_still_respects_restricted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b""

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx(restricted=["/mnt/shared"], redact_globs=["**/.env"])
    with pytest.raises(PathRestricted):
        await sudo_tools.ssh_sudo_read_redacted(host="h", path="/mnt/shared/.env", ctx=ctx)


# ---------------------------------------------------------------------------
# ssh_sudo_write
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_write_payload_mutex_neither_raises() -> None:
    ctx = _ctx()
    with pytest.raises(ValueError, match="None was set"):
        await sudo_tools.ssh_sudo_write(host="h", path="/tmp/x", ctx=ctx)


@pytest.mark.asyncio
async def test_sudo_write_payload_mutex_both_raises() -> None:
    ctx = _ctx()
    with pytest.raises(ValueError, match="Multiple were set"):
        await sudo_tools.ssh_sudo_write(
            host="h",
            path="/tmp/x",
            ctx=ctx,
            content_text="hi",
            content_base64=base64.b64encode(b"hi").decode("ascii"),
        )


@pytest.mark.asyncio
async def test_sudo_write_preserves_existing_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("appuser", "appgrp")

    async def _fake_write(
        _conn: Any,
        _path: str,
        _data: bytes,
        *,
        alias: str,
        settings: Any,
        mode: int,
        chown_user: str,
        chown_group: str,
        timeout: float | None = None,
    ) -> None:
        captured["chown_user"] = chown_user
        captured["chown_group"] = chown_group
        captured["mode"] = mode

    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_write(host="h", path="/etc/foo", ctx=ctx, content_text="hello")
    assert captured == {"chown_user": "appuser", "chown_group": "appgrp", "mode": 0o644}
    assert result.success is True
    assert result.bytes_written == len(b"hello")
    assert result.output_warnings == []  # file existed -> no warning


@pytest.mark.asyncio
async def test_sudo_write_defaults_root_root_for_new_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_stat(*_a: Any, **_k: Any) -> None:
        return None  # file does not exist

    captured: dict[str, str] = {}

    async def _fake_write(
        _c: Any,
        _p: str,
        _d: bytes,
        *,
        alias: str,
        settings: Any,
        mode: int,
        chown_user: str,
        chown_group: str,
        timeout: float | None = None,
    ) -> None:
        captured["chown_user"] = chown_user
        captured["chown_group"] = chown_group

    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_write(host="h", path="/etc/newfile", ctx=ctx, content_text="hi")
    assert captured == {"chown_user": "root", "chown_group": "root"}
    assert any("root:root" in w for w in result.output_warnings)


@pytest.mark.asyncio
async def test_sudo_write_explicit_chown_skips_stat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stat_called = False

    async def _fake_stat(*_a: Any, **_k: Any) -> Any:
        nonlocal stat_called
        stat_called = True
        return None

    async def _fake_write(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    await sudo_tools.ssh_sudo_write(
        host="h",
        path="/etc/foo",
        ctx=ctx,
        content_text="hi",
        chown_user="alice",
        chown_group="alice",
    )
    assert stat_called is False


@pytest.mark.asyncio
async def test_sudo_write_cap_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx(upload_cap=10)
    with pytest.raises(SudoFileOpError, match="exceeds SSH_UPLOAD_MAX_FILE_BYTES"):
        await sudo_tools.ssh_sudo_write(host="h", path="/etc/foo", ctx=ctx, content_text="x" * 100)


@pytest.mark.asyncio
async def test_sudo_write_three_way_mutex_rejects_text_plus_local(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _ctx()
    with pytest.raises(ValueError, match="Multiple were set"):
        await sudo_tools.ssh_sudo_write(
            host="h",
            path="/tmp/x",
            ctx=ctx,
            content_text="hi",
            local_path="/some/local/path",
        )


@pytest.mark.asyncio
async def test_sudo_write_local_path_happy(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """local_path branch reads bytes from local disk, pipes them into the
    sudo pipeline, and surfaces the canonical source path in
    local_path_written. Required for hardened-host workflows where the LLM
    can't generate a multi-MB base64 payload as a tool-call argument."""
    # Real local file on disk (tmp_path is pytest's built-in scratch dir).
    local_file = tmp_path / "release.tar.gz"
    payload = b"binary artifact payload" * 100  # ~2.4 KB
    local_file.write_bytes(payload)

    # resolve_local_path needs SSH_LOCAL_TRANSFER_ROOTS to include the tmp dir.
    # Patch the resolver so we don't have to plumb env settings through _ctx.
    from pathlib import Path

    def _fake_resolve_local(path: str, _settings: Any, *, mode: str) -> Path:
        return Path(path)

    monkeypatch.setattr(sudo_tools, "resolve_local_path", _fake_resolve_local)

    captured: dict[str, Any] = {}

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("root", "root")

    async def _fake_write(
        _conn: Any,
        _path: str,
        data: bytes,
        *,
        alias: str,
        settings: Any,
        mode: int,
        chown_user: str,
        chown_group: str,
        timeout: float | None = None,
    ) -> None:
        captured["data"] = data
        captured["chown"] = (chown_user, chown_group)

    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_write(
        host="h",
        path="/opt/app/release.tar.gz",
        ctx=ctx,
        local_path=str(local_file),
    )
    # Bytes from local disk made it through to the sudo write.
    assert captured["data"] == payload
    # Result surfaces the canonical local source for audit correlation.
    assert result.local_path_written == str(local_file)
    assert result.bytes_written == len(payload)
    assert "sudo-wrote from" in (result.message or "")


@pytest.mark.asyncio
async def test_sudo_write_local_path_cap_exceeded(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """local_path payload uses SSH_LOCAL_TRANSFER_MAX_BYTES (default 2 GiB),
    NOT the smaller upload cap. Verify the right cap fires."""
    local_file = tmp_path / "big.bin"
    local_file.write_bytes(b"x" * 1000)

    from pathlib import Path

    def _fake_resolve_local(path: str, _settings: Any, *, mode: str) -> Path:
        return Path(path)

    monkeypatch.setattr(sudo_tools, "resolve_local_path", _fake_resolve_local)

    # Settings ctor doesn't directly accept SSH_LOCAL_TRANSFER_MAX_BYTES via
    # _ctx; reach into the ctx and override.
    ctx = _ctx()
    ctx.lifespan_context["settings"].SSH_LOCAL_TRANSFER_MAX_BYTES = 100  # 100 B cap

    with pytest.raises(SudoFileOpError, match="SSH_LOCAL_TRANSFER_MAX_BYTES"):
        await sudo_tools.ssh_sudo_write(
            host="h",
            path="/opt/x",
            ctx=ctx,
            local_path=str(local_file),
        )


# ---------------------------------------------------------------------------
# ssh_sudo_edit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_edit_happy_single(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"foo=1\nbar=2\n"

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("root", "root")

    async def _fake_stat_mode(*_a: Any, **_k: Any) -> int:
        return 0o644

    captured: dict[str, Any] = {}

    async def _fake_write(_c: Any, _p: str, data: bytes, **kw: Any) -> None:
        captured["data"] = data
        captured["mode"] = kw.get("mode")

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_stat_mode", _fake_stat_mode)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_edit(
        host="h", path="/etc/foo", old_string="foo=1", new_string="foo=42", ctx=ctx
    )
    assert captured["data"] == b"foo=42\nbar=2\n"
    assert captured["mode"] == 0o644
    assert "replaced 1" in (result.message or "")


@pytest.mark.asyncio
async def test_sudo_edit_preserves_restrictive_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression for v1.4.0: a secrets file at 0o600 must stay 0o600 after
    edit. Before the fix, sudo_atomic_write was called with hardcoded 0o644
    so any restrictive-mode file got widened on every edit."""

    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"DB_PASSWORD=hunter2\n"

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("root", "root")

    async def _fake_stat_mode(*_a: Any, **_k: Any) -> int:
        return 0o600

    captured: dict[str, Any] = {}

    async def _fake_write(_c: Any, _p: str, _d: bytes, **kw: Any) -> None:
        captured["mode"] = kw.get("mode")

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_stat_mode", _fake_stat_mode)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    await sudo_tools.ssh_sudo_edit(
        host="h",
        path="/etc/myapp/secrets.env",
        old_string="hunter2",
        new_string="newpass",
        ctx=ctx,
    )
    # Critical: original 0o600 was preserved, NOT widened to 0o644.
    assert captured["mode"] == 0o600, "secrets file mode must not be widened by edit"


@pytest.mark.asyncio
async def test_sudo_edit_no_match_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"foo=1\n"

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("root", "root")

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)

    ctx = _ctx()
    with pytest.raises(SudoFileOpError, match="not found"):
        await sudo_tools.ssh_sudo_edit(
            host="h",
            path="/etc/foo",
            old_string="missing",
            new_string="replacement",
            ctx=ctx,
        )


@pytest.mark.asyncio
async def test_sudo_edit_non_utf8_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"\xff\xfe binary"

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    ctx = _ctx()
    with pytest.raises(SudoFileOpError, match="not valid UTF-8"):
        await sudo_tools.ssh_sudo_edit(host="h", path="/etc/foo", old_string="a", new_string="b", ctx=ctx)


@pytest.mark.asyncio
async def test_sudo_edit_occurrence_all(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_read(*_a: Any, **_k: Any) -> bytes:
        return b"x\nx\nx\n"

    async def _fake_stat(*_a: Any, **_k: Any) -> tuple[str, str]:
        return ("root", "root")

    async def _fake_stat_mode(*_a: Any, **_k: Any) -> int:
        return 0o644

    captured: dict[str, bytes] = {}

    async def _fake_write(_c: Any, _p: str, data: bytes, **_k: Any) -> None:
        captured["data"] = data

    monkeypatch.setattr(sudo_tools, "sudo_read_bytes", _fake_read)
    monkeypatch.setattr(sudo_tools, "sudo_stat_owner", _fake_stat)
    monkeypatch.setattr(sudo_tools, "sudo_stat_mode", _fake_stat_mode)
    monkeypatch.setattr(sudo_tools, "sudo_atomic_write", _fake_write)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_edit(
        host="h",
        path="/etc/foo",
        old_string="x",
        new_string="y",
        ctx=ctx,
        occurrence="all",
    )
    assert captured["data"] == b"y\ny\ny\n"
    assert "replaced 3" in (result.message or "")


# ---------------------------------------------------------------------------
# ssh_sudo_sftp_list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sudo_sftp_list_happy(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [
        SftpEntry(name="b.conf", kind="file", size=1, mode="0644", mtime="m"),
        SftpEntry(name="a.conf", kind="file", size=2, mode="0644", mtime="m"),
        SftpEntry(name="sub", kind="dir", size=4096, mode="0755", mtime="m"),
    ]

    async def _fake_ls(*_a: Any, **_k: Any) -> list[SftpEntry]:
        return list(entries)

    monkeypatch.setattr(sudo_tools, "sudo_ls_parsed", _fake_ls)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_sftp_list(host="h", path="/etc", ctx=ctx)
    # Sorted alphabetically.
    assert [e.name for e in result.entries] == ["a.conf", "b.conf", "sub"]
    assert result.has_more is False


@pytest.mark.asyncio
async def test_sudo_sftp_list_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [SftpEntry(name=f"f{i}", kind="file", size=1, mode="0644", mtime="m") for i in range(5)]

    async def _fake_ls(*_a: Any, **_k: Any) -> list[SftpEntry]:
        return list(entries)

    monkeypatch.setattr(sudo_tools, "sudo_ls_parsed", _fake_ls)

    ctx = _ctx()
    result = await sudo_tools.ssh_sudo_sftp_list(host="h", path="/etc", ctx=ctx, offset=2, limit=2)
    # Sorted alphabetically: f0, f1, f2, f3, f4. offset=2 limit=2 -> f2, f3.
    assert [e.name for e in result.entries] == ["f2", "f3"]
    assert result.has_more is True


@pytest.mark.asyncio
async def test_sudo_sftp_list_bad_limit_raises() -> None:
    ctx = _ctx()
    with pytest.raises(ValueError):
        await sudo_tools.ssh_sudo_sftp_list(host="h", path="/etc", ctx=ctx, limit=0)
    with pytest.raises(ValueError):
        await sudo_tools.ssh_sudo_sftp_list(host="h", path="/etc", ctx=ctx, offset=-1)
