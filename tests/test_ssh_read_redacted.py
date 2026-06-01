"""ssh_read_redacted (v1.4.1) -- the operator-blessed way to read a
redact-listed file.

Covers:

- Happy path for each format (env, yaml, json, ini, generic).
- A path that's BOTH in ``restricted_paths`` AND ``redact_paths_globs``
  ⇒ refuses (restricted wins).
- A path in ``redact_paths_globs`` but NOT restricted ⇒ succeeds and
  redacts.
- ``redactions[]`` list mirrors inline ``<sha:...>`` markers.
- Size cap returns ``truncated=True`` with empty content.
- Auto-detected format from extension.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services import path_policy
from ssh_mcp.ssh.errors import PathRestricted
from ssh_mcp.tools.sftp_read_tools import ssh_read_redacted


class _FakeAttrs:
    def __init__(self, size: int) -> None:
        self.size = size


class _FakeRemoteReadFile:
    def __init__(self, content: bytes) -> None:
        self._buf = content
        self._pos = 0

    async def __aenter__(self) -> _FakeRemoteReadFile:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def read(self, _chunk: int = -1) -> bytes:
        out = self._buf[self._pos :]
        self._pos = len(self._buf)
        return out


class _FakeSftp:
    def __init__(self, *, content: bytes) -> None:
        self._content = content

    async def __aenter__(self) -> _FakeSftp:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def stat(self, _path: str) -> _FakeAttrs:
        return _FakeAttrs(size=len(self._content))

    def open(self, _path: str, _mode: str) -> Any:
        return _FakeRemoteReadFile(self._content)


def _ctx(
    *,
    content: bytes,
    redact_globs: list[str] | None = None,
    restricted: list[str] | None = None,
    restricted_globs: list[str] | None = None,
    upload_cap: int = 256 << 20,
) -> Any:
    sftp = _FakeSftp(content=content)
    conn = MagicMock()
    conn.start_sftp_client = MagicMock(return_value=sftp)
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=conn)
    pool.sftp = MagicMock(return_value=sftp)
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
    )
    hosts = {"h": policy}
    settings = Settings(  # type: ignore[call-arg]
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_PATH_ALLOWLIST=["/"],
        SSH_UPLOAD_MAX_FILE_BYTES=upload_cap,
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
    """Skip the shell ``realpath`` call -- tests pass already-canonical paths."""

    async def _fake_canon(_conn: Any, path: str, *_a: Any, **_kw: Any) -> str:
        return path

    monkeypatch.setattr(path_policy, "canonicalize", _fake_canon)


# --- happy path per format ----------------------------------------------


@pytest.mark.asyncio
async def test_env_file_redacted() -> None:
    ctx = _ctx(
        content=b"DB_PASSWORD=hunter2\nNAME=app\n",
        redact_globs=["**/.env"],
    )
    result = await ssh_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    assert result.format_detected == "env"
    assert "hunter2" not in result.content
    assert "NAME=app" in result.content
    # redactions[] entry for DB_PASSWORD with same hash as the inline marker
    assert any(r["key"] == "DB_PASSWORD" for r in result.redactions)


@pytest.mark.asyncio
async def test_yaml_file_redacted() -> None:
    ctx = _ctx(
        content=b"password: hunter2\nname: app\n",
        redact_globs=["**/values.yaml"],
    )
    result = await ssh_read_redacted(host="h", path="/opt/app/values.yaml", ctx=ctx)
    assert result.format_detected == "yaml"
    assert "hunter2" not in result.content
    assert any(r["key"] == "password" for r in result.redactions)


@pytest.mark.asyncio
async def test_json_file_redacted() -> None:
    ctx = _ctx(content=b'{"password": "hunter2", "name": "app"}\n')
    result = await ssh_read_redacted(host="h", path="/opt/app/config.json", ctx=ctx)
    assert result.format_detected == "json"
    assert "hunter2" not in result.content


@pytest.mark.asyncio
async def test_ini_file_redacted() -> None:
    ctx = _ctx(content=b"[main]\npassword=hunter2\n")
    result = await ssh_read_redacted(host="h", path="/etc/app.ini", ctx=ctx)
    assert result.format_detected == "ini"
    assert "hunter2" not in result.content


@pytest.mark.asyncio
async def test_generic_file_with_entropy() -> None:
    ctx = _ctx(content=b"random_blob = " + b"a" * 40 + b"\n")
    result = await ssh_read_redacted(host="h", path="/opt/app/notes.txt", ctx=ctx)
    assert result.format_detected == "generic"
    assert "a" * 40 not in result.content


@pytest.mark.asyncio
async def test_explicit_format_overrides_extension() -> None:
    ctx = _ctx(content=b"DB_PASSWORD=hunter2\n")
    # pass format="env" even though the path has no .env hint
    result = await ssh_read_redacted(host="h", path="/opt/app/random", ctx=ctx, format="env")
    assert result.format_detected == "env"
    assert "hunter2" not in result.content


# --- restricted wins over redact list -----------------------------------


@pytest.mark.asyncio
async def test_restricted_path_refuses_even_in_redact_list() -> None:
    """A path in BOTH restricted_paths AND redact_paths_globs must STILL
    be refused -- restricted is a hard-deny, the redact list does not
    override it."""
    ctx = _ctx(
        content=b"DB_PASSWORD=hunter2\n",
        restricted=["/mnt/shared"],
        redact_globs=["**/.env"],
    )
    with pytest.raises(PathRestricted):
        await ssh_read_redacted(host="h", path="/mnt/shared/.env", ctx=ctx)


@pytest.mark.asyncio
async def test_restricted_glob_refuses_even_in_redact_list() -> None:
    """Same rule for the new restricted_globs list."""
    ctx = _ctx(
        content=b"DB_PASSWORD=hunter2\n",
        restricted_globs=["**/.env"],  # hard-deny via glob
        redact_globs=["**/.env"],  # also on redact list (irrelevant)
    )
    with pytest.raises(PathRestricted):
        await ssh_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)


# --- redact-list path WITHOUT restriction succeeds -----------------------


@pytest.mark.asyncio
async def test_redact_list_only_path_succeeds() -> None:
    """A path ONLY on the redact list (not restricted) is exactly what
    ssh_read_redacted is for. The bypass-block does NOT fire here even
    if the policy is set to block, because this tool is exempt."""
    ctx = _ctx(
        content=b"DB_PASSWORD=hunter2\n",
        redact_globs=["**/.env"],
    )
    # Even if some other tool would block on this path, ssh_read_redacted
    # delivers (with redaction).
    result = await ssh_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    assert "hunter2" not in result.content


# --- inline hash matches records[] ---------------------------------------


@pytest.mark.asyncio
async def test_redactions_list_mirrors_inline_hashes() -> None:
    ctx = _ctx(content=b"DB_PASSWORD=hunter2\n")
    result = await ssh_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    # Every record's hash MUST appear inline.
    for rec in result.redactions:
        assert f"<sha:{rec['hash']}" in result.content


# --- size cap -----------------------------------------------------------


@pytest.mark.asyncio
async def test_oversize_file_returns_truncated() -> None:
    # cap=10 bytes, file = 30 bytes ⇒ truncated
    ctx = _ctx(content=b"DB_PASSWORD=verylongsecretvalue\n", upload_cap=10)
    result = await ssh_read_redacted(host="h", path="/opt/app/.env", ctx=ctx)
    assert result.truncated is True
    assert result.content == ""
    assert any("SSH_UPLOAD_MAX_FILE_BYTES" in w for w in result.output_warnings)
