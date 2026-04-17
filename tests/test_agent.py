"""Agent identity enumeration + fingerprint matching. Uses a fake SSHAgentClient.

Also includes a live smoke test that runs against the operator's real agent
(Pageant / ssh-agent / Windows OpenSSH) when one is present — skipped otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys
from unittest.mock import patch

import pytest

from ssh_mcp.ssh.agent import list_agent_fingerprints, select_agent_key
from ssh_mcp.ssh.errors import AgentFingerprintNotFound


class _FakeKey:
    """Stand-in for asyncssh's SSHAgentKeyPair — only `public_data` is needed."""

    def __init__(self, seed: str) -> None:
        self.public_data = seed.encode("utf-8")

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.public_data).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class _FakeAgent:
    def __init__(self, keys: list[_FakeKey]) -> None:
        self._keys = keys

    async def __aenter__(self) -> _FakeAgent:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get_keys(self) -> list[_FakeKey]:
        return list(self._keys)


def _with_fake_agent(keys: list[_FakeKey]) -> object:
    return patch(
        "ssh_mcp.ssh.agent.asyncssh.SSHAgentClient",
        lambda _sock: _FakeAgent(keys),
    )


@pytest.mark.asyncio
async def test_list_fingerprints_from_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")
    keys = [_FakeKey("ops-seed"), _FakeKey("db-seed")]
    expected = [k.fingerprint for k in keys]
    with _with_fake_agent(keys):
        got = await list_agent_fingerprints()
    assert got == expected


@pytest.mark.asyncio
async def test_list_fingerprints_no_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    # On Unix, _resolve_socket returns None → []. On Windows, it returns "" and
    # asyncssh tries Pageant; the fake below ensures the test doesn't reach a real
    # agent even on Windows.
    with patch(
        "ssh_mcp.ssh.agent.asyncssh.SSHAgentClient",
        lambda _sock: _FakeAgent([]),
    ):
        got = await list_agent_fingerprints()
    assert got == []


@pytest.mark.asyncio
async def test_select_key_matches_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")
    keys = [_FakeKey("ops-seed"), _FakeKey("db-seed")]
    target = keys[1].fingerprint
    with _with_fake_agent(keys):
        picked = await select_agent_key(None, target)
    assert picked.public_data == b"db-seed"


@pytest.mark.asyncio
async def test_select_key_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")
    with _with_fake_agent([_FakeKey("only-seed")]), pytest.raises(
        AgentFingerprintNotFound, match="not found",
    ):
        await select_agent_key(None, "SHA256:definitely-not-present-anywhere")


@pytest.mark.asyncio
async def test_select_key_no_agent_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    if sys.platform == "win32":
        pytest.skip("on Windows, _resolve_socket returns '' for Pageant; covered by live test")
    with pytest.raises(AgentFingerprintNotFound, match="no SSH agent"):
        await select_agent_key(None, "SHA256:anything-abcdef1234")


# ---------- live smoke test (Pageant / ssh-agent) ----------


def _live_agent_reachable() -> bool:
    if os.environ.get("SSH_AUTH_SOCK"):
        return True
    if sys.platform == "win32":
        # Cheapest liveness probe: ask asyncssh to list keys; non-zero return → live.
        import asyncio

        import asyncssh

        async def _probe() -> bool:
            try:
                async with asyncssh.SSHAgentClient("") as agent:
                    await agent.get_keys()
                    return True
            except Exception:
                return False

        try:
            return asyncio.run(_probe())
        except Exception:
            return False
    return False


@pytest.mark.asyncio
@pytest.mark.skipif(not _live_agent_reachable(), reason="no live SSH agent / Pageant")
async def test_live_agent_returns_well_formed_fingerprints() -> None:
    fps = await list_agent_fingerprints()
    assert fps, "live agent reported no identities"
    for fp in fps:
        assert fp.startswith("SHA256:")
        body = fp[len("SHA256:") :]
        # SHA-256 → 32 bytes → 43 base64 chars without padding.
        assert len(body) == 43, f"unexpected fingerprint shape: {fp!r}"
