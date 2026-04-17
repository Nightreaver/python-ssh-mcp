"""Unit tests for ssh_host_list and ssh_host_reload.

Covers:
- ssh_host_list: returns sorted aliases, all safe fields present, no credentials.
- ssh_host_reload: correct added/removed/changed diff, parse failure leaves ctx intact,
  dict identity preserved after reload.

No live SSH connections; the tools never call pool.acquire() and load_hosts is
monkeypatched where needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import host_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy(
    alias: str,
    *,
    hostname: str | None = None,
    port: int = 22,
    platform: str = "posix",
    user: str = "deploy",
    method: str = "agent",
    key: Path | None = None,
) -> HostPolicy:
    """Build a minimal HostPolicy for the given alias."""
    auth_kwargs: dict[str, Any] = {"method": method}
    if key is not None:
        auth_kwargs["key"] = key
    return HostPolicy(
        hostname=hostname or alias,
        user=user,
        port=port,
        platform=platform,  # type: ignore[arg-type]
        auth=AuthPolicy(**auth_kwargs),
    )


def _ctx(hosts: dict[str, HostPolicy], *, hosts_file: Path | None = None) -> Any:
    """Stub FastMCP Context carrying exactly what host_tools reads."""

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": MagicMock(),
            "settings": Settings(
                SSH_HOSTS_FILE=hosts_file,
                SSH_HOSTS_ALLOWLIST=[],
            ),
            "hosts": hosts,
        }

    return _Ctx()


# ---------------------------------------------------------------------------
# ssh_host_list
# ---------------------------------------------------------------------------


class TestSshHostList:
    @pytest.mark.asyncio
    async def test_returns_sorted_by_alias(self) -> None:
        hosts = {
            "zebra": _policy("zebra"),
            "alpha": _policy("alpha"),
            "middle": _policy("middle"),
        }
        ctx = _ctx(hosts)
        result = await host_tools.ssh_host_list(ctx=ctx)
        assert [e.alias for e in result.hosts] == ["alpha", "middle", "zebra"]

    @pytest.mark.asyncio
    async def test_count_matches_number_of_entries(self) -> None:
        hosts = {"a": _policy("a"), "b": _policy("b")}
        ctx = _ctx(hosts)
        result = await host_tools.ssh_host_list(ctx=ctx)
        assert result.count == 2
        assert len(result.hosts) == 2

    @pytest.mark.asyncio
    async def test_empty_hosts_dict(self) -> None:
        ctx = _ctx({})
        result = await host_tools.ssh_host_list(ctx=ctx)
        assert result.count == 0
        assert result.hosts == []

    @pytest.mark.asyncio
    async def test_safe_fields_present(self) -> None:
        hosts = {
            "web01": _policy(
                "web01",
                hostname="web01.internal",
                port=2222,
                platform="posix",
                user="ci",
                method="key",
                key=Path("/home/ci/.ssh/id_ed25519"),
            )
        }
        ctx = _ctx(hosts)
        result = await host_tools.ssh_host_list(ctx=ctx)
        assert len(result.hosts) == 1
        entry = result.hosts[0]
        assert entry.alias == "web01"
        assert entry.hostname == "web01.internal"
        assert entry.port == 2222
        assert entry.platform == "posix"
        assert entry.user == "ci"
        assert entry.auth_method == "key"

    @pytest.mark.asyncio
    async def test_no_credential_leak_in_serialized_result(self) -> None:
        """Serialized output must never contain key_path, password, or passphrase."""
        key_path = Path("/home/deploy/.ssh/id_ed25519")
        hosts = {
            "srv": _policy("srv", method="key", key=key_path),
        }
        ctx = _ctx(hosts)
        result = await host_tools.ssh_host_list(ctx=ctx)
        # Serialize the way MCP would (model_dump -> JSON).
        payload = result.model_dump()
        payload_str = str(payload)

        # The actual key path string must not appear anywhere in the output.
        assert str(key_path) not in payload_str
        # These field names should not be present at any nesting level.
        for forbidden in ("key_path", "password", "passphrase", "passphrase_cmd", "password_cmd"):
            assert forbidden not in payload_str, f"Credential field {forbidden!r} leaked into output"

    @pytest.mark.asyncio
    async def test_auth_method_name_is_exposed_not_secret(self) -> None:
        """auth_method carries the method label ('agent', 'key', 'password')
        which is metadata the operator put in hosts.toml — not a secret value.
        """
        for method in ("agent", "key", "password"):
            hosts = {"h": _policy("h", method=method)}
            ctx = _ctx(hosts)
            result = await host_tools.ssh_host_list(ctx=ctx)
            assert result.hosts[0].auth_method == method

    @pytest.mark.asyncio
    async def test_windows_platform_preserved(self) -> None:
        hosts = {"winbox": _policy("winbox", platform="windows")}
        ctx = _ctx(hosts)
        result = await host_tools.ssh_host_list(ctx=ctx)
        assert result.hosts[0].platform == "windows"


# ---------------------------------------------------------------------------
# ssh_host_reload
# ---------------------------------------------------------------------------


class TestSshHostReload:
    @pytest.mark.asyncio
    async def test_added_aliases_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        old = {"existing": _policy("existing")}
        new = {
            "existing": _policy("existing"),
            "new_host": _policy("new_host"),
        }
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.added == ["new_host"]
        assert result.removed == []
        assert result.changed == []
        assert result.loaded == 2

    @pytest.mark.asyncio
    async def test_removed_aliases_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        old = {"a": _policy("a"), "b": _policy("b")}
        new = {"a": _policy("a")}
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.removed == ["b"]
        assert result.added == []
        assert result.changed == []
        assert result.loaded == 1

    @pytest.mark.asyncio
    async def test_changed_aliases_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        old = {"srv": _policy("srv", port=22)}
        new = {"srv": _policy("srv", port=2222)}
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.changed == ["srv"]
        assert result.added == []
        assert result.removed == []

    @pytest.mark.asyncio
    async def test_unchanged_aliases_not_in_changed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        policy = _policy("srv")
        old = {"srv": policy}
        # Construct an equal but not identical object.
        new = {"srv": _policy("srv")}
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.changed == []
        assert result.added == []
        assert result.removed == []

    @pytest.mark.asyncio
    async def test_parse_failure_does_not_mutate_hosts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If load_hosts raises, the live hosts dict must be left intact."""
        original = {"keep": _policy("keep")}
        live_hosts: dict[str, HostPolicy] = dict(original)
        original_id = id(live_hosts)

        def _raise(*_: Any) -> None:
            raise ValueError("bad TOML")

        monkeypatch.setattr(host_tools, "load_hosts", _raise)
        ctx = _ctx(live_hosts)

        with pytest.raises(ValueError, match="hosts reload failed"):
            await host_tools.ssh_host_reload(ctx=ctx)

        # Dict is unchanged: same content, same identity.
        assert set(live_hosts) == {"keep"}
        assert id(live_hosts) == original_id

    @pytest.mark.asyncio
    async def test_dict_identity_preserved_after_reload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The in-place clear+update keeps the same dict object alive so live
        references (e.g. the pool) continue to see the updated content."""
        old = {"a": _policy("a")}
        new = {"b": _policy("b")}
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)

        hosts_ref = ctx.lifespan_context["hosts"]
        before_id = id(hosts_ref)

        await host_tools.ssh_host_reload(ctx=ctx)

        # Same object.
        assert id(ctx.lifespan_context["hosts"]) == before_id
        # Content replaced.
        assert set(ctx.lifespan_context["hosts"]) == {"b"}

    @pytest.mark.asyncio
    async def test_source_reflects_settings_hosts_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        hosts_file = tmp_path / "hosts.toml"
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: {})
        ctx = _ctx({}, hosts_file=hosts_file)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.source == str(hosts_file)

    @pytest.mark.asyncio
    async def test_source_none_when_no_hosts_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: {})
        ctx = _ctx({}, hosts_file=None)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.source == "<none>"

    @pytest.mark.asyncio
    async def test_full_diff_scenario(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Combined: one added, one removed, one changed, one unchanged."""
        old = {
            "unchanged": _policy("unchanged"),
            "will_change": _policy("will_change", port=22),
            "will_remove": _policy("will_remove"),
        }
        new = {
            "unchanged": _policy("unchanged"),
            "will_change": _policy("will_change", port=2222),
            "newly_added": _policy("newly_added"),
        }
        monkeypatch.setattr(host_tools, "load_hosts", lambda *_: new)
        ctx = _ctx(old)
        result = await host_tools.ssh_host_reload(ctx=ctx)
        assert result.added == ["newly_added"]
        assert result.removed == ["will_remove"]
        assert result.changed == ["will_change"]
        assert result.loaded == 3
