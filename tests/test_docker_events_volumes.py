"""ssh_docker_events + ssh_docker_volumes: input validation + argv shape.

Pre-flight validation (since/until format, filter KEY=VALUE, volume name)
is tested directly. Happy-path argv assertion uses monkeypatched
`_run_docker` to capture what the tool would send -- the pattern that
caught B1 on ssh_docker_cp (pre-validation tests alone miss missing imports
and branch-assembly bugs).
"""
from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.tools.docker import read_tools
from ssh_mcp.tools.docker_tools import ssh_docker_events, ssh_docker_volumes

# INC-043: docker_tools.py was split into read/lifecycle/dangerous submodules.
# `ssh_docker_events` + `ssh_docker_volumes` live in `docker.read_tools`, so the
# `_run_docker` monkeypatches below MUST target `read_tools` -- patching the
# facade re-export wouldn't intercept the module-namespace lookup inside the
# tool body.


class _Ctx:
    def __init__(self, lifespan: dict) -> None:
        self.lifespan_context = lifespan


def _happy_ctx() -> Any:
    """ctx that reaches `_run_docker` without blowing up on policy lookup."""
    from ssh_mcp.config import Settings
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings()
    policy = HostPolicy(hostname="docker1", user="deploy", auth=AuthPolicy(method="agent"))

    class _C:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": {"docker1": policy},
        }

    return _C()


# --- ssh_docker_events: input validation ---


class TestEventsInputValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_since",
        [
            "15 minutes",     # human text
            "yesterday",      # relative word
            "rm -rf /",       # injection
            "10m;ls",         # injection
            "2026-04-16",     # date only, no time
            "-10m",           # negative
            "7d",             # `d` unit -- Go time.ParseDuration only accepts s/m/h
            "1d2h",           # `d` in mixed duration
        ],
    )
    async def test_rejects_bad_since(self, bad_since: str) -> None:
        with pytest.raises(ValueError, match="since"):
            await ssh_docker_events(host="docker1", ctx=_Ctx({}), since=bad_since)

    @pytest.mark.asyncio
    async def test_rejects_bad_until(self) -> None:
        with pytest.raises(ValueError, match="until"):
            await ssh_docker_events(
                host="docker1", ctx=_Ctx({}), until="yesterday",
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "good_time",
        [
            "10m",
            "2h",
            "24h30m",
            "1710000000",
            "1710000000.123",
            "2026-04-16T12:00:00Z",
            "2026-04-16T12:00:00+02:00",
            "now",
        ],
    )
    async def test_accepts_good_time_formats(self, good_time: str, monkeypatch) -> None:
        """Validator accepts these; we stop at `_run_docker` via monkeypatch
        so no I/O happens."""
        async def fake_run_docker(*_a, **_kw):
            return {"stdout": "", "exit_code": 0}

        monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
        # Either `since` or `until` exercise the same regex; pick since.
        await ssh_docker_events(host="docker1", ctx=_happy_ctx(), since=good_time)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_filter",
        [
            "container",                # no =
            "=foo",                     # empty key
            "container=",               # empty value
            "container=$(whoami)",      # shell substitution in value
            "container=a;rm",           # ; in value
            "contAIner!=foo",           # bad key char
        ],
    )
    async def test_rejects_bad_filter(self, bad_filter: str) -> None:
        with pytest.raises(ValueError, match="filter"):
            await ssh_docker_events(
                host="docker1", ctx=_Ctx({}), filters=[bad_filter],
            )


# --- ssh_docker_events: happy-path argv shape ---


@pytest.mark.asyncio
async def test_events_argv_default(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        captured["kwargs"] = kw
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_events(host="docker1", ctx=_happy_ctx())
    # Default: since=1h, until=now, no filters.
    assert captured["argv"] == [
        "events", "--since=1h", "--until=now",
        "--format", "{{json .}}",
    ]
    # When filters is None (default), no --filter token leaks into argv.
    # Explicit assertion so a future bug that added an empty --filter gets caught.
    assert "--filter" not in captured["argv"]


@pytest.mark.asyncio
async def test_events_argv_with_filters(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_events(
        host="docker1", ctx=_happy_ctx(),
        since="2h", until="now",
        filters=["container=nginx", "event=die"],
    )
    argv = captured["argv"]
    assert argv[:5] == ["events", "--since=2h", "--until=now", "--format", "{{json .}}"]
    # Each filter becomes a `--filter KEY=VALUE` pair.
    assert "--filter" in argv
    assert "container=nginx" in argv
    assert "event=die" in argv
    # Count: two `--filter` entries for two filters.
    assert argv.count("--filter") == 2


@pytest.mark.asyncio
async def test_events_parses_ndjson_stdout(monkeypatch) -> None:
    """Returned payload contains `events` list parsed from NDJSON stdout."""
    async def fake_run_docker(*_a, **_kw):
        return {
            "stdout": (
                '{"Type":"container","Action":"die","time":1710000000}\n'
                '{"Type":"container","Action":"start","time":1710000001}\n'
            ),
            "exit_code": 0,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_events(host="docker1", ctx=_happy_ctx())
    assert len(out["events"]) == 2
    assert out["events"][0]["Action"] == "die"
    assert out["events"][1]["Action"] == "start"


# --- ssh_docker_volumes ---


class TestVolumesInputValidation:
    @pytest.mark.asyncio
    async def test_rejects_bad_volume_name(self) -> None:
        with pytest.raises(ValueError, match="volume"):
            await ssh_docker_volumes(host="docker1", ctx=_Ctx({}), name="a;rm")


@pytest.mark.asyncio
async def test_volumes_ls_argv(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        return {
            "stdout": (
                '{"Name":"pg_data","Driver":"local",'
                '"Mountpoint":"/var/lib/docker/volumes/pg_data/_data"}\n'
            ),
            "exit_code": 0,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_volumes(host="docker1", ctx=_happy_ctx())
    assert captured["argv"] == ["volume", "ls", "--format", "{{json .}}"]
    assert len(out["volumes"]) == 1
    assert out["volumes"][0]["Name"] == "pg_data"


@pytest.mark.asyncio
async def test_volumes_inspect_argv(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        return {
            "stdout": '[{"Name":"pg_data","Driver":"local","CreatedAt":"2026-04-16T10:00:00Z"}]',
            "exit_code": 0,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_volumes(host="docker1", ctx=_happy_ctx(), name="pg_data")
    assert captured["argv"] == ["volume", "inspect", "--", "pg_data"]
    assert len(out["volumes"]) == 1
    assert out["volumes"][0]["Name"] == "pg_data"


@pytest.mark.asyncio
async def test_volumes_inspect_empty_on_nonzero_exit(monkeypatch) -> None:
    """Parity with ssh_docker_inspect: non-zero exit returns `volumes: []`."""
    async def fake_run_docker(*_a, **_kw):
        return {
            "stdout": "",
            "stderr": "Error: No such volume: missing\n",
            "exit_code": 1,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_volumes(host="docker1", ctx=_happy_ctx(), name="missing")
    assert out["volumes"] == []
