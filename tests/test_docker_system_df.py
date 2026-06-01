"""ssh_docker_system_df: argv shape + stdout parsing.

Same monkeypatch-on-the-submodule pattern as the other read-tier tests
(see test_docker_events_volumes.py for the rationale). Targets
`ssh_mcp.tools.docker.read_tools._run_docker` directly because that is
the binding the tool body resolves at call time after the INC-043 split.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.tools.docker import read_tools
from ssh_mcp.tools.docker_tools import ssh_docker_system_df


def _happy_ctx() -> Any:
    """ctx that resolves `docker1` to a real HostPolicy without I/O."""
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


@pytest.mark.asyncio
async def test_system_df_argv(monkeypatch) -> None:
    """Default argv is `system df --format '{{json .}}'`. Nothing extra
    is appended (no `-v`, no `--no-trunc`)."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_system_df(host="docker1", ctx=_happy_ctx())
    assert captured["argv"] == ["system", "df", "--format", "{{json .}}"]


@pytest.mark.asyncio
async def test_system_df_parses_four_categories(monkeypatch) -> None:
    """Standard four-row NDJSON output lands as parsed dicts under `categories`."""

    # Field order matches what docker actually emits (alphabetical). Confirmed
    # against a live host (Docker 24+): `docker system df --format '{{json .}}'`
    # emits keys alphabetically, all values as strings, Build Cache's
    # Reclaimable lacks the `(NN%)` suffix the other three rows carry.
    images_row = (
        '{"Active":"62","Reclaimable":"201.1GB (85%)","Size":"235.7GB","TotalCount":"190","Type":"Images"}'
    )
    containers_row = (
        '{"Active":"64","Reclaimable":"474.6MB (17%)","Size":"2.723GB","TotalCount":"67","Type":"Containers"}'
    )
    volumes_row = (
        '{"Active":"21","Reclaimable":"99.73GB (99%)","Size":"100.5GB",'
        '"TotalCount":"141","Type":"Local Volumes"}'
    )
    cache_row = (
        '{"Active":"0","Reclaimable":"17.54GB","Size":"72.6GB","TotalCount":"285","Type":"Build Cache"}'
    )

    async def fake_run_docker(*_a, **_kw):
        return {
            "stdout": f"{images_row}\n{containers_row}\n{volumes_row}\n{cache_row}\n",
            "exit_code": 0,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_system_df(host="docker1", ctx=_happy_ctx())
    cats = out["categories"]
    assert len(cats) == 4
    assert [c["Type"] for c in cats] == ["Images", "Containers", "Local Volumes", "Build Cache"]
    # Spot-check a single row preserves every field as a STRING (Docker's
    # human-readable format -- we do not byte-convert). Values are from the
    # live host fixture above.
    images = cats[0]
    assert images["TotalCount"] == "190"
    assert images["Size"] == "235.7GB"
    assert images["Reclaimable"] == "201.1GB (85%)"
    # Build Cache's Reclaimable lacks the percentage suffix the other rows
    # carry -- pin the asymmetry so a future Docker output drift is caught.
    cache = cats[3]
    assert cache["Type"] == "Build Cache"
    assert cache["Reclaimable"] == "17.54GB"
    assert "(" not in cache["Reclaimable"]


@pytest.mark.asyncio
async def test_system_df_empty_stdout_yields_empty_categories(monkeypatch) -> None:
    """Empty stdout (daemon down before output, or filter that hit nothing)
    yields `categories=[]` rather than raising. Caller reads `exit_code`
    to disambiguate."""

    async def fake_run_docker(*_a, **_kw):
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_system_df(host="docker1", ctx=_happy_ctx())
    assert out["categories"] == []
    assert out["exit_code"] == 0


@pytest.mark.asyncio
async def test_system_df_nonzero_exit_preserved(monkeypatch) -> None:
    """Non-zero exit (daemon down, permission denied) lands intact on the
    response so the caller can branch on it. `categories` reflects whatever
    stdout was -- typically `[]`."""

    async def fake_run_docker(*_a, **_kw):
        return {
            "stdout": "",
            "stderr": "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
            "exit_code": 1,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_system_df(host="docker1", ctx=_happy_ctx())
    assert out["exit_code"] == 1
    assert out["categories"] == []
    assert "Cannot connect" in out["stderr"]


@pytest.mark.asyncio
async def test_system_df_malformed_line_is_skipped(monkeypatch) -> None:
    """A garbage line in the middle of the NDJSON stream is dropped by
    `_parse_json_lines`; the remaining rows survive. Defensive -- Docker
    occasionally prints a warning before the JSON when the daemon is
    laggy."""

    async def fake_run_docker(*_a, **_kw):
        return {
            "stdout": (
                '{"Active":"1","Reclaimable":"0B (0%)","Size":"100MB","TotalCount":"1","Type":"Images"}\n'
                "NOT JSON AT ALL\n"
                '{"Active":"0","Reclaimable":"0B","Size":"0B","TotalCount":"0","Type":"Containers"}\n'
            ),
            "exit_code": 0,
        }

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    out = await ssh_docker_system_df(host="docker1", ctx=_happy_ctx())
    # The garbage line is dropped; the two valid lines survive.
    assert len(out["categories"]) == 2
    assert [c["Type"] for c in out["categories"]] == ["Images", "Containers"]
