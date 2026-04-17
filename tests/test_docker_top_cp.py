"""Input validation + happy-path argv shape for ssh_docker_top / ssh_docker_cp.

Two layers of coverage:

1. Pure pre-validation: bad container names, shell metacharacters in
   ``ps_options``, invalid ``direction`` values. Short-circuits before any
   I/O so we use a stub ctx with no lifespan_context.

2. Happy-path argv assertion: drives ``ssh_docker_cp`` past validation with
   stubbed pool / resolve_host / canonicalize so we can capture the argv
   that lands at ``_run_docker``. This is the layer that would have caught
   the missing-import NameError reported in the post-merge review.
"""
from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools.docker import lifecycle_tools
from ssh_mcp.tools.docker_tools import ssh_docker_cp, ssh_docker_top

# INC-043: `ssh_docker_cp` lives in `docker.lifecycle_tools` after the split.
# Monkeypatches targeting `_run_docker` / `canonicalize_and_check` /
# `check_not_restricted` MUST target that submodule rather than the
# `docker_tools` facade -- re-export aliases don't intercept the module-level
# name lookup inside the tool body.


class _Ctx:
    """Minimal ctx that surfaces just enough lifespan_context to trigger the
    validation we care about. Never reaches the pool."""

    def __init__(self, lifespan: dict) -> None:
        self.lifespan_context = lifespan


# --- ssh_docker_top ---


class TestDockerTopInputs:
    @pytest.mark.asyncio
    async def test_rejects_bad_container_name(self) -> None:
        with pytest.raises(ValueError, match="container"):
            await ssh_docker_top(
                host="docker1",
                container="a;rm -rf /",
                ctx=_Ctx({}),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_opts",
        [
            "foo | tee /tmp/x",   # pipe
            "foo && bar",         # &&
            "foo; bar",           # ;
            "foo `whoami`",       # backtick
            "foo $(whoami)",      # $(...)
            "foo > /tmp/x",       # redirect
            "foo\nbar",           # newline
        ],
    )
    async def test_rejects_ps_options_with_shell_metachars(self, bad_opts: str) -> None:
        with pytest.raises(ValueError, match="metacharacters"):
            await ssh_docker_top(
                host="docker1",
                container="nginx",
                ctx=_Ctx({}),  # type: ignore[arg-type]
                ps_options=bad_opts,
            )


# --- ssh_docker_cp ---


class TestDockerCpInputs:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "direction", ["from_container", "to_container"],
    )
    async def test_rejects_bad_container_name(self, direction: str) -> None:
        with pytest.raises(ValueError, match="container"):
            await ssh_docker_cp(
                host="docker1",
                container="bad;name",
                container_path="/app/file",
                host_path="/opt/app/file",
                direction=direction,  # type: ignore[arg-type]
                ctx=_Ctx({}),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_rejects_invalid_direction(self) -> None:
        # Literal type + explicit validator; both forms rejected.
        with pytest.raises((ValueError, TypeError)):
            await ssh_docker_cp(
                host="docker1",
                container="nginx",
                container_path="/app/file",
                host_path="/opt/app/file",
                direction="sideways",  # type: ignore[arg-type]
                ctx=_Ctx({}),  # type: ignore[arg-type]
            )


# --- ssh_docker_cp happy path: drive past validation, capture argv ---


def _stub_ctx_for_cp() -> Any:
    """Build a ctx whose lifespan_context contains the four keys the cp tool
    reaches for (`pool`, `settings`, `hosts`, `known_hosts`-not-needed-here).
    The pool is mocked to return a sentinel conn that never gets used."""
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings(
        SSH_PATH_ALLOWLIST=["/opt/app"],
        ALLOW_LOW_ACCESS_TOOLS=True,
    )
    policy = HostPolicy(
        hostname="docker1",
        user="deploy",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/opt/app"],
    )

    class _C:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": {"docker1": policy},
        }

    return _C(), pool


@pytest.mark.asyncio
async def test_cp_from_container_builds_correct_argv(monkeypatch) -> None:
    """Drive the from_container path past validation + path-policy and capture
    the argv that lands at `_run_docker`. This test would have failed at
    NameError if `effective_restricted_paths` / `check_not_restricted` were
    missing from the imports (INCIDENTS INC-029)."""
    captured: dict[str, Any] = {}

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path  # pretend it resolves to itself

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        captured["kwargs"] = kw
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(lifecycle_tools, "canonicalize_and_check", fake_canonicalize)
    monkeypatch.setattr(lifecycle_tools, "_run_docker", fake_run_docker)

    ctx, _pool = _stub_ctx_for_cp()
    await ssh_docker_cp(
        host="docker1",
        container="nginx",
        container_path="/app/report.xml",
        host_path="/opt/app/out.xml",
        direction="from_container",
        ctx=ctx,
    )

    assert captured["argv"] == ["cp", "--", "nginx:/app/report.xml", "/opt/app/out.xml"]


@pytest.mark.asyncio
async def test_cp_to_container_builds_correct_argv(monkeypatch) -> None:
    """Mirror happy-path test for the other direction."""
    captured: dict[str, Any] = {}

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    async def fake_run_docker(_ctx, _host, argv, **kw):
        captured["argv"] = argv
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(lifecycle_tools, "canonicalize_and_check", fake_canonicalize)
    monkeypatch.setattr(lifecycle_tools, "_run_docker", fake_run_docker)

    ctx, _pool = _stub_ctx_for_cp()
    await ssh_docker_cp(
        host="docker1",
        container="nginx",
        container_path="/etc/nginx/conf.d/site.conf",
        host_path="/opt/app/site.conf",
        direction="to_container",
        ctx=ctx,
    )

    assert captured["argv"] == ["cp", "--", "/opt/app/site.conf", "nginx:/etc/nginx/conf.d/site.conf"]


@pytest.mark.asyncio
async def test_cp_calls_restricted_path_check(monkeypatch) -> None:
    """Defense-in-depth: the cp body MUST invoke check_not_restricted on the
    canonicalized host path. If the import for that helper goes missing, this
    test fails at AttributeError on the monkeypatched callable. Catches the
    same class of bug as B1 from a different angle."""
    calls: list[Any] = []

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    def fake_check_not_restricted(canonical, restricted, platform):
        calls.append((canonical, list(restricted), platform))

    async def fake_run_docker(_ctx, _host, argv, **kw):
        return {"stdout": "", "stderr": "", "exit_code": 0}

    monkeypatch.setattr(lifecycle_tools, "canonicalize_and_check", fake_canonicalize)
    monkeypatch.setattr(lifecycle_tools, "check_not_restricted", fake_check_not_restricted)
    monkeypatch.setattr(lifecycle_tools, "_run_docker", fake_run_docker)

    ctx, _pool = _stub_ctx_for_cp()
    await ssh_docker_cp(
        host="docker1",
        container="nginx",
        container_path="/app/x",
        host_path="/opt/app/x",
        direction="from_container",
        ctx=ctx,
    )

    assert len(calls) == 1
    canonical, _restricted, platform = calls[0]
    assert canonical == "/opt/app/x"
    assert platform == "posix"
