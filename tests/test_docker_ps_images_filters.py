"""Filter kwargs for ssh_docker_ps / ssh_docker_images / ssh_docker_compose_ps.

Validates that the new server-side filter kwargs (name/status/label/ancestor
on ps, reference/dangling/label on images, service/status on compose-ps):

- reject shell metacharacters before any SSH connection opens
- assemble argv in the documented deterministic order
- pass-through the validated values verbatim to `_run_docker`
- co-exist with `all_` / `include_labels` / `compose_v1` flags

Same monkeypatch-`_run_docker` pattern as test_docker_events_volumes.py --
no real I/O.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.tools.docker import read_tools
from ssh_mcp.tools.docker_tools import (
    ssh_docker_compose_ps,
    ssh_docker_images,
    ssh_docker_ps,
)


def _happy_ctx() -> Any:
    """ctx that reaches `_run_docker` without blowing up on policy lookup."""
    from ssh_mcp.config import Settings
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings()
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

    return _C()


# ---------------------------------------------------------------------------
# ssh_docker_ps: filter kwargs
# ---------------------------------------------------------------------------


class TestPsFilterValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_name",
        [
            "a;rm",
            "$(whoami)",
            "name with space",
            "name`backtick`",
            "name|pipe",
            "/leading-slash",  # leading non-alnum
        ],
    )
    async def test_rejects_bad_name(self, bad_name: str, monkeypatch) -> None:
        with pytest.raises(ValueError, match="container"):
            await ssh_docker_ps(host="docker1", ctx=_happy_ctx(), name=bad_name)

    @pytest.mark.asyncio
    async def test_rejects_bad_ancestor(self, monkeypatch) -> None:
        with pytest.raises(ValueError, match="ancestor"):
            await ssh_docker_ps(host="docker1", ctx=_happy_ctx(), ancestor="a;rm")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_label",
        [
            "role=$(whoami)",  # shell substitution in value
            "role=a;rm",  # injection
            "ro le=foo",  # space in key
            "role=val ue",  # space in value
            "role=`backtick`",
            "" * 1,  # empty string — falls through to bare-key path
        ],
    )
    async def test_rejects_bad_label(self, bad_label: str, monkeypatch) -> None:
        with pytest.raises(ValueError, match="label"):
            await ssh_docker_ps(host="docker1", ctx=_happy_ctx(), label=bad_label)


@pytest.mark.asyncio
async def test_ps_argv_no_filters(monkeypatch) -> None:
    """Sanity: with no filters, no `--filter` token leaks into argv."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_ps(host="docker1", ctx=_happy_ctx())
    assert captured["argv"] == ["ps", "--format", "{{json .}}", "--no-trunc"]
    assert "--filter" not in captured["argv"]


@pytest.mark.asyncio
async def test_ps_argv_all_filters_in_documented_order(monkeypatch) -> None:
    """Argv ordering: name, status, label, ancestor (each as --filter), then -a."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_ps(
        host="docker1",
        ctx=_happy_ctx(),
        all_=True,
        name="web",
        status="running",
        label="role=frontend",
        ancestor="nginx",
    )
    argv = captured["argv"]
    assert argv[:4] == ["ps", "--format", "{{json .}}", "--no-trunc"]
    # Each filter is a separate `--filter` + KEY=VALUE pair, in documented order.
    expected_filters = [
        "--filter",
        "name=web",
        "--filter",
        "status=running",
        "--filter",
        "label=role=frontend",
        "--filter",
        "ancestor=nginx",
    ]
    assert argv[4 : 4 + len(expected_filters)] == expected_filters
    # -a comes after all filters.
    assert argv[-1] == "-a"


@pytest.mark.asyncio
async def test_ps_status_only(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_ps(host="docker1", ctx=_happy_ctx(), status="exited")
    assert "--filter" in captured["argv"]
    assert "status=exited" in captured["argv"]


@pytest.mark.asyncio
async def test_ps_label_bare_key(monkeypatch) -> None:
    """Bare key form (no `=`) is accepted -- matches any container with the label."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_ps(host="docker1", ctx=_happy_ctx(), label="role")
    assert "label=role" in captured["argv"]


@pytest.mark.asyncio
async def test_ps_kubernetes_style_label(monkeypatch) -> None:
    """Kubernetes-style label keys (`app.kubernetes.io/name=nginx`) are accepted."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_ps(
        host="docker1",
        ctx=_happy_ctx(),
        label="app.kubernetes.io/name=nginx",
    )
    assert "label=app.kubernetes.io/name=nginx" in captured["argv"]


# ---------------------------------------------------------------------------
# ssh_docker_images: filter kwargs
# ---------------------------------------------------------------------------


class TestImagesFilterValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "bad_reference",
        [
            "nginx;rm",
            "nginx`backtick`",
            "nginx $(whoami)",
            "nginx|pipe",
        ],
    )
    async def test_rejects_bad_reference(self, bad_reference: str) -> None:
        with pytest.raises(ValueError, match="reference"):
            await ssh_docker_images(
                host="docker1",
                ctx=_happy_ctx(),
                reference=bad_reference,
            )

    @pytest.mark.asyncio
    async def test_rejects_bad_label(self) -> None:
        with pytest.raises(ValueError, match="label"):
            await ssh_docker_images(
                host="docker1",
                ctx=_happy_ctx(),
                label="role=$(whoami)",
            )


@pytest.mark.asyncio
async def test_images_argv_no_filters(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_images(host="docker1", ctx=_happy_ctx())
    assert captured["argv"] == ["images", "--format", "{{json .}}"]
    assert "--filter" not in captured["argv"]


@pytest.mark.asyncio
async def test_images_argv_all_filters_in_documented_order(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_images(
        host="docker1",
        ctx=_happy_ctx(),
        reference="nginx:*",
        dangling=True,
        label="builder=ci",
    )
    expected_filters = [
        "--filter",
        "reference=nginx:*",
        "--filter",
        "dangling=true",
        "--filter",
        "label=builder=ci",
    ]
    assert captured["argv"][3 : 3 + len(expected_filters)] == expected_filters


@pytest.mark.asyncio
async def test_images_dangling_false_renders_lowercase(monkeypatch) -> None:
    """dangling=False must render `dangling=false` (lowercase), not `False`."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_images(host="docker1", ctx=_happy_ctx(), dangling=False)
    assert "dangling=false" in captured["argv"]
    # No accidental Python repr leak.
    assert "dangling=False" not in captured["argv"]


@pytest.mark.asyncio
async def test_images_reference_glob_wildcards(monkeypatch) -> None:
    """Docker glob wildcards (`*`, `?`) are accepted in reference."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    await ssh_docker_images(
        host="docker1",
        ctx=_happy_ctx(),
        reference="ghcr.io/org/*:*",
    )
    assert "reference=ghcr.io/org/*:*" in captured["argv"]


# ---------------------------------------------------------------------------
# ssh_docker_compose_ps: filter kwargs
# ---------------------------------------------------------------------------


def _compose_ctx(monkeypatch) -> Any:
    """ctx that bypasses path resolution -- compose_ps calls resolve_path."""
    from ssh_mcp.tools.docker import read_tools as rt

    async def fake_resolve_path(*_a, **_kw):
        return "/opt/app/docker-compose.yml"

    monkeypatch.setattr(rt, "resolve_path", fake_resolve_path)
    return _happy_ctx()


class TestComposePsFilterValidation:
    @pytest.mark.asyncio
    async def test_rejects_bad_service(self, monkeypatch) -> None:
        ctx = _compose_ctx(monkeypatch)
        with pytest.raises(ValueError, match="service"):
            await ssh_docker_compose_ps(
                host="docker1",
                ctx=ctx,
                compose_file="/opt/app/docker-compose.yml",
                service="a;rm",
            )


@pytest.mark.asyncio
async def test_compose_ps_argv_no_filters(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    ctx = _compose_ctx(monkeypatch)
    await ssh_docker_compose_ps(
        host="docker1",
        ctx=ctx,
        compose_file="/opt/app/docker-compose.yml",
    )
    assert captured["argv"] == [
        "-f",
        "/opt/app/docker-compose.yml",
        "ps",
        "--format",
        "json",
    ]
    assert "--filter" not in captured["argv"]


@pytest.mark.asyncio
async def test_compose_ps_argv_status_before_service_positional(monkeypatch) -> None:
    """Compose requires flags before positionals -- our argv must obey."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    ctx = _compose_ctx(monkeypatch)
    await ssh_docker_compose_ps(
        host="docker1",
        ctx=ctx,
        compose_file="/opt/app/docker-compose.yml",
        service="web",
        status="running",
    )
    argv = captured["argv"]
    # ... ps --format json --filter status=running web
    assert argv[:5] == ["-f", "/opt/app/docker-compose.yml", "ps", "--format", "json"]
    assert argv[5:7] == ["--filter", "status=running"]
    assert argv[7] == "web"  # service positional must be LAST


@pytest.mark.asyncio
async def test_compose_ps_status_removing_is_compose_only(monkeypatch) -> None:
    """`removing` is in the compose-ps status set (not in plain ps)."""
    captured: dict[str, Any] = {}

    async def fake_run_docker(_ctx, _host, argv, **_kw):
        captured["argv"] = argv
        return {"stdout": "", "exit_code": 0}

    monkeypatch.setattr(read_tools, "_run_docker", fake_run_docker)
    ctx = _compose_ctx(monkeypatch)
    await ssh_docker_compose_ps(
        host="docker1",
        ctx=ctx,
        compose_file="/opt/app/docker-compose.yml",
        status="removing",
    )
    assert "status=removing" in captured["argv"]
