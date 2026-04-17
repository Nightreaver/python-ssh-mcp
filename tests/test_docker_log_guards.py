"""ssh_docker_logs / ssh_docker_compose_logs -- context-protection guards."""
from __future__ import annotations

import pytest


def test_max_bytes_range_validation_logs() -> None:
    """max_bytes bounds exist to stop operators silently raising to 'unlimited'."""
    from ssh_mcp.tools.docker_tools import _DEFAULT_LOG_MAX_BYTES

    assert _DEFAULT_LOG_MAX_BYTES == 64 * 1024


@pytest.mark.asyncio
async def test_logs_rejects_max_bytes_too_small() -> None:
    from ssh_mcp.tools.docker_tools import ssh_docker_logs

    with pytest.raises(ValueError, match="max_bytes"):
        await ssh_docker_logs(
            host="web01", container="nginx", ctx=_noop_ctx(), max_bytes=512
        )


@pytest.mark.asyncio
async def test_logs_rejects_max_bytes_too_large() -> None:
    from ssh_mcp.tools.docker_tools import ssh_docker_logs

    with pytest.raises(ValueError, match="max_bytes"):
        await ssh_docker_logs(
            host="web01", container="nginx", ctx=_noop_ctx(), max_bytes=20 * 1024 * 1024
        )


@pytest.mark.asyncio
async def test_logs_rejects_tail_out_of_range() -> None:
    from ssh_mcp.tools.docker_tools import ssh_docker_logs

    with pytest.raises(ValueError, match="tail"):
        await ssh_docker_logs(
            host="web01", container="nginx", ctx=_noop_ctx(), tail=0
        )
    with pytest.raises(ValueError, match="tail"):
        await ssh_docker_logs(
            host="web01", container="nginx", ctx=_noop_ctx(), tail=100001
        )


@pytest.mark.asyncio
async def test_logs_rejects_bad_container_name() -> None:
    from ssh_mcp.tools.docker_tools import ssh_docker_logs

    with pytest.raises(ValueError, match="container"):
        await ssh_docker_logs(
            host="web01", container="a;rm -rf /", ctx=_noop_ctx()
        )


@pytest.mark.asyncio
async def test_compose_logs_rejects_bad_service_name() -> None:
    from ssh_mcp.tools.docker_tools import ssh_docker_compose_logs

    with pytest.raises(ValueError, match="service"):
        await ssh_docker_compose_logs(
            host="web01",
            compose_file="/opt/app/docker-compose.yml",
            ctx=_noop_ctx(),
            service="a;rm",
        )


def _noop_ctx() -> object:
    """Minimal fake context; tests above fail-fast BEFORE it gets used."""
    return object()
