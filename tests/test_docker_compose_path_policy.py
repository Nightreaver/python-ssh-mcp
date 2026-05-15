"""Restricted-zone enforcement on the 5 compose-file call sites (INC-061).

Pre-Sprint-1, the ``ssh_docker_compose_*`` tools resolved ``compose_file``
through ``canonicalize_and_check`` only -- they skipped ``check_not_restricted``.
So an operator's ``restricted_paths`` (e.g. SMB mount at ``/mnt/shared``)
blocked the LLM from reading/writing files there but did NOT block the LLM
from running ``docker compose -f /mnt/shared/stack.yml up``. Compose YAML can
mount volumes, declare ports, run init commands -- so "execute it" is a
meaningful "touch" of the file. The user (2026-05-03) decided to close the
gap and treat compose-file paths uniformly with every other path-bearing
tool.

Each test monkeypatches ``resolve_path`` on the tool module to raise
``PathRestricted`` and asserts the tool body actually invokes it. A future
refactor that drops the call regresses loudly.

Test pattern modelled on ``_stub_ctx_for_cp`` in ``test_docker_top_cp.py``.
"""

from __future__ import annotations

from typing import Any, ClassVar, NoReturn
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.ssh.errors import PathRestricted
from ssh_mcp.tools.docker import _helpers as docker_helpers
from ssh_mcp.tools.docker import dangerous_tools, read_tools
from ssh_mcp.tools.docker_tools import (
    ssh_docker_compose_down,
    ssh_docker_compose_logs,
    ssh_docker_compose_ps,
    ssh_docker_compose_start,
    ssh_docker_compose_up,
)


def _stub_ctx_for_compose() -> Any:
    """Build a ctx with a restricted zone configured."""
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings(
        SSH_PATH_ALLOWLIST=["/mnt/shared"],
        SSH_RESTRICTED_PATHS=["/mnt/shared"],
        ALLOW_LOW_ACCESS_TOOLS=True,
        ALLOW_DANGEROUS_TOOLS=True,
    )
    policy = HostPolicy(
        hostname="docker1",
        user="deploy",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/mnt/shared"],
        restricted_paths=["/mnt/shared"],
    )

    class _C:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": settings,
            "hosts": {"docker1": policy},
        }

    return _C()


async def _resolve_raises(*_a: Any, **_kw: Any) -> NoReturn:
    """Stub: simulate the bundled chain raising on a restricted path."""
    raise PathRestricted("compose file lives in restricted zone")


@pytest.mark.asyncio
async def test_compose_up_enforces_restricted_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dangerous_tools, "resolve_path", _resolve_raises)
    with pytest.raises(PathRestricted):
        await ssh_docker_compose_up(
            host="docker1",
            compose_file="/mnt/shared/stack.yml",
            ctx=_stub_ctx_for_compose(),
        )


@pytest.mark.asyncio
async def test_compose_down_enforces_restricted_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dangerous_tools, "resolve_path", _resolve_raises)
    with pytest.raises(PathRestricted):
        await ssh_docker_compose_down(
            host="docker1",
            compose_file="/mnt/shared/stack.yml",
            ctx=_stub_ctx_for_compose(),
        )


@pytest.mark.asyncio
async def test_compose_ps_enforces_restricted_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(read_tools, "resolve_path", _resolve_raises)
    with pytest.raises(PathRestricted):
        await ssh_docker_compose_ps(
            host="docker1",
            compose_file="/mnt/shared/stack.yml",
            ctx=_stub_ctx_for_compose(),
        )


@pytest.mark.asyncio
async def test_compose_logs_enforces_restricted_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(read_tools, "resolve_path", _resolve_raises)
    with pytest.raises(PathRestricted):
        await ssh_docker_compose_logs(
            host="docker1",
            compose_file="/mnt/shared/stack.yml",
            ctx=_stub_ctx_for_compose(),
        )


@pytest.mark.asyncio
async def test_compose_project_op_helper_enforces_restricted_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cover the shared `_compose_project_op` helper via one of its callers
    (`ssh_docker_compose_start`). Monkeypatch on the helper module, not the
    caller -- the caller delegates immediately to the helper, which is where
    the policy gate lives."""
    monkeypatch.setattr(docker_helpers, "resolve_path", _resolve_raises)
    with pytest.raises(PathRestricted):
        await ssh_docker_compose_start(
            host="docker1",
            compose_file="/mnt/shared/stack.yml",
            ctx=_stub_ctx_for_compose(),
        )
