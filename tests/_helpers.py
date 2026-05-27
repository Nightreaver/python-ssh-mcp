"""Shared test helpers.

Importable as ``from _helpers import make_ctx`` — ``conftest.py`` adds the
``tests/`` directory to ``sys.path`` so individual test modules can grab the
helper without per-package wiring.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock


def make_ctx(hostname: str = "testhost") -> Any:
    """Minimal fake FastMCP Context that resolves to a fake host policy.

    Used by the systemctl tool tests (read tier, mutation tier, audit
    plumbing). Builds a lifespan with a single host whose canonical
    ``HostPolicy.hostname`` matches the ``hostname`` argument so result
    models stamp the expected ``host`` field.
    """
    from ssh_mcp.config import Settings
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings()
    policy = HostPolicy(hostname=hostname, user="deploy", auth=AuthPolicy(method="agent"))

    class _Ctx:
        lifespan_context: ClassVar[dict] = {
            "pool": pool,
            "settings": settings,
            "hosts": {hostname: policy},
        }

    return _Ctx()
