"""Audit decorator must surface ``unit`` kwargs as ``unit_hash``.

Follow-up to the C1 sprint that landed the nine systemctl mutation tools
(``ssh_systemctl_start`` / ``_stop`` / ``_restart`` / ``_reload`` /
``_enable`` / ``_disable`` / ``_mask`` / ``_unmask`` / ``_reset_failed``).
Those tools all take ``unit: str`` but the audit log was only capturing
``host`` and ``tier`` -- the actual unit being mutated never appeared on
the audit line. This file pins the contract that operators can dedup
audit entries by target unit (hashed, for consistency with ``path_hash``
and ``command_hash``).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from _helpers import make_ctx

from ssh_mcp.services import audit
from ssh_mcp.tools import systemctl_tools
from ssh_mcp.tools.systemctl_tools import (
    ssh_systemctl_mask,
    ssh_systemctl_restart,
    ssh_systemctl_start,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_sink(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    return caplog


def _only_audit_event(caplog: pytest.LogCaptureFixture) -> dict:
    lines = [r.message for r in caplog.records if r.name == "ssh_mcp.audit"]
    assert len(lines) == 1, f"expected 1 audit line, got {len(lines)}: {lines}"
    return json.loads(lines[0])


# ---------------------------------------------------------------------------
# 1. record() carries unit_hash when ``unit`` is provided
# ---------------------------------------------------------------------------


def test_record_emits_unit_hash_when_provided(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    audit.record(
        tool="ssh_systemctl_start",
        tier="dangerous",
        host="web01",
        correlation_id="x",
        duration_ms=1,
        result="ok",
        unit="nginx.service",
    )
    event = _only_audit_event(audit_sink)
    assert "unit_hash" in event
    assert event["unit_hash"].startswith("sha256:")
    # 16 hex chars after the "sha256:" prefix -- same shape as path_hash.
    digest = event["unit_hash"].removeprefix("sha256:")
    assert len(digest) == 16
    assert all(c in "0123456789abcdef" for c in digest)


def test_record_omits_unit_hash_when_not_provided(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    audit.record(
        tool="ssh_mkdir",
        tier="low-access",
        host="web01",
        correlation_id="x",
        duration_ms=1,
        result="ok",
    )
    event = _only_audit_event(audit_sink)
    assert "unit_hash" not in event


def test_record_unit_hash_matches_internal_hash_helper(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """The hash value itself must be ``_hash(unit)`` -- not a length-prefixed
    or otherwise reshaped variant. Operators correlating across audit sinks
    rely on the canonical SHA-256-prefix-16 fingerprint.
    """
    audit.record(
        tool="ssh_systemctl_stop",
        tier="dangerous",
        host="web01",
        correlation_id="x",
        duration_ms=1,
        result="ok",
        unit="postgresql.service",
    )
    event = _only_audit_event(audit_sink)
    assert event["unit_hash"] == audit._hash("postgresql.service")


# ---------------------------------------------------------------------------
# 2. audited() picks up unit kwarg and forwards it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audited_captures_unit_kwarg(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    @audit.audited(tier="dangerous")
    async def ssh_fake_systemctl(host: str, unit: str) -> dict:
        return {"host": host, "unit": unit}

    await ssh_fake_systemctl(host="web01", unit="nginx.service")
    event = _only_audit_event(audit_sink)
    assert "unit_hash" in event
    assert event["unit_hash"] == audit._hash("nginx.service")


@pytest.mark.asyncio
async def test_audited_no_unit_kwarg_means_no_unit_hash(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    @audit.audited(tier="low-access")
    async def ssh_mkdir(host: str, path: str) -> dict:
        return {"host": host, "path": path}

    await ssh_mkdir(host="web01", path="/tmp/x")
    event = _only_audit_event(audit_sink)
    assert "unit_hash" not in event


@pytest.mark.asyncio
async def test_audited_non_string_unit_is_ignored(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """Mirroring the host-extraction defensive check: a non-string ``unit``
    value (someone forwarding the wrong type) must NOT smear into the
    audit stream. We just drop ``unit_hash`` rather than coercing.
    """

    @audit.audited(tier="dangerous")
    async def weird_signature(host: str, unit: object) -> dict:
        return {"host": host}

    await weird_signature(host="web01", unit=12345)  # type: ignore[arg-type]
    event = _only_audit_event(audit_sink)
    assert "unit_hash" not in event


# ---------------------------------------------------------------------------
# 3. Regression: real systemctl mutation tools surface unit_hash
# ---------------------------------------------------------------------------


_REGRESSION_TOOLS: list[tuple[Any, str]] = [
    (ssh_systemctl_start, "nginx.service"),
    (ssh_systemctl_restart, "postgresql.service"),
    (ssh_systemctl_mask, "snapd.service"),
]


@pytest.mark.parametrize(
    ("tool", "unit"),
    _REGRESSION_TOOLS,
    ids=[t.__name__ for t, _u in _REGRESSION_TOOLS],
)
@pytest.mark.asyncio
async def test_systemctl_mutation_audit_carries_unit_hash(
    monkeypatch: pytest.MonkeyPatch,
    audit_sink: pytest.LogCaptureFixture,
    tool: Any,
    unit: str,
) -> None:
    """End-to-end: invoking a real ``@audited(tier="dangerous")`` mutation
    tool with ``unit=...`` must emit ``unit_hash`` on the audit line.

    Three representative tools out of the nine; the audit-extraction logic
    is shared so the per-tool combinatorics are covered by the unit tests
    above.
    """

    async def fake(
        _ctx: Any,
        _host: str,
        _argv: list[str],
        **_kw: Any,
    ) -> tuple[str, str, int, list[str], str]:
        return ("", "", 0, [], "testhost")

    monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)

    await tool(host="testhost", unit=unit, ctx=make_ctx())

    event = _only_audit_event(audit_sink)
    assert event["tool"] == tool.__name__
    assert event["tier"] == "dangerous"
    assert event["host"] == "testhost"
    assert "unit_hash" in event, (
        f"{tool.__name__}: audit line missing unit_hash; "
        "the @audited decorator must extract `unit` from kwargs"
    )
    assert event["unit_hash"] == audit._hash(unit)
