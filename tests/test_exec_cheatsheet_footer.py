"""B2: cheatsheet-hint footer on ``ExecResult.output_warnings`` under the
``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS`` opt-out.

Default state (opt-out=false) rejects the call BEFORE exec runs -- that path is
covered by ``tests/test_exec_cheatsheet.py``. This module covers the
post-execution wiring: when the opt-out is on, the exec proceeds, and the
result's ``output_warnings`` gains a prepended hint pointing at the structured
wrapper the LLM should reach for next time.

Covered:

1. Per pattern class (parametrized): ``ssh_exec_run`` hits each of the seven
   pattern classes, the underlying exec is invoked, the result's first
   ``output_warnings`` entry is the cheatsheet hint with the right tool name +
   pattern id + suggested wrapper.
2. ``ssh_exec_run_streaming`` mirrors the same wiring (two sample patterns;
   logic shared with ``ssh_exec_run``).
3. ``ssh_sudo_exec`` uses tool name ``ssh_sudo_exec`` in the hint.
4. Negative: no cheatsheet match -> no footer (output_warnings stays as
   whatever the exec layer returned).
5. Control: opt-out=false -> rejection raises BEFORE exec runs (mock not
   called).
6. Sanitizer-warning co-existence: when the result already carries sanitizer
   flags (INC-057/058), the cheatsheet warning is PREPENDED so it lands first;
   sanitizer flags follow.
7. ``cheatsheet_hint_warning`` helper: pure-function exact string output.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest
from _helpers import make_ctx

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.models.results import ExecResult
from ssh_mcp.services.exec_cheatsheet import (
    CheatsheetMatch,
    cheatsheet_hint_warning,
    match_cheatsheet,
)
from ssh_mcp.ssh.errors import CommandIsCheatsheetMatch
from ssh_mcp.tools import exec_tools, sudo_tools
from ssh_mcp.tools.exec_tools import ssh_exec_run, ssh_exec_run_streaming
from ssh_mcp.tools.sudo_tools import ssh_sudo_exec

# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------


def _ctx_opt_out(*, opt_out: bool = True, hostname: str = "testhost") -> Any:
    """Build a fake Context with the opt-out toggled.

    Mirrors ``tests/test_exec_cheatsheet.py::_ctx_with_settings`` but always
    seeds ``ALLOW_ANY_COMMAND=True`` so the downstream ``check_command``
    gate doesn't fire before we get to the exec layer.
    """
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings(
        SSH_HOSTS_ALLOWLIST=[hostname],
        ALLOW_ANY_COMMAND=True,
        SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=opt_out,
    )
    policy = HostPolicy(hostname=hostname, user="deploy", auth=AuthPolicy(method="agent"))

    class _Ctx:
        lifespan_context: ClassVar[dict] = {
            "pool": pool,
            "settings": settings,
            "hosts": {hostname: policy},
        }

    return _Ctx()


def _ok_result(host: str = "testhost", *, output_warnings: list[str] | None = None) -> ExecResult:
    """Build a plausible ok ExecResult that the mocked exec layer returns."""
    return ExecResult(
        host=host,
        exit_code=0,
        stdout="ok\n",
        stderr="",
        stdout_bytes=3,
        stderr_bytes=0,
        duration_ms=1,
        output_warnings=list(output_warnings or []),
    )


class _StubProgress:
    """No-op stand-in for ``fastmcp.Progress`` outside a server context.

    Bare ``Progress()`` errors with "Progress must be used as a dependency"
    -- FastMCP expects the framework to inject the real backing impl. The
    streaming tool only calls these three awaitables, so the duck-typed
    stub is sufficient. Mirrors the helper in
    ``tests/e2e/test_e2e_real_hosts.py``.
    """

    async def set_total(self, total: int | None) -> None:
        return None

    async def increment(self, amount: int = 1) -> None:
        return None

    async def set_message(self, message: str) -> None:
        return None


# ---------------------------------------------------------------------------
# 1. Per pattern class -- ssh_exec_run prepends the hint to output_warnings
# ---------------------------------------------------------------------------


_FOOTER_CASES_EXEC: list[tuple[str, str, str]] = [
    # (command, pattern_id, suggested_tool)
    ("docker ps", "docker", "ssh_docker_ps"),
    ("systemctl restart nginx", "systemctl", "ssh_systemctl_restart"),
    ("journalctl -u nginx", "journalctl", "ssh_journalctl"),
    ("apt install nginx", "apt-mutation", "ssh_apt_install"),
    ("cat > /tmp/x <<EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("mkdir /tmp/foo", "single-fileop", "ssh_mkdir"),
    ("uname -a > /tmp/hostinfo", "output-redirect", "ssh_upload"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "pattern_id", "suggested_tool"),
    _FOOTER_CASES_EXEC,
    ids=[c[0][:40] for c in _FOOTER_CASES_EXEC],
)
async def test_ssh_exec_run_prepends_cheatsheet_hint_when_opt_out(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    pattern_id: str,
    suggested_tool: str,
) -> None:
    """Opt-out=true + cheatsheet match: exec runs, warning prepended."""
    ctx = _ctx_opt_out(opt_out=True)

    captured = AsyncMock(return_value=_ok_result())
    monkeypatch.setattr(exec_tools, "exec_run", captured)

    result = await ssh_exec_run(host="testhost", command=command, ctx=ctx)

    # Exec layer was actually called -- opt-out does not skip the exec.
    assert captured.await_count == 1
    # Hint is present, in slot 0, with the right tool name + pattern + wrapper.
    assert result.output_warnings, "expected cheatsheet hint in output_warnings"
    first = result.output_warnings[0]
    assert "ssh_exec_run command matched cheatsheet pattern" in first
    assert f"'{pattern_id}'" in first
    assert f"consider {suggested_tool} next time" in first


# ---------------------------------------------------------------------------
# 2. ssh_exec_run_streaming wires identically (sample of two patterns)
# ---------------------------------------------------------------------------


_FOOTER_CASES_STREAMING: list[tuple[str, str, str]] = [
    ("docker logs nginx", "docker", "ssh_docker_logs"),
    ("journalctl -f", "journalctl", "ssh_journalctl"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "pattern_id", "suggested_tool"),
    _FOOTER_CASES_STREAMING,
    ids=[c[0][:40] for c in _FOOTER_CASES_STREAMING],
)
async def test_ssh_exec_run_streaming_prepends_cheatsheet_hint_when_opt_out(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    pattern_id: str,
    suggested_tool: str,
) -> None:
    ctx = _ctx_opt_out(opt_out=True)

    captured = AsyncMock(return_value=_ok_result())
    monkeypatch.setattr(exec_tools, "exec_run_streaming", captured)

    result = await ssh_exec_run_streaming(
        host="testhost",
        command=command,
        ctx=ctx,
        progress=_StubProgress(),  # type: ignore[arg-type]
    )

    assert captured.await_count == 1
    assert result.output_warnings
    first = result.output_warnings[0]
    assert "ssh_exec_run_streaming command matched cheatsheet pattern" in first
    assert f"'{pattern_id}'" in first
    assert f"consider {suggested_tool} next time" in first


# ---------------------------------------------------------------------------
# 3. ssh_sudo_exec uses 'ssh_sudo_exec' in the hint tool name
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_sudo_exec_prepends_cheatsheet_hint_with_sudo_tool_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hint emitted by ``ssh_sudo_exec`` must surface the sudo tool name so
    the LLM redirect target is unambiguous."""
    ctx = _ctx_opt_out(opt_out=True)

    captured = AsyncMock(return_value=_ok_result())
    monkeypatch.setattr(sudo_tools, "run_sudo", captured)
    # Avoid touching the OS keyring / subprocess in tests.
    monkeypatch.setattr(sudo_tools, "fetch_sudo_password", lambda _s, _h: None)

    result = await ssh_sudo_exec(host="testhost", command="systemctl restart nginx", ctx=ctx)

    assert captured.await_count == 1
    assert result.output_warnings
    first = result.output_warnings[0]
    # The key contract: the hint says ssh_sudo_exec (NOT ssh_exec_run) so the
    # LLM picks the right refactoring target for privileged invocations.
    assert first.startswith("ssh_sudo_exec command matched cheatsheet pattern")
    assert "'systemctl'" in first
    assert "consider ssh_systemctl_restart next time" in first


# ---------------------------------------------------------------------------
# 4. No match -> no footer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_footer_when_no_cheatsheet_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commands that don't hit any cheatsheet pattern must NOT gain a footer
    -- even with the opt-out on, the matcher returns None and nothing is
    appended to output_warnings.
    """
    ctx = _ctx_opt_out(opt_out=True)

    # Pre-seed an existing sanitizer warning to assert it's preserved as-is
    # (no cheatsheet match -> no mutation of output_warnings).
    seeded = ["sanitizer: ANSI escapes stripped"]
    captured = AsyncMock(return_value=_ok_result(output_warnings=seeded))
    monkeypatch.setattr(exec_tools, "exec_run", captured)

    result = await ssh_exec_run(host="testhost", command="uname -a", ctx=ctx)

    assert captured.await_count == 1
    # Only the seeded warning -- nothing prepended.
    assert result.output_warnings == seeded


# ---------------------------------------------------------------------------
# 5. Control: opt-out=false -> rejection, no footer (exec not called)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_state_rejects_before_exec_no_footer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the default ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false``, a
    matching command raises ``CommandIsCheatsheetMatch`` BEFORE the exec
    layer is called. The footer wiring is therefore unreachable on this
    path -- this control test confirms the rejection contract (B1) still
    holds.
    """
    ctx = make_ctx()  # defaults: opt-out=False

    captured = AsyncMock(return_value=_ok_result())
    monkeypatch.setattr(exec_tools, "exec_run", captured)

    with pytest.raises(CommandIsCheatsheetMatch):
        await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)

    # Exec was NEVER invoked -- rejection short-circuits before pool acquire.
    assert captured.await_count == 0


# ---------------------------------------------------------------------------
# 6. Sanitizer warnings + cheatsheet hint coexist; cheatsheet is FIRST
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cheatsheet_hint_prepended_before_sanitizer_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the exec layer already returns output_warnings (sanitizer flags
    from INC-057/058) AND the command matched a cheatsheet pattern, both
    must be present and the cheatsheet hint must come first.
    """
    ctx = _ctx_opt_out(opt_out=True)

    sanitizer_flags = [
        "sanitizer: ANSI escape sequences stripped from stdout",
        "sanitizer: NUL bytes present in stderr",
    ]
    captured = AsyncMock(return_value=_ok_result(output_warnings=sanitizer_flags))
    monkeypatch.setattr(exec_tools, "exec_run", captured)

    result = await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)

    # Three warnings total: 1 cheatsheet hint + 2 sanitizer flags.
    assert len(result.output_warnings) == 3
    # Order: cheatsheet first, then sanitizer flags in original order.
    assert "ssh_exec_run command matched cheatsheet pattern" in result.output_warnings[0]
    assert "consider ssh_docker_ps next time" in result.output_warnings[0]
    assert result.output_warnings[1:] == sanitizer_flags


# ---------------------------------------------------------------------------
# 7. cheatsheet_hint_warning() helper -- pure function string contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "tool_name", "expected"),
    [
        (
            "docker ps",
            "ssh_exec_run",
            "ssh_exec_run command matched cheatsheet pattern 'docker'; consider ssh_docker_ps next time",
        ),
        (
            "systemctl restart nginx",
            "ssh_sudo_exec",
            (
                "ssh_sudo_exec command matched cheatsheet pattern 'systemctl'; "
                "consider ssh_systemctl_restart next time"
            ),
        ),
        (
            "apt install nginx",
            "ssh_exec_run_streaming",
            (
                "ssh_exec_run_streaming command matched cheatsheet pattern 'apt-mutation'; "
                "consider ssh_apt_install next time"
            ),
        ),
    ],
    ids=["docker-ps-exec", "systemctl-sudo", "apt-streaming"],
)
def test_cheatsheet_hint_warning_exact_string(command: str, tool_name: str, expected: str) -> None:
    match = match_cheatsheet(command)
    assert isinstance(match, CheatsheetMatch)
    assert cheatsheet_hint_warning(match=match, tool_name=tool_name) == expected


# ---------------------------------------------------------------------------
# 8. Audit field: ``cheatsheet_pattern_id`` lands on the audit line when the
# opt-out is used and a pattern matched. Operators grep
# ``jq 'select(.cheatsheet_pattern_id)'`` to count bypasses per pattern.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_line_carries_cheatsheet_pattern_id_on_opt_out_bypass(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Opt-out=true + cheatsheet match: the audit line gains
    ``cheatsheet_pattern_id=<id>`` so operators can grep abuse by pattern.
    """
    import json
    import logging

    ctx = _ctx_opt_out(opt_out=True)
    monkeypatch.setattr(exec_tools, "exec_run", AsyncMock(return_value=_ok_result()))
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")

    await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)

    audit_lines = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "ssh_mcp.audit"
    ]
    assert len(audit_lines) == 1, f"expected 1 audit line, got {len(audit_lines)}"
    event = audit_lines[0]
    assert event.get("cheatsheet_pattern_id") == "docker", (
        f"audit line missing cheatsheet_pattern_id=docker; got {event!r}"
    )
    # Sanity: the call succeeded, so the bypass is real (not a coincidence
    # with the rejection-suppression path).
    assert event["result"] == "ok"


@pytest.mark.asyncio
async def test_audit_line_omits_cheatsheet_field_when_no_match(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No cheatsheet match -> no ``cheatsheet_pattern_id`` field at all
    (not even ``null``). Keeps the audit shape compact for the common case.
    """
    import json
    import logging

    ctx = _ctx_opt_out(opt_out=True)
    monkeypatch.setattr(exec_tools, "exec_run", AsyncMock(return_value=_ok_result()))
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")

    # `uname -a` doesn't match any cheatsheet pattern.
    await ssh_exec_run(host="testhost", command="uname -a", ctx=ctx)

    audit_lines = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "ssh_mcp.audit"
    ]
    assert len(audit_lines) == 1
    assert "cheatsheet_pattern_id" not in audit_lines[0]


@pytest.mark.asyncio
async def test_audit_cheatsheet_field_does_not_leak_across_calls(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """ContextVar isolation: a bypass on call 1 must not stamp call 2's
    audit line. Sequential tool dispatch on one task is the common shape
    (the LLM chains calls); leakage would corrupt the telemetry.
    """
    import json
    import logging

    ctx = _ctx_opt_out(opt_out=True)
    monkeypatch.setattr(exec_tools, "exec_run", AsyncMock(return_value=_ok_result()))
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")

    # Call 1: bypass (cheatsheet match under opt-out).
    await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)
    # Call 2: no match -- must NOT inherit call 1's pattern_id.
    await ssh_exec_run(host="testhost", command="uname -a", ctx=ctx)

    audit_lines = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "ssh_mcp.audit"
    ]
    assert len(audit_lines) == 2
    assert audit_lines[0].get("cheatsheet_pattern_id") == "docker"
    assert "cheatsheet_pattern_id" not in audit_lines[1], (
        "ContextVar leaked across calls -- the reset() token did not bound the slot."
    )
