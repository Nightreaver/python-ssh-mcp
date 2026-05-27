"""Unit tests for the dangerous-tier systemctl mutation tools.

Coverage per tool (one parametrised class for the nine verbs):
1. Tag set carries ``{"dangerous", "group:systemctl"}`` -- the lifespan's
   ``Visibility(False, tags={"dangerous"})`` transform hides them from
   ``tools/list`` when ``ALLOW_DANGEROUS_TOOLS=false``. We verify the tag
   contract here (the Visibility wiring itself is covered by
   ``test_tool_registration.py``).
2. Happy-path: mocked ``_run_systemctl`` returns ok -> result fields are
   populated and shape matches ``SystemctlUnitActionResult``.
3. Unit-name validation: shell metacharacters, slashes, unknown unit-type
   suffix, and empty string are all rejected by ``_validate_systemd_unit_name``.
4. Non-zero exit codes propagate as data (no exception).
5. ``output_warnings`` plumb through from ``_run_systemctl`` into the
   tool's returned dict.
6. argv shape: ``["systemctl", <verb>, "--", <unit>]`` exactly, so the
   unit name can never be parsed as a flag.
7. ``timeout=`` kwarg reaches ``_run_systemctl`` unchanged.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from _helpers import make_ctx

from ssh_mcp.models.systemctl import SystemctlUnitActionResult
from ssh_mcp.tools import systemctl_tools
from ssh_mcp.tools.systemctl_tools import (
    ssh_systemctl_disable,
    ssh_systemctl_enable,
    ssh_systemctl_mask,
    ssh_systemctl_reload,
    ssh_systemctl_reset_failed,
    ssh_systemctl_restart,
    ssh_systemctl_start,
    ssh_systemctl_stop,
    ssh_systemctl_unmask,
)

# Map (tool_callable, verb). The verb is both the argv token AND the action
# literal on the result model -- there's no divergence (``reset-failed`` is
# dashed in both places). The model's ``SystemctlUnitAction`` Literal mirrors
# this list exactly.
_TOOL_TABLE: list[tuple[Any, str]] = [
    (ssh_systemctl_start, "start"),
    (ssh_systemctl_stop, "stop"),
    (ssh_systemctl_restart, "restart"),
    (ssh_systemctl_reload, "reload"),
    (ssh_systemctl_enable, "enable"),
    (ssh_systemctl_disable, "disable"),
    (ssh_systemctl_mask, "mask"),
    (ssh_systemctl_unmask, "unmask"),
    (ssh_systemctl_reset_failed, "reset-failed"),
]

# All nine tools should carry exactly these tags (subset check: FastMCP
# may add its own internal tags, so we assert >= ours).
_EXPECTED_TAGS: set[str] = {"dangerous", "group:systemctl"}


# ---------------------------------------------------------------------------
# 1. Tag contract -- ALLOW_DANGEROUS_TOOLS=false hides via Visibility
# ---------------------------------------------------------------------------


class TestDangerousTagContract:
    """Each mutation tool must declare ``{"dangerous", "group:systemctl"}``.

    The Visibility transform in lifespan filters by tag, so if the tag is
    missing the tool would leak into tools/list under default-deny.
    """

    @pytest.mark.parametrize(
        "tool",
        [t for t, _verb in _TOOL_TABLE],
        ids=[t.__name__ for t, _verb in _TOOL_TABLE],
    )
    @pytest.mark.asyncio
    async def test_tool_is_registered_with_dangerous_tag(self, tool: Any) -> None:
        from ssh_mcp.server import mcp_server

        # Use ``_list_tools`` (unfiltered) so the test does not depend on the
        # ambient ALLOW_DANGEROUS_TOOLS flag -- we are asserting the tag set,
        # which is the *input* to the Visibility transform.
        tools = {t.name: t for t in await mcp_server._list_tools()}
        assert tool.__name__ in tools, f"{tool.__name__} not registered"
        tags = set(getattr(tools[tool.__name__], "tags", set()) or set())
        assert _EXPECTED_TAGS.issubset(tags), f"{tool.__name__}: want {_EXPECTED_TAGS}, got {tags}"

    @pytest.mark.asyncio
    async def test_visibility_transform_hides_them_when_dangerous_off(self) -> None:
        """Apply the lifespan's own ``Visibility(False, tags={"dangerous"})``
        transform to an isolated FastMCP server populated with the nine mutation
        tools, then confirm tools/list returns zero of them.

        We do not exercise the global ``mcp_server`` here because the lifespan
        (which wires Visibility) does not run under pytest. Instead we replay
        the exact transform call lifespan.py performs and check the contract
        end-to-end against the real tool objects.
        """
        from fastmcp import FastMCP
        from fastmcp.server.transforms import Visibility

        from ssh_mcp.server import mcp_server

        # Copy the nine tool objects onto a fresh server so the global one is
        # not mutated for the rest of the suite.
        registry = {t.name: t for t in await mcp_server._list_tools()}
        sandbox = FastMCP("sandbox")
        for tool, _verb in _TOOL_TABLE:
            assert tool.__name__ in registry, f"{tool.__name__} not registered globally"
            sandbox.add_tool(registry[tool.__name__])

        # This is verbatim what ``lifespan._configure_visibility`` does when
        # ALLOW_DANGEROUS_TOOLS=False:
        sandbox.add_transform(Visibility(False, tags={"dangerous"}))

        visible = {t.name for t in await sandbox.list_tools()}
        mutation_names = {tool.__name__ for tool, _verb in _TOOL_TABLE}
        leaked = visible & mutation_names
        assert not leaked, f"dangerous-tier tools leaked past Visibility: {sorted(leaked)}"


# ---------------------------------------------------------------------------
# 2. Happy path -- mocked _run_systemctl returns ok, result fields populated
# ---------------------------------------------------------------------------


class TestHappyPath:
    @pytest.mark.parametrize(
        ("tool", "verb"),
        _TOOL_TABLE,
        ids=[t.__name__ for t, _v in _TOOL_TABLE],
    )
    @pytest.mark.asyncio
    async def test_returns_expected_shape(
        self,
        monkeypatch: Any,
        tool: Any,
        verb: str,
    ) -> None:
        captured: dict[str, Any] = {}

        async def fake(
            _ctx: Any,
            _host: str,
            argv: list[str],
            **_kw: Any,
        ) -> tuple[str, str, int, list[str], str]:
            captured["argv"] = argv
            return ("", "", 0, [], "testhost")

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await tool(host="testhost", unit="nginx.service", ctx=make_ctx())

        # Field shape matches SystemctlUnitActionResult (extra=forbid).
        # Re-construct from the dict to catch any drift.
        SystemctlUnitActionResult(**result)

        assert result["host"] == "testhost"
        assert result["unit"] == "nginx.service"
        assert result["action"] == verb
        assert result["exit_code"] == 0
        assert result["stdout"] == ""
        assert result["stderr"] == ""
        assert result["output_warnings"] == []
        # ``duration_ms`` intentionally NOT on the result -- the audit log
        # is the system of record for per-call timing.
        assert "duration_ms" not in result

        # 6. argv shape -- exactly ["systemctl", <verb>, "--", "nginx.service"].
        # The "--" stops systemctl from parsing further tokens as flags, even
        # though our validator already rejects "--" prefixes.
        assert captured["argv"] == ["systemctl", verb, "--", "nginx.service"]


# ---------------------------------------------------------------------------
# 3. Unit-name validation -- bad names rejected before the SSH boundary
# ---------------------------------------------------------------------------


class TestUnitValidation:
    # ``--evil`` is intentionally NOT in this list: dash-prefixed strings
    # pass the existing validator (no dots, all chars in [A-Za-z0-9@._-]),
    # but the argv shape ``["systemctl", <verb>, "--", <unit>]`` neuters any
    # would-be flag injection. The validator's job is to keep shell metas
    # out, which it does.
    @pytest.mark.parametrize(
        "bad",
        [
            "foo;bar.service",  # semicolon injection
            "",  # empty
            "nginx & ls",  # ampersand
            "nginx|ls",  # pipe
            "`whoami`",  # backtick
            "$(rm -rf /)",  # subshell
            "/etc/nginx.service",  # slash (path)
            "nginx.notaunit",  # unknown suffix
            "nginx\nls",  # newline injection
            "nginx\x00bad",  # null byte
        ],
    )
    @pytest.mark.parametrize(
        "tool",
        [t for t, _v in _TOOL_TABLE],
        ids=[t.__name__ for t, _v in _TOOL_TABLE],
    )
    @pytest.mark.asyncio
    async def test_bad_unit_raises_value_error(
        self,
        monkeypatch: Any,
        tool: Any,
        bad: str,
    ) -> None:
        # Even if validation somehow leaked through, fake _run_systemctl
        # would record the argv so we can be sure no shell saw the input.
        called = False

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int, list[str], str]:
            nonlocal called
            called = True
            return ("", "", 0, [], "testhost")

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        with pytest.raises(ValueError):
            await tool(host="testhost", unit=bad, ctx=make_ctx())
        assert not called, f"_run_systemctl reached the wire for bad unit {bad!r}"


# ---------------------------------------------------------------------------
# 4. Non-zero exit codes are data, not raised
# ---------------------------------------------------------------------------


class TestNonZeroExitPropagatesAsData:
    @pytest.mark.parametrize(
        ("tool", "verb"),
        _TOOL_TABLE,
        ids=[t.__name__ for t, _v in _TOOL_TABLE],
    )
    @pytest.mark.asyncio
    async def test_nonzero_exit_returned_in_result(
        self,
        monkeypatch: Any,
        tool: Any,
        verb: str,
    ) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int, list[str], str]:
            # systemctl exit code 5: unit could not be loaded.
            return ("", "Failed to start nginx.service: Unit not found.\n", 5, [], "testhost")

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await tool(host="testhost", unit="nginx.service", ctx=make_ctx())
        assert result["exit_code"] == 5
        assert "Unit not found" in result["stderr"]
        assert result["action"] == verb


# ---------------------------------------------------------------------------
# 5. output_warnings plumb through
# ---------------------------------------------------------------------------


class TestOutputWarningsPlumbThrough:
    @pytest.mark.parametrize(
        "tool",
        [t for t, _v in _TOOL_TABLE],
        ids=[t.__name__ for t, _v in _TOOL_TABLE],
    )
    @pytest.mark.asyncio
    async def test_output_warnings_carried_into_result(
        self,
        monkeypatch: Any,
        tool: Any,
    ) -> None:
        warnings_in = ["ANSI escape sequences stripped from stdout"]

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int, list[str], str]:
            return ("cleaned stdout\n", "", 0, list(warnings_in), "testhost")

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await tool(host="testhost", unit="nginx.service", ctx=make_ctx())
        assert result["output_warnings"] == warnings_in


# ---------------------------------------------------------------------------
# 6. timeout= kwarg plumbs through to _run_systemctl unchanged
# ---------------------------------------------------------------------------


class TestTimeoutPlumbing:
    @pytest.mark.asyncio
    async def test_timeout_reaches_runner(self, monkeypatch: Any) -> None:
        """The per-tool ``timeout`` kwarg must arrive at ``_run_systemctl``
        as ``timeout=<int>`` -- no coercion or default-substitution between
        the tool wrapper and the runner.
        """
        captured: dict[str, Any] = {}
        fake = AsyncMock(return_value=("", "", 0, [], "testhost"))

        async def spy(
            ctx: Any,
            host: str,
            argv: list[str],
            **kw: Any,
        ) -> tuple[str, str, int, list[str], str]:
            captured.update(kw)
            return await fake(ctx, host, argv, **kw)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", spy)
        await ssh_systemctl_restart(
            host="testhost",
            unit="nginx.service",
            ctx=make_ctx(),
            timeout=42,
        )
        assert captured.get("timeout") == 42


# ---------------------------------------------------------------------------
# Defensive: the verb dispatch rejects junk -- shields against a future
# copy-paste typo in the per-tool wrappers.
# ---------------------------------------------------------------------------


class TestDispatchVerbGuard:
    @pytest.mark.asyncio
    async def test_unknown_verb_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported systemctl mutation verb"):
            await systemctl_tools._run_unit_action(
                make_ctx(),
                "testhost",
                verb="halt-and-catch-fire",  # type: ignore[arg-type]
                unit="nginx.service",
                timeout=None,
            )


# ---------------------------------------------------------------------------
# Model round-trip
# ---------------------------------------------------------------------------


class TestModelRoundTrip:
    def test_minimal_construction(self) -> None:
        m = SystemctlUnitActionResult(
            host="h",
            unit="nginx.service",
            action="start",
            exit_code=0,
            stdout="",
            stderr="",
        )
        d = m.model_dump()
        assert d["action"] == "start"
        assert d["output_warnings"] == []
        assert "duration_ms" not in d

    def test_extra_fields_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            SystemctlUnitActionResult(
                host="h",
                unit="nginx.service",
                action="start",
                exit_code=0,
                stdout="",
                stderr="",
                bogus="x",  # type: ignore[call-arg]
            )

    @pytest.mark.parametrize(
        "action",
        [
            "start",
            "stop",
            "restart",
            "reload",
            "enable",
            "disable",
            "mask",
            "unmask",
            "reset-failed",
        ],
    )
    def test_every_action_literal_accepted(self, action: str) -> None:
        m = SystemctlUnitActionResult(
            host="h",
            unit="nginx.service",
            action=action,  # type: ignore[arg-type]
            exit_code=0,
            stdout="",
            stderr="",
        )
        assert m.action == action
