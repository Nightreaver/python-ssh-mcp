"""Unit tests for systemctl_tools and systemctl models.

All tests are pure Python — no SSH connections, no real hosts.
The SSH runner is monkeypatched at the ``_run_systemctl`` boundary.

Coverage:
- Unit-name validator: valid names pass, invalid names raise ValueError.
- Pattern validator: wildcards OK, metacharacters rejected.
- Property-name validator: PascalCase pass, other strings rejected.
- Time-anchor validator: accepted and rejected formats.
- Grep validator: safe patterns pass, metachars rejected.
- _parse_show_properties: key=value parsing edge cases.
- _parse_is_active_state: every enum value round-trips.
- _parse_is_enabled_state: every enum value round-trips.
- _parse_list_units: typical rows, whitespace edge cases.
- _parse_active_state: parses Active: line correctly.
- ssh_journalctl: lines>1000 raises, lines=0 raises, since/until/grep validate.
- Tool happy paths: monkeypatched runner returns expected model shape.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.models.systemctl import (
    JournalctlResult,
    SystemctlCatResult,
    SystemctlIsActiveResult,
    SystemctlIsEnabledResult,
    SystemctlIsFailedResult,
    SystemctlListUnitsResult,
    SystemctlShowResult,
    SystemctlStatusResult,
    SystemctlUnitEntry,
)
from ssh_mcp.tools import systemctl_tools
from ssh_mcp.tools.systemctl_tools import (
    _parse_active_state,
    _parse_is_active_state,
    _parse_is_enabled_state,
    _parse_list_units,
    _parse_show_properties,
    _validate_grep,
    _validate_pattern,
    _validate_property_names,
    _validate_systemd_unit_name,
    _validate_time_anchor,
    ssh_journalctl,
    ssh_systemctl_cat,
    ssh_systemctl_is_active,
    ssh_systemctl_is_enabled,
    ssh_systemctl_is_failed,
    ssh_systemctl_list_units,
    ssh_systemctl_show,
    ssh_systemctl_status,
)

# ---------------------------------------------------------------------------
# Shared test context helpers
# ---------------------------------------------------------------------------


def _make_ctx(hostname: str = "testhost") -> Any:
    """Return a minimal fake FastMCP Context usable by the tools."""
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


# ---------------------------------------------------------------------------
# _validate_systemd_unit_name
# ---------------------------------------------------------------------------


class TestValidateUnitName:
    @pytest.mark.parametrize(
        "name",
        [
            "nginx",
            "nginx.service",
            "ssh.socket",
            "multi-user.target",
            "cron.timer",
            "proc-sys-fs-binfmt_misc.automount",
            "home.mount",
            "dev-sda1.swap",
            "system.slice",
            "session-1.scope",
            "sda.device",
            "foo@bar.service",  # template instance
            "foo@.service",  # template definition
            "a",  # single char
            "A",  # uppercase
            "foo_bar",  # underscores
            "foo-bar",  # hyphens
        ],
    )
    def test_valid_names(self, name: str) -> None:
        assert _validate_systemd_unit_name(name) == name

    @pytest.mark.parametrize(
        "bad",
        [
            "",  # empty
            "nginx.service;ls",  # semicolon injection
            "nginx & ls",  # ampersand injection
            "nginx|ls",  # pipe injection
            "`whoami`",  # backtick injection
            "$(whoami)",  # dollar injection
            "nginx\nls",  # newline injection
            "nginx\r",  # CR injection
            "\x00",  # null byte
            "nginx(1)",  # parenthesis
            "nginx<1>",  # angle bracket
            "/etc/nginx",  # path slash
            "nginx.notaunit",  # unknown unit suffix
            "foo.bar",  # dot with unknown suffix
        ],
    )
    def test_invalid_names_raise(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _validate_systemd_unit_name(bad)


# ---------------------------------------------------------------------------
# _validate_pattern
# ---------------------------------------------------------------------------


class TestValidatePattern:
    @pytest.mark.parametrize(
        "pat",
        [
            "nginx*",
            "*.service",
            "nginx?.service",
            "foo-bar*",
            "multi*",
        ],
    )
    def test_valid_patterns(self, pat: str) -> None:
        assert _validate_pattern(pat) == pat

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "nginx;*",
            "nginx|*",
            "*$(cmd)*",
            "/etc/*",
        ],
    )
    def test_invalid_patterns_raise(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _validate_pattern(bad)


# ---------------------------------------------------------------------------
# _validate_property_names
# ---------------------------------------------------------------------------


class TestValidatePropertyNames:
    @pytest.mark.parametrize(
        "props",
        [
            ["ActiveState"],
            ["ExecMainPID", "NRestarts", "Result"],
            ["MainPID"],
            ["A"],
        ],
    )
    def test_valid_properties(self, props: list[str]) -> None:
        assert _validate_property_names(props) == props

    @pytest.mark.parametrize(
        "props",
        [
            ["activeState"],  # lowercase start
            ["_ActiveState"],  # underscore start
            ["Active-State"],  # hyphen
            ["Active State"],  # space
            [""],  # empty string
        ],
    )
    def test_invalid_properties_raise(self, props: list[str]) -> None:
        with pytest.raises(ValueError):
            _validate_property_names(props)


# ---------------------------------------------------------------------------
# _validate_time_anchor
# ---------------------------------------------------------------------------


class TestValidateTimeAnchor:
    @pytest.mark.parametrize(
        "anchor",
        [
            "10m",
            "2h",
            "24h30m",
            "1s",
            "7d",  # journalctl: d (days) supported via systemd.time(7)
            "1w",  # weeks
            "6M",  # months (capital M)
            "1y",  # years
            "1d2h",  # mixed d+h
            "1710000000",
            "1710000000.123",
            "2026-04-16T12:00:00Z",
            "2026-04-16T12:00:00+02:00",
            "2026-04-16T12:00:00.123456Z",
            "2026-04-16",
            "2026-04-16 12:00",
            "2026-04-16 12:00:00",
            "yesterday",
            "today",
            "now",
            "tomorrow",
        ],
    )
    def test_valid_anchors(self, anchor: str) -> None:
        assert _validate_time_anchor(anchor, param="since") == anchor

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "15 minutes",  # space-separated human text
            "rm -rf /",  # injection
            "10m;ls",  # semicolon
            "2026-04-16T",  # incomplete ISO
            "-10m",  # negative
            "7D",  # lowercase-only 'd' for days; capital-D rejected
            "1h ",  # trailing whitespace
        ],
    )
    def test_invalid_anchors_raise(self, bad: str) -> None:
        with pytest.raises(ValueError, match="since"):
            _validate_time_anchor(bad, param="since")


# ---------------------------------------------------------------------------
# _validate_grep
# ---------------------------------------------------------------------------


class TestValidateGrep:
    @pytest.mark.parametrize(
        "pattern",
        [
            "error",
            "FAILED",
            "Connection refused",
            "nginx: worker",
            "status 500",
            "a" * 200,  # exactly at limit
        ],
    )
    def test_valid_grep(self, pattern: str) -> None:
        assert _validate_grep(pattern) == pattern

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "a" * 201,  # over limit
            "error|warn",  # pipe
            "$(rm -rf /)",  # substitution
            "error;drop",  # semicolon
            "error\nwarn",  # newline
            "error`exec`",  # backtick
        ],
    )
    def test_invalid_grep_raises(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _validate_grep(bad)


# ---------------------------------------------------------------------------
# _parse_show_properties
# ---------------------------------------------------------------------------


class TestParseShowProperties:
    def test_basic_key_value(self) -> None:
        stdout = "ActiveState=active\nSubState=running\n"
        result = _parse_show_properties(stdout)
        assert result == {"ActiveState": "active", "SubState": "running"}

    def test_empty_value(self) -> None:
        stdout = "ExecMainPID=\nActiveState=active\n"
        result = _parse_show_properties(stdout)
        assert result["ExecMainPID"] == ""
        assert result["ActiveState"] == "active"

    def test_value_with_equals_sign(self) -> None:
        # Values may themselves contain '='; partition on first '=' only.
        stdout = "Environment=FOO=bar\n"
        result = _parse_show_properties(stdout)
        assert result["Environment"] == "FOO=bar"

    def test_last_write_wins_for_duplicate_keys(self) -> None:
        # systemctl show can emit the same key more than once for arrays
        # (e.g. ExecStartPre=). We document last-write-wins.
        stdout = "ExecStartPre=first\nExecStartPre=second\n"
        result = _parse_show_properties(stdout)
        assert result["ExecStartPre"] == "second"

    def test_lines_without_equals_skipped(self) -> None:
        stdout = "# comment line\nActiveState=active\n"
        result = _parse_show_properties(stdout)
        assert "# comment line" not in result
        assert result["ActiveState"] == "active"

    def test_empty_stdout(self) -> None:
        assert _parse_show_properties("") == {}

    def test_whitespace_only_stdout(self) -> None:
        assert _parse_show_properties("   \n  \n") == {}


# ---------------------------------------------------------------------------
# _parse_is_active_state
# ---------------------------------------------------------------------------


class TestParseIsActiveState:
    @pytest.mark.parametrize(
        ("word", "expected"),
        [
            ("active", "active"),
            ("inactive", "inactive"),
            ("failed", "failed"),
            ("activating", "activating"),
            ("deactivating", "deactivating"),
            ("reloading", "reloading"),
            ("unknown", "unknown"),
        ],
    )
    def test_known_states_round_trip(self, word: str, expected: str) -> None:
        assert _parse_is_active_state(word + "\n", 0) == expected

    def test_unrecognised_word_becomes_unknown(self) -> None:
        assert _parse_is_active_state("degraded\n", 1) == "unknown"

    def test_empty_stdout_becomes_unknown(self) -> None:
        assert _parse_is_active_state("", 1) == "unknown"

    def test_exit_code_4_is_unknown_regardless_of_stdout(self) -> None:
        # systemctl exit code 4 means "no such unit" — normalise to unknown
        # even if stdout happens to contain a state word.
        assert _parse_is_active_state("inactive\n", 4) == "unknown"
        assert _parse_is_active_state("", 4) == "unknown"
        assert _parse_is_active_state("active\n", 4) == "unknown"


# ---------------------------------------------------------------------------
# _parse_is_enabled_state
# ---------------------------------------------------------------------------


class TestParseIsEnabledState:
    @pytest.mark.parametrize(
        "word",
        [
            "enabled",
            "enabled-runtime",
            "linked",
            "linked-runtime",
            "alias",
            "masked",
            "masked-runtime",
            "static",
            "indirect",
            "disabled",
            "generated",
            "transient",
            "bad",
            "not-found",
        ],
    )
    def test_all_known_states_round_trip(self, word: str) -> None:
        assert _parse_is_enabled_state(word + "\n") == word

    def test_unrecognised_becomes_unknown(self) -> None:
        assert _parse_is_enabled_state("vendor-preset\n") == "unknown"


# ---------------------------------------------------------------------------
# _parse_list_units
# ---------------------------------------------------------------------------


class TestParseListUnits:
    def test_typical_row(self) -> None:
        stdout = (
            "nginx.service  loaded active running"
            "  A high performance web server and a reverse proxy server\n"
        )
        rows = _parse_list_units(stdout)
        assert len(rows) == 1
        row = rows[0]
        assert row.unit == "nginx.service"
        assert row.load == "loaded"
        assert row.active == "active"
        assert row.sub == "running"
        assert "web server" in row.description

    def test_multiple_rows(self) -> None:
        stdout = (
            "cron.service      loaded active running  Regular background program processing daemon\n"
            "ssh.service       loaded active running  OpenBSD Secure Shell server\n"
            "syslog.service    loaded active running  System Logging Service\n"
        )
        rows = _parse_list_units(stdout)
        assert len(rows) == 3
        assert rows[0].unit == "cron.service"
        assert rows[1].unit == "ssh.service"

    def test_skips_empty_lines(self) -> None:
        stdout = "\n  \nnginx.service  loaded active running  web\n\n"
        rows = _parse_list_units(stdout)
        assert len(rows) == 1

    def test_skips_short_rows(self) -> None:
        # Lines with fewer than 4 whitespace-delimited tokens are not units.
        stdout = "nginx.service  loaded\n"
        rows = _parse_list_units(stdout)
        assert rows == []

    def test_description_may_be_empty(self) -> None:
        # Exactly 4 tokens — description is empty string.
        stdout = "foo.service  loaded active running\n"
        rows = _parse_list_units(stdout)
        assert len(rows) == 1
        assert rows[0].description == ""

    def test_empty_stdout(self) -> None:
        assert _parse_list_units("") == []


# ---------------------------------------------------------------------------
# _parse_active_state
# ---------------------------------------------------------------------------


class TestParseActiveState:
    def test_active_running(self) -> None:
        stdout = (
            "* nginx.service - A high performance web server\n"
            "   Loaded: loaded (/lib/systemd/system/nginx.service; enabled)\n"
            "   Active: active (running) since Mon 2026-04-14 10:00:00 UTC; 3 days ago\n"
        )
        assert _parse_active_state(stdout) == "active"

    def test_inactive(self) -> None:
        stdout = "* nginx.service\n" "   Active: inactive (dead) since Mon 2026-04-14 09:00:00 UTC\n"
        assert _parse_active_state(stdout) == "inactive"

    def test_failed(self) -> None:
        stdout = (
            "* nginx.service\n" "   Active: failed (Result: exit-code) since Mon 2026-04-14 08:00:00 UTC\n"
        )
        assert _parse_active_state(stdout) == "failed"

    def test_no_active_line_returns_none(self) -> None:
        stdout = "Unit nginx.service could not be found.\n"
        assert _parse_active_state(stdout) is None

    def test_indented_active_line(self) -> None:
        # systemctl status indents by 3 spaces — strip() handles it.
        stdout = "   Active: active (running)\n"
        assert _parse_active_state(stdout) == "active"


# ---------------------------------------------------------------------------
# ssh_journalctl — validation guards (no SSH)
# ---------------------------------------------------------------------------


class TestJournalctlValidation:
    @pytest.mark.asyncio
    async def test_lines_above_1000_raises(self) -> None:
        with pytest.raises(ValueError, match="1000"):
            await ssh_journalctl(host="h", unit="nginx.service", ctx=_make_ctx(), lines=1001)

    @pytest.mark.asyncio
    async def test_lines_at_exactly_1000_accepted(self, monkeypatch: Any) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("line\n" * 1000, "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_journalctl(host="testhost", unit="nginx.service", ctx=_make_ctx(), lines=1000)
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_lines_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            await ssh_journalctl(host="h", unit="nginx.service", ctx=_make_ctx(), lines=0)

    @pytest.mark.asyncio
    async def test_invalid_since_raises(self) -> None:
        with pytest.raises(ValueError, match="since"):
            await ssh_journalctl(host="h", unit="nginx.service", ctx=_make_ctx(), since="yesterday morning")

    @pytest.mark.asyncio
    async def test_invalid_until_raises(self) -> None:
        with pytest.raises(ValueError, match="until"):
            await ssh_journalctl(host="h", unit="nginx.service", ctx=_make_ctx(), until="some time ago")

    @pytest.mark.asyncio
    async def test_invalid_grep_raises(self) -> None:
        with pytest.raises(ValueError):
            await ssh_journalctl(host="h", unit="nginx.service", ctx=_make_ctx(), grep="error|warn")

    @pytest.mark.asyncio
    async def test_invalid_unit_name_raises(self) -> None:
        with pytest.raises(ValueError):
            await ssh_journalctl(host="h", unit="nginx;drop", ctx=_make_ctx())


# ---------------------------------------------------------------------------
# Tool happy-path shapes (monkeypatched _run_systemctl)
# ---------------------------------------------------------------------------


class TestToolShapes:
    """Verify that each tool returns the expected dict shape."""

    @pytest.mark.asyncio
    async def test_systemctl_status_shape(self, monkeypatch: Any) -> None:
        stdout = "* nginx.service - nginx\n" "   Active: active (running) since Mon 2026-04-14 10:00:00 UTC\n"

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return (stdout, "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_status(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["host"] == "testhost"
        assert result["unit"] == "nginx.service"
        assert result["exit_code"] == 0
        assert result["active_state"] == "active"
        assert "nginx" in result["stdout"]

    @pytest.mark.asyncio
    async def test_systemctl_status_inactive_exit3(self, monkeypatch: Any) -> None:
        """Exit code 3 (inactive/dead) must not be treated as an error."""
        stdout = "* nginx.service\n   Active: inactive (dead)\n"

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return (stdout, "", 3)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_status(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["exit_code"] == 3
        assert result["active_state"] == "inactive"

    @pytest.mark.asyncio
    async def test_systemctl_is_active_shape(self, monkeypatch: Any) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("active\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_is_active(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["state"] == "active"
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_systemctl_is_enabled_shape(self, monkeypatch: Any) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("enabled\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_is_enabled(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["state"] == "enabled"

    @pytest.mark.asyncio
    async def test_systemctl_is_failed_true(self, monkeypatch: Any) -> None:
        # Exit 0 means IS failed (the unit IS in a failed state).
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("failed\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_is_failed(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["failed"] is True
        assert result["state"] == "failed"

    @pytest.mark.asyncio
    async def test_systemctl_is_failed_false(self, monkeypatch: Any) -> None:
        # Non-zero exit means NOT failed.
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("active\n", "", 1)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_is_failed(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["failed"] is False

    @pytest.mark.asyncio
    async def test_systemctl_list_units_shape(self, monkeypatch: Any) -> None:
        stdout = "nginx.service  loaded active running  nginx web server\n"

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return (stdout, "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_list_units(host="testhost", ctx=_make_ctx())
        assert result["exit_code"] == 0
        assert len(result["units"]) == 1
        assert result["units"][0]["unit"] == "nginx.service"

    @pytest.mark.asyncio
    async def test_systemctl_show_shape(self, monkeypatch: Any) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("ActiveState=active\nNRestarts=0\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_show(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert result["properties"]["ActiveState"] == "active"
        assert result["properties"]["NRestarts"] == "0"

    @pytest.mark.asyncio
    async def test_systemctl_show_with_properties_filter(self, monkeypatch: Any) -> None:
        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return ("ActiveState=active\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_show(
            host="testhost",
            unit="nginx.service",
            ctx=_make_ctx(),
            properties=["ActiveState"],
        )
        assert "ActiveState" in result["properties"]

    @pytest.mark.asyncio
    async def test_systemctl_cat_shape(self, monkeypatch: Any) -> None:
        unit_file = "[Unit]\nDescription=nginx\n[Service]\nExecStart=/usr/sbin/nginx\n"

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return (unit_file, "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_systemctl_cat(host="testhost", unit="nginx.service", ctx=_make_ctx())
        assert "[Unit]" in result["stdout"]
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_journalctl_shape(self, monkeypatch: Any) -> None:
        log_lines = "Apr 14 10:00:00 nginx: starting\nApr 14 10:00:01 nginx: started\n"

        async def fake(*_a: Any, **_kw: Any) -> tuple[str, str, int]:
            return (log_lines, "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        result = await ssh_journalctl(host="testhost", unit="nginx.service", ctx=_make_ctx(), lines=50)
        assert result["exit_code"] == 0
        assert result["lines_returned"] == 2
        assert "nginx" in result["stdout"]

    @pytest.mark.asyncio
    async def test_journalctl_with_all_options(self, monkeypatch: Any) -> None:
        captured: dict[str, Any] = {}

        async def fake(ctx: Any, host: str, argv: list[str], **kw: Any) -> tuple[str, str, int]:
            captured["argv"] = argv
            return ("log line\n", "", 0)

        monkeypatch.setattr(systemctl_tools, "_run_systemctl", fake)
        await ssh_journalctl(
            host="testhost",
            unit="nginx.service",
            ctx=_make_ctx(),
            since="15m",
            until="now",
            lines=100,
            grep="error",
        )
        argv = captured["argv"]
        assert "journalctl" in argv
        assert "-u" in argv
        assert "nginx.service" in argv
        assert "--since" in argv
        assert "15m" in argv
        assert "--until" in argv
        assert "now" in argv
        assert "--grep" in argv
        assert "error" in argv
        assert "-n" in argv
        assert "100" in argv


# ---------------------------------------------------------------------------
# Model round-trip sanity
# ---------------------------------------------------------------------------


class TestModelRoundTrip:
    def test_status_result(self) -> None:
        m = SystemctlStatusResult(
            host="h", unit="nginx.service", stdout="", exit_code=0, active_state="active"
        )
        d = m.model_dump()
        assert d["active_state"] == "active"
        assert d["exit_code"] == 0

    def test_is_active_result(self) -> None:
        m = SystemctlIsActiveResult(host="h", unit="nginx.service", state="active", exit_code=0)
        assert m.model_dump()["state"] == "active"

    def test_is_enabled_result(self) -> None:
        m = SystemctlIsEnabledResult(host="h", unit="nginx.service", state="disabled", exit_code=1)
        assert m.model_dump()["state"] == "disabled"

    def test_is_failed_result(self) -> None:
        m = SystemctlIsFailedResult(host="h", unit="nginx.service", failed=True, state="failed", exit_code=0)
        assert m.model_dump()["failed"] is True

    def test_list_units_result(self) -> None:
        entry = SystemctlUnitEntry(
            unit="nginx.service", load="loaded", active="active", sub="running", description="nginx"
        )
        m = SystemctlListUnitsResult(host="h", units=[entry], exit_code=0)
        d = m.model_dump()
        assert len(d["units"]) == 1
        assert d["units"][0]["unit"] == "nginx.service"

    def test_show_result(self) -> None:
        m = SystemctlShowResult(
            host="h", unit="nginx.service", properties={"ActiveState": "active"}, exit_code=0
        )
        assert m.model_dump()["properties"]["ActiveState"] == "active"

    def test_cat_result(self) -> None:
        m = SystemctlCatResult(host="h", unit="nginx.service", stdout="[Unit]\n", exit_code=0)
        assert m.model_dump()["stdout"] == "[Unit]\n"

    def test_journalctl_result(self) -> None:
        m = JournalctlResult(host="h", unit="nginx.service", stdout="log\n", lines_returned=1, exit_code=0)
        assert m.model_dump()["lines_returned"] == 1
