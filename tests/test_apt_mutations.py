"""Unit tests for the apt mutation + read-hold tools.

Five mutation tools (dangerous tier): ``ssh_apt_install``,
``ssh_apt_upgrade``, ``ssh_apt_remove``, ``ssh_apt_autoremove``,
``ssh_apt_mark``. Plus one read-tier sibling ``ssh_apt_show_holds`` that
exposes ``apt-mark showhold`` separately so its tag set (``safe, read``)
and result shape (``AptHoldsResult``) match its actual blast radius.

Coverage:
1. Tag set carries ``{"dangerous", "group:pkg"}`` -- Visibility hides
   the mutators when ``ALLOW_DANGEROUS_TOOLS=false``.
2. Happy path: mocked ``_run_apt`` returns ok -> result fields populated.
3. Argv construction: explicit assertion on the exact argv passed to
   ``_run_apt`` for each tool (catches drive-by edits that drop ``--``
   or insert flags before it).
4. Package-name injection attempts rejected by ``validate_package_name``.
5. Empty-list rejection for install / remove / mark(hold) / mark(unhold).
6. ``ssh_apt_show_holds`` is a read-tier sibling -- no packages arg, no
   dangerous tag.
7. ``ssh_apt_show_holds`` parsing: whitespace-stripped, empties dropped.
8. ``update_first=True``: install runs ``apt-get update`` first.
9. ``purge=True``: remove uses the ``purge`` verb (and ``action="purge"``
   on the result).
10. Non-zero exit propagates as data (no raise).
11. ``output_warnings`` plumb through to the result.
12. Negative: no ``ssh_apt_do_release_upgrade`` exists.
13. Audit: ``packages`` shows up as ``command_hash`` on the audit line.
14. Defensive: ``_run_apt_mutation`` rejects an unknown verb.
"""

from __future__ import annotations

import json
import logging
from typing import Any, ClassVar

import pytest
from _helpers import make_ctx

from ssh_mcp.models.apt import AptHoldsResult, AptMutationResult
from ssh_mcp.services import audit
from ssh_mcp.tools import apt_tools
from ssh_mcp.tools.apt_tools import (
    ssh_apt_autoremove,
    ssh_apt_install,
    ssh_apt_mark,
    ssh_apt_remove,
    ssh_apt_show_holds,
    ssh_apt_upgrade,
)

_DANGEROUS_TOOLS: list[Any] = [
    ssh_apt_install,
    ssh_apt_upgrade,
    ssh_apt_remove,
    ssh_apt_autoremove,
    ssh_apt_mark,
]

# All five tools should carry exactly these tags (subset check: FastMCP may
# add its own internal tags, so we assert >= ours).
_EXPECTED_TAGS: set[str] = {"dangerous", "group:pkg"}


# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------


def _patch_apt(
    monkeypatch: pytest.MonkeyPatch,
    *,
    runs: list[tuple[str, str, int, list[str]]] | None = None,
) -> dict[str, list[Any]]:
    """Patch ``_probe_apt`` (always succeeds) and ``_run_apt`` (queue-driven).

    ``runs`` is a queue of ``(stdout, stderr, exit_code, output_warnings)``
    tuples; each call to ``_run_apt`` consumes the head. We synthesise the
    fifth element (``stdout_truncated``) ourselves -- the existing fixture
    in test_apt_tools.py does the same.
    """
    runs_q = list(runs or [])
    captured: dict[str, list[Any]] = {"argv": [], "host": [], "timeout": []}

    async def fake_probe(_ctx: Any, _host: str) -> None:
        return None

    async def fake_run(
        _ctx: Any,
        host: str,
        argv: list[str],
        *,
        timeout: int | None = None,
    ) -> tuple[str, str, int, list[str], bool]:
        captured["argv"].append(list(argv))
        captured["host"].append(host)
        captured["timeout"].append(timeout)
        if not runs_q:
            return ("", "", 0, [], False)
        stdout, stderr, exit_code, warnings = runs_q.pop(0)
        return (stdout, stderr, exit_code, warnings, False)

    monkeypatch.setattr(apt_tools, "_probe_apt", fake_probe)
    monkeypatch.setattr(apt_tools, "_run_apt", fake_run)
    return captured


# ---------------------------------------------------------------------------
# 1. Tag contract -- ALLOW_DANGEROUS_TOOLS=false hides via Visibility
# ---------------------------------------------------------------------------


class TestDangerousTagContract:
    @pytest.mark.parametrize(
        "tool",
        _DANGEROUS_TOOLS,
        ids=[t.__name__ for t in _DANGEROUS_TOOLS],
    )
    @pytest.mark.asyncio
    async def test_tool_is_registered_with_dangerous_tag(self, tool: Any) -> None:
        from ssh_mcp.server import mcp_server

        # ``_list_tools`` is unfiltered so we are asserting the tag set itself
        # rather than depending on the ambient ALLOW_DANGEROUS_TOOLS flag.
        tools = {t.name: t for t in await mcp_server._list_tools()}
        assert tool.__name__ in tools, f"{tool.__name__} not registered"
        tags = set(getattr(tools[tool.__name__], "tags", set()) or set())
        assert _EXPECTED_TAGS.issubset(tags), f"{tool.__name__}: want {_EXPECTED_TAGS}, got {tags}"

    @pytest.mark.asyncio
    async def test_visibility_transform_hides_them_when_dangerous_off(self) -> None:
        """Replay the lifespan's ``Visibility(False, tags={"dangerous"})``
        transform on a sandbox FastMCP holding only the five mutation tools
        and confirm tools/list returns zero of them.
        """
        from fastmcp import FastMCP
        from fastmcp.server.transforms import Visibility

        from ssh_mcp.server import mcp_server

        registry = {t.name: t for t in await mcp_server._list_tools()}
        sandbox = FastMCP("sandbox")
        for tool in _DANGEROUS_TOOLS:
            assert tool.__name__ in registry, f"{tool.__name__} not registered globally"
            sandbox.add_tool(registry[tool.__name__])

        sandbox.add_transform(Visibility(False, tags={"dangerous"}))

        visible = {t.name for t in await sandbox.list_tools()}
        mutation_names = {tool.__name__ for tool in _DANGEROUS_TOOLS}
        leaked = visible & mutation_names
        assert not leaked, f"dangerous-tier apt tools leaked past Visibility: {sorted(leaked)}"


# ---------------------------------------------------------------------------
# 2. Happy path -- mocked _run_apt returns ok, result fields populated
# ---------------------------------------------------------------------------


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        result = await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        AptMutationResult(**result)
        assert result["host"] == "testhost"
        assert result["action"] == "install"
        assert result["packages"] == ["nginx"]
        assert result["exit_code"] == 0
        assert result["stdout"] == "ok\n"
        assert result["output_warnings"] == []
        # duration_ms is a fresh field on AptMutationResult (audit alone is
        # the system of record for systemctl, but apt operations are long
        # enough that the user-visible result wants its own value).
        assert "duration_ms" in result
        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_upgrade(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("Reading...\n", "", 0, [])])
        result = await ssh_apt_upgrade(host="testhost", ctx=make_ctx())
        AptMutationResult(**result)
        assert result["action"] == "upgrade"
        assert result["packages"] == []
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_remove(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("removed\n", "", 0, [])])
        result = await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        AptMutationResult(**result)
        assert result["action"] == "remove"
        assert result["packages"] == ["nginx"]

    @pytest.mark.asyncio
    async def test_autoremove(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("Reading...\n", "", 0, [])])
        result = await ssh_apt_autoremove(host="testhost", ctx=make_ctx())
        AptMutationResult(**result)
        assert result["action"] == "autoremove"
        assert result["packages"] == []

    @pytest.mark.asyncio
    async def test_mark_hold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("nginx set on hold.\n", "", 0, [])])
        result = await ssh_apt_mark(
            host="testhost",
            action="hold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        AptMutationResult(**result)
        assert result["action"] == "hold"
        assert result["packages"] == ["nginx"]

    @pytest.mark.asyncio
    async def test_mark_unhold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("Canceled hold on nginx.\n", "", 0, [])])
        result = await ssh_apt_mark(
            host="testhost",
            action="unhold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        AptMutationResult(**result)
        assert result["action"] == "unhold"
        assert result["packages"] == ["nginx"]


# ---------------------------------------------------------------------------
# 3. Argv construction -- explicit shape for each tool, includes ``--``
# ---------------------------------------------------------------------------


class TestArgvConstruction:
    @pytest.mark.asyncio
    async def test_install_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_install(
            host="testhost",
            packages=["nginx", "curl"],
            ctx=make_ctx(),
        )
        assert cap["argv"] == [["apt-get", "-y", "install", "--", "nginx", "curl"]]

    @pytest.mark.asyncio
    async def test_install_argv_with_update_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
            update_first=True,
        )
        # Two _run_apt calls, in order: update, then install.
        assert cap["argv"] == [
            ["apt-get", "update"],
            ["apt-get", "-y", "install", "--", "nginx"],
        ]

    @pytest.mark.asyncio
    async def test_upgrade_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_upgrade(host="testhost", ctx=make_ctx())
        assert cap["argv"] == [["apt-get", "-y", "upgrade"]]

    @pytest.mark.asyncio
    async def test_remove_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        assert cap["argv"] == [["apt-get", "-y", "remove", "--", "nginx"]]

    @pytest.mark.asyncio
    async def test_remove_argv_with_purge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
            purge=True,
        )
        # ``purge`` substituted for ``remove``; ``--`` still present.
        assert cap["argv"] == [["apt-get", "-y", "purge", "--", "nginx"]]

    @pytest.mark.asyncio
    async def test_autoremove_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_autoremove(host="testhost", ctx=make_ctx())
        assert cap["argv"] == [["apt-get", "-y", "autoremove"]]

    @pytest.mark.asyncio
    async def test_mark_hold_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_mark(
            host="testhost",
            action="hold",
            ctx=make_ctx(),
            packages=["nginx", "linux-image-generic"],
        )
        assert cap["argv"] == [["apt-mark", "hold", "--", "nginx", "linux-image-generic"]]

    @pytest.mark.asyncio
    async def test_mark_unhold_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_mark(
            host="testhost",
            action="unhold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        assert cap["argv"] == [["apt-mark", "unhold", "--", "nginx"]]

    @pytest.mark.asyncio
    async def test_show_holds_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_show_holds(host="testhost", ctx=make_ctx())
        # ssh_apt_show_holds takes NO packages argument and NO ``--`` separator.
        assert cap["argv"] == [["apt-mark", "showhold"]]


# ---------------------------------------------------------------------------
# 4. Package-name injection attempts rejected at the validator boundary
# ---------------------------------------------------------------------------


class TestPackageNameInjection:
    _INJECTION_PAYLOADS: ClassVar[list[str]] = [
        "nginx;rm -rf /",
        "nginx`whoami`",
        "$(rm -rf /)",
        "nginx ls",  # space
        "nginx\nls",  # newline
        "--evil",  # leading dash; ``--`` separator catches this at argv
        "pkg/path",  # slash
        "pkg name",  # space inside
        "nginx|cat",  # pipe
        "nginx&ls",  # ampersand
        "\x00bad",  # null byte
    ]

    @pytest.mark.parametrize("bad", _INJECTION_PAYLOADS)
    @pytest.mark.asyncio
    async def test_install_rejects_bad_name(
        self,
        monkeypatch: pytest.MonkeyPatch,
        bad: str,
    ) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError):
            await ssh_apt_install(
                host="testhost",
                packages=["nginx", bad],
                ctx=make_ctx(),
            )
        assert cap["argv"] == [], "validator must reject before any SSH I/O"

    @pytest.mark.parametrize("bad", _INJECTION_PAYLOADS)
    @pytest.mark.asyncio
    async def test_remove_rejects_bad_name(
        self,
        monkeypatch: pytest.MonkeyPatch,
        bad: str,
    ) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError):
            await ssh_apt_remove(
                host="testhost",
                packages=[bad],
                ctx=make_ctx(),
            )
        assert cap["argv"] == []

    @pytest.mark.parametrize("bad", _INJECTION_PAYLOADS)
    @pytest.mark.asyncio
    async def test_mark_hold_rejects_bad_name(
        self,
        monkeypatch: pytest.MonkeyPatch,
        bad: str,
    ) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError):
            await ssh_apt_mark(
                host="testhost",
                action="hold",
                ctx=make_ctx(),
                packages=[bad],
            )
        assert cap["argv"] == []


# ---------------------------------------------------------------------------
# 5. Empty-list rejection for install / remove / mark(hold/unhold)
# ---------------------------------------------------------------------------


class TestEmptyListRejected:
    @pytest.mark.asyncio
    async def test_install_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="packages must be non-empty"):
            await ssh_apt_install(host="testhost", packages=[], ctx=make_ctx())
        assert cap["argv"] == []

    @pytest.mark.asyncio
    async def test_remove_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="packages must be non-empty"):
            await ssh_apt_remove(host="testhost", packages=[], ctx=make_ctx())
        assert cap["argv"] == []

    @pytest.mark.asyncio
    async def test_mark_hold_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="packages must be non-empty"):
            await ssh_apt_mark(
                host="testhost",
                action="hold",
                ctx=make_ctx(),
                packages=[],
            )
        assert cap["argv"] == []

    @pytest.mark.asyncio
    async def test_mark_hold_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``packages=None`` is the FastMCP-default for the kwarg; for
        ``hold`` it must be treated like an empty list."""
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="packages must be non-empty"):
            await ssh_apt_mark(
                host="testhost",
                action="hold",
                ctx=make_ctx(),
                packages=None,
            )
        assert cap["argv"] == []

    @pytest.mark.asyncio
    async def test_mark_unhold_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="packages must be non-empty"):
            await ssh_apt_mark(
                host="testhost",
                action="unhold",
                ctx=make_ctx(),
                packages=[],
            )
        assert cap["argv"] == []


# ---------------------------------------------------------------------------
# 6. ssh_apt_show_holds is a read-tier sibling -- no packages arg, no
#    dangerous tag. The old "showhold rejects a packages list" arity guard
#    is gone with the split: the new tool's signature simply has no
#    ``packages`` parameter, so Python's call-site type system enforces it.
# ---------------------------------------------------------------------------


class TestShowHoldsContract:
    @pytest.mark.asyncio
    async def test_empty_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("", "", 0, [])])
        result = await ssh_apt_show_holds(host="testhost", ctx=make_ctx())
        AptHoldsResult(**result)
        assert result["held"] == []

    @pytest.mark.asyncio
    async def test_no_packages_kwarg_in_signature(self) -> None:
        """The split's whole point: ssh_apt_show_holds rejects ``packages=``
        because it has no such parameter. Catches accidental signature drift
        that would re-introduce the conflated tool shape.
        """
        import inspect

        sig = inspect.signature(ssh_apt_show_holds)
        assert "packages" not in sig.parameters, (
            "ssh_apt_show_holds gained a ``packages`` parameter -- the tool "
            "must stay read-tier with no mutation surface."
        )

    @pytest.mark.asyncio
    async def test_tag_set_is_safe_read(self) -> None:
        """Read-tier tool MUST NOT carry the dangerous tag -- Visibility uses
        the tag set to gate the tool registry."""
        from ssh_mcp.server import mcp_server

        tools = {t.name: t for t in await mcp_server._list_tools()}
        assert "ssh_apt_show_holds" in tools, "ssh_apt_show_holds not registered"
        tags = set(getattr(tools["ssh_apt_show_holds"], "tags", set()) or set())
        assert "dangerous" not in tags, (
            f"ssh_apt_show_holds is read-tier; tags={tags!r} must not include 'dangerous'"
        )
        assert {"safe", "read", "group:pkg"}.issubset(tags), (
            f"ssh_apt_show_holds missing expected tags; got {tags!r}"
        )


# ---------------------------------------------------------------------------
# 7. ssh_apt_show_holds parsing -- whitespace stripped, empties dropped
# ---------------------------------------------------------------------------


class TestShowHoldsParsing:
    @pytest.mark.asyncio
    async def test_parsing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # apt-mark showhold prints one package per line; whitespace-only
        # lines should be dropped. Per the spec: "nginx\nlocked-pkg\n  \n"
        # -> ["nginx", "locked-pkg"].
        _patch_apt(monkeypatch, runs=[("nginx\nlocked-pkg\n  \n", "", 0, [])])
        result = await ssh_apt_show_holds(host="testhost", ctx=make_ctx())
        AptHoldsResult(**result)
        assert result["held"] == ["nginx", "locked-pkg"]
        assert result["exit_code"] == 0
        # Sanity-check the raw stdout is still preserved.
        assert result["stdout"] == "nginx\nlocked-pkg\n  \n"

    @pytest.mark.asyncio
    async def test_empty_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("", "", 0, [])])
        result = await ssh_apt_show_holds(host="testhost", ctx=make_ctx())
        assert result["held"] == []


# ---------------------------------------------------------------------------
# 8. update_first runs apt-get update first (covered in TestArgvConstruction
#    but pinned again here for clarity / future regression).
# ---------------------------------------------------------------------------


class TestUpdateFirst:
    @pytest.mark.asyncio
    async def test_two_calls_in_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
            update_first=True,
        )
        assert len(cap["argv"]) == 2
        assert cap["argv"][0] == ["apt-get", "update"]
        assert cap["argv"][1] == ["apt-get", "-y", "install", "--", "nginx"]

    @pytest.mark.asyncio
    async def test_default_is_no_update(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cap = _patch_apt(monkeypatch)
        await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        # Exactly one call -- the install. ``update_first`` default is False.
        assert len(cap["argv"]) == 1


# ---------------------------------------------------------------------------
# 9. purge=True swaps verb (covered in TestArgvConstruction; assert action
#    field too).
# ---------------------------------------------------------------------------


class TestPurgeActionField:
    @pytest.mark.asyncio
    async def test_purge_action_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        result = await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
            purge=True,
        )
        AptMutationResult(**result)
        assert result["action"] == "purge"
        assert result["packages"] == ["nginx"]


# ---------------------------------------------------------------------------
# 10. Non-zero exit propagates as data (no raise)
# ---------------------------------------------------------------------------


class TestNonZeroExitIsData:
    @pytest.mark.asyncio
    async def test_install_exit_100(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch, runs=[("", "E: Unable to fetch.\n", 100, [])])
        result = await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        assert result["exit_code"] == 100
        assert "Unable to fetch" in result["stderr"]
        assert result["action"] == "install"

    @pytest.mark.asyncio
    async def test_remove_exit_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(
            monkeypatch,
            runs=[("", "E: Package 'nginx' is not installed.\n", 1, [])],
        )
        result = await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        assert result["exit_code"] == 1
        assert "not installed" in result["stderr"]


# ---------------------------------------------------------------------------
# 11. output_warnings plumb through
# ---------------------------------------------------------------------------


class TestOutputWarningsPlumb:
    @pytest.mark.asyncio
    async def test_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        warnings_in = ["ANSI escape sequences stripped from stdout"]
        _patch_apt(monkeypatch, runs=[("cleaned\n", "", 0, list(warnings_in))])
        result = await ssh_apt_install(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        assert result["output_warnings"] == warnings_in

    @pytest.mark.asyncio
    async def test_show_holds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        warnings_in = ["NUL bytes stripped"]
        _patch_apt(monkeypatch, runs=[("nginx\n", "", 0, list(warnings_in))])
        result = await ssh_apt_show_holds(host="testhost", ctx=make_ctx())
        assert result["output_warnings"] == warnings_in
        assert result["held"] == ["nginx"]


# ---------------------------------------------------------------------------
# 12. Negative: no ssh_apt_do_release_upgrade is exposed
# ---------------------------------------------------------------------------


class TestNoDoReleaseUpgradeTool:
    @pytest.mark.asyncio
    async def test_not_registered(self) -> None:
        from ssh_mcp.server import mcp_server

        tools = {t.name for t in await mcp_server._list_tools()}
        # Sprint plan: release-upgrades stay an explicit ssh_exec_run decision.
        # If this assertion ever fails, somebody added the wrapper -- bring
        # the sprint plan along for the conversation.
        forbidden = {
            "ssh_apt_do_release_upgrade",
            "ssh_apt_release_upgrade",
            "ssh_do_release_upgrade",
        }
        leaked = tools & forbidden
        assert not leaked, f"do-release-upgrade tool was added against the sprint plan: {sorted(leaked)}"


# ---------------------------------------------------------------------------
# 13. Audit: ``packages`` shows up as ``command_hash`` on the audit line
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_sink(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    return caplog


def _only_audit_event(caplog: pytest.LogCaptureFixture) -> dict:
    lines = [r.message for r in caplog.records if r.name == "ssh_mcp.audit"]
    assert len(lines) == 1, f"expected 1 audit line, got {len(lines)}: {lines}"
    return json.loads(lines[0])


class TestAuditPackagesHash:
    @pytest.mark.asyncio
    async def test_install_audit_carries_command_hash(
        self,
        monkeypatch: pytest.MonkeyPatch,
        audit_sink: pytest.LogCaptureFixture,
    ) -> None:
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        await ssh_apt_install(
            host="testhost",
            packages=["nginx", "curl"],
            ctx=make_ctx(),
        )
        event = _only_audit_event(audit_sink)
        assert event["tool"] == "ssh_apt_install"
        assert event["tier"] == "dangerous"
        assert "command_hash" in event, (
            "audit line for ssh_apt_install must carry command_hash derived " "from the packages kwarg"
        )
        assert event["command_hash"].startswith("sha256:")
        # The hash must equal _hash(redact(" ".join(packages))). Since the
        # package names contain no secret-flag markers, redaction is a no-op.
        assert event["command_hash"] == audit._hash("nginx curl")

    @pytest.mark.asyncio
    async def test_remove_audit_carries_command_hash(
        self,
        monkeypatch: pytest.MonkeyPatch,
        audit_sink: pytest.LogCaptureFixture,
    ) -> None:
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        await ssh_apt_remove(
            host="testhost",
            packages=["nginx"],
            ctx=make_ctx(),
        )
        event = _only_audit_event(audit_sink)
        assert event["tool"] == "ssh_apt_remove"
        assert "command_hash" in event
        assert event["command_hash"] == audit._hash("nginx")

    @pytest.mark.asyncio
    async def test_upgrade_no_packages_no_command_hash(
        self,
        monkeypatch: pytest.MonkeyPatch,
        audit_sink: pytest.LogCaptureFixture,
    ) -> None:
        """``ssh_apt_upgrade`` has no packages kwarg -- the audit line must
        not carry a command_hash. This protects the dedup invariant for the
        upgrade tool (one host, one hash bucket)."""
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        await ssh_apt_upgrade(host="testhost", ctx=make_ctx())
        event = _only_audit_event(audit_sink)
        assert event["tool"] == "ssh_apt_upgrade"
        assert "command_hash" not in event

    @pytest.mark.asyncio
    async def test_mark_hold_audit_carries_command_hash(
        self,
        monkeypatch: pytest.MonkeyPatch,
        audit_sink: pytest.LogCaptureFixture,
    ) -> None:
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, [])])
        await ssh_apt_mark(
            host="testhost",
            action="hold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        event = _only_audit_event(audit_sink)
        assert event["tool"] == "ssh_apt_mark"
        assert "command_hash" in event
        # The audit prefixes ``action`` onto the packages so hold/unhold land
        # in distinct buckets -- the hash is _hash("hold nginx"), not bare
        # _hash("nginx"). See the sibling hold-vs-unhold test below.
        assert event["command_hash"] == audit._hash("hold nginx")

    @pytest.mark.asyncio
    async def test_mark_hold_vs_unhold_have_distinct_audit_hashes(
        self,
        monkeypatch: pytest.MonkeyPatch,
        audit_sink: pytest.LogCaptureFixture,
    ) -> None:
        """``ssh_apt_mark`` surfaces ``action`` at the tool surface;
        ``_capture_command_surface`` prefixes it onto the packages so
        ``hold`` and ``unhold`` on the same package list land in distinct
        ``command_hash`` buckets. Without the prefix, an operator grepping
        for "how often did we hold nginx" would catch unhold calls too.
        """
        _patch_apt(monkeypatch, runs=[("ok\n", "", 0, []), ("ok\n", "", 0, [])])
        await ssh_apt_mark(
            host="testhost",
            action="hold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        await ssh_apt_mark(
            host="testhost",
            action="unhold",
            ctx=make_ctx(),
            packages=["nginx"],
        )
        events = [
            json.loads(r.message)
            for r in audit_sink.records
            if r.name == "ssh_mcp.audit"
        ]
        assert len(events) == 2
        assert events[0]["command_hash"] == audit._hash("hold nginx")
        assert events[1]["command_hash"] == audit._hash("unhold nginx")
        assert events[0]["command_hash"] != events[1]["command_hash"], (
            "hold and unhold on the same packages collapsed to one hash; "
            "the action prefix in _capture_command_surface is not firing."
        )


# ---------------------------------------------------------------------------
# 14. Probe ordering: install(update_first=True) must probe BEFORE update
# ---------------------------------------------------------------------------


class TestInstallProbeBeforeUpdate:
    """Regression: on a non-Debian host, ``ssh_apt_install(update_first=True)``
    must surface ``PlatformNotSupported`` BEFORE running ``apt-get update``.
    Earlier versions ran update first, so non-Debian targets received a raw
    ``apt-get: command not found`` exec failure instead of the clean
    platform error. The fix hoists ``_probe_apt`` ahead of the update branch.
    """

    @pytest.mark.asyncio
    async def test_probe_failure_short_circuits_before_update(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from ssh_mcp.ssh.errors import PlatformNotSupported

        cap = _patch_apt(monkeypatch)

        async def failing_probe(_ctx: Any, _host: str) -> None:
            raise PlatformNotSupported("apt not available on host 'testhost'")

        monkeypatch.setattr(apt_tools, "_probe_apt", failing_probe)

        with pytest.raises(PlatformNotSupported):
            await ssh_apt_install(
                host="testhost",
                packages=["nginx"],
                ctx=make_ctx(),
                update_first=True,
            )

        assert cap["argv"] == [], (
            "ssh_apt_install issued an apt-get call before the probe fired; "
            "non-Debian hosts must see PlatformNotSupported, not a raw exec "
            "failure from apt-get update."
        )

    @pytest.mark.asyncio
    async def test_probe_failure_without_update_first_also_short_circuits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sanity: without ``update_first``, ``_run_apt_mutation`` does the
        probe -- a non-Debian host still raises before argv hits the wire."""
        from ssh_mcp.ssh.errors import PlatformNotSupported

        cap = _patch_apt(monkeypatch)

        async def failing_probe(_ctx: Any, _host: str) -> None:
            raise PlatformNotSupported("apt not available on host 'testhost'")

        monkeypatch.setattr(apt_tools, "_probe_apt", failing_probe)

        with pytest.raises(PlatformNotSupported):
            await ssh_apt_install(
                host="testhost",
                packages=["nginx"],
                ctx=make_ctx(),
            )
        assert cap["argv"] == []


# ---------------------------------------------------------------------------
# 15. Defensive: _run_apt_mutation rejects an unknown verb
# ---------------------------------------------------------------------------


class TestDispatchVerbGuard:
    @pytest.mark.asyncio
    async def test_unknown_action_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="unsupported apt mutation action"):
            await apt_tools._run_apt_mutation(
                make_ctx(),
                "testhost",
                action="halt-and-catch-fire",  # type: ignore[arg-type]
                argv=["apt-get", "-y", "halt-and-catch-fire"],
                packages=[],
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_mark_unknown_action_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The Literal at the FastMCP layer catches typos for typed callers;
        the dispatcher's ``_MUTATION_ACTIONS`` frozenset is the runtime
        tripwire for in-process callers (tests, scripts) that bypass
        FastMCP's enum validation. After the showhold split the tool itself
        no longer carries a runtime literal check, so the rejection now
        surfaces from ``_run_apt_mutation`` instead.
        """
        _patch_apt(monkeypatch)
        with pytest.raises(ValueError, match="unsupported apt mutation action"):
            await ssh_apt_mark(
                host="testhost",
                action="halt",  # type: ignore[arg-type]
                packages=["nginx"],
                ctx=make_ctx(),
            )


# ---------------------------------------------------------------------------
# Model round-trip
# ---------------------------------------------------------------------------


class TestModelRoundTrip:
    def test_mutation_minimal(self) -> None:
        m = AptMutationResult(
            host="h",
            action="install",
            packages=["nginx"],
            exit_code=0,
            stdout="",
            stderr="",
            duration_ms=12,
        )
        d = m.model_dump()
        assert d["action"] == "install"
        assert d["output_warnings"] == []
        assert d["stdout_truncated"] is False

    def test_mutation_extra_fields_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AptMutationResult(
                host="h",
                action="install",
                packages=["nginx"],
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=12,
                bogus="x",  # type: ignore[call-arg]
            )

    def test_holds_minimal(self) -> None:
        m = AptHoldsResult(
            host="h",
            held=["nginx"],
            stdout="nginx\n",
            stderr="",
            exit_code=0,
            duration_ms=8,
        )
        d = m.model_dump()
        assert d["held"] == ["nginx"]
        assert d["output_warnings"] == []

    @pytest.mark.parametrize(
        "action",
        ["install", "upgrade", "remove", "purge", "autoremove", "hold", "unhold"],
    )
    def test_every_action_literal_accepted(self, action: str) -> None:
        m = AptMutationResult(
            host="h",
            action=action,  # type: ignore[arg-type]
            packages=[],
            exit_code=0,
            stdout="",
            stderr="",
            duration_ms=0,
        )
        assert m.action == action
