"""HookRegistry behavior: register, emit, timeout, exception isolation, loader."""
from __future__ import annotations

import asyncio
import logging

import pytest

from ssh_mcp.services.hooks import (
    HookContext,
    HookEvent,
    HookRegistry,
    load_external_hooks,
)


@pytest.mark.asyncio
async def test_empty_registry_emit_is_noop() -> None:
    r = HookRegistry()
    await r.emit(HookContext(event=HookEvent.STARTUP), blocking=True)  # no raise


@pytest.mark.asyncio
async def test_blocking_emit_awaits_hooks_in_order() -> None:
    r = HookRegistry()
    order: list[int] = []

    async def h1(ctx: HookContext) -> None:
        order.append(1)

    async def h2(ctx: HookContext) -> None:
        order.append(2)

    r.register(HookEvent.STARTUP, h1)
    r.register(HookEvent.STARTUP, h2)
    await r.emit(HookContext(event=HookEvent.STARTUP), blocking=True)
    assert order == [1, 2]


@pytest.mark.asyncio
async def test_non_blocking_emit_returns_before_hooks_complete() -> None:
    r = HookRegistry()
    started = asyncio.Event()
    finished = asyncio.Event()

    async def slow(ctx: HookContext) -> None:
        started.set()
        await asyncio.sleep(0.05)
        finished.set()

    r.register(HookEvent.POST_TOOL_CALL, slow)
    await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=False)
    # emit() returned; hook is scheduled but not done yet.
    await asyncio.wait_for(started.wait(), timeout=1.0)
    assert not finished.is_set()
    await asyncio.wait_for(finished.wait(), timeout=1.0)


@pytest.mark.asyncio
async def test_exception_in_hook_does_not_kill_others(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = HookRegistry()
    after_boom = asyncio.Event()

    async def boom(ctx: HookContext) -> None:
        raise RuntimeError("kaboom")

    async def survivor(ctx: HookContext) -> None:
        after_boom.set()

    r.register(HookEvent.POST_TOOL_CALL, boom)
    r.register(HookEvent.POST_TOOL_CALL, survivor)

    caplog.set_level(logging.WARNING, logger="ssh_mcp.services.hooks")
    await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=True)

    assert after_boom.is_set(), "survivor hook must still fire"
    assert any("kaboom" in rec.message or "RuntimeError" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_timeout_does_not_crash_emit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = HookRegistry(default_timeout=0.02)

    async def stuck(ctx: HookContext) -> None:
        await asyncio.sleep(5)

    r.register(HookEvent.POST_TOOL_CALL, stuck)
    caplog.set_level(logging.WARNING, logger="ssh_mcp.services.hooks")
    await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=True)
    assert any("timeout" in rec.message.lower() for rec in caplog.records)


@pytest.mark.asyncio
async def test_hook_receives_populated_context() -> None:
    r = HookRegistry()
    seen: list[HookContext] = []

    async def capture(ctx: HookContext) -> None:
        seen.append(ctx)

    r.register(HookEvent.POST_TOOL_CALL, capture)
    await r.emit(
        HookContext(
            event=HookEvent.POST_TOOL_CALL,
            tool="ssh_exec_run",
            host="web01",
            tier="dangerous",
            correlation_id="abc123",
            result="ok",
            duration_ms=42,
        ),
        blocking=True,
    )
    assert len(seen) == 1
    ctx = seen[0]
    assert ctx.tool == "ssh_exec_run"
    assert ctx.host == "web01"
    assert ctx.tier == "dangerous"
    assert ctx.correlation_id == "abc123"
    assert ctx.result == "ok"
    assert ctx.duration_ms == 42


def test_registered_count_per_event() -> None:
    r = HookRegistry()

    async def noop(ctx: HookContext) -> None:
        return None

    r.register(HookEvent.STARTUP, noop)
    r.register(HookEvent.STARTUP, noop)
    r.register(HookEvent.SHUTDOWN, noop)
    assert r.registered_count(HookEvent.STARTUP) == 2
    assert r.registered_count(HookEvent.SHUTDOWN) == 1
    assert r.registered_count(HookEvent.POST_TOOL_CALL) == 0
    assert r.registered_count() == 3


# --- load_external_hooks ---


def test_loader_returns_zero_for_missing_module(
    caplog: pytest.LogCaptureFixture,
) -> None:
    r = HookRegistry()
    caplog.set_level(logging.WARNING, logger="ssh_mcp.services.hooks")
    added = load_external_hooks(r, "does.not.exist.nowhere")
    assert added == 0
    assert r.registered_count() == 0
    assert any("not importable" in rec.message for rec in caplog.records)


def test_loader_returns_zero_for_none() -> None:
    r = HookRegistry()
    assert load_external_hooks(r, None) == 0
    assert r.registered_count() == 0


def test_loader_registers_module_hooks(tmp_path, monkeypatch) -> None:
    # Write a module at a known path, point sys.path at it, load it.
    import sys

    module_src = (
        "async def _observer(ctx): pass\n"
        "def register_hooks(registry):\n"
        "    from ssh_mcp.services.hooks import HookEvent\n"
        "    registry.register(HookEvent.STARTUP, _observer)\n"
        "    registry.register(HookEvent.SHUTDOWN, _observer)\n"
    )
    module_dir = tmp_path / "hook_pkg"
    module_dir.mkdir()
    (module_dir / "__init__.py").write_text("")
    (module_dir / "my_hooks.py").write_text(module_src)
    monkeypatch.syspath_prepend(str(tmp_path))

    # Clear any cached import from a prior run.
    sys.modules.pop("hook_pkg.my_hooks", None)

    r = HookRegistry()
    added = load_external_hooks(r, "hook_pkg.my_hooks")
    assert added == 2
    assert r.registered_count() == 2


@pytest.mark.asyncio
async def test_non_blocking_emit_tracks_pending_tasks() -> None:
    """INC-021: emit() must register fire-and-forget tasks so they can be
    observed, and must clear them when the hook finishes."""
    r = HookRegistry()
    gate = asyncio.Event()

    async def waits(ctx: HookContext) -> None:
        await gate.wait()

    r.register(HookEvent.POST_TOOL_CALL, waits)
    assert r.pending_count() == 0
    await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=False)
    assert r.pending_count() == 1, "non-blocking emit must track the task"

    gate.set()
    # Yield so the task can run to completion and the done-callback can fire.
    for _ in range(5):
        await asyncio.sleep(0)
        if r.pending_count() == 0:
            break
    assert r.pending_count() == 0, "done-callback must clear the task"


@pytest.mark.asyncio
async def test_hook_backlog_warning_fires_once_over_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """INC-021: warn once when pending tasks exceed the threshold."""
    from ssh_mcp.services import hooks as hooks_mod

    # Shrink the threshold for the test so we don't have to schedule 100 hooks.
    monkey_threshold = 3
    original = hooks_mod._HOOK_PENDING_WARN_THRESHOLD
    hooks_mod._HOOK_PENDING_WARN_THRESHOLD = monkey_threshold
    try:
        r = HookRegistry()
        gate = asyncio.Event()

        async def waits(ctx: HookContext) -> None:
            await gate.wait()

        # Register enough handlers per emit to push us past the threshold.
        for _ in range(monkey_threshold):
            r.register(HookEvent.POST_TOOL_CALL, waits)

        caplog.set_level(logging.WARNING, logger="ssh_mcp.services.hooks")
        await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=False)
        # First emit: monkey_threshold tasks now pending -> warn.
        backlog_warnings = [
            rec for rec in caplog.records if "hook backlog" in rec.message
        ]
        assert len(backlog_warnings) == 1

        # A second emit while still over-threshold must not double-warn.
        await r.emit(HookContext(event=HookEvent.POST_TOOL_CALL), blocking=False)
        backlog_warnings = [
            rec for rec in caplog.records if "hook backlog" in rec.message
        ]
        assert len(backlog_warnings) == 1

        gate.set()
        for _ in range(10):
            await asyncio.sleep(0)
            if r.pending_count() == 0:
                break
        assert r.pending_count() == 0
    finally:
        hooks_mod._HOOK_PENDING_WARN_THRESHOLD = original


def test_loader_handles_module_without_register_hooks(
    tmp_path, monkeypatch, caplog: pytest.LogCaptureFixture,
) -> None:
    import sys

    module_dir = tmp_path / "bad_pkg"
    module_dir.mkdir()
    (module_dir / "__init__.py").write_text("")
    (module_dir / "no_register.py").write_text("x = 1\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("bad_pkg.no_register", None)

    r = HookRegistry()
    caplog.set_level(logging.WARNING, logger="ssh_mcp.services.hooks")
    added = load_external_hooks(r, "bad_pkg.no_register")
    assert added == 0
    assert any("register_hooks" in rec.message for rec in caplog.records)
