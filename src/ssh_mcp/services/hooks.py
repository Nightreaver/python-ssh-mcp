"""Lifecycle hooks. No hooks registered by default.

An operator extends the server by:

  1. Writing a Python module that exposes ``register_hooks(registry)``.
  2. Pointing ``SSH_HOOKS_MODULE`` at the module's dotted import path.

On lifespan start the module is imported and its ``register_hooks`` is called
with the live registry. Inside, operators call ``registry.register(event, cb)``
for each hook they want.

Current events (intentionally small; grow as needed):

  - ``STARTUP``         -- fired once after the pool + hosts are ready
  - ``SHUTDOWN``        -- fired once before the pool closes
  - ``PRE_TOOL_CALL``   -- before every ``@audited`` tool executes
  - ``POST_TOOL_CALL``  -- after every ``@audited`` tool completes or raises

Hooks are **side-effect-only**: they observe, they don't decide. Blocking
pre-hooks (that can reject a tool call) are deliberately out of scope for the
first iteration -- they need a return-value contract and more testing.

Safety properties:

  - Each hook runs under a bounded timeout (default 5 s).
  - Any exception in a hook is logged and swallowed; other hooks still fire.
  - Non-blocking emit (the default) schedules hooks as background tasks; the
    caller does not wait. Blocking emit awaits all hooks before returning.
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class HookEvent(str, Enum):
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    PRE_TOOL_CALL = "pre_tool_call"
    POST_TOOL_CALL = "post_tool_call"


@dataclass
class HookContext:
    """Read-only payload every hook receives.

    ``payload`` is a free-form dict for event-specific extras. Core fields are
    called out explicitly so hooks can cover the 90% case without dictionary
    lookups.
    """

    event: HookEvent
    timestamp: float = field(default_factory=time.time)
    tool: str | None = None
    host: str | None = None
    tier: str | None = None
    correlation_id: str | None = None
    result: str | None = None        # "ok" / "error" for POST_TOOL_CALL
    error: str | None = None         # exception class name on error
    duration_ms: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)


Hook = Callable[[HookContext], Awaitable[None]]
"""A hook handler. Return value ignored; exceptions logged and swallowed.

Signature: ``async def my_hook(ctx: HookContext) -> None``.
"""


# INC-021: non-blocking emit used to spawn background tasks without tracking
# them -- a slow or reentrant hook on a high-frequency event could accumulate
# pending tasks faster than they drain. We now keep a set of in-flight tasks
# (cleared via done-callback) and log a warning when the set crosses this
# threshold. The threshold is a "something is wrong" signal, not a hard cap;
# hooks are still fire-and-forget and are not cancelled.
_HOOK_PENDING_WARN_THRESHOLD = 100


class HookRegistry:
    def __init__(self, *, default_timeout: float = 5.0) -> None:
        self._hooks: dict[HookEvent, list[Hook]] = {}
        self._default_timeout = default_timeout
        self._pending: set[asyncio.Task[None]] = set()
        self._warned_over_threshold = False

    def pending_count(self) -> int:
        """Number of in-flight non-blocking hook tasks. For diagnostics / tests."""
        return len(self._pending)

    def register(self, event: HookEvent, hook: Hook) -> None:
        """Add a hook for ``event``. Order of registration is preserved on emit."""
        self._hooks.setdefault(event, []).append(hook)
        logger.debug("hook registered event=%s handler=%r", event.value, hook)

    def registered_count(self, event: HookEvent | None = None) -> int:
        """For diagnostics / tests."""
        if event is None:
            return sum(len(v) for v in self._hooks.values())
        return len(self._hooks.get(event, []))

    async def emit(
        self,
        ctx: HookContext,
        *,
        blocking: bool = False,
        timeout: float | None = None,
    ) -> None:
        """Fire hooks for ``ctx.event``.

        ``blocking=False`` (default): schedule each hook as a background task
        and return immediately. Use for POST_TOOL_CALL / SHUTDOWN style
        events where the main flow shouldn't wait.

        ``blocking=True``: await every hook. Use for STARTUP or pre-hooks
        where the caller needs the side effects to complete first.
        """
        hooks = self._hooks.get(ctx.event)
        if not hooks:
            return
        to = timeout if timeout is not None else self._default_timeout

        async def _run(h: Hook) -> None:
            try:
                await asyncio.wait_for(h(ctx), timeout=to)
            except TimeoutError:
                logger.warning(
                    "hook timeout event=%s handler=%r timeout=%.1fs",
                    ctx.event.value, h, to,
                )
            except Exception as exc:
                logger.warning(
                    "hook error event=%s handler=%r error=%s: %s",
                    ctx.event.value, h, type(exc).__name__, exc,
                )

        if blocking:
            # Await all hooks in order so operators get deterministic pre-hook
            # semantics when that matters.
            for h in hooks:
                await _run(h)
        else:
            # Fire and forget, but track the tasks so we can notice if they're
            # accumulating (slow hook on a hot event, reentrant scheduling).
            # Tasks remove themselves via done-callback; nothing is cancelled.
            for h in hooks:
                task = asyncio.create_task(_run(h))
                self._pending.add(task)
                task.add_done_callback(self._pending.discard)
            if (
                len(self._pending) >= _HOOK_PENDING_WARN_THRESHOLD
                and not self._warned_over_threshold
            ):
                logger.warning(
                    "hook backlog: %d in-flight tasks (threshold=%d). Hooks "
                    "must be short-lived and non-reentrant; investigate slow "
                    "or re-scheduling handlers.",
                    len(self._pending), _HOOK_PENDING_WARN_THRESHOLD,
                )
                self._warned_over_threshold = True
            elif (
                self._warned_over_threshold
                and len(self._pending) < _HOOK_PENDING_WARN_THRESHOLD // 2
            ):
                # Re-arm once the backlog has drained well below the threshold
                # so recurrent spikes get reported.
                self._warned_over_threshold = False


def load_external_hooks(registry: HookRegistry, module_path: str | None) -> int:
    """Import ``module_path`` and call its ``register_hooks(registry)``.

    Returns the number of hooks registered by the module. Returns 0 without
    erroring if ``module_path`` is None or the module has no ``register_hooks``.

    An import failure is logged but does not crash startup; the server comes
    up with zero hooks and the operator fixes the module.
    """
    if not module_path:
        return 0
    before = registry.registered_count()
    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        logger.warning(
            "SSH_HOOKS_MODULE=%r not importable (%s); continuing with no hooks",
            module_path, exc,
        )
        return 0
    register_fn = getattr(mod, "register_hooks", None)
    if register_fn is None:
        logger.warning(
            "SSH_HOOKS_MODULE=%r has no 'register_hooks(registry)' function",
            module_path,
        )
        return 0
    try:
        register_fn(registry)
    except Exception as exc:
        logger.warning(
            "SSH_HOOKS_MODULE=%r register_hooks raised %s: %s",
            module_path, type(exc).__name__, exc,
        )
        return 0
    added = registry.registered_count() - before
    logger.info("loaded %d hook(s) from %s", added, module_path)
    return added
