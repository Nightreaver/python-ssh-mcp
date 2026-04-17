"""Structured audit log for mutating tool calls. See DESIGN.md sections 4.2, 8.

Every dangerous / low-access / sudo invocation writes one JSON line to the
`ssh_mcp.audit` logger.

Paths and command summaries are reduced to a short SHA-256 prefix. Note:
this is **aggregation/dedup support, not a privacy control** -- the hashes are
trivially rainbow-tableable for common commands and canonical paths. If audit
sinks need confidentiality, enforce it via transport encryption and access
control on the log backend, or salt the hash per-deployment.

INC-008: the `error` field records the exception class name only. Full
exception text (including any remote stderr) stays on the same logger at
DEBUG level, co-correlated by correlation_id, so forensics has the context
locally without shipping it to shared log infra.

Operators wire the `ssh_mcp.audit` logger to their desired sink (file,
Loki, Elasticsearch, etc.) in their own logging config.
"""
from __future__ import annotations

import functools
import hashlib
import json
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from ..telemetry import redact_argv, redact_command_string

# `redact_command_string` preserves the secret's byte-length (`<redacted:7>`)
# so log readers can spot anomalies. For audit hashes that goal flips: we want
# DEDUP, so two calls that differ only in password value produce the same
# `command_hash`. Strip the `:N` so length variation doesn't fragment the hash.
_REDACTED_LEN_SUFFIX_RE = re.compile(r"<redacted:\d+>")

_logger = logging.getLogger("ssh_mcp.audit")

F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def _hash(value: str | None) -> str | None:
    if value is None:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def record(
    *,
    tool: str,
    tier: str,
    host: str,
    correlation_id: str,
    duration_ms: int,
    result: str,
    path: str | None = None,
    command: str | None = None,
    exit_code: int | None = None,
    error: str | None = None,
) -> None:
    """Emit a single JSON audit line."""
    event: dict[str, Any] = {
        "ts": time.time(),
        "correlation_id": correlation_id,
        "tool": tool,
        "tier": tier,
        "host": host,
        "result": result,
        "duration_ms": duration_ms,
    }
    if path is not None:
        event["path_hash"] = _hash(path)
    if command is not None:
        # Redact secret-flag values BEFORE hashing. The hash is intended for
        # dedup/aggregation, but `sha256("foo --password=hunter2")` is a stable
        # fingerprint of the actual secret -- trivially rainbow-tableable for any
        # password an attacker can guess. Redacting first means the hash dedups
        # by command shape, not by the secret value smuggled inside it. The
        # length suffix is also stripped so two calls with different password
        # lengths still collapse to the same command_hash.
        redacted = _REDACTED_LEN_SUFFIX_RE.sub(
            "<redacted>", redact_command_string(command),
        )
        event["command_hash"] = _hash(redacted)
    if exit_code is not None:
        event["exit_code"] = exit_code
    if error is not None:
        event["error"] = error
    _logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))


def audited(tier: str) -> Callable[[F], F]:
    """Decorator: emit an audit line around each tool call.

    Extracts `host` and `path` from the tool's kwargs (best-effort) so the
    audit line always knows the target. Timing and errors are captured.

    Apply BELOW `@mcp_server.tool(...)` so the tool registry sees the
    wrapped function (metadata preserved via functools.wraps).
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            cid = new_correlation_id()
            # Prefer kwargs["host"] (how FastMCP delivers arguments); fall back
            # to args[0] for the odd positional-only caller. INC-048: type-check
            # args[0] so a tool signature that happens to put ``ctx`` or a
            # non-string positional first doesn't smear an ambiguous value
            # across the audit stream. Non-string positional → record "?" and
            # let the tool body fail loudly on its own contract instead.
            host = kwargs.get("host")
            if not isinstance(host, str):
                host = args[0] if args and isinstance(args[0], str) else "?"
            path = kwargs.get("path") or kwargs.get("src") or kwargs.get("dst")
            # Capture the command surface for the audit line. ssh_exec_run /
            # ssh_exec_run_streaming / ssh_sudo_exec / ssh_docker_exec all use
            # `command: str`; ssh_docker_run uses `args: list[str]`. `script:`
            # bodies (ssh_exec_script) are intentionally NOT logged -- they go
            # via stdin so they never hit argv/process-listings, and the tool
            # docstring promises they don't appear in audit lines either.
            command_capture: str | None = None
            cmd_kw = kwargs.get("command")
            if isinstance(cmd_kw, str):
                command_capture = cmd_kw
            else:
                argv_kw = kwargs.get("args")
                if isinstance(argv_kw, list) and all(isinstance(a, str) for a in argv_kw):
                    # Pre-redacted via redact_argv; record() also runs
                    # redact_command_string + length-suffix-strip so the hash
                    # dedups regardless of secret value or length.
                    command_capture = " ".join(redact_argv(argv_kw))
            result_state = "error"
            error_msg: str | None = None
            hook_registry = _hook_registry_from(kwargs)
            if hook_registry is not None:
                from .hooks import HookContext, HookEvent  # local import: avoid cycle
                await hook_registry.emit(
                    HookContext(
                        event=HookEvent.PRE_TOOL_CALL,
                        tool=fn.__name__,
                        tier=tier,
                        host=str(host),
                        correlation_id=cid,
                    ),
                    blocking=False,
                )
            try:
                out = await fn(*args, **kwargs)
                result_state = "ok"
                # Prefer the canonical path from the tool's own result.
                if isinstance(out, dict):
                    resolved = out.get("path") or out.get("result", {}).get("path")
                    if isinstance(resolved, str):
                        path = resolved
                return out
            except BaseException as exc:
                # INC-008: audit sinks are often shipped to shared log backends.
                # `str(exc)` can carry remote stderr (sudo prompts, paths, internal
                # errors). Record the exception class name only; full text stays at
                # DEBUG level on the named logger so forensics still has it locally.
                error_msg = type(exc).__name__
                _logger.debug(
                    "%s full error: %s", cid, exc, exc_info=True
                )
                raise
            finally:
                duration_ms = int((time.monotonic() - start) * 1000)
                if hook_registry is not None:
                    from .hooks import HookContext, HookEvent
                    await hook_registry.emit(
                        HookContext(
                            event=HookEvent.POST_TOOL_CALL,
                            tool=fn.__name__,
                            tier=tier,
                            host=str(host),
                            correlation_id=cid,
                            result=result_state,
                            error=error_msg,
                            duration_ms=duration_ms,
                        ),
                        blocking=False,
                    )
                record(
                    tool=fn.__name__,
                    tier=tier,
                    host=str(host),
                    correlation_id=cid,
                    duration_ms=duration_ms,
                    result=result_state,
                    path=path if isinstance(path, str) else None,
                    command=command_capture,
                    error=error_msg,
                )

        return wrapper  # type: ignore[return-value]

    return decorator


def _hook_registry_from(kwargs: dict[str, Any]) -> Any:
    """Best-effort extraction of the HookRegistry from a tool's kwargs.

    All our tools take ``ctx: Context`` with a FastMCP Context object whose
    ``lifespan_context`` dict holds our live registry. Tools invoked outside
    the server (tests, scripts) don't have one; we return None and the
    decorator skips hook emission silently.
    """
    ctx = kwargs.get("ctx")
    if ctx is None:
        return None
    lifespan = getattr(ctx, "lifespan_context", None)
    if not isinstance(lifespan, dict):
        return None
    return lifespan.get("hooks")
