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

Cheatsheet rejection behavior (B1 sprint, v1.9.0):

- When ``ssh_exec_run`` / ``_streaming`` / ``ssh_sudo_exec`` refuse a
  command via ``CommandIsCheatsheetMatch`` (default-on
  ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false`` path), the audit
  ``record()`` call is SUPPRESSED — no ``result=error`` line is emitted
  for a refusal that didn't touch the host. The DEBUG-level full-error
  log on this same logger still fires, so local forensics keeps the
  signal.
- ``HookRegistry`` ``PRE_TOOL_CALL`` and ``POST_TOOL_CALL`` hooks DO
  still fire for rejected calls. The pre-hook is unavoidable (it fires
  before the function body even runs the precheck), and we keep the
  post-hook for symmetry so operator-installed hooks see matched
  PRE/POST pairs. Hook handlers that want to skip cheatsheet rejections
  should inspect ``HookContext.error == "CommandIsCheatsheetMatch"`` in
  the POST_TOOL_CALL handler and early-return.
- When ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true`` lets a matching
  command through, the audit line gains ``cheatsheet_pattern_id=<id>``
  so operators can grep ``jq 'select(.cheatsheet_pattern_id)'`` to
  count opt-out bypasses by pattern.

Redact-bypass field (v1.5.0):

- When a path-bearing tool resolves a path that matches the
  ``SSH_REDACT_PATHS_GLOBS`` set under ``warn`` or ``audit_only``
  policy, ``services.redact_policy.check_redact_bypass`` flips a
  per-call ContextVar and the audit line gains ``redact_bypass: true``.
  ``block`` mode raises ``RedactBypassBlocked`` upstream and shows up
  as ``result=error`` with that error class, so it doesn't carry the
  flag (would be redundant). Operators grep
  ``jq 'select(.redact_bypass)'`` to find raw-secret deliveries.
"""

from __future__ import annotations

import contextvars
import functools
import hashlib
import json
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from ..ssh.errors import CommandIsCheatsheetMatch
from ..telemetry import redact_argv, redact_command_string

# Per-call telemetry slot: when the cheatsheet pre-check runs under the
# ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true`` opt-out and a pattern matched,
# ``cheatsheet_precheck`` writes the ``pattern_id`` here. The audit decorator
# reads it at ``finally`` time and emits ``cheatsheet_pattern_id`` on the
# audit line so operators can grep ``jq 'select(.cheatsheet_pattern_id)'``
# to count opt-out bypasses by pattern (eval doc item #8, "per-tool audit
# counter", at a per-call granularity instead of an aggregate threshold).
#
# Reset at the top of every ``@audited`` wrapper invocation so stale state
# from a previous call (same task, sequential tool dispatch) never leaks.
_cheatsheet_bypass_pattern: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "ssh_mcp_cheatsheet_bypass_pattern",
    default=None,
)


def set_cheatsheet_bypass(pattern_id: str) -> None:
    """Mark the current tool call as a cheatsheet opt-out bypass.

    Called by :func:`ssh_mcp.services.exec_cheatsheet.cheatsheet_precheck`
    when a command matched a cheatsheet pattern but the operator has
    ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true`` set, so the tool ran
    instead of refusing. The ``@audited`` wrapper picks this up in
    ``finally`` and stamps it onto the audit line.
    """
    _cheatsheet_bypass_pattern.set(pattern_id)


# Per-call telemetry slot: when ``services.redact_policy.check_redact_bypass``
# resolves to ``warn`` or ``audit_only`` -- i.e. the path matched a redact
# glob and the policy delivered raw bytes to the LLM anyway -- the helper
# flips this to ``True`` so the audit decorator emits ``redact_bypass: true``
# on the audit line. The ``block`` path raises ``RedactBypassBlocked`` upstream
# and already shows up as ``result=error`` so the flag is not needed there.
#
# Parallel construction to ``_cheatsheet_bypass_pattern``: reset at the top of
# every ``@audited`` wrapper invocation so a previous tool call's state never
# leaks into the next one on the same task / contextvars copy.
_redact_bypass_active: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ssh_mcp_redact_bypass_active",
    default=False,
)


def set_redact_bypass_active(active: bool = True) -> None:
    """Mark the current tool call as having delivered raw bytes from a
    redact-list path (``warn`` or ``audit_only`` bypass mode).

    Called by :func:`ssh_mcp.services.redact_policy.check_redact_bypass`
    (and any caller in tools that surfaces the bypass) so the ``@audited``
    wrapper can stamp ``redact_bypass: true`` onto the audit line in
    ``finally``. The flag is intentionally a bool, not a mode string --
    one optional field keeps audit lines lean (per briefing) and operators
    only need to grep ``jq 'select(.redact_bypass)'``; the mode is
    recoverable from policy config when forensics need it.
    """
    _redact_bypass_active.set(active)


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
    unit: str | None = None,
    exit_code: int | None = None,
    error: str | None = None,
    cheatsheet_pattern_id: str | None = None,
    redact_bypass: bool = False,
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
    if unit is not None:
        # Hashed for consistency with path_hash / command_hash (see module
        # docstring): the audit format never carries cleartext identifiers
        # that could be sensitive. Operators who need the unit name can
        # correlate via ``correlation_id`` to the DEBUG log line on the
        # same logger.
        event["unit_hash"] = _hash(unit)
    if command is not None:
        # Redact secret-flag values BEFORE hashing. The hash is intended for
        # dedup/aggregation, but `sha256("foo --password=hunter2")` is a stable
        # fingerprint of the actual secret -- trivially rainbow-tableable for any
        # password an attacker can guess. Redacting first means the hash dedups
        # by command shape, not by the secret value smuggled inside it. The
        # length suffix is also stripped so two calls with different password
        # lengths still collapse to the same command_hash.
        redacted = _REDACTED_LEN_SUFFIX_RE.sub(
            "<redacted>",
            redact_command_string(command),
        )
        event["command_hash"] = _hash(redacted)
    if exit_code is not None:
        event["exit_code"] = exit_code
    if error is not None:
        event["error"] = error
    if cheatsheet_pattern_id is not None:
        # Emitted only when the operator's opt-out
        # (``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true``) let a cheatsheet-
        # matching command through. Cleartext (not hashed) -- pattern IDs
        # are a short, fixed enum (``docker`` / ``systemctl`` / ``apt-mutation``
        # / ``heredoc`` / ``single-fileop`` / ``output-redirect`` /
        # ``journalctl``) with no secret content, and operators need to
        # filter on them directly: ``jq 'select(.cheatsheet_pattern_id)'``.
        event["cheatsheet_pattern_id"] = cheatsheet_pattern_id
    if redact_bypass:
        # Emitted only when this call delivered raw bytes from a redact-list
        # path under ``warn`` or ``audit_only`` policy. Omitted (not
        # ``false``) in the common case to keep audit lines lean -- same
        # convention as ``cheatsheet_pattern_id``. Operators dedup with
        # ``jq 'select(.redact_bypass)'``.
        event["redact_bypass"] = True
    _logger.info(json.dumps(event, separators=(",", ":"), sort_keys=True))


def _capture_command_surface(kwargs: dict[str, Any]) -> str | None:
    """Pick the audit ``command`` field for a tool call from its kwargs.

    Three shapes in use today, dispatched by kwarg name + value type:

    1. ``command: str`` -- ssh_exec_run / _streaming / ssh_sudo_exec /
       ssh_docker_exec. Captured verbatim; record() does the redaction.
    2. ``args: list[str]`` -- ssh_docker_run. Pre-redacted via
       :func:`redact_argv` (secret flags collapsed BEFORE the join) and
       joined into a single string for the hash bucket.
    3. ``packages: list[str]`` -- ssh_apt_install / _remove / _mark.
       No redaction (package names aren't secrets); joined for the hash.
       When a sibling ``action: str`` kwarg is present (only ``ssh_apt_mark``
       today, with ``hold`` / ``unhold``), the action is prefixed onto the
       joined packages so the two verbs hash into distinct buckets.

    Returns ``None`` when none of the three kwargs are present in a usable
    shape -- the audit line then carries no ``command_hash`` (and that's
    the right answer for tools like ``ssh_apt_upgrade`` that take no
    command-surface kwarg at all).

    The order matters: ``command`` wins over ``args`` wins over
    ``packages``. No real tool sets more than one, but in case a future
    tool does, the priority follows the historical layering of these
    fields.
    """
    cmd_kw = kwargs.get("command")
    if isinstance(cmd_kw, str):
        return cmd_kw
    argv_kw = kwargs.get("args")
    if isinstance(argv_kw, list) and all(isinstance(a, str) for a in argv_kw):
        # redact_argv collapses secret-flag values before the join so the
        # hash dedups by command shape, not by the secret value smuggled
        # in. record() also strips length suffixes, so two calls with
        # different secret-value lengths still collapse to one bucket.
        return " ".join(redact_argv(argv_kw))
    pkgs_kw = kwargs.get("packages")
    if isinstance(pkgs_kw, list) and pkgs_kw and all(isinstance(p, str) for p in pkgs_kw):
        # ``ssh_apt_mark`` surfaces the verb as ``action: Literal["hold","unhold"]``
        # -- prefix it so the two land in distinct ``command_hash`` buckets.
        # Other apt tools (install / remove / autoremove) have no ``action``
        # kwarg at the tool surface (the action is derived inside the function
        # body from ``purge`` / fixed verb), so the prefix never fires for them.
        action_kw = kwargs.get("action")
        if isinstance(action_kw, str):
            return f"{action_kw} {' '.join(pkgs_kw)}"
        return " ".join(pkgs_kw)
    return None


def audited(tier: str) -> Callable[[F], F]:
    """Decorator: emit an audit line around each tool call.

    Extracts `host` and `path` from the tool's kwargs (best-effort) so the
    audit line always knows the target. Command-surface capture is
    delegated to :func:`_capture_command_surface`. Timing and errors are
    captured.

    Apply BELOW `@mcp_server.tool(...)` so the tool registry sees the
    wrapped function (metadata preserved via functools.wraps).
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.monotonic()
            cid = new_correlation_id()
            # Reset cheatsheet-bypass slot for this call. If the precheck
            # later sets it (opt-out match), ``finally`` reads it; if not,
            # the audit line carries no ``cheatsheet_pattern_id``. The
            # token-based reset bounds the variable to this call's scope
            # even when many tools dispatch sequentially on one task.
            cheatsheet_token = _cheatsheet_bypass_pattern.set(None)
            # Same token-reset shape for the redact-bypass flag. ``warn`` and
            # ``audit_only`` modes flip it via ``set_redact_bypass_active``
            # below; ``block`` mode raises upstream so this stays False on
            # the error path. Read + reset in ``finally`` so the audit line
            # gets ``redact_bypass: true`` only when the helper actually
            # marked the call.
            redact_token = _redact_bypass_active.set(False)
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
            # Capture the command surface for the audit line. ``script:``
            # bodies (ssh_exec_script) are intentionally NOT logged -- they
            # go via stdin so they never hit argv/process-listings, and the
            # tool docstring promises they don't appear in audit lines.
            command_capture = _capture_command_surface(kwargs)
            # systemctl mutation tools (ssh_systemctl_start / stop / restart /
            # reload / enable / disable / mask / unmask / reset_failed) pass
            # the target as ``unit: str``. Surface it via ``unit_hash`` so
            # operators can dedup audit lines by target unit the same way
            # they already can for paths and commands.
            unit_kw = kwargs.get("unit")
            unit_capture = unit_kw if isinstance(unit_kw, str) else None
            result_state = "error"
            error_msg: str | None = None
            # Set when the function raised ``CommandIsCheatsheetMatch`` -- the
            # cheatsheet pre-check refuses the call BEFORE any host-side work
            # happens (no pool acquire, no command_allowlist check, no exec).
            # We suppress the audit ``record()`` for the rejected attempt so
            # operators don't see a ``result=error`` line for a call that was
            # entirely a local-machine policy refusal. DEBUG full-error logging
            # below still fires, so forensics keeps the signal locally.
            suppress_audit_record = False
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
                if isinstance(exc, CommandIsCheatsheetMatch):
                    suppress_audit_record = True
                _logger.debug("%s full error: %s", cid, exc, exc_info=True)
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
                cheatsheet_pattern_id = _cheatsheet_bypass_pattern.get()
                _cheatsheet_bypass_pattern.reset(cheatsheet_token)
                redact_bypass_flag = _redact_bypass_active.get()
                _redact_bypass_active.reset(redact_token)
                if not suppress_audit_record:
                    record(
                        tool=fn.__name__,
                        tier=tier,
                        host=str(host),
                        correlation_id=cid,
                        duration_ms=duration_ms,
                        result=result_state,
                        path=path if isinstance(path, str) else None,
                        command=command_capture,
                        unit=unit_capture,
                        error=error_msg,
                        cheatsheet_pattern_id=cheatsheet_pattern_id,
                        redact_bypass=redact_bypass_flag,
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
