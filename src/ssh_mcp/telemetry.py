"""OpenTelemetry helpers for SSH transport spans. See DESIGN.md §PI-4 / §8.

FastMCP 3 auto-instruments tool, resource, and prompt spans when OTel is
installed. This module provides the SSH-side wrappers (`ssh.connect`,
`ssh.exec`, `sftp.op`) with **redaction by default** — we record host,
duration, and exit code but never the full command or payload.

Usage:

    from ssh_mcp.telemetry import span, redact_argv

    with span("ssh.exec", host=policy.hostname, argv_len=len(argv)) as s:
        result = await conn.run(argv)
        s.set_attribute("ssh.exit_code", result.exit_status)
"""
from __future__ import annotations

import contextlib
import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

_SECRET_FLAG_RE = re.compile(
    r"(?i)^(--)?(password|token|secret|passwd|pwd|auth|api[-_]?key)=", re.IGNORECASE
)


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Open an OTel span if available; no-op otherwise.

    Never imports OTel at module load — cost is paid only on the first call.
    Unknown OTel state degrades to a dummy context manager with `.set_attribute`.
    """
    tracer = _get_tracer()
    if tracer is None:
        yield _NoopSpan()
        return
    with tracer.start_as_current_span(name) as s:
        for k, v in attributes.items():
            s.set_attribute(k, v)
        yield s


def redact_argv(argv: list[str]) -> list[str]:
    """Replace secret-looking argv values with `<redacted:N>` (length preserved).

    Matches `--password=...`, `--token=...`, `--secret=...`, `--api-key=...`, etc.
    Use before attaching argv (as an attribute or message) to a span or log.
    """
    out: list[str] = []
    for arg in argv:
        match = _SECRET_FLAG_RE.match(arg)
        if match:
            prefix = match.group(0)
            rest = arg[len(prefix) :]
            out.append(f"{prefix}<redacted:{len(rest)}>")
        else:
            out.append(arg)
    return out


# Same flag set as `_SECRET_FLAG_RE`, but built to scan ANYWHERE in a string
# (not just the start) and consume the secret value up to the next whitespace.
# Used by `redact_command_string` for raw-string commands -- shlex.split would
# fail on invalid shell syntax (unmatched quotes, partial pipelines), and even
# when it works, re-quoting via shlex.quote rewrites the operator's input in a
# way that breaks audit-line readability for non-secret arguments.
_SECRET_INLINE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"           # boundary: not part of a longer token
    r"((?:--)?(?:password|token|secret|passwd|pwd|auth|api[-_]?key)=)"
    r"(\S+)",
)


def redact_command_string(command: str) -> str:
    """Redact secret-looking values in a single shell-command string.

    Counterpart to `redact_argv` for tools whose audit/log surface is a single
    command string (e.g. `ssh_exec_run(command="...")`). Length-preserving:
    `--password=hunter2` -> `--password=<redacted:7>`. Only the secret value
    changes; the rest of the string -- including non-secret args, quoting, and
    pipes -- is left intact so audit hashes remain useful for dedup.
    """
    return _SECRET_INLINE_RE.sub(
        lambda m: f"{m.group(1)}<redacted:{len(m.group(2))}>",
        command,
    )


def _get_tracer() -> Any:
    try:
        from fastmcp.telemetry import get_tracer  # type: ignore[import-not-found]

        return get_tracer()
    except Exception:
        return None


class _NoopSpan:
    def set_attribute(self, _key: str, _value: Any) -> None:
        return None

    def record_exception(self, _exc: BaseException) -> None:
        return None

    def set_status(self, _status: Any) -> None:
        return None
