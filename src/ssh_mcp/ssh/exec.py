"""Remote command execution helpers. See DESIGN.md §4.3 and §5.3 (timeout + pkill).

Non-zero exit codes are **data**, not errors (ADR-0005). Only transport
failures and timeouts raise. stdout/stderr are capped at configurable byte
limits; anything past the cap is dropped and `*_truncated` is set to True.
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import time
from typing import TYPE_CHECKING

from ..models.results import ExecResult
from ..telemetry import span
from .errors import ConnectError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import asyncssh

logger = logging.getLogger(__name__)


def _as_str(data: bytes | bytearray | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes | bytearray):
        return data.decode("utf-8", errors="replace")
    return data


def _truncate(data: str, cap: int) -> tuple[str, int, bool]:
    raw = data.encode("utf-8", errors="replace")
    size = len(raw)
    if size <= cap:
        return data, size, False
    truncated = raw[:cap].decode("utf-8", errors="replace")
    return truncated, size, True


# We deliberately don't allocate a remote PTY (see services/shell_sessions.py
# module docstring for why). Some commands fail with a recognizable stderr
# when no TTY is present -- detect those and surface a remediation hint so
# the LLM doesn't burn turns guessing.
_NO_TTY_MARKERS = (
    "is not a tty",        # GNU coreutils / sudo
    "stdin: not a tty",    # interactive shell
    "must be run from a terminal",  # passwd, su variants
    "you must run this from a terminal",
)


def _tty_hint_or_none(stderr: str) -> str | None:
    s = stderr.lower()
    if any(marker in s for marker in _NO_TTY_MARKERS):
        return (
            "command appears to require a TTY, but this server runs commands "
            "without a remote PTY by design. Use batch-mode flags (e.g. "
            "`top -bn1`, `htop -t`, `vim -es`, `chpasswd` instead of `passwd`), "
            "or pipe the script body via ssh_exec_script."
        )
    return None


async def run(
    conn: asyncssh.SSHClientConnection,
    command: str | list[str],
    *,
    host: str,
    timeout: float,
    stdout_cap: int,
    stderr_cap: int,
    stdin: str | bytes | None = None,
) -> ExecResult:
    """Execute `command` on the pre-opened connection and return an ExecResult.

    `command` may be a string (shell-parsed by the server — caller owns quoting)
    or a list (argv; joined via shlex for servers that require a string). `stdin`
    is the optional payload piped to the remote process — used by `ssh_exec_script`.
    """
    start = time.monotonic()
    args = shlex.join(command) if isinstance(command, list) else command

    # Telemetry: never attach `args` itself -- it can contain secrets the caller
    # passed inline (`mysql -p<password>`, `curl -H 'Authorization: Bearer ...'`).
    # `argv_len` and exit code are enough to spot anomalies without leaking content.
    with span(
        "ssh.exec",
        **{
            "ssh.host": host,
            "ssh.argv_len": len(args),
            "ssh.timeout_s": timeout,
        },
    ) as s:
        try:
            result = await asyncio.wait_for(
                conn.run(
                    args,
                    check=False,
                    input=stdin,
                    timeout=None,
                ),
                timeout=timeout,
            )
        except TimeoutError:
            duration_ms = int((time.monotonic() - start) * 1000)
            partial = _partial_on_timeout(conn, args)
            await _kill_remote(conn, args)
            s.set_attribute("ssh.exit_code", -1)
            s.set_attribute("ssh.duration_ms", duration_ms)
            s.set_attribute("ssh.timed_out", True)
            return ExecResult(
                host=host,
                exit_code=-1,
                stdout=partial.get("stdout", ""),
                stderr=partial.get("stderr", ""),
                stdout_bytes=len(partial.get("stdout", "").encode("utf-8")),
                stderr_bytes=len(partial.get("stderr", "").encode("utf-8")),
                duration_ms=duration_ms,
                timed_out=True,
            )
        except Exception as exc:
            raise ConnectError(f"command transport error: {exc}") from exc

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_text, stdout_raw_size, stdout_trunc = _truncate(
            _as_str(result.stdout), stdout_cap
        )
        stderr_text, stderr_raw_size, stderr_trunc = _truncate(
            _as_str(result.stderr), stderr_cap
        )

        killed_by = None
        if getattr(result, "signal", None):
            killed_by = str(result.signal)

        exit_code = int(result.exit_status if result.exit_status is not None else -1)
        s.set_attribute("ssh.exit_code", exit_code)
        s.set_attribute("ssh.duration_ms", duration_ms)
        s.set_attribute("ssh.timed_out", False)
        s.set_attribute("ssh.stdout_bytes", stdout_raw_size)
        s.set_attribute("ssh.stderr_bytes", stderr_raw_size)
        return ExecResult(
            host=host,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_bytes=stdout_raw_size,
            stderr_bytes=stderr_raw_size,
            stdout_truncated=stdout_trunc,
            stderr_truncated=stderr_trunc,
            duration_ms=duration_ms,
            timed_out=False,
            killed_by_signal=killed_by,
            hint=_tty_hint_or_none(stderr_text),
        )


def _partial_on_timeout(
    _conn: asyncssh.SSHClientConnection, _args: str
) -> dict[str, str]:
    """Hook point for future partial-capture-on-timeout. For now returns empty.

    asyncssh's `conn.run` buffers internally and doesn't expose partial output
    when the call is cancelled by `wait_for`. A streaming variant with
    `create_process` can capture partials — that's ssh_exec_run_streaming.
    """
    return {}


async def _kill_remote(conn: asyncssh.SSHClientConnection, args: str) -> None:
    """Best-effort cleanup after a timeout: `timeout 3s pkill -f -- <pattern>`.

    Borrowed from the reference implementation. Capped at 5 s so a stuck pkill
    can't compound the problem. `shlex.quote` defends the argv; we still run
    under a shell because pkill's pattern is a regex string.
    """
    pattern = shlex.quote(args)
    cleanup = f"timeout 3s pkill -f -- {pattern}"
    try:
        await asyncio.wait_for(conn.run(cleanup, check=False), timeout=5.0)
    except (TimeoutError, Exception) as exc:
        logger.debug("pkill cleanup failed (ignored): %s", exc)


async def run_streaming(
    conn: asyncssh.SSHClientConnection,
    command: str | list[str],
    *,
    host: str,
    timeout: float,
    stdout_cap: int,
    stderr_cap: int,
    chunk_cb: Callable[[str, str], Awaitable[None]] | None = None,
) -> ExecResult:
    """Like `run()` but captures output incrementally via `create_process`.

    When `chunk_cb` is provided, it's awaited with `(stream, chunk)` for every
    non-empty read, where stream is "stdout" or "stderr". Used by the streaming
    MCP tool to emit progress while the command is still running.
    """
    start = time.monotonic()
    args = shlex.join(command) if isinstance(command, list) else command

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_bytes_seen = 0
    stderr_bytes_seen = 0
    timed_out = False
    killed_by_signal: str | None = None
    exit_code = -1

    # Telemetry: same redaction posture as `run()` -- attach `argv_len`/host but
    # never `args`. `streaming=true` distinguishes the streaming consumer from
    # the buffered one in trace queries.
    with span(
        "ssh.exec",
        **{
            "ssh.host": host,
            "ssh.argv_len": len(args),
            "ssh.timeout_s": timeout,
            "ssh.streaming": True,
        },
    ) as s:
        try:
            process = await conn.create_process(args)
        except Exception as exc:
            raise ConnectError(f"command transport error: {exc}") from exc

        async def _pump(reader: object, buf: bytearray, cap: int, stream_name: str) -> int:
            # INC-005: update nonlocal byte counters as each chunk arrives so that
            # a timeout cancellation still reports the bytes we've seen. Returning
            # `total` only on clean EOF means truncated=true was unreachable on timeout.
            nonlocal stdout_bytes_seen, stderr_bytes_seen
            total = 0
            while True:
                chunk = await reader.read(16 * 1024)  # type: ignore[attr-defined]
                if not chunk:
                    return total
                raw = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
                total += len(raw)
                if stream_name == "stdout":
                    stdout_bytes_seen = total
                else:
                    stderr_bytes_seen = total
                remaining = cap - len(buf)
                captured = raw[:remaining] if remaining > 0 else b""
                if captured:
                    buf.extend(captured)
                # INC-011: hand the callback only what we actually captured, so
                # streaming consumers don't see bytes the caller thinks were dropped.
                if chunk_cb is not None and captured:
                    await chunk_cb(stream_name, captured.decode("utf-8", errors="replace"))

        try:
            pump_out = asyncio.create_task(_pump(process.stdout, stdout_buf, stdout_cap, "stdout"))
            pump_err = asyncio.create_task(_pump(process.stderr, stderr_buf, stderr_cap, "stderr"))
            try:
                await asyncio.wait_for(process.wait_closed(), timeout=timeout)
                stdout_bytes_seen = await pump_out
                stderr_bytes_seen = await pump_err
                exit_code = int(process.exit_status if process.exit_status is not None else -1)
                if getattr(process, "exit_signal", None):
                    killed_by_signal = str(process.exit_signal)
            except TimeoutError:
                timed_out = True
                process.terminate()
                pump_out.cancel()
                pump_err.cancel()
                # Await the cancelled pumps so they finish teardown before we fall
                # out of the scope. Without this, an exception raised mid-cancel
                # (e.g. the reader raising during `read()`) would be attached to
                # a Task that nobody retrieves, producing the dreaded
                # "Task exception was never retrieved" warning at process exit
                # and, worse, a lingering task that could reference the closed
                # SSH channel. `return_exceptions=True` swallows `CancelledError`
                # and any secondary error so the timeout path stays clean.
                await asyncio.gather(pump_out, pump_err, return_exceptions=True)
                await _kill_remote(conn, args)
        finally:
            process.close()

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_text = stdout_buf.decode("utf-8", errors="replace")
        stderr_text = stderr_buf.decode("utf-8", errors="replace")
        if timed_out:
            if exit_code == -1:
                exit_code = -1
        else:
            if stdout_bytes_seen == 0:
                stdout_bytes_seen = len(stdout_text.encode("utf-8"))
            if stderr_bytes_seen == 0:
                stderr_bytes_seen = len(stderr_text.encode("utf-8"))

        s.set_attribute("ssh.exit_code", exit_code)
        s.set_attribute("ssh.duration_ms", duration_ms)
        s.set_attribute("ssh.timed_out", timed_out)
        s.set_attribute("ssh.stdout_bytes", stdout_bytes_seen)
        s.set_attribute("ssh.stderr_bytes", stderr_bytes_seen)
        return ExecResult(
            host=host,
            exit_code=exit_code,
            stdout=stdout_text,
            stderr=stderr_text,
            stdout_bytes=stdout_bytes_seen,
            stderr_bytes=stderr_bytes_seen,
            stdout_truncated=stdout_bytes_seen > stdout_cap,
            stderr_truncated=stderr_bytes_seen > stderr_cap,
            duration_ms=duration_ms,
            timed_out=timed_out,
            killed_by_signal=killed_by_signal,
            hint=_tty_hint_or_none(stderr_text),
        )
