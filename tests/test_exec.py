"""ssh/exec.run + run_streaming — truncation, timeout + pkill, stderr-as-data.

Uses a fake asyncssh connection so we don't need a live sshd.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from ssh_mcp.ssh.exec import run, run_streaming


@dataclass
class FakeRunResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int | None = 0
    signal: str | None = None


class FakeConn:
    """Scripted conn.run. Records every call; supports slow/hanging commands."""

    def __init__(
        self,
        *,
        result: FakeRunResult | None = None,
        hang: bool = False,
    ) -> None:
        # Avoid `FakeRunResult()` in the default-arg slot (B008): a single
        # frozen instance would be shared across every FakeConn that doesn't
        # pass `result=`. Mutating one's attrs would leak into the others.
        self.result = result if result is not None else FakeRunResult()
        self.hang = hang
        self.calls: list[dict[str, Any]] = []

    async def run(
        self,
        args: str,
        *,
        check: bool = False,
        input: Any = None,
        timeout: Any = None,
    ) -> FakeRunResult:
        self.calls.append({"args": args, "input": input})
        if self.hang:
            await asyncio.sleep(10)
        return self.result


# --- basic shapes ---


@pytest.mark.asyncio
async def test_run_returns_exit_code_as_data() -> None:
    conn = FakeConn(result=FakeRunResult(stdout="", stderr="file not found", exit_status=2))
    out = await run(
        conn,
        "ls /nope",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    assert out.exit_code == 2  # non-zero is not an error
    assert out.stderr == "file not found"
    assert out.timed_out is False


@pytest.mark.asyncio
async def test_run_truncates_stdout() -> None:
    big = "x" * 5000
    conn = FakeConn(result=FakeRunResult(stdout=big))
    out = await run(
        conn,
        "echo",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    assert len(out.stdout.encode("utf-8")) == 1024
    assert out.stdout_bytes == 5000
    assert out.stdout_truncated is True


@pytest.mark.asyncio
async def test_run_stderr_not_treated_as_failure() -> None:
    # curl prints progress to stderr; exit 0 is still success.
    conn = FakeConn(result=FakeRunResult(stdout="ok", stderr="progress noise", exit_status=0))
    out = await run(conn, "curl -s url", host="web01", timeout=5.0, stdout_cap=1024, stderr_cap=1024)
    assert out.exit_code == 0
    assert out.stderr == "progress noise"


@pytest.mark.asyncio
async def test_run_propagates_exit_signal() -> None:
    conn = FakeConn(result=FakeRunResult(exit_status=-1, signal="TERM"))
    out = await run(conn, "sleep 1", host="web01", timeout=5.0, stdout_cap=1024, stderr_cap=1024)
    assert out.killed_by_signal == "TERM"


@pytest.mark.asyncio
async def test_run_emits_tty_hint_on_no_tty_stderr() -> None:
    """ssh-mcp-server#31 echo: surface a remediation hint when a command fails
    because no PTY is allocated."""
    conn = FakeConn(result=FakeRunResult(
        stdout="", stderr="sudo: a password is required\nstdin: is not a tty\n",
        exit_status=1,
    ))
    out = await run(conn, "top", host="web01", timeout=5.0, stdout_cap=1024, stderr_cap=1024)
    assert out.hint is not None
    assert "TTY" in out.hint or "tty" in out.hint
    assert "batch" in out.hint.lower()


@pytest.mark.asyncio
async def test_run_no_hint_for_normal_failure() -> None:
    conn = FakeConn(result=FakeRunResult(
        stderr="ls: cannot access '/nonexistent': No such file or directory",
        exit_status=2,
    ))
    out = await run(conn, "ls /nonexistent", host="web01", timeout=5.0, stdout_cap=1024, stderr_cap=1024)
    assert out.hint is None


# --- timeout + pkill ---


@pytest.mark.asyncio
async def test_run_timeout_sets_timed_out_and_attempts_pkill() -> None:
    # First call hangs forever; pkill cleanup call should still complete.
    class TwoStageConn:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def run(self, args: str, **_: Any) -> FakeRunResult:
            self.calls.append(args)
            if len(self.calls) == 1:
                await asyncio.sleep(10)  # simulate hang
            return FakeRunResult()  # pkill returns

    conn = TwoStageConn()
    out = await run(
        conn,  # type: ignore[arg-type]
        "sleep 9999",
        host="web01",
        timeout=0.05,
        stdout_cap=1024,
        stderr_cap=1024,
    )
    assert out.timed_out is True
    assert out.exit_code == -1
    # The pkill cleanup should have been invoked (second call).
    assert any("pkill" in c for c in conn.calls)


# --- stdin piping (script variant) ---


@pytest.mark.asyncio
async def test_run_forwards_stdin_payload() -> None:
    conn = FakeConn(result=FakeRunResult(stdout="done"))
    await run(
        conn,
        "sh -s --",
        host="web01",
        timeout=5.0,
        stdout_cap=1024,
        stderr_cap=1024,
        stdin="echo hello",
    )
    assert conn.calls[0]["input"] == "echo hello"


# --- run_streaming with chunk callback ---


class _FakeReader:
    def __init__(self, parts: list[str]) -> None:
        self._parts = list(parts)

    async def read(self, _n: int) -> str:
        if not self._parts:
            return ""
        return self._parts.pop(0)


class _FakeProcess:
    def __init__(self, stdout_parts: list[str], stderr_parts: list[str], exit_status: int = 0) -> None:
        self.stdout = _FakeReader(stdout_parts)
        self.stderr = _FakeReader(stderr_parts)
        self.exit_status = exit_status
        self.exit_signal: str | None = None
        self._closed = False

    async def wait_closed(self) -> None:
        return None

    def terminate(self) -> None:
        self._closed = True

    def close(self) -> None:
        self._closed = True


class _StreamingConn:
    def __init__(self, proc: _FakeProcess) -> None:
        self._proc = proc

    async def create_process(self, _args: str) -> _FakeProcess:
        return self._proc

    async def run(self, *_: Any, **__: Any) -> FakeRunResult:
        return FakeRunResult()  # for pkill fallbacks


@pytest.mark.asyncio
async def test_run_streaming_invokes_chunk_cb_and_caps_output() -> None:
    # INC-011: the callback now receives only bytes that were actually
    # captured (i.e. clamped to the remaining cap). Past-cap chunks do not
    # surface through the callback -- `stdout_bytes` still reports the true
    # total so consumers can detect truncation.
    proc = _FakeProcess(
        stdout_parts=["hello\n", "world\n"],
        stderr_parts=["warn\n"],
    )
    conn = _StreamingConn(proc)

    seen: list[tuple[str, str]] = []

    async def cb(stream: str, chunk: str) -> None:
        seen.append((stream, chunk))

    out = await run_streaming(
        conn,  # type: ignore[arg-type]
        "tail -f log",
        host="web01",
        timeout=5.0,
        stdout_cap=3,  # cap below the total -- forces truncation
        stderr_cap=1024,
        chunk_cb=cb,
    )
    assert out.exit_code == 0
    assert out.stdout_truncated is True
    # Only the first 3 bytes of the first chunk are captured; that's what
    # the callback sees. The rest of that chunk and all later chunks are
    # dropped. stdout_bytes still reports the full 12 bytes seen.
    assert ("stdout", "hel") in seen
    assert not any(s == "stdout" and "world" in c for s, c in seen)
    assert out.stdout_bytes == len("hello\nworld\n")
    # stderr cap was generous so the full chunk passes.
    assert ("stderr", "warn\n") in seen
