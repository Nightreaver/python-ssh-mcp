"""ssh_broadcast (INC-052) — fan-out exec across pre-configured hosts.

Pinned contracts:
- Empty hosts / over-cap rejected up front.
- Unknown / blocked aliases raise ValueError before any fan-out.
- Repeated aliases deduplicated.
- Per-host command allowlist failure surfaces in `errors`, not `succeeded`,
  and does NOT abort other hosts.
- Windows hosts in the list raise `PlatformNotSupported` per-host.
- Timeouts (`timed_out=True`) categorize as `failed`, not `succeeded`.
- Transport-layer surprises captured per-host instead of bringing the
  whole call down (defense-in-depth catch-all).
- `command` is echoed in the result so the broadcast call is self-describing.
"""
from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.models.results import ExecResult
from ssh_mcp.tools import multi_host_tools
from ssh_mcp.tools.multi_host_tools import _BROADCAST_MAX_HOSTS, ssh_broadcast


def _policy(
    alias: str,
    *,
    platform: str = "posix",
    command_allowlist: list[str] | None = None,
) -> HostPolicy:
    return HostPolicy(
        hostname=alias,
        user="deploy",
        port=22,
        platform=platform,  # type: ignore[arg-type]
        auth=AuthPolicy(method="agent"),
        command_allowlist=command_allowlist or [],
    )


def _exec_result(
    host: str,
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> ExecResult:
    raw_stdout = stdout.encode("utf-8")
    raw_stderr = stderr.encode("utf-8")
    return ExecResult(
        host=host,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_bytes=len(raw_stdout),
        stderr_bytes=len(raw_stderr),
        duration_ms=10,
        timed_out=timed_out,
    )


def _ctx(
    hosts: dict[str, HostPolicy],
    *,
    pool_acquire: Any = None,
    command_allowlist: list[str] | None = None,
) -> Any:
    """Build a stub FastMCP Context that ssh_broadcast can drive end to end.

    `pool_acquire` is plugged into `pool.acquire` and called once per host
    in the broadcast. Default returns a unique sentinel per call so callers
    can verify acquisition occurred without modeling a real connection.
    """
    pool = MagicMock()
    pool.acquire = AsyncMock(side_effect=pool_acquire or (lambda _p: object()))

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_ALLOWLIST=[],
                SSH_HOSTS_BLOCKLIST=[],
                # `is not None` (not `or`) -- callers pass `[]` to disable the
                # env allowlist entirely so per-host policy is the only gate.
                SSH_COMMAND_ALLOWLIST=(
                    command_allowlist
                    if command_allowlist is not None
                    else ["uname", "echo", "systemctl", "uptime"]
                ),
                ALLOW_DANGEROUS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": list(hosts.keys()),
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


# ---------------------------------------------------------------------------
# Pre-flight validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_hosts_raises() -> None:
    with pytest.raises(ValueError, match="cannot be empty"):
        await ssh_broadcast(hosts=[], command="uname -r", ctx=_ctx({}))


@pytest.mark.asyncio
async def test_too_many_hosts_raises() -> None:
    too_many = [f"h{i}" for i in range(_BROADCAST_MAX_HOSTS + 1)]
    with pytest.raises(ValueError, match=f"max is {_BROADCAST_MAX_HOSTS}"):
        await ssh_broadcast(hosts=too_many, command="uname -r", ctx=_ctx({}))


@pytest.mark.asyncio
async def test_unknown_host_raises_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Typos must be loud, not buried in the per-host `errors` map."""
    hosts = {"web01": _policy("web01")}
    captured = AsyncMock(return_value=_exec_result("web01"))
    monkeypatch.setattr(multi_host_tools, "exec_run", captured)

    with pytest.raises(ValueError, match="unknown / blocked hosts"):
        await ssh_broadcast(
            hosts=["web01", "typo01"], command="uname -r", ctx=_ctx(hosts),
        )
    # No fan-out happened -- exec_run never invoked.
    assert captured.await_count == 0


@pytest.mark.asyncio
async def test_blocked_host_raises_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Blocklist hits also short-circuit -- policy denial is a caller error."""
    hosts = {"web01": _policy("web01"), "blocked": _policy("blocked")}
    pool = MagicMock()
    pool.acquire = AsyncMock()

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_HOSTS_BLOCKLIST=["blocked"],
                SSH_COMMAND_ALLOWLIST=["uname"],
                ALLOW_DANGEROUS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": ["web01", "blocked"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    with pytest.raises(ValueError, match="blocked.*HostBlocked"):
        await ssh_broadcast(
            hosts=["web01", "blocked"], command="uname -r", ctx=_Ctx(),
        )


@pytest.mark.asyncio
async def test_dedupes_repeated_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = {"web01": _policy("web01")}
    captured = AsyncMock(return_value=_exec_result("web01"))
    monkeypatch.setattr(multi_host_tools, "exec_run", captured)

    out = await ssh_broadcast(
        hosts=["web01", "web01", "web01"], command="uname -r", ctx=_ctx(hosts),
    )
    assert captured.await_count == 1
    assert list(out.results.keys()) == ["web01"]
    assert out.succeeded == ["web01"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_all_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    hosts = {a: _policy(a) for a in ("web01", "web02", "web03")}

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host, stdout=f"Linux {host}")

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    out = await ssh_broadcast(
        hosts=["web01", "web02", "web03"], command="uname -r", ctx=_ctx(hosts),
    )
    assert sorted(out.succeeded) == ["web01", "web02", "web03"]
    assert out.failed == []
    assert out.errors == {}
    assert out.command == "uname -r"
    assert out.results["web01"].stdout == "Linux web01"
    assert out.elapsed_ms >= 0


@pytest.mark.asyncio
async def test_command_field_echoed_in_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Audit logs broadcast as `host="?"` -- the result body is the durable
    record of *what* was run. Echo verbatim, no transformation."""
    hosts = {"web01": _policy("web01")}
    monkeypatch.setattr(
        multi_host_tools, "exec_run",
        AsyncMock(return_value=_exec_result("web01")),
    )

    out = await ssh_broadcast(
        hosts=["web01"], command="systemctl is-active myapp", ctx=_ctx(hosts),
    )
    assert out.command == "systemctl is-active myapp"


# ---------------------------------------------------------------------------
# Per-host failures don't abort the broadcast
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_host_command_allowlist_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One host denies the command; siblings still run."""
    hosts = {
        "permissive": _policy("permissive", command_allowlist=["uname", "echo"]),
        "strict": _policy("strict", command_allowlist=["echo"]),  # no `uname`
    }

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host, stdout=f"Linux {host}")

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    # Empty env allowlist so the per-host `command_allowlist` is the ONLY
    # gate -- otherwise `effective_command_allowlist` unions env in and
    # `uname` would be permitted on `strict` too.
    out = await ssh_broadcast(
        hosts=["permissive", "strict"],
        command="uname -r",
        ctx=_ctx(hosts, command_allowlist=[]),
    )
    assert out.succeeded == ["permissive"]
    assert "strict" in out.failed
    assert out.errors["strict"] == "CommandNotAllowed"
    # The permissive host still produced an ExecResult.
    assert "permissive" in out.results
    assert "strict" not in out.results


@pytest.mark.asyncio
async def test_windows_host_returns_platform_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts = {
        "linux01": _policy("linux01"),
        "win01": _policy("win01", platform="windows"),
    }

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host)

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    out = await ssh_broadcast(
        hosts=["linux01", "win01"], command="uname -r", ctx=_ctx(hosts),
    )
    assert out.succeeded == ["linux01"]
    assert out.errors["win01"] == "PlatformNotSupported"
    assert "win01" in out.failed


@pytest.mark.asyncio
async def test_per_host_transport_error_doesnt_abort_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch-all on `Exception` keeps the broadcast useful even when one
    host's connection collapses unexpectedly."""
    hosts = {a: _policy(a) for a in ("web01", "web02")}

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        if host == "web02":
            raise RuntimeError("simulated transport collapse")
        return _exec_result(host)

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    out = await ssh_broadcast(
        hosts=["web01", "web02"], command="uname -r", ctx=_ctx(hosts),
    )
    assert out.succeeded == ["web01"]
    assert out.errors["web02"] == "RuntimeError"


@pytest.mark.asyncio
async def test_timeout_categorizes_as_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """timed_out=True is the canonical 'host did not finish' signal -- it
    must NOT count as success even though the call returned an ExecResult."""
    hosts = {"web01": _policy("web01")}

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host, exit_code=-1, timed_out=True)

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    out = await ssh_broadcast(
        hosts=["web01"],
        command="sleep 9999",
        ctx=_ctx(hosts, command_allowlist=["sleep"]),
    )
    assert out.succeeded == []
    assert out.failed == ["web01"]
    # ExecResult is still in `results` -- the LLM can read the timeout flag.
    assert out.results["web01"].timed_out is True


@pytest.mark.asyncio
async def test_nonzero_exit_categorizes_as_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADR-0005: non-zero exit is data, not a raise. But for broadcast
    bucketing, exit_code != 0 still means the host did not succeed."""
    hosts = {"web01": _policy("web01"), "web02": _policy("web02")}

    async def fake_exec(_conn: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host, exit_code=0 if host == "web01" else 1)

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    out = await ssh_broadcast(
        hosts=["web01", "web02"], command="systemctl is-active myapp", ctx=_ctx(hosts),
    )
    assert out.succeeded == ["web01"]
    assert out.failed == ["web02"]
    # web02's ExecResult is preserved -- exit_code visible to the LLM.
    assert out.results["web02"].exit_code == 1


@pytest.mark.asyncio
async def test_pool_acquire_called_once_per_unique_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dedup must happen BEFORE pool.acquire -- otherwise concurrent acquires
    for the same alias would race or burn extra connections."""
    hosts = {"web01": _policy("web01"), "web02": _policy("web02")}
    captured_acquire = AsyncMock(side_effect=lambda _p: object())

    pool = MagicMock()
    pool.acquire = captured_acquire

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(
                SSH_HOSTS_FILE=None,
                SSH_COMMAND_ALLOWLIST=["uname"],
                ALLOW_DANGEROUS_TOOLS=True,
            ),
            "hosts": hosts,
            "host_allowlist": ["web01", "web02"],
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    async def fake_exec(_c: Any, _cmd: str, *, host: str, **__: Any) -> ExecResult:
        return _exec_result(host)

    monkeypatch.setattr(multi_host_tools, "exec_run", fake_exec)

    await ssh_broadcast(
        hosts=["web01", "web02", "web01", "web02"],
        command="uname -r",
        ctx=_Ctx(),
    )
    assert captured_acquire.await_count == 2
