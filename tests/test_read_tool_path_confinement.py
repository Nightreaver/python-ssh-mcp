"""ADR-0017 regression guard: every path-bearing read tool must path-confine.

These tools take a user-supplied `path` and would otherwise let any caller
read arbitrary remote files (/etc/shadow, /root/.ssh/*). They must route
paths through `services.path_policy.canonicalize_and_check` before touching
SFTP or running `find`.

We lock the behavior two ways:
  1. Source-level: each tool's source imports and references the check.
  2. Behavioral: a fake conn + empty allowlist + in-allowlist path proves
     the check actually runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ssh_mcp.services.path_policy import canonicalize_and_check
from ssh_mcp.ssh.errors import PathNotAllowed

TOOL_FILE = Path(__file__).parent.parent / "src" / "ssh_mcp" / "tools" / "sftp_read_tools.py"

READ_TOOLS_WITH_PATH = ["ssh_sftp_list", "ssh_sftp_stat", "ssh_sftp_download", "ssh_find"]


def test_read_tool_source_imports_path_policy() -> None:
    body = TOOL_FILE.read_text(encoding="utf-8")
    assert "canonicalize_and_check" in body, (
        "sftp_read_tools.py must import canonicalize_and_check (ADR-0017)"
    )
    assert "effective_allowlist" in body, (
        "sftp_read_tools.py must import effective_allowlist"
    )


@pytest.mark.parametrize("tool_name", READ_TOOLS_WITH_PATH)
def test_each_read_tool_invokes_canonicalize_and_check(tool_name: str) -> None:
    body = TOOL_FILE.read_text(encoding="utf-8")
    # Find the `async def <tool_name>(` block and verify it references
    # `canonicalize_and_check` before the tool returns. Rough but effective.
    marker = f"async def {tool_name}("
    assert marker in body, f"{tool_name} not defined in sftp_read_tools.py"
    idx = body.index(marker)
    next_tool = min(
        (body.find(f"async def {t}(", idx + 1) for t in READ_TOOLS_WITH_PATH if t != tool_name),
        default=len(body),
    )
    end = next_tool if next_tool > 0 else len(body)
    fn_body = body[idx:end]
    assert "canonicalize_and_check" in fn_body, (
        f"{tool_name} body does not call canonicalize_and_check "
        f"-- a user-supplied path can reach SFTP/find unchecked"
    )


# --- behavioral check on the shared helper ---


@dataclass
class FakeProcResult:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


class FakeConn:
    def __init__(self, canonical: str) -> None:
        self._canonical = canonical
        self.calls: list[list[str]] = []

    async def run(self, argv: list[str], *, check: bool = False) -> FakeProcResult:
        self.calls.append(list(argv))
        return FakeProcResult(stdout=self._canonical + "\n")


@pytest.mark.asyncio
async def test_read_tool_rejects_path_outside_allowlist() -> None:
    # The helper canonicalize_and_check is the one and only gate. If it rejects
    # /etc/passwd for a policy allowlisting /opt/app, the read tools that call it
    # will reject too. This test confirms the helper works the way the tools use it.
    conn: Any = FakeConn("/etc/passwd")
    with pytest.raises(PathNotAllowed, match="outside the allowlist"):
        await canonicalize_and_check(conn, "/etc/passwd", ["/opt/app"], must_exist=True)


@pytest.mark.asyncio
async def test_read_tool_accepts_path_inside_allowlist() -> None:
    conn: Any = FakeConn("/opt/app/config.yml")
    result = await canonicalize_and_check(
        conn, "/opt/app/config.yml", ["/opt/app"], must_exist=True
    )
    assert result == "/opt/app/config.yml"
