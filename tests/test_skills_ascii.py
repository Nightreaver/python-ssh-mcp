"""Regression guard: every SKILL.md must be pure ASCII.

FastMCP 3.2.4's SkillsDirectoryProvider calls `Path.read_text()` without an
explicit `encoding=` argument. On Windows that defaults to cp1252 and
explodes on any non-ASCII byte. Until the upstream fix lands, we enforce
ASCII-only skills at test time.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).parent.parent
SKILLS_DIR = _PROJECT_ROOT / "skills"
RUNBOOKS_DIR = _PROJECT_ROOT / "runbooks"


def _all_skill_files() -> list[Path]:
    """Union of per-tool skills + workflow runbooks -- the FastMCP ASCII bug
    applies to anything SkillsDirectoryProvider reads, regardless of which
    directory it lives in."""
    return sorted(
        list(SKILLS_DIR.glob("*/SKILL.md"))
        + list(RUNBOOKS_DIR.glob("*/SKILL.md"))
    )


@pytest.mark.parametrize(
    "skill_path",
    _all_skill_files(),
    ids=lambda p: f"{p.parent.parent.name}/{p.parent.name}",
)
def test_skill_is_ascii(skill_path: Path) -> None:
    raw = skill_path.read_bytes()
    try:
        raw.decode("ascii")
    except UnicodeDecodeError as exc:
        snippet = raw[max(0, exc.start - 20) : exc.start + 20]
        pytest.fail(
            f"{skill_path} contains non-ASCII byte 0x{raw[exc.start]:02x} "
            f"at offset {exc.start}; context: {snippet!r}"
        )


def test_skills_directory_exists() -> None:
    assert SKILLS_DIR.is_dir()
    # Floor set close to the actual count so a mass-accidental-deletion
    # (rm -rf on the wrong glob) trips CI instead of sliding through. Bump
    # when we add genuinely new tool skills; don't lower when trimming.
    assert len(list(SKILLS_DIR.glob("*/SKILL.md"))) >= 50


def test_runbooks_directory_exists() -> None:
    assert RUNBOOKS_DIR.is_dir()
    # Same posture as the skills floor: tight enough to catch regression,
    # loose enough that adding/removing one runbook during refactors doesn't
    # require a parallel test edit.
    assert len(list(RUNBOOKS_DIR.glob("*/SKILL.md"))) >= 7


@pytest.mark.asyncio
async def test_every_tool_has_a_matching_skill() -> None:
    """Regression guard: adding a new tool without a SKILL.md should fail CI.

    Policy: every tool with an `ssh_<name>` id has a `skills/ssh-<name>/SKILL.md`.
    Dashed skill names are the tool's underscored name with underscores replaced
    by dashes (consistent with the existing 46+ skill directories).
    """
    from ssh_mcp.server import mcp_server

    tools = await mcp_server.list_tools()
    tool_slugs = {t.name.replace("_", "-") for t in tools}
    skill_slugs = {p.parent.name for p in SKILLS_DIR.glob("*/SKILL.md")}
    missing = sorted(tool_slugs - skill_slugs)
    assert not missing, (
        f"tools without a skill: {missing}. Write "
        f"skills/<slug>/SKILL.md for each, or adjust this test if the tool "
        f"is intentionally skill-less."
    )
