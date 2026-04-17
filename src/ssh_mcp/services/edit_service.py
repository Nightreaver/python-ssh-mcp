"""Pure-Python file transforms: structured edit + unified-diff patch apply.

Both work on bytes in memory. Callers are responsible for downloading the
original file and uploading the result atomically via SFTP — this module
does not touch the network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from unidiff import PatchSet


class EditError(ValueError):
    pass


class PatchError(ValueError):
    pass


@dataclass(frozen=True)
class EditOutcome:
    new_text: str
    replacements: int


def apply_edit(
    text: str,
    old_string: str,
    new_string: str,
    *,
    occurrence: Literal["single", "all"] = "single",
) -> EditOutcome:
    """Replace `old_string` with `new_string`.

    `single` — require exactly one occurrence; raise otherwise.
    `all`    — replace every occurrence.
    """
    if old_string == "":
        raise EditError("old_string must not be empty")
    if old_string == new_string:
        raise EditError("old_string and new_string are identical — no-op")

    count = text.count(old_string)
    if count == 0:
        raise EditError("old_string not found in file")

    if occurrence == "single":
        if count > 1:
            raise EditError(
                f"old_string appears {count} times; use occurrence='all' or make it unique"
            )
        return EditOutcome(new_text=text.replace(old_string, new_string, 1), replacements=1)

    if occurrence == "all":
        return EditOutcome(new_text=text.replace(old_string, new_string), replacements=count)

    raise EditError(f"unknown occurrence mode {occurrence!r}")


@dataclass(frozen=True)
class PatchOutcome:
    new_text: str
    hunks_applied: int
    hunks_rejected: int


def apply_unified_diff(text: str, diff: str) -> PatchOutcome:
    """Apply a unified diff to `text`. Rejects the whole patch on any hunk mismatch.

    Single-file diffs only. The first file header in the patch identifies the
    target implicitly; we do not enforce filename matching here (the caller
    knows which file it downloaded).
    """
    try:
        patches = PatchSet.from_string(diff)
    except Exception as exc:  # unidiff raises generic Exception for malformed diffs
        raise PatchError(f"invalid unified diff: {exc}") from exc

    if len(patches) == 0:
        raise PatchError("no files found in diff")
    if len(patches) > 1:
        raise PatchError(f"diff touches {len(patches)} files; exactly one expected")

    patched_file = patches[0]
    lines = text.splitlines(keepends=True)
    result_lines: list[str] = []
    src_idx = 0  # 0-based pointer into `lines`

    for hunk in patched_file:
        hunk_start = hunk.source_start - 1  # diff lines are 1-based
        if hunk_start < src_idx:
            raise PatchError(
                f"hunk at source line {hunk.source_start} overlaps or precedes a previous hunk"
            )
        # Carry over unchanged lines up to the hunk start.
        result_lines.extend(lines[src_idx:hunk_start])
        src_idx = hunk_start

        for line in hunk:
            if line.is_context:
                if src_idx >= len(lines) or lines[src_idx].rstrip("\n") != line.value.rstrip("\n"):
                    raise PatchError(
                        f"context mismatch at line {src_idx + 1}: "
                        f"expected {line.value!r}, got "
                        f"{(lines[src_idx] if src_idx < len(lines) else '<EOF>')!r}"
                    )
                result_lines.append(lines[src_idx])
                src_idx += 1
            elif line.is_removed:
                if src_idx >= len(lines) or lines[src_idx].rstrip("\n") != line.value.rstrip("\n"):
                    raise PatchError(
                        f"removal mismatch at line {src_idx + 1}: "
                        f"expected {line.value!r}, got "
                        f"{(lines[src_idx] if src_idx < len(lines) else '<EOF>')!r}"
                    )
                src_idx += 1
            elif line.is_added:
                value = line.value
                if not value.endswith("\n"):
                    value += "\n"
                result_lines.append(value)
            # else: \ No newline at end of file marker — skip.

    # Carry over any trailing content past the last hunk.
    result_lines.extend(lines[src_idx:])
    return PatchOutcome(
        new_text="".join(result_lines),
        hunks_applied=len(patched_file),
        hunks_rejected=0,
    )
