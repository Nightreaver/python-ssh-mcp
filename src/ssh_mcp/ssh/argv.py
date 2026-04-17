"""Safe argv construction. Phase 0: no-op helpers; extended in later phases."""
from __future__ import annotations

import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


def build_argv(*parts: str) -> list[str]:
    """Return argv as a list. Never shell-interpolate untrusted values upstream of this."""
    return [str(p) for p in parts]


def join_for_shell(argv: Iterable[str]) -> str:
    """Quote argv for transports that require a single command string."""
    return shlex.join(argv)
