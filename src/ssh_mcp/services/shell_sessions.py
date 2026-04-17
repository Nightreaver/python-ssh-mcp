"""Persistent shell sessions: in-memory state across MCP calls.

A "session" is a logical shell that tracks **cwd** across invocations. Each
`ssh_shell_exec` prefixes the command with `cd <session.cwd>` and appends a
sentinel that reports the new `$PWD` on a line by itself; the exec service
parses the sentinel out of stdout before returning and updates the session.

We intentionally do NOT manage a real remote PTY. Real PTYs would give us
shell history + interactive prompts, but they also require brittle prompt-
boundary regex parsing and PTY state that drifts under SSH reconnects. The
cwd-sentinel approach gives us 90% of the value with none of that risk.

MVP scope:
  - Tracks `cwd` only. Env-var persistence is deferred.
  - Sessions live in memory, scoped to the lifespan. Reaped on idle.
  - `ssh_shell_exec` runs each command through a fresh channel (no PTY).
    Concurrent calls for the same session_id would race on the cwd update
    after sentinel parsing, so each ``ShellSession`` owns an ``asyncio.Lock``
    that ``ssh_shell_exec`` acquires around the exec + cwd write (INC-023).
  - INC-047: cwd updates go through ``session.set_cwd(new_cwd)`` which
    asserts the exec lock is held. Direct attribute writes ``session.cwd =
    ...`` are still possible (Python has no private state) but any caller
    that forgot to acquire the lock trips an assertion at runtime instead
    of silently racing. Read-side access to ``session.cwd`` is unlocked --
    it's a single-reference read of a str.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)


# Sentinel the remote shell prints on a line by itself after the user command,
# followed by the final $PWD. Chosen to be unlikely to collide with real
# command output while still being a valid shell identifier.
SENTINEL = "__SSHMCP_STATE__"


@dataclass
class ShellSession:
    id: str
    host: str
    cwd: str = "~"
    last_used: float = field(default_factory=time.monotonic)
    created: float = field(default_factory=time.monotonic)
    # Acquired by ssh_shell_exec via ``exec_scope()`` around the remote exec
    # + cwd update so two concurrent calls with the same session_id don't
    # stomp on each other's cwd (INC-023). Cheap when uncontended. Kept as
    # ``lock`` (no leading underscore) for backward compat with the
    # INC-023 regression test that type-checks ``isinstance(s.lock, Lock)``.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False, compare=False)

    @asynccontextmanager
    async def exec_scope(self) -> AsyncIterator[ShellSession]:
        """Acquire the session's exec lock and yield ``self``.

        INC-047: every ``ssh_shell_exec`` call MUST wrap its remote exec +
        ``set_cwd`` update inside this scope. The context manager is the
        ONE approved way to hold the lock -- direct ``async with
        session.lock:`` still works, but ``exec_scope()`` is the intent-
        revealing name and gives us a single place to change the locking
        primitive later (e.g. swap to a read/write lock).
        """
        async with self.lock:
            yield self

    def set_cwd(self, new_cwd: str) -> None:
        """Update the session cwd. MUST be called inside ``exec_scope()``.

        INC-047: asserting ``self.lock.locked()`` at the write site catches
        the "caller forgot to hold the lock" regression class that INC-027
        worried about. The assertion is runtime, not static, but it fires
        on any parallel test or prod call where a developer bypasses the
        scope -- enough to convert the issue from "silent race" to "loud
        failure in the first test run".
        """
        if not self.lock.locked():
            raise RuntimeError(
                f"ShellSession.set_cwd called without holding exec_scope() "
                f"on session {self.id!r}; this would race with concurrent "
                f"ssh_shell_exec updates (INC-047)."
            )
        self.cwd = new_cwd


class SessionRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, ShellSession] = {}

    def open(self, host: str) -> ShellSession:
        session_id = uuid.uuid4().hex[:16]
        session = ShellSession(id=session_id, host=host)
        self._sessions[session_id] = session
        logger.info("shell session opened id=%s host=%s", session_id, host)
        return session

    def get(self, session_id: str) -> ShellSession | None:
        return self._sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        if session_id in self._sessions:
            self._sessions[session_id].last_used = time.monotonic()

    def close(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        logger.info("shell session closed id=%s host=%s", session_id, session.host)
        return True

    def list(self) -> list[dict[str, str | int | float]]:
        now = time.monotonic()
        return [
            {
                "id": s.id,
                "host": s.host,
                "cwd": s.cwd,
                "idle_seconds": int(now - s.last_used),
                "age_seconds": int(now - s.created),
            }
            for s in self._sessions.values()
        ]

    def size(self) -> int:
        return len(self._sessions)

    def reap_idle(self, max_idle_seconds: int) -> list[str]:
        """Close sessions idle past the limit; return the list of closed ids."""
        now = time.monotonic()
        closed: list[str] = []
        for sid, session in list(self._sessions.items()):
            if (now - session.last_used) > max_idle_seconds:
                self._sessions.pop(sid, None)
                closed.append(sid)
                logger.info("shell session reaped id=%s (idle)", sid)
        return closed


def wrap_command(session: ShellSession, command: str) -> str:
    """Wrap `command` so the session's cwd persists and the new cwd is reported.

    Shape: `cd <cwd> || cd ~; <command>; __rc=$?; printf '\\n%s%s\\n' SENTINEL $PWD; exit $__rc`
    The sentinel is printed ON A LINE BY ITSELF so `strip_sentinel` can split
    cleanly. `$?` preservation means the user's exit code surfaces through.
    """
    # Use shlex-quoted cwd so spaces etc in paths don't break the wrapper.
    import shlex as _shlex

    cwd_q = _shlex.quote(session.cwd)
    # Note: not shlex-quoting user `command` -- caller owns the semantics as
    # with ssh_exec_run. The shell interprets the whole string.
    return (
        f"cd {cwd_q} || cd ~; "
        f"{command}\n"
        f"__sshmcp_rc=$?; printf '\\n%s%s\\n' '{SENTINEL}' \"$PWD\"; exit $__sshmcp_rc"
    )


def strip_sentinel(stdout: str) -> tuple[str, str | None]:
    """Remove the sentinel line from stdout and extract the final cwd.

    Returns (clean_stdout, new_cwd). If the sentinel wasn't found (truncated
    output, command didn't reach the trailing printf, etc.), new_cwd is None
    and stdout is returned unchanged -- callers should leave cwd unchanged.
    """
    marker_idx = stdout.rfind("\n" + SENTINEL)
    if marker_idx == -1:
        return stdout, None
    before = stdout[:marker_idx]
    rest = stdout[marker_idx + 1 :]  # drop the preceding \n
    # rest starts with SENTINEL. Strip SENTINEL prefix and take until next \n.
    line = rest.split("\n", 1)[0]
    new_cwd = line[len(SENTINEL) :].rstrip("\r")
    return before, new_cwd or None
