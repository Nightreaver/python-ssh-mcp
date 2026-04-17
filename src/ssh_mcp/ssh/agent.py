"""SSH agent identity enumeration + fingerprint matching. See ADR-0004.

Works with Unix sockets (`SSH_AUTH_SOCK`), Windows OpenSSH named pipes
(`\\\\.\\pipe\\openssh-ssh-agent`), and PuTTY Pageant on Windows. asyncssh's
agent client returns `SSHAgentKeyPair` objects (not `SSHKey`), which lack a
`get_fingerprint` method — we compute the standard `SHA256:<b64>` digest from
the key's raw public bytes so the format matches `ssh-keygen -l -f key.pub`.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import sys
from typing import TYPE_CHECKING, Any

import asyncssh

from .errors import AgentFingerprintNotFound

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _fingerprint_of(key: Any) -> str:
    """Return `SHA256:<base64>` matching `ssh-keygen -l -E sha256`."""
    data: bytes = key.public_data
    digest = hashlib.sha256(data).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


async def list_agent_fingerprints(agent_path: Path | None = None) -> list[str]:
    """Return SHA256 fingerprints of every identity the agent exposes.

    Returns `[]` when no agent is reachable (no socket / no pipe / no Pageant).
    """
    sock = _resolve_socket(agent_path)
    if sock is None:
        return []
    try:
        async with asyncssh.SSHAgentClient(sock) as agent:
            keys = await agent.get_keys()
            return [_fingerprint_of(k) for k in keys]
    except (OSError, asyncssh.Error) as exc:
        logger.debug("agent enumeration failed at %r: %s", sock, exc)
        return []


async def select_agent_key(
    agent_path: Path | None,
    fingerprint: str,
) -> Any:
    """Return the asyncssh agent-key handle whose SHA256 fingerprint matches.

    Raises AgentFingerprintNotFound if the agent is unreachable or the
    fingerprint is not present.
    """
    sock = _resolve_socket(agent_path)
    if sock is None:
        raise AgentFingerprintNotFound(
            f"no SSH agent reachable (agent_path={agent_path}, SSH_AUTH_SOCK unset)"
        )
    async with asyncssh.SSHAgentClient(sock) as agent:
        keys = await agent.get_keys()
    for key in keys:
        if _fingerprint_of(key) == fingerprint:
            return key
    available = ", ".join(_fingerprint_of(k)[:30] + "..." for k in keys) or "none"
    raise AgentFingerprintNotFound(
        f"identity {fingerprint!r} not found in agent at {sock!r}; available: {available}"
    )


def _resolve_socket(agent_path: Path | None) -> str | None:
    """Return the asyncssh agent_path argument: expanded str, or empty string for
    the platform default (Unix socket on *nix, Pageant on Windows), or None if
    nothing is reachable."""
    if agent_path is not None:
        expanded = os.path.expandvars(str(agent_path))
        return os.path.expanduser(expanded)
    sock = os.environ.get("SSH_AUTH_SOCK")
    if sock:
        return sock
    if sys.platform == "win32":
        # asyncssh's Windows backend treats "" as "auto-detect Pageant / OpenSSH pipe".
        return ""
    return None
