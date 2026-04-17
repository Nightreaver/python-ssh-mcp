"""Shared exceptions for the SSH transport layer.

These map to MCP error responses (see DESIGN.md §2.4 / §6). Errors that are
security-relevant (HostKeyMismatch, UnknownHost, HostNotAllowed, PathNotAllowed)
are logged at WARNING; transport failures at INFO.
"""
from __future__ import annotations


class SSHMCPError(Exception):
    """Base class for all SSH MCP transport errors."""


class HostNotAllowed(SSHMCPError):
    """Host is not in the allowlist (and not defined in hosts.toml)."""


class HostBlocked(SSHMCPError):
    """Host is on the blocklist — deny wins over allow."""


class UnknownHost(SSHMCPError):
    """Host key not present in known_hosts; operator must verify out-of-band."""


class HostKeyMismatch(SSHMCPError):
    """Host key does not match known_hosts — potential MITM."""

    def __init__(self, host: str, expected: str, actual: str) -> None:
        super().__init__(
            f"host key for {host} does not match known_hosts "
            f"(expected {expected}, got {actual})"
        )
        self.host = host
        self.expected_fingerprint = expected
        self.actual_fingerprint = actual


class AuthenticationFailed(SSHMCPError):
    """SSH auth failed (no method succeeded)."""


class AgentFingerprintNotFound(SSHMCPError):
    """Requested identity_fingerprint not present in the live ssh-agent."""


class ConnectError(SSHMCPError):
    """TCP/SSH handshake failed (timeout, refused, etc.)."""


class CommandTimeout(SSHMCPError):
    """Remote command exceeded its timeout."""


class PathNotAllowed(SSHMCPError):
    """Resolved path is outside the allowlist."""


class PathRestricted(SSHMCPError):
    """Resolved path is inside a restricted zone.

    Low-access + sftp-read tools refuse to touch restricted paths even when
    the path is inside the allowlist. Operator can still reach the path via
    ``ssh_exec_run`` / ``ssh_sudo_exec`` (subject to dangerous-tier gating).
    """


class PlatformNotSupported(SSHMCPError):
    """Tool doesn't run on this host's platform (e.g. POSIX-only on Windows).

    Raised when a tool assumes POSIX semantics (shell, ``/proc``, ``realpath``,
    ``sudo``) and the host's policy sets ``platform = "windows"``. The error
    message names the specific capability missing so the LLM can pick an
    alternative (SFTP-based equivalent, or decide the operation isn't feasible).
    """
