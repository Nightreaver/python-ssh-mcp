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
            f"host key for {host} does not match known_hosts (expected {expected}, got {actual})"
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


class PathNotAllowed(SSHMCPError):
    """Resolved path is outside the allowlist."""


class PathRestricted(SSHMCPError):
    """Resolved path is inside a restricted zone.

    Low-access + sftp-read tools refuse to touch restricted paths even when
    the path is inside the allowlist. Operator can still reach the path via
    ``ssh_exec_run`` / ``ssh_sudo_exec`` (subject to dangerous-tier gating).
    """


class RedactBypassBlocked(SSHMCPError):
    """A path-bearing tool tried to deliver raw content for a path that
    matches ``redact_paths_globs`` while ``redact_bypass_policy = "block"``.

    From the LLM's perspective this looks like a :class:`PathRestricted`
    refusal -- but the message explicitly points at ``ssh_read_redacted``
    as the right alternative. The redact-globs list marks paths whose
    contents the operator deems sensitive enough that ANY raw delivery
    (download, hash-over-bytes-the-LLM-sees, find-then-cat dance) needs
    to route through the redactor first.

    Attributes
    ----------
    path : str
        Canonical remote path that triggered the block.
    suggested_tool : str
        Tool the caller should use instead. Always ``"ssh_read_redacted"``
        today but kept structured so future alternatives (e.g. a streaming
        variant) can be surfaced without parsing the message.
    """

    def __init__(self, path: str, *, suggested_tool: str = "ssh_read_redacted") -> None:
        super().__init__(
            f"path {path!r} matches a redact-list glob; raw delivery is blocked "
            f"by redact_bypass_policy='block'. Use {suggested_tool}(host, path) "
            "to read a redacted view, or ask the operator to switch the host "
            "to redact_bypass_policy='warn' / 'audit_only' if raw access is "
            "really needed."
        )
        self.path = path
        self.suggested_tool = suggested_tool


class SudoFileOpError(SSHMCPError):
    """Sudo-tier file pipeline (``services.sudo_file_ops``) failed.

    Raised by :mod:`ssh_mcp.services.sudo_file_ops` helpers when the
    ``sudo cat`` / ``sudo stat`` / ``sudo sh -c '...mktemp...mv...'`` /
    ``sudo ls`` invocation returns a non-zero exit, when the SFTP-side
    cap (``SSH_UPLOAD_MAX_FILE_BYTES`` for reads,
    ``SSH_EDIT_MAX_FILE_BYTES`` for sudo edits) is exceeded, or when the
    parsed output (``ls -la`` row, ``stat`` owner string) is malformed.

    Distinct from :class:`PathRestricted` / :class:`PathNotAllowed`: those
    fire in :func:`ssh_mcp.services.path_policy.resolve_path` BEFORE the
    sudo pipeline runs. By the time a ``SudoFileOpError`` is raised the
    path passed the policy check and the failure is downstream -- sudo
    refused, the target wasn't readable even via sudo, the file was
    larger than the cap, or our parser couldn't read the response.
    """


class LocalPathPolicyError(SSHMCPError):
    """A `local_path=` argument failed the MCP-host filesystem allowlist check.

    Raised by :func:`ssh_mcp.services.local_path_policy.resolve_local_path`
    on any of:

    - ``SSH_LOCAL_TRANSFER_ROOTS`` is empty (mode disabled entirely)
    - the canonical path is not a child of any allowlisted root (escape
      attempt, typo, or root not yet configured)
    - read-mode and the target does not exist or is not a regular file
    - write-mode and the parent directory does not exist

    Parallel to :class:`PathNotAllowed` but for the MCP server's OWN
    filesystem rather than a remote host's. The message names the
    configuration knob (``SSH_LOCAL_TRANSFER_ROOTS`` /
    ``SSH_LOCAL_TRANSFER_MAX_BYTES``) when relevant so the operator can fix
    the env without grep'ing the codebase.
    """


class PlatformNotSupported(SSHMCPError):
    """Tool doesn't run on this host's platform (e.g. POSIX-only on Windows).

    Raised when a tool assumes POSIX semantics (shell, ``/proc``, ``realpath``,
    ``sudo``) and the host's policy sets ``platform = "windows"``. The error
    message names the specific capability missing so the LLM can pick an
    alternative (SFTP-based equivalent, or decide the operation isn't feasible).
    """


class SFTPSubsystemUnavailable(SSHMCPError):
    """SSH server refused the sftp subsystem channel request.

    Raised by :meth:`ssh_mcp.ssh.pool.ConnectionPool._acquire_sftp` when
    ``asyncssh.start_sftp_client()`` fails with
    ``ChannelOpenError(OPEN_REQUEST_SESSION_FAILED, "Session request failed")``
    -- the SSH server accepted the connection but refused to spin up the
    ``sftp`` subsystem on this channel. Without the translation, the raw
    ``"Session request failed"`` text bubbled up through every SFTP-backed
    tool (``ssh_upload``, ``ssh_edit``, ``ssh_mkdir``, ``ssh_sftp_*``,
    ``ssh_find``, ...) and the LLM had no way to map it to a server-side
    config issue.

    Channel-based tools (``ssh_exec_run``, ``ssh_sudo_exec``,
    ``ssh_host_ping``) continue to work on the same connection -- only
    the sftp subsystem is unavailable. Typical causes:

    - ``Subsystem sftp <path>`` missing or commented out in sshd_config
    - A ``Match User`` block that disallows subsystem requests
    - Hardened appliances (DSM, OPNsense, some embedded SSH servers) that
      strip the sftp subsystem to reduce attack surface
    """

    def __init__(self, *, user: str, host: str, port: int) -> None:
        super().__init__(
            f"SFTP subsystem unavailable on {user}@{host}:{port} -- the SSH "
            f"server refused the subsystem=sftp channel request. Likely "
            f"sshd_config missing 'Subsystem sftp ...' or a Match block "
            f"disallowing subsystems. Channel-based tools (ssh_exec_run, "
            f"ssh_sudo_exec, ssh_host_ping) still work; for file ops fix "
            f"the server config or fall back to exec."
        )
        self.user = user
        self.host = host
        self.port = port


class CommandIsCheatsheetMatch(SSHMCPError):
    """Raised by ``ssh_exec_run`` / ``_streaming`` / ``ssh_sudo_exec`` when
    the supplied command matches a cheatsheet pattern and the
    ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS`` opt-out is not enabled.

    The exec tier is last-resort: every cheatsheet pattern has a dedicated MCP
    wrapper that is safer (policy-gated, audited), cheaper (no
    command_allowlist round-trip), and structured (typed result instead of
    raw stdout). The matcher names the suggested wrapper in
    :attr:`suggested_tool` so the LLM can redirect cleanly.

    Attributes mirror the :class:`CheatsheetMatch` payload so the caller can
    re-render the rejection (audit, output_warnings in B2) without re-parsing
    the message.
    """

    def __init__(
        self,
        *,
        pattern_id: str,
        command: str,
        suggested_tool: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.pattern_id = pattern_id
        self.command = command
        self.suggested_tool = suggested_tool
