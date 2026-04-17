"""Sudo execution. See DESIGN.md section 4.4 and ADR notes in BACKLOG.

Two strategies in the design; Phase 4 ships only **per-call**. If a host is
configured with `sudo_mode = "persistent-su"`, the lifespan logs a WARNING and
this module falls back to per-call. Persistent su-shells are deferred because
they require brittle prompt-matching and cross-invocation state.

Password sourcing priority (fetch_sudo_password):
  1. `SSH_SUDO_PASSWORD_CMD` -- operator-configured shell command whose stdout is
     the password. Invoked per call; never cached on disk.
  2. OS keychain via `keyring`, service name `ssh-mcp-sudo`, user `default`.
  3. Passwordless sudoers entry (returns None; we pass `sudo -n`).

`SSH_SUDO_PASSWORD` env-var passwords are **rejected** at startup (INC-009):
environment is visible via `/proc/self/environ` and leaks into child processes
and crash dumps. The lifespan raises if the variable is set.

Passwords are never logged, never written to the pool state, and never included
in argv -- always on stdin, followed by the script body (if any) for
`ssh_sudo_run_script`.
"""
from __future__ import annotations

import logging
import os
import shlex
import subprocess
from typing import TYPE_CHECKING

from .errors import AuthenticationFailed
from .exec import run as exec_run

if TYPE_CHECKING:
    import asyncssh

    from ..config import Settings
    from ..models.results import ExecResult

logger = logging.getLogger(__name__)


# Seconds allowed for the operator's `SSH_SUDO_PASSWORD_CMD` subprocess
# (typically `pass show`, `secret-tool lookup`, `op item get`, ...) to
# return. Same rationale as `_SECRET_CMD_TIMEOUT_SECONDS` in ssh/connection.py:
# a short blocking call during exec, no operator knob needed.
_SECRET_CMD_TIMEOUT_SECONDS = 10


def fetch_sudo_password(settings: Settings) -> str | None:
    """Resolve the sudo password via the documented priority chain."""
    if settings.SSH_SUDO_PASSWORD_CMD:
        try:
            return _run_secret_cmd(settings.SSH_SUDO_PASSWORD_CMD)
        except AuthenticationFailed as exc:
            logger.warning("SSH_SUDO_PASSWORD_CMD failed: %s", exc)

    try:
        import keyring  # type: ignore[import-not-found]

        pw = keyring.get_password("ssh-mcp-sudo", "default")
        if pw:
            return pw
    except ImportError:
        logger.debug("keyring not installed; skipping OS keychain lookup")
    except Exception as exc:
        logger.debug("keyring lookup failed: %s", exc)

    # INC-009: SSH_SUDO_PASSWORD env var removed -- rejected at startup.
    # Use SSH_SUDO_PASSWORD_CMD or the OS keychain. Passwordless sudoers is
    # the recommended deployment (see README Sudo section).
    return None


def _run_secret_cmd(cmd: str) -> str:
    """Run the operator's secret command locally and return stdout."""
    result = subprocess.run(  # noqa: S602 -- cmd comes from operator config
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=_SECRET_CMD_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise AuthenticationFailed(
            f"sudo password command exited {result.returncode} "
            "(stderr hidden for safety)"
        )
    return result.stdout.rstrip("\n")


def build_sudo_wrapper(command: str, *, password: str | None) -> tuple[str, str | None]:
    """Build the shell string + stdin payload for a sudo-wrapped command.

    Returns ``(remote_args, stdin_prefix)``. `stdin_prefix` is the sudo
    password followed by a newline when -S is used, or None for `sudo -n`.
    Callers that also want to pipe additional stdin (e.g. a script body for
    sh -s) concatenate their stdin after the prefix.
    """
    quoted_cmd = shlex.quote(command)
    if password is None:
        # Passwordless sudoers entry or nothing available.
        return (f"sudo -n -- sh -c {quoted_cmd}", None)
    # -S reads the password from stdin. -p '' keeps the prompt out of stderr.
    return (f"sudo -S -p '' -- sh -c {quoted_cmd}", password + "\n")


def build_sudo_script_wrapper(password: str | None) -> tuple[str, str]:
    """Wrapper for `ssh_sudo_run_script`: `sudo ... sh -s --`.

    Script body is appended to the returned `stdin_prefix` by the caller.
    The returned prefix is the password line (empty when passwordless).
    """
    if password is None:
        return ("sudo -n -- sh -s --", "")
    return ("sudo -S -p '' -- sh -s --", password + "\n")


async def run_sudo(
    conn: asyncssh.SSHClientConnection,
    command: str,
    *,
    host: str,
    timeout: float,
    stdout_cap: int,
    stderr_cap: int,
    password: str | None,
) -> ExecResult:
    """Per-call sudo: wraps the command, pipes the password on stdin."""
    args, stdin = build_sudo_wrapper(command, password=password)
    return await exec_run(
        conn,
        args,
        host=host,
        timeout=timeout,
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
        stdin=stdin,
    )


async def run_sudo_script(
    conn: asyncssh.SSHClientConnection,
    script: str,
    *,
    host: str,
    timeout: float,
    stdout_cap: int,
    stderr_cap: int,
    password: str | None,
) -> ExecResult:
    """Per-call sudo script: sudo ... sh -s -- with password + script on stdin."""
    args, prefix = build_sudo_script_wrapper(password)
    return await exec_run(
        conn,
        args,
        host=host,
        timeout=timeout,
        stdout_cap=stdout_cap,
        stderr_cap=stderr_cap,
        stdin=prefix + script,
    )


def warn_if_persistent_mode(settings: Settings) -> None:
    """Phase 4 MVP: persistent-su is not implemented; warn once at startup."""
    if settings.SSH_SUDO_MODE == "persistent-su":
        logger.warning(
            "SSH_SUDO_MODE=persistent-su is not implemented in Phase 4; "
            "falling back to per-call."
        )


def reject_env_password() -> None:
    """INC-009: refuse to start if SSH_SUDO_PASSWORD is in the environment.

    Env-var passwords leak via /proc/self/environ, child processes, and crash
    dumps. Operators must use SSH_SUDO_PASSWORD_CMD or a keyring entry instead.
    """
    if os.environ.get("SSH_SUDO_PASSWORD"):
        raise AuthenticationFailed(
            "SSH_SUDO_PASSWORD is set in the environment -- rejected. "
            "Use SSH_SUDO_PASSWORD_CMD (e.g. 'pass show ops/sudo') or a "
            "keyring entry (service=ssh-mcp-sudo user=default)."
        )
