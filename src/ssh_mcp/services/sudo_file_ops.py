"""Sudo-elevated file pipeline helpers (v1.5.0).

The sudo-tier path-bearing tools (``ssh_sudo_read``, ``ssh_sudo_write``,
``ssh_sudo_edit``, ``ssh_sudo_sftp_list``, ``ssh_sudo_read_redacted``)
all need the same low-level building blocks: read bytes via ``sudo cat``,
stat ownership via ``sudo stat``, write atomically via ``sudo sh -c
'... mktemp ... mv ...'``, list a directory via ``sudo ls -la``. Each
helper is a thin wrapper around the existing sudo-password plumbing in
:mod:`ssh_mcp.ssh.sudo` so we never re-implement the password resolution
chain (keyring -> SSH_SUDO_PASSWORD_CMD -> default fallback) here.

Why these live in ``services/`` rather than ``ssh/``: they reach into
the path-policy + redaction layer (see the tool surface), and that layer
already imports from ``services/``. Keeping the helpers here mirrors the
``edit_service`` placement and avoids a back-edge to ``ssh/`` from the
tool layer.

The helpers raise :class:`ssh_mcp.ssh.errors.SudoFileOpError` on any
non-policy failure: cap exceeded, sudo refused, cat/ls/stat failed,
parse failure. Path-policy failures (``PathNotAllowed`` /
``PathRestricted`` / ``RedactBypassBlocked``) are raised UPSTREAM in
:func:`ssh_mcp.services.path_policy.resolve_path` before the sudo
pipeline ever runs.
"""

from __future__ import annotations

import logging
import re
import shlex
from typing import TYPE_CHECKING

from ..ssh.errors import SudoFileOpError
from ..ssh.sudo import fetch_sudo_password

if TYPE_CHECKING:
    import asyncssh

    from ..config import Settings
    from ..models.results import SftpEntry

logger = logging.getLogger(__name__)


# Default seconds for any one sudo file-op probe. Same default as the
# exec tier's ``SSH_COMMAND_TIMEOUT`` (60 s). The caller can shadow via
# the tool's ``timeout=`` parameter if a host is known-slow.
_DEFAULT_OP_TIMEOUT = 60.0


async def _run_sudo_bytes(
    conn: asyncssh.SSHClientConnection,
    inner_command: str,
    *,
    alias: str,
    settings: Settings,
    stdin_extra: bytes | None = None,
    timeout: float | None = None,
) -> tuple[int, bytes, bytes]:
    """Run ``inner_command`` under sudo and return ``(exit, stdout, stderr)``.

    Unlike :func:`ssh_mcp.ssh.exec.run`, this helper does NOT truncate,
    sanitize, or decode -- the bytes round-trip raw so callers that need
    binary fidelity (file content via ``sudo cat``) get it. The trade-off
    is the loss of the ExecResult plumbing (output_warnings,
    stdout_truncated, audit-friendly hint); the tool layer doesn't need
    those because the sudo pipeline is downstream of policy checks and
    the tool builds its own result model.

    ``stdin_extra`` (when set) is appended AFTER the sudo password line,
    so ``sudo -S`` consumes the password first and the inner shell then
    reads the appended bytes from stdin. Used by :func:`sudo_atomic_write`
    to feed the file body.
    """
    password = fetch_sudo_password(settings, alias)
    quoted = shlex.quote(inner_command)
    if password is None:
        argv = f"sudo -n -- sh -c {quoted}"
        stdin_payload: bytes = stdin_extra or b""
    else:
        argv = f"sudo -S -p '' -- sh -c {quoted}"
        prefix = (password + "\n").encode("utf-8")
        stdin_payload = prefix + (stdin_extra or b"")

    # ``encoding=None`` tells asyncssh to keep stdout / stderr as raw bytes
    # rather than decoding them. Required for binary-safe reads (``sudo cat``
    # on a non-UTF-8 file would otherwise come back decoded with ``replace``
    # placeholders that corrupt the round-trip).
    proc = await conn.run(
        argv,
        check=False,
        input=stdin_payload,
        encoding=None,
        timeout=timeout if timeout is not None else _DEFAULT_OP_TIMEOUT,
    )
    stdout = proc.stdout
    stderr = proc.stderr
    if isinstance(stdout, str):  # defensive: asyncssh sometimes ignores encoding=None
        stdout = stdout.encode("utf-8", errors="replace")
    if isinstance(stderr, str):
        stderr = stderr.encode("utf-8", errors="replace")
    if stdout is None:
        stdout = b""
    if stderr is None:
        stderr = b""
    exit_code = int(proc.exit_status if proc.exit_status is not None else -1)
    return exit_code, stdout, stderr


async def sudo_read_bytes(
    conn: asyncssh.SSHClientConnection,
    canonical_path: str,
    *,
    alias: str,
    settings: Settings,
    cap: int | None = None,
    timeout: float | None = None,
) -> bytes:
    """Read ``canonical_path`` via ``sudo cat --`` and return the raw bytes.

    Size cap defaults to ``SSH_UPLOAD_MAX_FILE_BYTES`` -- same as the
    non-sudo SFTP read path. Oversized files raise :class:`SudoFileOpError`
    so the caller never sees a half-truncated buffer claiming to be the
    file. The cap check happens AFTER the read (sudo cat streams the
    whole file before we can measure), so this helper is not safe to
    point at multi-GiB targets even when the operator's hostneeds the
    bigger cap -- bump the cap via ``SSH_UPLOAD_MAX_FILE_BYTES`` if
    that's intentional.
    """
    effective_cap = cap if cap is not None else settings.SSH_UPLOAD_MAX_FILE_BYTES
    inner = f"cat -- {shlex.quote(canonical_path)}"
    exit_code, stdout, stderr = await _run_sudo_bytes(
        conn, inner, alias=alias, settings=settings, timeout=timeout
    )
    if exit_code != 0:
        raise SudoFileOpError(
            f"sudo cat -- {canonical_path!r} exited {exit_code}: "
            f"{stderr.decode('utf-8', errors='replace').strip() or '(no stderr)'}"
        )
    if len(stdout) > effective_cap:
        raise SudoFileOpError(
            f"sudo read of {canonical_path!r} returned {len(stdout)} bytes which "
            f"exceeds cap {effective_cap}; raise SSH_UPLOAD_MAX_FILE_BYTES or "
            f"use ssh_sftp_download with local_path= for large files (where the "
            f"ssh user has read access)."
        )
    return stdout


async def sudo_stat_owner(
    conn: asyncssh.SSHClientConnection,
    canonical_path: str,
    *,
    alias: str,
    settings: Settings,
    timeout: float | None = None,
) -> tuple[str, str] | None:
    """Return ``(user, group)`` for ``canonical_path``, or ``None`` if missing.

    Implementation: ``sudo stat -c '%U:%G' -- <path>``. ``stat`` exits 1
    when the file does not exist; any other non-zero exit is treated as
    a sudo / stat failure and raises :class:`SudoFileOpError`. Used by
    :func:`sudo_atomic_write` to decide whether to preserve existing
    ownership or fall back to ``root:root`` + warning.
    """
    inner = f"stat -c '%U:%G' -- {shlex.quote(canonical_path)}"
    exit_code, stdout, stderr = await _run_sudo_bytes(
        conn, inner, alias=alias, settings=settings, timeout=timeout
    )
    if exit_code == 1:
        # GNU stat returns 1 for "cannot stat: No such file or directory".
        # Distinguish from "stat itself failed" (exit > 1) by sniffing the
        # stderr -- ENOENT shows up as "No such file" / "no such" etc.
        err_text = stderr.decode("utf-8", errors="replace").lower()
        if "no such" in err_text or "cannot stat" in err_text:
            return None
        # Some busybox/embedded stat builds use exit 1 for other failures;
        # surface those as SudoFileOpError so the caller doesn't silently
        # assume "file missing" when it's actually a sudo / perm problem.
        raise SudoFileOpError(
            f"sudo stat -- {canonical_path!r} exited 1 but stderr did not look "
            f"like ENOENT: {stderr.decode('utf-8', errors='replace').strip()!r}"
        )
    if exit_code != 0:
        raise SudoFileOpError(
            f"sudo stat -- {canonical_path!r} exited {exit_code}: "
            f"{stderr.decode('utf-8', errors='replace').strip() or '(no stderr)'}"
        )
    line = stdout.decode("utf-8", errors="replace").strip()
    if ":" not in line:
        raise SudoFileOpError(f"sudo stat returned unparseable owner line {line!r} for {canonical_path!r}")
    user, _, group = line.partition(":")
    if not user or not group:
        raise SudoFileOpError(f"sudo stat returned empty user/group: {line!r} for {canonical_path!r}")
    return user, group


async def sudo_stat_mode(
    conn: asyncssh.SSHClientConnection,
    canonical_path: str,
    *,
    alias: str,
    settings: Settings,
    timeout: float | None = None,
) -> int | None:
    """Return the file's octal permission bits, or ``None`` if missing.

    Implementation: ``sudo stat -c '%a' -- <path>``. Same ENOENT vs
    error disambiguation as :func:`sudo_stat_owner`. Used by
    :func:`ssh_sudo_edit` to preserve mode across the read+write cycle
    so a secret file at ``0o600`` doesn't get widened to the write
    helper's ``0o644`` default.
    """
    inner = f"stat -c '%a' -- {shlex.quote(canonical_path)}"
    exit_code, stdout, stderr = await _run_sudo_bytes(
        conn, inner, alias=alias, settings=settings, timeout=timeout
    )
    if exit_code == 1:
        err_text = stderr.decode("utf-8", errors="replace").lower()
        if "no such" in err_text or "cannot stat" in err_text:
            return None
        raise SudoFileOpError(
            f"sudo stat -- {canonical_path!r} exited 1 but stderr did not look "
            f"like ENOENT: {stderr.decode('utf-8', errors='replace').strip()!r}"
        )
    if exit_code != 0:
        raise SudoFileOpError(
            f"sudo stat -- {canonical_path!r} exited {exit_code}: "
            f"{stderr.decode('utf-8', errors='replace').strip() or '(no stderr)'}"
        )
    raw = stdout.decode("utf-8", errors="replace").strip()
    try:
        return int(raw, 8)
    except ValueError as exc:
        raise SudoFileOpError(f"sudo stat returned unparseable mode {raw!r} for {canonical_path!r}") from exc


async def sudo_atomic_write(
    conn: asyncssh.SSHClientConnection,
    canonical_path: str,
    data: bytes,
    *,
    alias: str,
    settings: Settings,
    mode: int = 0o644,
    chown_user: str,
    chown_group: str,
    timeout: float | None = None,
) -> None:
    """Atomic sudo write: tmp-in-parent + chmod + chown + mv.

    Implementation: ``sudo sh -c '
        umask 077
        t=$(mktemp -p "$(dirname "$1")" .ssh-mcp-tmp.XXXXXXXX)
        cat > "$t"
        chmod "$2" "$t"
        chown "$3" "$t"
        mv -- "$t" "$1"
    ' _ <canonical_path> <octal_mode> <user>:<group>``

    Content streams via stdin AFTER the sudo password line. Tmp lives in
    the SAME directory as the destination so the final ``mv`` is a
    rename (atomic on the same filesystem) rather than a cross-FS copy.

    On any failure mid-pipeline the tmp file lingers next to the
    destination -- documented behavior, simpler than a trap-cleanup
    that would complicate the parser. Operators can sweep
    ``.ssh-mcp-tmp.*`` siblings periodically if a target host pattern
    surfaces orphans.
    """
    octal_mode = f"{mode & 0o7777:o}"
    chown_arg = f"{chown_user}:{chown_group}"
    # Inline the three operator-supplied values as shell variables at the
    # top of the script body, each wrapped via ``shlex.quote`` so paths
    # with spaces / metachars round-trip unharmed. We deliberately do
    # NOT use positional args via ``sh -c '<script>' _ <a> <b> <c>``:
    # ``_run_sudo_bytes`` wraps the inner with ``shlex.quote`` and runs
    # ``sudo ... sh -c <quoted_inner>`` -- everything passed in
    # ``inner_command`` becomes the BODY of that outer ``sh -c``, so
    # trailing positional-arg tokens (``_ <dest> ...``) end up parsed as
    # statements after the script, not as positional args. That's the bug
    # that surfaced on live runs as ``sh: 1: Syntax error: word unexpected``
    # at stage cat>tmp. Shell-variable assignment inside the script body
    # is the clean fix without touching the helper's signature.
    inner = (
        f"dest={shlex.quote(canonical_path)}; "
        f"mode={shlex.quote(octal_mode)}; "
        f"owner={shlex.quote(chown_arg)}; "
        "umask 077; "
        't=$(mktemp -p "$(dirname "$dest")" .ssh-mcp-tmp.XXXXXXXX) || exit 1; '
        'cat > "$t" || { rm -f "$t"; exit 2; }; '
        'chmod "$mode" "$t" || { rm -f "$t"; exit 3; }; '
        'chown "$owner" "$t" || { rm -f "$t"; exit 4; }; '
        'mv -- "$t" "$dest" || { rm -f "$t"; exit 5; }'
    )
    exit_code, _stdout, stderr = await _run_sudo_bytes(
        conn,
        inner,
        alias=alias,
        settings=settings,
        stdin_extra=data,
        timeout=timeout,
    )
    if exit_code != 0:
        stage = {
            1: "mktemp",
            2: "cat>tmp",
            3: "chmod",
            4: "chown",
            5: "mv",
        }.get(exit_code, f"unknown(exit={exit_code})")
        raise SudoFileOpError(
            f"sudo atomic write to {canonical_path!r} failed at stage {stage}: "
            f"{stderr.decode('utf-8', errors='replace').strip() or '(no stderr)'}"
        )


# ``ls -la --time-style=full-iso`` row shape, e.g.
#   -rw-r--r-- 1 root root 1234 2026-05-30 12:34:56.000000000 +0000 file.txt
# We parse defensively: permission column, link count, user, group, size,
# date, time (+ optional fractional + offset), then everything else is
# the name (possibly with a `-> target` for symlinks).
_LS_ROW_RE = re.compile(
    r"^(?P<perm>[\-dlcbpsDLCBPS][rwxstST\-]{9}[+.@]?)\s+"
    r"(?P<nlink>\d+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<group>\S+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[+\-]\d{4})?)\s+"
    r"(?P<rest>.+)$"
)


def _ls_kind_from_perm(perm: str) -> str:
    """Map the first column of an ``ls -la`` row to our ``kind`` enum."""
    if not perm:
        return "other"
    first = perm[0]
    if first == "d":
        return "dir"
    if first == "l":
        return "symlink"
    if first == "-":
        return "file"
    return "other"


def _ls_mode_octal(perm: str) -> str:
    """Convert ``rwxr-xr-x`` style perm string to four-digit octal.

    Approximation: setuid / setgid / sticky bits surface in the perm
    string as ``s`` / ``S`` / ``t`` / ``T`` and bump the high bit; we
    keep the parser simple and only translate the standard ``rwx`` bits.
    Operators who need precise mode bits should fall back to ``sudo stat``.
    """
    if len(perm) < 10:
        return "0000"
    bits = 0
    for i, ch in enumerate(perm[1:10]):
        if ch in ("r", "w", "x", "s", "t"):
            bits |= 1 << (8 - i)
    return f"{bits:04o}"


async def sudo_ls_parsed(
    conn: asyncssh.SSHClientConnection,
    canonical_path: str,
    *,
    alias: str,
    settings: Settings,
    timeout: float | None = None,
) -> list[SftpEntry]:
    """Run ``sudo ls -la --time-style=full-iso --`` and parse the rows.

    Returns a list of :class:`SftpEntry`. The total / ``.`` / ``..``
    rows that GNU ls emits at the top are skipped. Symlink targets
    (``name -> target``) are split out into ``symlink_target``.

    Empty directories: GNU ls emits a single ``total 0`` line and
    nothing else; we return ``[]``. BusyBox ls without
    ``--time-style=full-iso`` will not match :data:`_LS_ROW_RE` and the
    rows will be skipped silently -- documented limitation. Operators
    targeting BusyBox hosts should rely on the non-sudo
    :func:`ssh_sftp_list` (it talks SFTP, not shell).
    """
    # Local import: avoid the cycle between models.results and this module.
    from ..models.results import SftpEntry

    inner = "ls -la --time-style=full-iso -- " f"{shlex.quote(canonical_path)}"
    exit_code, stdout, stderr = await _run_sudo_bytes(
        conn, inner, alias=alias, settings=settings, timeout=timeout
    )
    if exit_code != 0:
        raise SudoFileOpError(
            f"sudo ls -la -- {canonical_path!r} exited {exit_code}: "
            f"{stderr.decode('utf-8', errors='replace').strip() or '(no stderr)'}"
        )
    text = stdout.decode("utf-8", errors="replace")
    entries: list[SftpEntry] = []
    for line in text.splitlines():
        if not line or line.startswith("total "):
            continue
        m = _LS_ROW_RE.match(line)
        if m is None:
            # Defensive: unrecognized row shape (busybox, exotic locale).
            # Skip silently; documented limit. Logging at DEBUG so operators
            # debugging "missing entries" can grep for it.
            logger.debug("sudo_ls_parsed: skipping unparseable row %r", line)
            continue
        rest = m.group("rest")
        symlink_target: str | None = None
        if " -> " in rest:
            name, _, symlink_target = rest.partition(" -> ")
        else:
            name = rest
        if name in (".", ".."):
            continue
        perm = m.group("perm")
        entries.append(
            SftpEntry(
                name=name,
                kind=_ls_kind_from_perm(perm),
                size=int(m.group("size")),
                mode=_ls_mode_octal(perm),
                mtime=f"{m.group('date')}T{m.group('time')}",
                symlink_target=symlink_target,
            )
        )
    return entries
