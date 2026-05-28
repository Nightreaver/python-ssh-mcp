"""Read-only SFTP + find tools. Tagged {"safe", "read", "group:sftp-read"}."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import re
import secrets
import shlex
import stat as stat_module
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal

import asyncssh
from fastmcp import Context

from ..app import mcp_server
from ..models.results import (
    DownloadResult,
    FindResult,
    HashResult,
    SftpEntry,
    SftpListResult,
    StatResult,
)
from ..services.audit import audited
from ..services.local_path_policy import LOCAL_STREAM_CHUNK_BYTES, resolve_local_path
from ..services.output_sanitizer import scan as _scan_output
from ..services.path_policy import resolve_path
from ..services.text import as_str
from ..ssh.errors import SSHMCPError
from ._context import pool_from, resolve_host, settings_from

if TYPE_CHECKING:
    from pathlib import Path

    from ..config import Settings
    from ..models.policy import ResolvedHost
    from ..ssh.pool import ConnectionPool

# POSIX binary per algorithm. All coreutils-standard; output shape is
# identical (`<lowercase-hex>  <path>`), so one parser covers them all.
_POSIX_HASH_CMD = {
    "md5": "md5sum",
    "sha1": "sha1sum",
    "sha256": "sha256sum",
    "sha512": "sha512sum",
}

# Windows PowerShell `-Algorithm` values. `Get-FileHash` accepts these case-
# insensitively and returns the digest as UPPERCASE hex -- we lowercase it in
# the parser to match POSIX behavior.
_WINDOWS_HASH_ALGO = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "sha512": "SHA512",
}

_FIND_NAME_RE = re.compile(r"^[A-Za-z0-9._*?\-\[\]]{1,128}$")


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
@audited(tier="read")
async def ssh_sftp_list(
    host: str,
    path: str,
    ctx: Context,
    offset: int = 0,
    limit: int = 100,
) -> SftpListResult:
    """List a remote directory with offset/limit pagination."""
    if limit <= 0 or limit > 1000:
        raise ValueError("limit must be in 1..1000")
    if offset < 0:
        raise ValueError("offset must be >= 0")

    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    async with pool.sftp(resolved) as sftp:
        names = sorted(await sftp.listdir(canonical))
        if "." in names:
            names.remove(".")
        if ".." in names:
            names.remove("..")
        total = len(names)
        page = names[offset : offset + limit]
        entries: list[SftpEntry] = []
        for name in page:
            full = f"{canonical.rstrip('/')}/{name}" if canonical != "/" else f"/{name}"
            entries.append(await _stat_entry(sftp, full, name))

    return SftpListResult(
        host=policy.hostname,
        path=canonical,
        entries=entries,
        offset=offset,
        limit=limit,
        has_more=(offset + len(page)) < total,
    )


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
@audited(tier="read")
async def ssh_sftp_stat(host: str, path: str, ctx: Context) -> StatResult:
    """Remote file/dir metadata."""
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)
    async with pool.sftp(resolved) as sftp:
        attrs = await sftp.lstat(canonical)
        symlink_target: str | None = None
        if stat_module.S_ISLNK(attrs.permissions or 0):
            symlink_target = str(await sftp.readlink(canonical))

    return StatResult(
        path=canonical,
        kind=_kind_from_mode(attrs.permissions or 0),
        size=attrs.size or 0,
        mode=_mode_to_octal(attrs.permissions or 0),
        mtime=_format_mtime(attrs.mtime),
        owner=str(attrs.uid) if attrs.uid is not None else None,
        group=str(attrs.gid) if attrs.gid is not None else None,
        symlink_target=symlink_target,
    )


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
@audited(tier="read")
async def ssh_sftp_download(
    host: str,
    path: str,
    ctx: Context,
    local_path: str | None = None,
) -> DownloadResult:
    """Download a remote file.

    Two delivery modes:

    - default (no ``local_path``): the bytes round-trip through the MCP
      JSON channel as base64 in ``content_base64``. Subject to
      ``SSH_UPLOAD_MAX_FILE_BYTES`` (default 256 MiB); files larger than
      the cap come back with ``truncated=True`` and an empty payload --
      use ``local_path`` for those.
    - ``local_path=<absolute MCP-host path>`` (v1.3.0): the MCP server
      streams the remote file directly onto its OWN filesystem. The LLM
      never sees the payload. Requires the operator to allowlist the
      destination directory via ``SSH_LOCAL_TRANSFER_ROOTS``. Subject to
      the larger ``SSH_LOCAL_TRANSFER_MAX_BYTES`` cap (default 2 GiB).
      Response carries ``content_base64=""`` + ``truncated=False`` +
      ``local_path_written=<canonical destination>``. The write is
      atomic: bytes land in ``<local_path>.ssh-mcp-tmp.<rand>`` and are
      ``os.replace``'d into place once the stream finishes -- a crash
      mid-transfer leaves the tmp, never a partial final file.
    """
    settings = settings_from(ctx)
    # When `local_path` is set, validate the destination against the
    # MCP-host allowlist BEFORE acquiring the SSH connection -- a
    # policy-disabled call shouldn't pay for a remote handshake.
    canonical_local: Path | None = None
    if local_path is not None:
        canonical_local = resolve_local_path(local_path, settings, mode="write")

    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    if canonical_local is not None:
        return await _sftp_download_to_local(
            pool=pool,
            resolved=resolved,
            policy_hostname=policy.hostname,
            canonical=canonical,
            canonical_local=canonical_local,
            settings=settings,
        )

    cap = settings.SSH_UPLOAD_MAX_FILE_BYTES  # reuse the upload cap for downloads
    async with pool.sftp(resolved) as sftp:
        attrs = await sftp.stat(canonical)
        size = attrs.size or 0
        if size > cap:
            return DownloadResult(
                host=policy.hostname,
                path=canonical,
                size=size,
                content_base64="",
                truncated=True,
            )
        async with sftp.open(canonical, "rb") as f:
            data_raw = await f.read()
    # asyncssh's stub for `SFTPFile.read()` is `str | bytes` even in "rb"
    # mode; in practice it's always bytes here, but coerce defensively
    # so both the decode-for-warnings and the b64encode-for-payload work
    # under mypy strict without per-line ignores.
    data: bytes = (
        data_raw if isinstance(data_raw, bytes | bytearray) else data_raw.encode("utf-8", errors="replace")
    )
    # INC-058: scan a UTF-8 view for suspicious patterns (ANSI / NUL /
    # bidi / zero-width / C1 / LLM markers / fake conversation turns).
    # We do NOT modify the bytes -- callers may need the raw payload
    # for binary files. The warnings list tells the LLM what a text
    # decode would surface so it can `sanitize()` after decoding if it
    # plans to process as text.
    warnings = _scan_output(data.decode("utf-8", errors="replace"))
    return DownloadResult(
        host=policy.hostname,
        path=canonical,
        size=len(data),
        content_base64=base64.b64encode(data).decode("ascii"),
        truncated=False,
        output_warnings=warnings,
    )


async def _sftp_download_to_local(
    *,
    pool: ConnectionPool,
    resolved: ResolvedHost,
    policy_hostname: str,
    canonical: str,
    canonical_local: Path,
    settings: Settings,
) -> DownloadResult:
    """Stream `<canonical>` from the remote SFTP server straight onto the
    MCP host's filesystem at ``canonical_local``.

    ``canonical_local`` is the already-policy-checked destination (from
    :func:`resolve_local_path`); validation happens at the caller so the
    allowlist check fails fast without acquiring an SSH connection.

    Atomic via tmp+rename on the LOCAL side: bytes land in
    ``<canonical_local>.ssh-mcp-tmp.<rand>`` and are ``os.replace``'d
    into final position once the SFTP stream completes. ``os.replace``
    is atomic on POSIX (rename within a filesystem) and on Windows for
    same-volume moves; operators are expected to point their
    allowlisted roots at sane filesystems.

    Any exception mid-transfer triggers a best-effort unlink of the tmp
    file so partial downloads never pollute the destination directory.
    The size cap is enforced via ``sftp.stat`` BEFORE opening the local
    tmp -- a too-large remote raises ``SftpDownloadError`` without
    touching the local disk at all.
    """
    cap = settings.SSH_LOCAL_TRANSFER_MAX_BYTES

    async with pool.sftp(resolved) as sftp:
        attrs = await sftp.stat(canonical)
        size = int(attrs.size or 0)
        if size > cap:
            raise SftpDownloadError(
                f"remote file {canonical!r} is {size} bytes which exceeds "
                f"SSH_LOCAL_TRANSFER_MAX_BYTES={cap}"
            )

        tmp_path = canonical_local.with_name(f"{canonical_local.name}.ssh-mcp-tmp.{secrets.token_hex(8)}")
        bytes_written = 0
        # Open the local tmp file outside the SFTP stream so a failure
        # opening it (no perm, no space) surfaces BEFORE we start reading
        # from the remote. ``"xb"`` (exclusive) fails if a colliding tmp
        # already exists -- prevents a second concurrent download from
        # clobbering ours.
        try:
            local_fh = await asyncio.to_thread(open, tmp_path, "xb")
        except OSError as exc:
            raise SftpDownloadError(f"could not open local tmp {tmp_path!s}: {exc}") from exc
        local_fh_closed = False
        try:
            async with sftp.open(canonical, "rb") as remote_fh:
                while True:
                    chunk_raw = await remote_fh.read(LOCAL_STREAM_CHUNK_BYTES)
                    if not chunk_raw:
                        break
                    chunk: bytes = (
                        chunk_raw
                        if isinstance(chunk_raw, bytes | bytearray)
                        else chunk_raw.encode("utf-8", errors="replace")
                    )
                    await asyncio.to_thread(local_fh.write, chunk)
                    bytes_written += len(chunk)
            await asyncio.to_thread(local_fh.close)
            local_fh_closed = True
            await asyncio.to_thread(os.replace, tmp_path, canonical_local)
        except BaseException:
            # Cleanup tmp on ANY failure (including cancellation). Use a
            # best-effort unlink so a missing tmp (already cleaned up by
            # the OS or by a sibling thread) doesn't mask the original
            # error.
            if not local_fh_closed:
                with contextlib.suppress(OSError):
                    await asyncio.to_thread(local_fh.close)
            with contextlib.suppress(OSError):
                await asyncio.to_thread(os.unlink, tmp_path)
            raise

    return DownloadResult(
        host=policy_hostname,
        path=canonical,
        size=bytes_written,
        content_base64="",
        truncated=False,
        local_path_written=str(canonical_local),
    )


class SftpDownloadError(SSHMCPError):
    """``ssh_sftp_download`` failed before the bytes landed.

    Cap-violation or local-FS error during the ``local_path`` mode --
    raised in place of returning a half-populated DownloadResult so the
    audit log records ``result=error`` and no partial file lingers on
    disk.
    """


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
@audited(tier="read")
async def ssh_find(
    host: str,
    path: str,
    ctx: Context,
    name_pattern: str = "*",
    kind: str = "f",
    max_depth: int | None = None,
) -> FindResult:
    """Run `find` with fixed argv. Name pattern is passed as a single argv element.

    Start narrow -- searching from ``/`` is expensive and usually unnecessary.
    See the SKILL for the scope-narrowing ladder.
    """
    if not _FIND_NAME_RE.match(name_pattern):
        raise ValueError("name_pattern contains disallowed characters")
    if kind not in ("f", "d", "l"):
        raise ValueError("kind must be one of 'f', 'd', 'l'")

    settings = settings_from(ctx)
    depth = min(max_depth or settings.SSH_FIND_MAX_DEPTH, settings.SSH_FIND_MAX_DEPTH)

    pool = pool_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical_root = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    cap = settings.SSH_FIND_MAX_RESULTS
    if policy.platform == "windows":
        matches, truncated = await _sftp_walk_find(
            pool,
            resolved,
            canonical_root,
            depth,
            kind,
            name_pattern,
            cap,
        )
    else:
        argv = [
            "find",
            canonical_root,
            "-maxdepth",
            str(depth),
            "-type",
            kind,
            "-name",
            name_pattern,
        ]
        # asyncssh.conn.run() wants a string. shlex.join preserves argv boundaries.
        result = await conn.run(shlex.join(argv), check=False)
        stdout = result.stdout
        if isinstance(stdout, bytes | bytearray):
            stdout = stdout.decode(errors="replace")
        matches = [line for line in stdout.splitlines() if line]
        truncated = len(matches) > cap
        matches = matches[:cap]
    return FindResult(
        host=policy.hostname,
        root=canonical_root,
        matches=matches,
        truncated=truncated,
    )


# ---- ssh_file_hash ----


_VALID_HASH_DIGEST_RE = re.compile(r"^[0-9a-f]+$")


class HashError(SSHMCPError):
    """Remote hash command failed or returned unparseable output."""


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
@audited(tier="read")
async def ssh_file_hash(
    host: str,
    path: str,
    ctx: Context,
    algorithm: Literal["md5", "sha1", "sha256", "sha512"] = "sha256",
    timeout: int | None = None,
) -> HashResult:
    """Compute a cryptographic hash of a remote file.

    Use this to verify a file landed intact after `ssh_upload` / `ssh_deploy`
    / `ssh_docker_cp`, or to confirm a pinned binary hasn't drifted. Returns
    the digest as lowercase hex plus the file's byte size so the caller can
    sanity-check both.

    POSIX runs ``<algo>sum -- <canonical_path>`` (md5sum / sha1sum / sha256sum
    / sha512sum -- coreutils-standard, present on every mainstream distro).
    Fixed argv, no shell interpolation.

    Windows (INC-028) runs PowerShell's ``Get-FileHash`` via ``powershell.exe
    -NoProfile -NonInteractive -EncodedCommand <base64-UTF16LE>``. The whole
    script (including the ``-LiteralPath '<path>'`` clause) is base64-UTF16LE-
    encoded into a single opaque argv token so cmd.exe can't misparse it --
    sidesteps every shell-quoting corner the pure ``shlex.join`` approach
    couldn't reach (see INC-031 / INC-028 history).

    Path confined via `path_allowlist` + `restricted_paths` like every other
    sftp-read tool. ``md5`` and ``sha1`` are fine for the common case here
    (confirm a transfer landed intact, detect config drift). Use ``sha256``
    or ``sha512`` when the source of the expected hash is attacker-reachable
    -- both MD5 and SHA1 have practical collision attacks.

    ``timeout`` (seconds) defaults to ``SSH_COMMAND_TIMEOUT`` (60). Hashing
    streams the file in fixed-size chunks so memory is constant regardless
    of size, but wall time scales linearly: a 10+ GiB file will exceed the
    default and the call will come back with ``timed_out=True`` on the
    underlying transport. Bump ``timeout`` for known-large files.
    """
    if algorithm not in _POSIX_HASH_CMD:
        raise ValueError(f"algorithm must be one of {sorted(_POSIX_HASH_CMD)}, got {algorithm!r}")

    pool = pool_from(ctx)
    settings = settings_from(ctx)
    resolved = resolve_host(ctx, host)
    policy = resolved.policy
    conn = await pool.acquire(resolved)
    canonical = await resolve_path(conn, path, policy, settings, must_exist=True, pool=pool)

    effective_timeout = float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT)
    if policy.platform == "windows":
        digest, size = await _hash_windows(pool, resolved, conn, canonical, algorithm, effective_timeout)
    else:
        digest, size = await _hash_posix(pool, resolved, conn, canonical, algorithm, effective_timeout)

    if not _VALID_HASH_DIGEST_RE.fullmatch(digest):
        raise HashError(f"remote hash command returned unparseable digest {digest!r} for {canonical!r}")

    return HashResult(
        host=policy.hostname,
        path=canonical,
        algorithm=algorithm,
        digest=digest,
        size=size,
    )


async def _hash_posix(
    pool: ConnectionPool,
    resolved: ResolvedHost,
    conn: asyncssh.SSHClientConnection,
    canonical: str,
    algorithm: str,
    timeout: float,
) -> tuple[str, int]:
    """Run `<algo>sum -- <path>` and parse `<hex>  <path>`."""
    cmd = _POSIX_HASH_CMD[algorithm]
    argv = [cmd, "--", canonical]
    result = await conn.run(shlex.join(argv), check=False, timeout=timeout)
    stdout = as_str(result.stdout)
    stderr = as_str(result.stderr)
    if result.exit_status != 0:
        raise HashError(
            f"{cmd} exited {result.exit_status} for {canonical!r}: {stderr.strip() or '(no stderr)'}"
        )
    # Format: "<hex>  <path>\n". Split once on whitespace; the path may
    # contain spaces which is fine because we don't parse it back out.
    first_line = stdout.splitlines()[0] if stdout else ""
    parts = first_line.split(None, 1)
    if not parts:
        raise HashError(f"{cmd} produced no output for {canonical!r}")
    digest = parts[0].lower()

    # Separate SFTP stat to get the size. Cheap; keeps the result shape
    # consistent with `ssh_sftp_stat`.
    size = await _stat_size(pool, resolved, canonical)
    return digest, size


async def _hash_windows(
    pool: ConnectionPool,
    resolved: ResolvedHost,
    conn: asyncssh.SSHClientConnection,
    canonical: str,
    algorithm: str,
    timeout: float,
) -> tuple[str, int]:
    """Run PowerShell `Get-FileHash` and parse a bare hex digest from stdout.

    INC-028: the previous Windows attempt (INC-031) used POSIX `shlex.join`
    on a PowerShell command line. That fails because the POSIX single-quote
    escape (``'"'"'``) isn't parsed by cmd.exe OR PowerShell -- neither host
    understands it. ``-EncodedCommand`` dodges the whole question: we encode
    the script as base64-UTF16LE (a string of [A-Za-z0-9+/=] only) and pass
    it as a single argv token. No shell on the path gets to quote anything.

    Path escape inside the script is the PowerShell rule (single-quoted
    literal doubles ``'`` to ``''``); the ``-LiteralPath`` parameter then
    consumes the value verbatim -- no wildcard expansion, no path-normalization
    surprises.
    """
    algo = _WINDOWS_HASH_ALGO[algorithm]
    # PowerShell single-quoted string: ' -> '' (doubling). `-LiteralPath`
    # means the resulting value is taken exactly as-is (no wildcards).
    ps_escaped = canonical.replace("'", "''")
    # `$ProgressPreference='SilentlyContinue'` prevents Get-FileHash from
    # emitting Write-Progress records. Without this, OpenSSH-for-Windows
    # serializes progress as CLIXML (`#< CLIXML <Objs …>…`) into stderr, which
    # our error-path picks up as a bogus failure even when the digest is fine.
    # Explicit `exit 0` forces PowerShell to emit an exit-status channel
    # request; some OpenSSH-for-Windows versions close the channel without one
    # when the script ends in an expression, leaving `exit_status=None`.
    script = (
        "$ProgressPreference='SilentlyContinue';"
        f"(Get-FileHash -Algorithm {algo} -LiteralPath '{ps_escaped}').Hash;"
        "exit 0"
    )
    # PowerShell -EncodedCommand expects base64 of the UTF-16-LE bytes.
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    # Build the outer argv for cmd.exe. Every token is safe ASCII so no
    # quoting is needed; a plain space-join is what cmd.exe parses correctly.
    # `-NoProfile` stops PowerShell sourcing the user's $PROFILE (which could
    # print banners or redefine Get-FileHash). `-NonInteractive` refuses any
    # prompt that would otherwise hang the SSH channel.
    cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"
    result = await conn.run(cmd, check=False, timeout=timeout)
    stdout = as_str(result.stdout)
    stderr = as_str(result.stderr)
    # Get-FileHash returns UPPERCASE hex on its own line. Strip whitespace
    # (Windows CRLF) and lowercase to match the POSIX parser's contract.
    digest = stdout.strip().lower()
    # Fallback: Windows OpenSSH occasionally closes the channel without an
    # exit-status request even with explicit `exit 0` (observed on
    # OpenSSH_for_Windows_9.5). Accept the call as success when the digest
    # has the expected shape for the algorithm -- even if exit_status is None.
    expected_len = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[algorithm]
    digest_ok = len(digest) == expected_len and all(c in "0123456789abcdef" for c in digest)
    if not digest_ok or (result.exit_status not in (0, None)):
        raise HashError(
            f"powershell Get-FileHash exited {result.exit_status} for {canonical!r}: "
            f"{stderr.strip() or '(no stderr)'}"
        )
    size = await _stat_size(pool, resolved, canonical)
    return digest, size


async def _stat_size(pool: ConnectionPool, resolved: ResolvedHost, canonical: str) -> int:
    """Best-effort file size via SFTP stat. Returns -1 if unavailable.

    Catches ``asyncssh.Error`` (base class) rather than only ``SFTPError``
    so a transport-level failure during the stat round-trip also degrades
    to the -1 sentinel instead of escaping through the hash call.
    """
    try:
        async with pool.sftp(resolved) as sftp:
            attrs = await sftp.stat(canonical)
        return int(attrs.size or 0)
    except asyncssh.Error:
        return -1


# ---- SFTP walk for `ssh_find` on Windows targets ----


async def _sftp_walk_find(
    pool: ConnectionPool,
    resolved: ResolvedHost,
    root: str,
    max_depth: int,
    kind: str,
    name_pattern: str,
    cap: int,
) -> tuple[list[str], bool]:
    """Emulate `find -maxdepth N -type T -name PATTERN` via SFTP walk.

    Used on Windows targets where no `find` binary is available. Same limits
    as the POSIX path: depth capped, result list capped. `fnmatch` for the
    name glob so operators can use the same `*.log` / `foo?bar` patterns they
    use on POSIX.

    Slow vs. native `find` on big trees (one SFTP roundtrip per directory),
    but OK for reasonably-sized scopes.
    """
    import fnmatch

    want_kinds = {"f": "file", "d": "dir", "l": "symlink"}
    target_kind = want_kinds.get(kind, "file")

    matches: list[str] = []
    # BFS queue: (path, depth). Normalize to forward slashes for output so the
    # LLM sees consistent separators regardless of how the server reports them.
    queue: list[tuple[str, int]] = [(root, 0)]
    async with pool.sftp(resolved) as sftp:
        while queue and len(matches) <= cap:
            cur, depth = queue.pop(0)
            try:
                names = await sftp.listdir(cur)
            except asyncssh.SFTPError:
                continue
            for name in names:
                if name in (".", ".."):
                    continue
                sep = "/" if not cur.endswith(("/", "\\")) else ""
                full = f"{cur}{sep}{name}"
                try:
                    attrs = await sftp.lstat(full)
                except asyncssh.SFTPError:
                    continue
                perms = attrs.permissions or 0
                entry_kind = _kind_from_mode(perms)
                if entry_kind == target_kind and fnmatch.fnmatch(name, name_pattern):
                    matches.append(full)
                    if len(matches) > cap:
                        return matches[:cap], True
                if entry_kind == "dir" and depth + 1 < max_depth:
                    queue.append((full, depth + 1))
    return matches, False


# ---- helpers ----


async def _stat_entry(sftp: asyncssh.SFTPClient, full_path: str, name: str) -> SftpEntry:
    attrs = await sftp.lstat(full_path)
    perms = attrs.permissions or 0
    target: str | None = None
    if stat_module.S_ISLNK(perms):
        try:
            target = str(await sftp.readlink(full_path))
        except asyncssh.SFTPError:
            target = None
    return SftpEntry(
        name=name,
        kind=_kind_from_mode(perms),
        size=attrs.size or 0,
        mode=_mode_to_octal(perms),
        mtime=_format_mtime(attrs.mtime),
        symlink_target=target,
    )


def _kind_from_mode(mode: int) -> str:
    if stat_module.S_ISDIR(mode):
        return "dir"
    if stat_module.S_ISLNK(mode):
        return "symlink"
    if stat_module.S_ISREG(mode):
        return "file"
    return "other"


def _mode_to_octal(mode: int) -> str:
    return f"{mode & 0o7777:04o}"


def _format_mtime(mtime: int | float | None) -> str:
    if mtime is None:
        return ""
    return datetime.fromtimestamp(float(mtime), tz=UTC).isoformat()
