"""Read-only SFTP + find tools. Tagged {"safe", "read", "group:sftp-read"}."""

from __future__ import annotations

import base64
import re
import shlex
import stat as stat_module
from datetime import UTC, datetime
from typing import Literal

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
from ..services.path_policy import (
    canonicalize_and_check,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
)
from ..ssh.errors import SSHMCPError
from ._context import pool_from, resolve_host, settings_from

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

# Windows support deferred -- `_hash_windows` + `_WINDOWS_HASH_ALGO` were
# removed in the post-review pass after code review flagged POSIX `shlex.join`
# quoting as incompatible with Windows OpenSSH's cmd.exe / PowerShell parsing
# (the `'"'"'` single-quote escape sequence is POSIX-shell-only). A future
# implementation would need PowerShell's `-EncodedCommand <base64-UTF16LE>`
# form plus a Windows-aware argv serializer. Until then, `ssh_file_hash`
# gates via `require_posix`.

_FIND_NAME_RE = re.compile(r"^[A-Za-z0-9._*?\-\[\]]{1,128}$")


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
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
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=True,
        platform=policy.platform,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
    )

    async with conn.start_sftp_client() as sftp:
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
async def ssh_sftp_stat(host: str, path: str, ctx: Context) -> StatResult:
    """Remote file/dir metadata."""
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=True,
        platform=policy.platform,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
    )
    async with conn.start_sftp_client() as sftp:
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
async def ssh_sftp_download(host: str, path: str, ctx: Context) -> DownloadResult:
    """Download a remote file. Size-capped; content is base64-encoded."""
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=True,
        platform=policy.platform,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
    )
    cap = settings.SSH_UPLOAD_MAX_FILE_BYTES  # reuse the upload cap for downloads

    async with conn.start_sftp_client() as sftp:
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
            data = await f.read()
    return DownloadResult(
        host=policy.hostname,
        path=canonical,
        size=len(data),
        content_base64=base64.b64encode(data).decode("ascii"),
        truncated=False,
    )


@mcp_server.tool(tags={"safe", "read", "group:sftp-read"}, version="1.0")
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
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical_root = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=True,
        platform=policy.platform,
    )
    check_not_restricted(
        canonical_root,
        effective_restricted_paths(policy, settings),
        policy.platform,
    )

    cap = settings.SSH_FIND_MAX_RESULTS
    if policy.platform == "windows":
        matches, truncated = await _sftp_walk_find(
            conn,
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


# Validation uses the intersection of both platform dicts so a platform-only
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
        raise ValueError(f"algorithm must be one of {sorted(_POSIX_HASH_CMD)}, " f"got {algorithm!r}")

    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=True,
        platform=policy.platform,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
    )

    effective_timeout = float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT)
    if policy.platform == "windows":
        digest, size = await _hash_windows(conn, canonical, algorithm, effective_timeout)
    else:
        digest, size = await _hash_posix(conn, canonical, algorithm, effective_timeout)

    if not _VALID_HASH_DIGEST_RE.fullmatch(digest):
        raise HashError(f"remote hash command returned unparseable digest {digest!r} " f"for {canonical!r}")

    return HashResult(
        host=policy.hostname,
        path=canonical,
        algorithm=algorithm,
        digest=digest,
        size=size,
    )


async def _hash_posix(
    conn: asyncssh.SSHClientConnection,
    canonical: str,
    algorithm: str,
    timeout: float,
) -> tuple[str, int]:
    """Run `<algo>sum -- <path>` and parse `<hex>  <path>`."""
    cmd = _POSIX_HASH_CMD[algorithm]
    argv = [cmd, "--", canonical]
    result = await conn.run(shlex.join(argv), check=False, timeout=timeout)
    stdout = _as_str(result.stdout)
    stderr = _as_str(result.stderr)
    if result.exit_status != 0:
        raise HashError(
            f"{cmd} exited {result.exit_status} for {canonical!r}: " f"{stderr.strip() or '(no stderr)'}"
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
    size = await _stat_size(conn, canonical)
    return digest, size


async def _hash_windows(
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
    stdout = _as_str(result.stdout)
    stderr = _as_str(result.stderr)
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
    size = await _stat_size(conn, canonical)
    return digest, size


async def _stat_size(conn: asyncssh.SSHClientConnection, canonical: str) -> int:
    """Best-effort file size via SFTP stat. Returns -1 if unavailable.

    Catches ``asyncssh.Error`` (base class) rather than only ``SFTPError``
    so a transport-level failure during the stat round-trip also degrades
    to the -1 sentinel instead of escaping through the hash call.
    """
    try:
        async with conn.start_sftp_client() as sftp:
            attrs = await sftp.stat(canonical)
        return int(attrs.size or 0)
    except asyncssh.Error:
        return -1


def _as_str(data: object) -> str:
    if isinstance(data, bytes | bytearray):
        return data.decode(errors="replace")
    return data if isinstance(data, str) else ""


# ---- SFTP walk for `ssh_find` on Windows targets ----


async def _sftp_walk_find(
    conn: asyncssh.SSHClientConnection,
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
    async with conn.start_sftp_client() as sftp:
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
