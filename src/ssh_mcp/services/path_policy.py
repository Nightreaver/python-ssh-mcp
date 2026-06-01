"""Remote path canonicalization + allowlist enforcement.

All low-access tools route paths through `canonicalize_and_check`. We never
trust a caller-supplied path directly — always canonicalize on the remote
(`realpath -m`) and verify the result is inside an allowlisted root.

Windows targets take a different branch: no `realpath` binary, backslash
separators, case-insensitive comparisons. `canonicalize` routes to SFTP
realpath (protocol-level, platform-agnostic) with a python-side `ntpath`
fallback for paths that don't yet exist; allowlist prefix matching uses
case-folded forward-slash form on Windows so `C:\\opt\\app` matches either
``C:\\OPT\\APP\\file`` or ``C:/opt/app/file`` equivalently.

POSIX chrooted-SFTP fallback (INC-063):

Some sshd configs run the SFTP subsystem in a chroot while the SSH session
channel (used by ``conn.run``) sees the real filesystem (DSM 7.x internal-
sftp is the canonical case). On such hosts the LLM gets paths from SFTP
discovery (``ssh_sftp_list("/")`` returns chroot-view paths like
``/docker/...``) but ``_canonicalize_posix`` running shell ``realpath`` on
the SSH channel sees a different view (``/volume1/docker/...``) and ENOENTs
on every path the LLM produces.

To unblock SFTP-backed tools on these hosts, ``_canonicalize_posix`` falls
back to ``sftp.realpath`` (SSH_FXP_REALPATH) when shell realpath fails.
The SFTP realpath runs inside the SFTP subsystem's view, so its answer
matches what subsequent SFTP I/O (``sftp.open`` / ``sftp.stat`` / etc.)
will see. A WARNING line on this logger signals the operator that the
fallback fired -- typical fix is to disable the chroot server-side, or
treat shell-backed tools (``ssh_cp``, ``ssh_delete_folder``'s rm fallback,
``ssh_mv`` cross-fs fallback) as expected to fail on chroot-view paths.
"""

from __future__ import annotations

import contextlib
import logging
import ntpath
import posixpath
import shlex
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Literal

import asyncssh

from ..ssh.errors import PathNotAllowed, PathRestricted, RedactBypassBlocked
from ..telemetry import span

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from ..config import Settings
    from ..models.policy import HostPolicy
    from ..ssh.pool import ConnectionPool

Platform = Literal["posix", "windows"]


def _normalize_for_compare(path: str, platform: Platform) -> str:
    """Return the form used for prefix matching.

    POSIX: as-is (posix paths are case-sensitive, `/` separator).
    Windows: backslashes -> forward slashes, lowercased (case-insensitive).
    """
    if platform == "windows":
        return path.replace("\\", "/").casefold()
    return path


def _normpath_for_platform(path: str, platform: Platform) -> str:
    if platform == "windows":
        # ntpath.normpath folds `a/b\..\c` -> `a\c` and cleans up slashes.
        # Drive letter + separator preserved.
        return ntpath.normpath(path)
    return posixpath.normpath(path)


def effective_allowlist(policy: HostPolicy, settings: Settings) -> list[str]:
    """Per-host allowlist unioned with the env-level allowlist, order preserved."""
    merged: list[str] = []
    seen: set[str] = set()
    for root in (*policy.path_allowlist, *settings.SSH_PATH_ALLOWLIST):
        normalized = _normpath_for_platform(root, policy.platform)
        if normalized not in seen:
            seen.add(normalized)
            merged.append(normalized)
    return merged


def effective_restricted_paths(policy: HostPolicy, settings: Settings) -> list[str]:
    """Per-host restricted zones unioned with env-level ``SSH_RESTRICTED_PATHS``.

    Empty result is the common case -- most hosts have no restricted zones.
    Callers that get `[]` skip the check entirely.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for root in (*policy.restricted_paths, *settings.SSH_RESTRICTED_PATHS):
        normalized = _normpath_for_platform(root, policy.platform)
        if normalized not in seen:
            seen.add(normalized)
            merged.append(normalized)
    return merged


def _prefix_match(canonical: str, root: str, platform: Platform) -> bool:
    """Does `canonical` equal `root` or lie directly inside `root`?

    Separator + case handling is delegated to `_normalize_for_compare`.
    """
    c = _normalize_for_compare(canonical.rstrip("/\\") or canonical, platform)
    r_stripped = root.rstrip("/\\")
    # POSIX "/" collapses to "" above; restore as "/".
    r = _normalize_for_compare(r_stripped or "/", platform)
    return c == r or c.startswith(r + "/")


def check_not_restricted(
    canonical: str,
    restricted: list[str],
    platform: Platform = "posix",
    restricted_globs: list[str] | None = None,
) -> None:
    """Raise ``PathRestricted`` if ``canonical`` is inside any restricted root
    OR matches any glob in ``restricted_globs`` (v1.4.0).

    Prefix semantics identical to ``check_in_allowlist`` (i.e. ``/mnt/shared``
    as a restricted root rejects ``/mnt/shared`` itself and ``/mnt/shared/**``).
    No wildcard sentinels: ``"*"`` as a restricted entry would disable the
    entire low-access + sftp-read tiers on the host; if that's the intent,
    turn the tier flag off instead.

    ``restricted_globs`` are matched via ``pathlib.PurePosixPath.match`` (or
    ``PureWindowsPath.match`` on Windows hosts). Empty / None => glob check
    is skipped entirely. The two lists are UNIONED on the deny side, prefix
    semantics for ``restricted`` and glob semantics for ``restricted_globs``.
    """
    if restricted:
        for root in restricted:
            if _prefix_match(canonical, root, platform):
                raise PathRestricted(
                    f"path {canonical!r} is inside restricted zone {root!r}; "
                    f"low-access and sftp-read tools refuse restricted paths. Use "
                    f"ssh_exec_run / ssh_sudo_exec (requires ALLOW_DANGEROUS_TOOLS) "
                    f"if you really need to touch this path."
                )
    if restricted_globs:
        path_obj: PurePosixPath | PureWindowsPath = (
            PureWindowsPath(canonical) if platform == "windows" else PurePosixPath(canonical)
        )
        for glob in restricted_globs:
            if path_obj.match(glob):
                raise PathRestricted(
                    f"path {canonical!r} matches restricted glob {glob!r}; "
                    f"low-access and sftp-read tools refuse restricted paths."
                )


_ALLOW_ALL_SENTINELS = frozenset({"*", "/"})


def check_in_allowlist(canonical: str, allowlist: list[str], platform: Platform = "posix") -> None:
    """Raise PathNotAllowed if `canonical` is not inside any allowlisted root.

    Sentinels: an allowlist entry of ``"*"`` or ``"/"`` means "every absolute
    path is allowed". Use sparingly -- this widens path confinement to whatever
    the SSH user on the remote can reach. OS-level file permissions still
    apply, but the MCP's per-host scoping is fully open for that host.
    """
    if not allowlist:
        raise PathNotAllowed(
            "no SSH_PATH_ALLOWLIST configured for this host. "
            "Remediation: ask the operator to configure path_allowlist in "
            "hosts.toml or SSH_PATH_ALLOWLIST in the env."
        )
    for root in allowlist:
        if root in _ALLOW_ALL_SENTINELS:
            return
        if _prefix_match(canonical, root, platform):
            return
    raise PathNotAllowed(
        f"path {canonical!r} is outside the allowlist. "
        f"Remediation: pick a path inside one of {allowlist!r}, or ask the "
        f"operator to add the needed root to path_allowlist."
    )


def reject_bad_characters(path: str) -> None:
    """Reject NULs and control characters before the path ever touches the wire."""
    if not path:
        raise PathNotAllowed("path is empty")
    if "\x00" in path:
        raise PathNotAllowed("path contains NUL byte")
    for ch in path:
        if ord(ch) < 0x20:
            raise PathNotAllowed(f"path contains control character 0x{ord(ch):02x}")


async def canonicalize(
    conn: asyncssh.SSHClientConnection,
    path: str,
    *,
    must_exist: bool,
    platform: Platform = "posix",
    pool: ConnectionPool | None = None,
    policy: HostPolicy | None = None,
) -> str:
    """Canonicalize `path` on the remote and return the canonical form.

    POSIX: shells out to `realpath [-m] -- <path>`. `-m` resolves even if the
    final component does not exist -- required for create/upload ops.

    Windows: SFTP ``realpath`` extension is platform-agnostic and resolves
    symlinks + normalizes separators. If SFTP realpath fails (older server,
    non-existing path on strict server), we fall back to python-side
    ``ntpath.normpath`` and require the result to be absolute. Symlink
    escape via a non-resolving fallback is a weaker guarantee than POSIX
    gives us -- documented in ADR-0023.

    ``pool`` + ``policy`` are optional and only consulted on the Windows
    branch -- they route the SFTP realpath probe through the pool's cached
    SFTPClient so we share the same subsystem channel as the rest of the
    tool surface (avoids opening a fresh SFTP channel per path resolve,
    which on DSM-style servers exhausts MaxSessions). Both must be passed
    together or both omitted; passing one without the other raises
    ``TypeError`` rather than silently falling back -- half-contract calls
    used to degrade invisibly, which masked bugs at the call site.
    Omitting both falls back to a per-call ``conn.start_sftp_client()``
    (legacy path, kept for docker tools and tests that don't have a pool
    handy).
    """
    _check_pool_policy_pair(pool, policy)
    reject_bad_characters(path)
    if platform == "windows":
        return await _canonicalize_windows(conn, path, must_exist=must_exist, pool=pool, policy=policy)
    return await _canonicalize_posix(conn, path, must_exist=must_exist, pool=pool, policy=policy)


async def _canonicalize_posix(
    conn: asyncssh.SSHClientConnection,
    path: str,
    *,
    must_exist: bool,
    pool: ConnectionPool | None = None,
    policy: HostPolicy | None = None,
) -> str:
    # GNU realpath modes:
    #   default: parent must exist; leaf may not
    #   -e:      ALL components must exist (what `must_exist=True` actually wants)
    #   -m:      NO components need exist (write-targets, upload, mkdir)
    # The original code dropped `-e` for must_exist=True and relied on the SFTP
    # operation to surface missing-file errors -- which leaked SFTPNoSuchFile
    # to callers that expected PathNotAllowed (caught by e2e mv-then-stat test).
    argv = ["realpath"]
    argv.append("-e" if must_exist else "-m")
    argv.extend(["--", path])

    # asyncssh.conn.run() expects a string, not a list -- passing a list crashes
    # internally with "can't concat list to bytes". shlex.join quotes each argv
    # element for the remote shell, so the separation between arguments is
    # preserved and nothing is shell-interpolated from untrusted input.
    result = await conn.run(shlex.join(argv), check=False)
    stdout = result.stdout
    stderr = result.stderr
    if isinstance(stdout, bytes | bytearray):
        stdout = stdout.decode(errors="replace")
    if isinstance(stderr, bytes | bytearray):
        stderr = stderr.decode(errors="replace")
    # asyncssh can hand back None when the stream stayed empty -- coerce to
    # "" so downstream ``.strip()`` calls don't blow up.
    stdout = stdout or ""
    stderr = stderr or ""
    if result.exit_status != 0:
        # Shell `realpath` failed. Before giving up, try the SFTP-protocol
        # REALPATH (asyncssh's ``sftp.realpath``) as a fallback. On hosts
        # with chrooted SFTP (DSM internal-sftp, OPNsense, some appliances),
        # the SSH session channel sees the real filesystem view (e.g.
        # ``/volume1/docker/...``) while the SFTP subsystem sees the
        # chroot view (e.g. ``/docker/...``). The LLM gets paths from SFTP
        # discovery (``ssh_sftp_list``), so canonicalizing those against
        # the shell view will always ENOENT under chroot -- but the SFTP
        # view will resolve them correctly, and SFTP-backed tools that
        # consume the canonical path will operate in the same view.
        sftp_canonical = await _try_sftp_realpath(conn, path, pool, policy)
        if sftp_canonical is not None:
            # ``realpath -m`` (must_exist=False) tolerates missing leaves.
            # If the caller wanted strict existence, double-check via
            # ``sftp.stat`` so the contract still holds on the chroot path.
            if must_exist:
                stat_ok = await _try_sftp_stat(conn, sftp_canonical, pool, policy)
                if not stat_ok:
                    raise PathNotAllowed(
                        f"cannot canonicalize {path!r}: shell realpath says "
                        f"{stderr.strip() or '(no stderr)'}; SFTP realpath "
                        f"resolved to {sftp_canonical!r} but sftp.stat says "
                        f"it does not exist."
                    )
            logger.warning(
                "shell realpath failed for %r (%s); used SFTP-protocol "
                "realpath fallback -> %r. Likely chrooted SFTP -- shell and "
                "SFTP see different filesystem views on this host. "
                "Shell-backed tools (ssh_cp / ssh_mv cross-fs / ssh_delete_folder "
                "rm -rf fallback) may still fail on this path; use ssh_exec_run "
                "or fix the server's SFTP chroot config.",
                path,
                stderr.strip() or "(no stderr)",
                sftp_canonical,
            )
            return sftp_canonical
        raise PathNotAllowed(
            f"cannot canonicalize {path!r}: shell realpath says "
            f"{stderr.strip() or '(no stderr)'}; SFTP-protocol realpath "
            f"fallback also failed. If this host runs chrooted SFTP, even "
            f"the SFTP subsystem could not resolve the path."
        )

    canonical = stdout.strip()
    if not canonical.startswith("/"):
        raise PathNotAllowed(f"realpath returned non-absolute path: {canonical!r}")
    return canonical


async def _try_sftp_realpath(
    conn: asyncssh.SSHClientConnection,
    path: str,
    pool: ConnectionPool | None,
    policy: HostPolicy | None,
) -> str | None:
    """Best-effort SFTP-protocol REALPATH. Returns the resolved path or
    ``None`` on any SFTP-layer failure.

    Used as the chroot fallback in :func:`_canonicalize_posix`. Swallows
    ``asyncssh.Error`` (base class) rather than only ``SFTPError`` so a
    pure transport failure during the probe degrades to ``None`` -- the
    caller then re-raises the original shell-realpath error.
    """
    try:
        async with _sftp_for_canonicalize(conn, pool, policy) as sftp:
            resolved = await sftp.realpath(path)
        if isinstance(resolved, bytes | bytearray):
            resolved = resolved.decode(errors="replace")
        resolved_str = str(resolved).strip()
        if not resolved_str or not resolved_str.startswith("/"):
            return None
        return resolved_str
    except asyncssh.Error:
        return None


async def _try_sftp_stat(
    conn: asyncssh.SSHClientConnection,
    path: str,
    pool: ConnectionPool | None,
    policy: HostPolicy | None,
) -> bool:
    """Best-effort ``sftp.stat``. ``True`` iff the path resolves cleanly."""
    try:
        async with _sftp_for_canonicalize(conn, pool, policy) as sftp:
            await sftp.stat(path)
        return True
    except asyncssh.Error:
        return False


def _is_windows_absolute(path: str) -> bool:
    # `C:\foo` or `C:/foo` (UNC `\\host\share` also absolute but rarer).
    if len(path) >= 3 and path[1:3] in (":\\", ":/") and path[0].isalpha():
        return True
    return bool(path.startswith("\\\\") or path.startswith("//"))


def _check_pool_policy_pair(
    pool: ConnectionPool | None,
    policy: HostPolicy | None,
) -> None:
    """Enforce the both-or-neither contract for the ``pool`` + ``policy`` pair.

    Half-contract calls (one supplied, the other ``None``) silently fell
    back to the per-call SFTP channel in earlier revisions, which masked
    the bug. We raise ``TypeError`` so the offending call site fails loudly
    and is fixed at its source rather than degrading invisibly.
    """
    if (pool is None) != (policy is None):
        raise TypeError(
            "canonicalize: pool and policy must be passed together "
            f"(pool={'set' if pool is not None else 'None'}, "
            f"policy={'set' if policy is not None else 'None'}). "
            "Pass both for pool-cached SFTP, or neither for the legacy "
            "per-call channel fallback."
        )


@contextlib.asynccontextmanager
async def _sftp_for_canonicalize(
    conn: asyncssh.SSHClientConnection,
    pool: ConnectionPool | None,
    policy: HostPolicy | None,
) -> AsyncIterator[asyncssh.SFTPClient]:
    """Yield an SFTPClient for canonicalization -- pool-cached when
    possible, fall back to a per-call channel when no pool is threaded in.

    The fallback exists so docker tools (which don't yet pass ``pool``)
    keep working, and so tests that build a mock ``conn`` without a pool
    can still exercise the windows branch. The both-or-neither contract
    is enforced at the public entry point (``canonicalize``); by the time
    we reach here, the pair has already been validated.
    """
    if pool is not None and policy is not None:
        async with pool.sftp_policy(policy) as sftp:
            yield sftp
        return
    async with conn.start_sftp_client() as sftp:
        yield sftp


async def _canonicalize_windows(
    conn: asyncssh.SSHClientConnection,
    path: str,
    *,
    must_exist: bool,
    pool: ConnectionPool | None = None,
    policy: HostPolicy | None = None,
) -> str:
    # One SFTPClient for both the realpath probe and the (optional) must-exist
    # stat. In the pool-cached path both ops share the same multiplexed channel
    # already; in the fallback path (no pool, e.g. docker tools and tests) this
    # avoids opening TWO SFTP subsystem channels per canonicalize call. The
    # extra ntpath/string fixup inside the with-block holds the client open for
    # microseconds -- negligible -- and keeps the success path one
    # async-context-manager entry instead of two.
    async with _sftp_for_canonicalize(conn, pool, policy) as sftp:
        # SFTP realpath -- works regardless of remote OS and respects existing
        # symlinks. Servers that refuse realpath on non-existing targets fall
        # through to the ntpath fallback below.
        try:
            canonical_raw = await sftp.realpath(path)
        except asyncssh.SFTPError:
            canonical_raw = None

        if canonical_raw is None:
            # Python-side fallback: `ntpath.normpath` folds `..`, unifies slashes.
            # Does NOT resolve symlinks -- on Windows we accept this weaker
            # guarantee for non-existing paths (upload / mkdir targets).
            if not _is_windows_absolute(path):
                raise PathNotAllowed(f"path {path!r} is not absolute; expected `C:\\...` or `C:/...`")
            canonical_raw = ntpath.normpath(path)

        if isinstance(canonical_raw, bytes):
            canonical_raw = canonical_raw.decode(errors="replace")
        canonical = str(canonical_raw)
        # OpenSSH-for-Windows' SFTP subsystem returns realpath in Cygwin/WSL form:
        # `C:\Users` comes back as `/C:/Users`. Strip the spurious leading `/` so
        # the result lines up with `_is_windows_absolute` (and with user-supplied
        # paths which use the native drive form).
        #
        # UNC (`\\host\share` or `//host/share`) is intentionally left intact --
        # it's already absolute under `_is_windows_absolute`, and admin-share
        # forms like `//host/C$/...` share no prefix shape with `/C:/...` so the
        # strip below can't fire on them.
        if (
            len(canonical) >= 4
            and canonical[0] == "/"
            and canonical[2:4] in (":/", ":\\")
            and canonical[1].isalpha()
        ):
            canonical = canonical[1:]
        if not _is_windows_absolute(canonical):
            raise PathNotAllowed(f"canonicalized path is not absolute: {canonical!r}")

        if must_exist:
            # Double-check via SFTP stat so the same "must exist" semantics apply
            # on Windows as POSIX (realpath alone may succeed on a phantom path).
            try:
                await sftp.stat(canonical)
            except asyncssh.SFTPError as exc:
                raise PathNotAllowed(f"cannot canonicalize {path!r}: {exc}") from exc
    return canonical


async def canonicalize_and_check(
    conn: asyncssh.SSHClientConnection,
    path: str,
    allowlist: list[str],
    *,
    must_exist: bool = True,
    platform: Platform = "posix",
    pool: ConnectionPool | None = None,
    policy: HostPolicy | None = None,
) -> str:
    """Canonicalize on the remote and verify the result is allowlisted.

    ``pool`` + ``policy`` forwarded to :func:`canonicalize`; see its
    docstring for the rationale (Windows SFTP realpath uses the pool's
    cached SFTPClient when available). The both-or-neither contract is
    enforced here too -- passing one without the other raises ``TypeError``.
    """
    _check_pool_policy_pair(pool, policy)
    # Telemetry: path content can be sensitive (user-supplied), so attach
    # `path_len` only. `allowlist_len` is operator config, useful for spotting
    # hosts that lost their allowlist after a config reload.
    with span(
        "path.canonicalize",
        **{
            "ssh.platform": platform,
            "path.len": len(path),
            "path.must_exist": must_exist,
            "path.allowlist_len": len(allowlist),
        },
    ) as s:
        canonical = await canonicalize(
            conn,
            path,
            must_exist=must_exist,
            platform=platform,
            pool=pool,
            policy=policy,
        )
        check_in_allowlist(canonical, allowlist, platform)
        s.set_attribute("path.canonical_len", len(canonical))
        return canonical


async def resolve_path(
    conn: asyncssh.SSHClientConnection,
    path: str,
    policy: HostPolicy,
    settings: Settings,
    *,
    must_exist: bool = True,
    pool: ConnectionPool | None = None,
) -> str:
    """Canonicalize ``path``, enforce allowlist + restricted-zones in one shot.

    Bundles the standard low-access path resolution chain so callers can't
    accidentally skip the restricted-paths check. Returns the canonical path.

    ``pool`` (optional): when threaded in, the Windows SFTP realpath probe
    uses the pool's cached SFTPClient instead of opening a fresh channel
    per call. POSIX targets ignore it. Callers in SFTP-heavy paths
    (low_access_tools, sftp_read_tools, multi_host_tools) should pass it.

    v1.4.0: also enforces ``restricted_globs`` (glob-aware deny list,
    unioned with ``restricted_paths``) and the ``redact_bypass_policy=block``
    case for ``redact_paths_globs``. The bypass-block raises
    :class:`RedactBypassBlocked` -- the LLM sees an error that names
    ``ssh_read_redacted`` as the right alternative. ``warn`` and
    ``audit_only`` modes do NOT raise here; callers consult
    :func:`ssh_mcp.services.redact_policy.check_redact_bypass` after
    ``resolve_path`` returns and attach the appropriate side effect.
    """
    # Local import: redact_policy depends on Settings/HostPolicy which this
    # module already imports under TYPE_CHECKING. A top-level import would
    # work but the redact layer is logically a layer ABOVE path_policy,
    # so we keep the runtime coupling explicit.
    from .redact_policy import resolve_restricted_globs, should_block_redact_bypass

    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=must_exist,
        platform=policy.platform,
        pool=pool,
        policy=policy,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
        restricted_globs=resolve_restricted_globs(policy, settings),
    )
    if should_block_redact_bypass(canonical, policy, settings):
        raise RedactBypassBlocked(canonical)
    return canonical


async def resolve_path_for_redacted_read(
    conn: asyncssh.SSHClientConnection,
    path: str,
    policy: HostPolicy,
    settings: Settings,
    *,
    must_exist: bool = True,
    pool: ConnectionPool | None = None,
) -> str:
    """Like :func:`resolve_path` but the redact-bypass BLOCK does not fire
    -- this is the entry point for ``ssh_read_redacted``, which IS the
    operator-blessed way to read a redact-listed file.

    Still enforces the standard allowlist + ``restricted_paths`` + the new
    ``restricted_globs`` (the deny list is independent of the redact list;
    a path that's hard-denied stays denied even from the redactor). Only
    the ``redact_paths_globs`` BLOCK is skipped, by design.
    """
    from .redact_policy import resolve_restricted_globs

    canonical = await canonicalize_and_check(
        conn,
        path,
        effective_allowlist(policy, settings),
        must_exist=must_exist,
        platform=policy.platform,
        pool=pool,
        policy=policy,
    )
    check_not_restricted(
        canonical,
        effective_restricted_paths(policy, settings),
        policy.platform,
        restricted_globs=resolve_restricted_globs(policy, settings),
    )
    return canonical
