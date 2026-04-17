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
"""
from __future__ import annotations

import ntpath
import posixpath
import shlex
from typing import TYPE_CHECKING, Literal

import asyncssh

from ..ssh.errors import PathNotAllowed, PathRestricted
from ..telemetry import span

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import HostPolicy

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
    canonical: str, restricted: list[str], platform: Platform = "posix"
) -> None:
    """Raise ``PathRestricted`` if ``canonical`` is inside any restricted root.

    Prefix semantics identical to ``check_in_allowlist`` (i.e. ``/mnt/shared``
    as a restricted root rejects ``/mnt/shared`` itself and ``/mnt/shared/**``).
    No wildcard sentinels: ``"*"`` as a restricted entry would disable the
    entire low-access + sftp-read tiers on the host; if that's the intent,
    turn the tier flag off instead.
    """
    if not restricted:
        return
    for root in restricted:
        if _prefix_match(canonical, root, platform):
            raise PathRestricted(
                f"path {canonical!r} is inside restricted zone {root!r}; "
                f"low-access and sftp-read tools refuse restricted paths. Use "
                f"ssh_exec_run / ssh_sudo_exec (requires ALLOW_DANGEROUS_TOOLS) "
                f"if you really need to touch this path."
            )


_ALLOW_ALL_SENTINELS = frozenset({"*", "/"})


def check_in_allowlist(
    canonical: str, allowlist: list[str], platform: Platform = "posix"
) -> None:
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
    """
    reject_bad_characters(path)
    if platform == "windows":
        return await _canonicalize_windows(conn, path, must_exist=must_exist)
    return await _canonicalize_posix(conn, path, must_exist=must_exist)


async def _canonicalize_posix(
    conn: asyncssh.SSHClientConnection, path: str, *, must_exist: bool,
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
    if result.exit_status != 0:
        raise PathNotAllowed(f"cannot canonicalize {path!r}: {stderr.strip()}")

    canonical = stdout.strip()
    if not canonical.startswith("/"):
        raise PathNotAllowed(f"realpath returned non-absolute path: {canonical!r}")
    return canonical


def _is_windows_absolute(path: str) -> bool:
    # `C:\foo` or `C:/foo` (UNC `\\host\share` also absolute but rarer).
    if len(path) >= 3 and path[1:3] in (":\\", ":/") and path[0].isalpha():
        return True
    return bool(path.startswith("\\\\") or path.startswith("//"))


async def _canonicalize_windows(
    conn: asyncssh.SSHClientConnection, path: str, *, must_exist: bool,
) -> str:
    # SFTP realpath -- works regardless of remote OS and respects existing
    # symlinks. Servers that refuse realpath on non-existing targets fall
    # through to the ntpath fallback below.
    try:
        async with conn.start_sftp_client() as sftp:
            canonical_raw = await sftp.realpath(path)
    except asyncssh.SFTPError:
        canonical_raw = None

    if canonical_raw is None:
        # Python-side fallback: `ntpath.normpath` folds `..`, unifies slashes.
        # Does NOT resolve symlinks -- on Windows we accept this weaker
        # guarantee for non-existing paths (upload / mkdir targets).
        if not _is_windows_absolute(path):
            raise PathNotAllowed(
                f"path {path!r} is not absolute; expected `C:\\...` or `C:/...`"
            )
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
        raise PathNotAllowed(
            f"canonicalized path is not absolute: {canonical!r}"
        )

    if must_exist:
        # Double-check via SFTP stat so the same "must exist" semantics apply
        # on Windows as POSIX (realpath alone may succeed on a phantom path).
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.stat(canonical)
        except asyncssh.SFTPError as exc:
            raise PathNotAllowed(
                f"cannot canonicalize {path!r}: {exc}"
            ) from exc
    return canonical


async def canonicalize_and_check(
    conn: asyncssh.SSHClientConnection,
    path: str,
    allowlist: list[str],
    *,
    must_exist: bool = True,
    platform: Platform = "posix",
) -> str:
    """Canonicalize on the remote and verify the result is allowlisted."""
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
        canonical = await canonicalize(conn, path, must_exist=must_exist, platform=platform)
        check_in_allowlist(canonical, allowlist, platform)
        s.set_attribute("path.canonical_len", len(canonical))
        return canonical
