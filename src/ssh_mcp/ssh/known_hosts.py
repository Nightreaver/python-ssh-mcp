"""known_hosts loader + lookup. See ADR-0008.

The file is reloaded transparently when its mtime changes. This matters
because operators routinely add entries mid-session (the README's three-step
pin flow appends to ~/.ssh/known_hosts), and we don't want those changes to
only take effect after a server restart.

Mtime-checked reload is called on every `fingerprint_for()` and every
`as_asyncssh_param()` -- the fast path is a single `stat()` when unchanged;
a full reparse only runs when the file genuinely moved.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import asyncssh

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class KnownHosts:
    """Thin wrapper around asyncssh's known_hosts parser + lookup.

    asyncssh enforces host key verification natively when `known_hosts=` is
    passed to `connect()`. This class also exposes a synchronous `fingerprint_for`
    method for the `ssh_known_hosts_verify` tool, and reloads the file when
    its mtime changes so manual pinning takes effect without a restart.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._hostkeys: Any = asyncssh.import_known_hosts("")
        self._mtime: float | None = None
        self._missing_warned = False
        self._reload_if_stale()

    def _reload_if_stale(self) -> None:
        """Check mtime; re-parse the file if it has changed since last load.

        Keeps the previous parsed data on any I/O error (stale > silently empty).
        Note: `asyncssh.read_known_hosts` is synchronous -- keep the file
        on a local filesystem. We also keep this call out of any hot loop by
        guarding with an mtime check (the stat is cheap).
        """
        expanded = self.path.expanduser()
        try:
            current_mtime = expanded.stat().st_mtime
        except FileNotFoundError:
            if not self._missing_warned:
                logger.warning(
                    "known_hosts file %s does not exist; every host will be "
                    "reported as unknown until you pin at least one entry",
                    expanded,
                )
                self._missing_warned = True
            # Keep whatever we had (empty at startup, possibly populated after a
            # reload, then file removed -- unlikely). Don't reset to empty on
            # transient absence; the next stat will pick the file back up.
            return
        except OSError as exc:
            logger.debug("known_hosts stat failed for %s: %s", expanded, exc)
            return

        if current_mtime == self._mtime:
            return

        try:
            self._hostkeys = asyncssh.read_known_hosts(str(expanded))
            self._mtime = current_mtime
            self._missing_warned = False
            if self._mtime is not None:
                logger.info("known_hosts reloaded from %s", expanded)
        except (OSError, asyncssh.Error) as exc:
            logger.warning(
                "known_hosts reload from %s failed (%s); keeping previous state",
                expanded,
                exc,
            )

    def as_asyncssh_param(self) -> Any:
        """Value to pass as `known_hosts=` to asyncssh.connect().

        Always returns the freshest parsed object -- a file edit since the last
        connect will be visible to the next connect without a server restart.
        """
        self._reload_if_stale()
        return self._hostkeys

    def fingerprint_for(self, host: str, port: int = 22) -> str | None:
        """Return the SHA256 fingerprint recorded for host:port, or None if absent.

        Used by `ssh_known_hosts_verify` to report what we expect without opening
        a connection. Reloads if the file changed since last lookup.
        """
        self._reload_if_stale()
        try:
            # asyncssh.SSHKnownHosts.match returns a 7-tuple:
            #   (trusted_host_keys, trusted_ca_keys, revoked_host_keys,
            #    trusted_x509, revoked_x509,
            #    trusted_name_patterns, revoked_name_patterns)
            # We only care about trusted host keys (index 0). An earlier version
            # unpacked 3 values and caught ValueError, which made this function
            # silently return None for every lookup on Windows and everywhere else.
            result = self._hostkeys.match(host, "", port)
        except (KeyError, TypeError) as exc:
            logger.debug("known_hosts match failed for %s:%d: %s", host, port, exc)
            return None
        trusted = result[0]
        if not trusted:
            return None
        # Prefer the first match; multiple entries are rare in practice.
        return trusted[0].get_fingerprint("sha256")
