"""Open asyncssh connections honoring HostPolicy. ProxyJump handled recursively."""
from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING, Any

import asyncssh

from ..telemetry import span
from .agent import select_agent_key
from .errors import AuthenticationFailed, ConnectError, HostKeyMismatch, UnknownHost

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import AuthPolicy, HostPolicy
    from .known_hosts import KnownHosts
    from .pool import ConnectionPool

logger = logging.getLogger(__name__)


# Seconds allowed for an operator-configured `password_cmd` / `passphrase_cmd`
# subprocess (`pass show`, `secret-tool lookup`, `op item get`, etc.) to return
# its stdout. Deliberately hardcoded -- this is a short blocking call during
# connection setup, not something operators want to tune. If a secret helper
# takes longer than this the operator has a bigger problem than the timeout.
_SECRET_CMD_TIMEOUT_SECONDS = 10


async def open_connection(
    policy: HostPolicy,
    settings: Settings,
    known_hosts: KnownHosts,
    pool: ConnectionPool | None = None,
) -> asyncssh.SSHClientConnection:
    """Open a connection to policy.hostname, resolving the proxy chain via the pool.

    The pool is reused for bastions so a single bastion connection serves many targets.
    """
    tunnel: asyncssh.SSHClientConnection | None = None
    if policy.proxy_chain():
        if pool is None:
            raise ConnectError("proxy_jump requires a pool to reuse bastion connections")
        for hop_name in policy.proxy_chain():
            hop_policy = pool.host(hop_name)
            if hop_policy is None:
                raise ConnectError(f"proxy_jump hop {hop_name!r} not in hosts.toml")
            tunnel = await pool.acquire(hop_policy)

    return await _open_single(policy, settings, known_hosts, tunnel)


async def _open_single(
    policy: HostPolicy,
    settings: Settings,
    known_hosts: KnownHosts,
    tunnel: asyncssh.SSHClientConnection | None,
) -> asyncssh.SSHClientConnection:
    kwargs: dict[str, Any] = {
        "host": policy.hostname,
        "port": policy.port,
        "username": policy.user,
        "known_hosts": known_hosts.as_asyncssh_param(),
        "connect_timeout": settings.SSH_CONNECT_TIMEOUT,
        "keepalive_interval": settings.SSH_KEEPALIVE_INTERVAL,
        "agent_forwarding": False,
    }
    if tunnel is not None:
        kwargs["tunnel"] = tunnel

    # Honor ~/.ssh/config when the operator points us at one. Explicit kwargs
    # already set above (host/port/username/known_hosts/timeouts) win over the
    # config file -- asyncssh applies the file as a fallback for fields we
    # didn't pass. Useful coverage in practice: `IdentityFile`, `ProxyCommand`,
    # `Host alias -> HostName real.example.com` aliases, and Ciphers/MACs/
    # KexAlgorithms overrides for legacy gear. Path is expanduser()'d here
    # because pydantic's Path coercion does not.
    if settings.SSH_CONFIG_FILE is not None:
        kwargs["config"] = [str(settings.SSH_CONFIG_FILE.expanduser())]

    auth_kwargs = await _resolve_auth(policy.auth)
    kwargs.update(auth_kwargs)

    # Telemetry: hostname/port/user are operator-configured (not tool input) and
    # already appear in audit lines, so they're safe to attach. Auth secrets in
    # `kwargs` are deliberately NOT attached.
    with span(
        "ssh.connect",
        **{
            "ssh.host": policy.hostname,
            "ssh.port": policy.port,
            "ssh.user": policy.user,
            "ssh.auth_method": policy.auth.method,
            "ssh.proxy_hops": len(policy.proxy_chain()),
            "ssh.tunneled": tunnel is not None,
        },
    ) as s:
        try:
            conn = await asyncssh.connect(**kwargs)
        except asyncssh.HostKeyNotVerifiable as exc:
            # INC-007: disambiguate unknown-host vs mismatch via known_hosts lookup,
            # not exception message text. asyncssh raises HostKeyNotVerifiable for both
            # the "no matching entry" and "entry exists but key differs" cases; the
            # distinction lives in whether we have a pinned fingerprint for this host.
            expected = known_hosts.fingerprint_for(policy.hostname, policy.port)
            if expected is None:
                raise UnknownHost(
                    f"host key for {policy.hostname} not in known_hosts; verify out-of-band"
                ) from exc
            # asyncssh's `HostKeyNotVerifiable` doesn't expose the key the server
            # actually offered, so we can't surface it in the mismatch message --
            # the operator has to pull it via `ssh-keyscan -p <port> <host>`
            # out-of-band. Placeholder is an explicit sentence, not a magic-string
            # literal that might read like a bad f-string substitution.
            raise HostKeyMismatch(
                policy.hostname, expected, "unknown (asyncssh did not expose the received key)",
            ) from exc
        except asyncssh.ChannelOpenError as exc:
            raise ConnectError(str(exc)) from exc
        except asyncssh.PermissionDenied as exc:
            raise AuthenticationFailed(f"auth failed for {policy.user}@{policy.hostname}") from exc
        except asyncssh.DisconnectError as exc:
            raise ConnectError(str(exc)) from exc
        except (TimeoutError, OSError) as exc:
            raise ConnectError(f"cannot reach {policy.hostname}:{policy.port}: {exc}") from exc
        s.set_attribute("ssh.connected", True)
        return conn


async def _resolve_auth(auth: AuthPolicy) -> dict[str, Any]:
    """Translate AuthPolicy into asyncssh connect kwargs. See DESIGN.md §5.7a."""
    if auth.method == "agent":
        kwargs: dict[str, Any] = {}
        if auth.identity_agent is not None:
            kwargs["agent_path"] = str(auth.identity_agent)
        if auth.identity_fingerprint is not None:
            key = await select_agent_key(auth.identity_agent, auth.identity_fingerprint)
            kwargs["client_keys"] = [key]
            if auth.identities_only:
                # agent_path left set; client_keys restricts which ones are offered.
                pass
        elif auth.identities_only:
            # identities_only without a fingerprint makes no sense for agent auth.
            raise AuthenticationFailed(
                "identities_only=true requires identity_fingerprint for agent auth"
            )
        return kwargs

    if auth.method == "key":
        if auth.key is None:
            raise AuthenticationFailed("method='key' requires key path")
        kwargs = {"client_keys": [str(auth.key)], "agent_path": None}
        if auth.passphrase_cmd:
            kwargs["passphrase"] = _run_command_for_secret(auth.passphrase_cmd)
        return kwargs

    if auth.method == "password":
        if not auth.password_cmd:
            raise AuthenticationFailed("method='password' requires password_cmd")
        return {
            "password": _run_command_for_secret(auth.password_cmd),
            "agent_path": None,
            "client_keys": None,
        }

    raise AuthenticationFailed(f"unknown auth method {auth.method!r}")


def _run_command_for_secret(cmd: str) -> str:
    """Run a command and return its stdout as a secret. Never logged."""
    result = subprocess.run(  # noqa: S602 — cmd comes from operator config, not tool input
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=_SECRET_CMD_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise AuthenticationFailed(
            f"secret command exited {result.returncode} (stderr hidden for safety)"
        )
    return result.stdout.rstrip("\n")
