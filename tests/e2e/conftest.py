"""E2E fixtures: dedicated `hosts-e2e.toml` (fallback to live `hosts.toml`),
operator's known_hosts + SSH agent.

Unlike `tests/integration/` (a dockerized sshd on 127.0.0.1:2222), this suite
talks to the actual hosts the operator has configured in `hosts.toml`. Run with:

    pytest -m e2e

Per-host reachability is probed once per session and unreachable hosts are
skipped, not failed -- you should be able to run the suite with any subset
of hosts up.

Auth uses whatever `hosts.toml` declares (typically `method = "agent"` with a
pinned fingerprint) -- meaning the operator's running ssh-agent is the source
of truth. We do **not** override `SSH_KNOWN_HOSTS` either: real verification
must run against the operator's pinned `~/.ssh/known_hosts` to catch drift.

The global `tests/conftest.py` clears auth-related env vars and force-disables
.env loading. We undo that here for the e2e session by constructing `Settings`
explicitly with the right values, then reach into `os.environ` only to ensure
.env is *re-enabled* if the operator depends on it.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.hosts import load_hosts
from ssh_mcp.services.hooks import HookRegistry
from ssh_mcp.services.shell_sessions import SessionRegistry
from ssh_mcp.ssh.known_hosts import KnownHosts
from ssh_mcp.ssh.pool import ConnectionPool

if TYPE_CHECKING:
    from ssh_mcp.models.policy import HostPolicy

ROOT = Path(__file__).resolve().parent.parent.parent

# E2E uses a dedicated `hosts-e2e.toml` so test runs can't accidentally hit the
# operator's live fleet (and so the live `hosts.toml` can be edited mid-session
# without breaking an in-flight e2e run). Override path via `SSH_E2E_HOSTS_FILE`.
# Falls back to `hosts.toml` if no dedicated e2e file exists (backward-compat).
_E2E_HOSTS_OVERRIDE = os.environ.get("SSH_E2E_HOSTS_FILE")
if _E2E_HOSTS_OVERRIDE:
    HOSTS_FILE = Path(_E2E_HOSTS_OVERRIDE)
elif (ROOT / "hosts-e2e.toml").is_file():
    HOSTS_FILE = ROOT / "hosts-e2e.toml"
else:
    HOSTS_FILE = ROOT / "hosts.toml"


def _tcp_reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def e2e_settings() -> Settings:
    """Real Settings tuned for talking to operator hosts.

    Does NOT inherit from the global conftest's stripped env -- we build the
    instance directly. .env stays disabled to keep behavior reproducible across
    machines (operators with custom env can still override per field below).
    """
    if not HOSTS_FILE.exists():
        pytest.skip(f"e2e hosts file not found at {HOSTS_FILE}")
    return Settings(
        SSH_HOSTS_FILE=HOSTS_FILE,
        SSH_KNOWN_HOSTS=Path.home() / ".ssh" / "known_hosts",
        # /tmp on POSIX, C:\Users\<u>\AppData\Local\Temp on Windows: covers
        # both targets without opening up the whole filesystem.
        SSH_PATH_ALLOWLIST=["/tmp", "/etc", "/var/log", "C:\\Users", "C:\\Windows"],
        ALLOW_LOW_ACCESS_TOOLS=True,
        SSH_CONNECT_TIMEOUT=5,
        SSH_COMMAND_TIMEOUT=15,
    )


@pytest.fixture(scope="session")
def e2e_hosts(e2e_settings: Settings) -> dict[str, HostPolicy]:
    """All hosts declared in hosts.toml, keyed by alias."""
    hosts = load_hosts(e2e_settings.SSH_HOSTS_FILE, e2e_settings)
    if not hosts:
        pytest.skip("hosts.toml declares no hosts")
    return hosts


@pytest.fixture(scope="session")
def e2e_known_hosts(e2e_settings: Settings) -> KnownHosts:
    """Operator's known_hosts. Required -- pool refuses unknown keys."""
    if not e2e_settings.SSH_KNOWN_HOSTS.exists():
        pytest.skip(f"known_hosts not found at {e2e_settings.SSH_KNOWN_HOSTS}")
    return KnownHosts(e2e_settings.SSH_KNOWN_HOSTS)


@pytest.fixture(scope="session")
def e2e_reachable(e2e_hosts: dict[str, HostPolicy]) -> dict[str, bool]:
    """Per-alias TCP reachability. Tests skip individually when False."""
    return {alias: _tcp_reachable(policy.hostname, policy.port) for alias, policy in e2e_hosts.items()}


@pytest.fixture
async def e2e_pool(
    e2e_settings: Settings,
    e2e_hosts: dict[str, HostPolicy],
    e2e_known_hosts: KnownHosts,
):
    """Function-scoped pool bound to the real hosts.

    Scope is function (not session) because asyncssh sockets are bound to the
    event loop that created them, and pytest-asyncio default-mode gives each
    test a fresh loop. A session pool would throw
    ``AttributeError: 'NoneType' object has no attribute 'send'`` on the
    second test (the first loop's proactor is gone).
    """
    pool = ConnectionPool(e2e_settings)
    pool.bind(e2e_hosts, e2e_known_hosts)
    try:
        yield pool
    finally:
        await pool.close_all()


class _Ctx:
    """Stand-in for `fastmcp.Context`.

    Tools only ever read ``ctx.lifespan_context[<key>]`` -- no other Context
    methods are used in the tool layer (``ctx.info`` / ``ctx.report_progress``
    are absent on purpose -- adding them would make the tools harder to test
    in isolation). The ``audited`` decorator looks up ``hooks`` here too, so
    we wire an empty registry to keep its emit path no-op.
    """

    def __init__(self, lifespan_context: dict[str, Any]) -> None:
        self.lifespan_context = lifespan_context


@pytest.fixture
def e2e_ctx(
    e2e_pool: ConnectionPool,
    e2e_settings: Settings,
    e2e_hosts: dict[str, HostPolicy],
    e2e_known_hosts: KnownHosts,
) -> _Ctx:
    """Single Context shared across a test invocation.

    Wires the same keys the real lifespan does: ``pool``, ``settings``,
    ``hosts``, ``known_hosts``, ``hooks``, ``shell_sessions``. Each test gets
    a fresh registry so persistent-session tests don't leak state.
    """
    return _Ctx(
        {
            "pool": e2e_pool,
            "settings": e2e_settings,
            "hosts": e2e_hosts,
            "known_hosts": e2e_known_hosts,
            "hooks": HookRegistry(),
            "shell_sessions": SessionRegistry(),
        }
    )


def skip_if_unreachable(reachable: dict[str, bool], alias: str) -> None:
    if not reachable.get(alias):
        pytest.skip(f"host {alias!r} not reachable on this network")


def skip_if_windows(policy: HostPolicy) -> None:
    if policy.platform == "windows":
        pytest.skip(f"{policy.hostname}: POSIX-only tool")


def skip_if_posix(policy: HostPolicy) -> None:
    if policy.platform != "windows":
        pytest.skip(f"{policy.hostname}: windows-only assertion")


# ---------- Feature gates / capability probes ---------------------------


# Session-scoped capability caches. Populated lazily the first time a test
# asks. Keyed by alias so failures on one host don't poison the others.
_DOCKER_CACHE: dict[str, bool] = {}
_COMPOSE_CACHE: dict[str, bool] = {}


async def _probe_capability(pool: ConnectionPool, policy: HostPolicy, argv: list[str]) -> bool:
    """Run ``argv`` on ``policy`` and return True iff exit_status == 0.

    Skips the probe on Windows -- none of the capabilities we probe today
    (docker, docker compose) are typically installed there, and cmd.exe's
    quoting differs enough that false positives would be worse than silence.
    """
    if policy.platform == "windows":
        return False
    try:
        import shlex

        conn = await pool.acquire(policy)
        result = await conn.run(shlex.join(argv), check=False, timeout=10)
        return result.exit_status == 0
    except Exception:
        return False


async def has_docker(alias: str, pool: ConnectionPool, policy: HostPolicy) -> bool:
    """True if ``docker version`` succeeds on the host. Cached per alias."""
    if alias not in _DOCKER_CACHE:
        _DOCKER_CACHE[alias] = await _probe_capability(
            pool, policy, ["docker", "version", "--format", "{{.Server.Version}}"]
        )
    return _DOCKER_CACHE[alias]


async def has_compose(alias: str, pool: ConnectionPool, policy: HostPolicy) -> bool:
    """True if ``docker compose version`` succeeds. Cached per alias."""
    if alias not in _COMPOSE_CACHE:
        _COMPOSE_CACHE[alias] = await _probe_capability(pool, policy, ["docker", "compose", "version"])
    return _COMPOSE_CACHE[alias]


def sudo_password_from_env() -> str | None:
    """Pull ``SSH_E2E_SUDO_PASSWORD`` out of the environment.

    Separate from ``SSH_SUDO_PASSWORD`` so the e2e suite opts in explicitly --
    operators who accidentally leave ``SSH_SUDO_PASSWORD`` in their shell
    history won't trigger privileged tests. Returns None if unset; tests that
    need it should ``pytest.skip`` rather than fail.
    """
    return os.environ.get("SSH_E2E_SUDO_PASSWORD")


def skip_if_no_sudo() -> None:
    if sudo_password_from_env() is None:
        pytest.skip(
            "sudo e2e tests require SSH_E2E_SUDO_PASSWORD in the environment; "
            "set it to the sudo password for the e2e hosts to opt in."
        )
