"""Fixtures for the dockerized-sshd integration tests.

Workflow:
  1. Run `pytest -m integration` once -- the `_ephemeral_keypair` fixture
     generates an ed25519 keypair at `tests/integration/keys/test[.pub]`
     if missing. The public key is what the container will authorize.
  2. Bring the container up:
       docker compose -f tests/integration/docker-compose.yml up -d
     (Keep a running `--force-recreate` workflow in mind for fresh host keys.)
  3. Re-run `pytest -m integration` -- the `_discover_host_key` fixture pins
     the container's SSH host key into `tests/integration/known_hosts` by
     doing one `known_hosts=None` handshake.
  4. Actual tests then run through our `ConnectionPool` with strict known-
     hosts enforcement, exercising real HostPolicy resolution.

Both fixtures are session-scoped. The keypair persists across runs; the
known_hosts file is regenerated each session because
linuxserver/openssh-server rolls host keys on container recreate.

Everything in `keys/` + `known_hosts` is in `.gitignore` -- never committed.
"""
from __future__ import annotations

import asyncio
import socket
import stat
import sys
from pathlib import Path

import asyncssh
import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.ssh.known_hosts import KnownHosts
from ssh_mcp.ssh.pool import ConnectionPool

HOST = "127.0.0.1"
PORT = 2222
USER = "tester"
HOST_ALIAS = "sshd-test"

_HERE = Path(__file__).parent
KEYS_DIR = _HERE / "keys"
PRIVATE_KEY = KEYS_DIR / "test"
PUBLIC_KEY = KEYS_DIR / "test.pub"
KNOWN_HOSTS = _HERE / "known_hosts"


def sshd_reachable() -> bool:
    """TCP-reachability probe. If false, every integration test skips."""
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def ephemeral_keypair() -> tuple[Path, Path]:
    """Generate `keys/test` + `keys/test.pub` if they don't already exist.

    The container mounts `keys/` read-only and copies `test.pub` into the
    tester user's `authorized_keys` at boot. If you regenerate the key after
    the container is already up, recreate the container so it re-reads the
    public key: `docker compose up -d --force-recreate`.
    """
    KEYS_DIR.mkdir(exist_ok=True)
    if PRIVATE_KEY.exists() and PUBLIC_KEY.exists():
        return PRIVATE_KEY, PUBLIC_KEY

    key = asyncssh.generate_private_key("ssh-ed25519", comment="ssh-mcp-integration")
    PRIVATE_KEY.write_bytes(key.export_private_key())
    PUBLIC_KEY.write_bytes(key.export_public_key())
    # chmod 600 on POSIX; Windows ignores the mode bits but asyncssh doesn't
    # complain either. Don't hard-require the chmod to succeed.
    if sys.platform != "win32":
        PRIVATE_KEY.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return PRIVATE_KEY, PUBLIC_KEY


@pytest.fixture(scope="session")
def known_hosts_file(ephemeral_keypair: tuple[Path, Path]) -> Path:
    """Pin the live container's SSH host key.

    One-shot handshake with ``known_hosts=None`` captures the server public
    key; we serialize it to OpenSSH known_hosts format and keep the file for
    the rest of the session.
    """
    if not sshd_reachable():
        pytest.skip("no sshd on 127.0.0.1:2222")
    priv, _pub = ephemeral_keypair

    async def _probe() -> str:
        async with asyncssh.connect(
            HOST,
            port=PORT,
            username=USER,
            client_keys=[str(priv)],
            known_hosts=None,
        ) as conn:
            host_key = conn.get_server_host_key()
            if host_key is None:
                raise RuntimeError("server did not expose a host key")
            # export_public_key() returns b"<type> <base64> [comment]\n"
            pubkey_line = host_key.export_public_key().decode().strip()

        # Entry format: `[host]:port keytype base64data`
        return f"[{HOST}]:{PORT} {pubkey_line}\n"

    entry = asyncio.run(_probe())
    KNOWN_HOSTS.write_text(entry, encoding="utf-8")
    return KNOWN_HOSTS


@pytest.fixture(scope="session")
def integration_settings(known_hosts_file: Path) -> Settings:
    """Settings tuned for the container: strict known_hosts, no .env leak,
    path allowlist opened to the user's home so sftp reads work."""
    import os

    os.environ["SSH_MCP_DISABLE_DOTENV"] = "1"
    return Settings(
        SSH_KNOWN_HOSTS=known_hosts_file,
        SSH_HOSTS_ALLOWLIST=[HOST],
        SSH_PATH_ALLOWLIST=["/config", "/tmp"],
        ALLOW_LOW_ACCESS_TOOLS=True,
        SSH_CONNECT_TIMEOUT=5,
        SSH_COMMAND_TIMEOUT=15,
    )


@pytest.fixture(scope="session")
def integration_policy(ephemeral_keypair: tuple[Path, Path]) -> HostPolicy:
    """HostPolicy resolvable via alias `sshd-test` or by literal hostname."""
    priv, _pub = ephemeral_keypair
    return HostPolicy(
        hostname=HOST,
        port=PORT,
        user=USER,
        auth=AuthPolicy(method="key", key=priv),
        path_allowlist=["/config", "/tmp"],
    )


@pytest.fixture
async def pool(integration_settings: Settings, integration_policy: HostPolicy):
    """Function-scoped pool bound to the container. Closed cleanly after each test."""
    if not sshd_reachable():
        pytest.skip("no sshd on 127.0.0.1:2222")
    pool = ConnectionPool(integration_settings)
    pool.bind(
        {HOST_ALIAS: integration_policy},
        KnownHosts(integration_settings.SSH_KNOWN_HOSTS),
    )
    try:
        yield pool
    finally:
        await pool.close_all()
