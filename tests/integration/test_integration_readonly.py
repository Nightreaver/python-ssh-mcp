"""Integration tests against a dockerized sshd on 127.0.0.1:2222.

Skipped unless the container is up (TCP probe in conftest.sshd_reachable).
Run:
    docker compose -f tests/integration/docker-compose.yml up -d
    pytest -m integration

See conftest.py for fixtures (ephemeral keypair, pinned host key, pool).
"""
from __future__ import annotations

import shlex
import socket

import pytest

from ssh_mcp.services.path_policy import canonicalize_and_check
from ssh_mcp.ssh.exec import run as exec_run


def _sshd_reachable() -> bool:
    # Duplicated from conftest -- pytest conftest.py can't be re-imported as
    # a regular module for use at collection time.
    try:
        with socket.create_connection(("127.0.0.1", 2222), timeout=1):
            return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _sshd_reachable(), reason="no sshd on 127.0.0.1:2222"),
]


@pytest.mark.asyncio
async def test_pool_acquires_connection(pool, integration_policy) -> None:
    """Basic: pool opens a real connection against the container."""
    conn = await pool.acquire(integration_policy)
    assert conn is not None
    # Confirm the handshake really completed.
    banner = conn.get_extra_info("server_version")
    assert banner, "no SSH banner -- handshake may have failed"


@pytest.mark.asyncio
async def test_exec_run_returns_stdout(pool, integration_policy, integration_settings) -> None:
    """Real remote exec: `echo hello` via our ssh/exec.run wrapper."""
    conn = await pool.acquire(integration_policy)
    result = await exec_run(
        conn,
        shlex.join(["echo", "hello from integration"]),
        host=integration_policy.hostname,
        timeout=10.0,
        stdout_cap=integration_settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=integration_settings.SSH_STDERR_CAP_BYTES,
    )
    assert result.exit_code == 0
    assert "hello from integration" in result.stdout
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_exec_run_nonzero_is_data_not_failure(
    pool, integration_policy, integration_settings
) -> None:
    """ADR-0005: non-zero exit is returned, not raised."""
    conn = await pool.acquire(integration_policy)
    result = await exec_run(
        conn,
        "false",
        host=integration_policy.hostname,
        timeout=5.0,
        stdout_cap=integration_settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=integration_settings.SSH_STDERR_CAP_BYTES,
    )
    assert result.exit_code != 0
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_canonicalize_and_check_rejects_out_of_scope(pool, integration_policy) -> None:
    """Real remote `realpath -m` -- verifies the path-policy helper end-to-end.

    Policy allows /config + /tmp. `/etc/hostname` is outside both -> PathNotAllowed.
    """
    from ssh_mcp.ssh.errors import PathNotAllowed

    conn = await pool.acquire(integration_policy)
    allowlist = integration_policy.path_allowlist
    # A path inside allowlist: should resolve cleanly.
    canonical = await canonicalize_and_check(
        conn, "/tmp", allowlist, must_exist=True, platform="posix",
    )
    assert canonical == "/tmp"

    # A path outside allowlist must be refused.
    with pytest.raises(PathNotAllowed):
        await canonicalize_and_check(
            conn, "/etc/hostname", allowlist, must_exist=True, platform="posix",
        )


@pytest.mark.asyncio
async def test_sftp_list_tmp(pool, integration_policy) -> None:
    """SFTP listdir on /tmp -- the most basic read-only file-ops primitive."""
    conn = await pool.acquire(integration_policy)
    async with conn.start_sftp_client() as sftp:
        entries = await sftp.listdir("/tmp")
    # `.` and `..` may or may not show up depending on server version; the
    # list just needs to be non-None (no protocol error). /tmp may even be
    # empty inside a fresh container -- we only assert the call worked.
    assert isinstance(entries, list)


@pytest.mark.asyncio
async def test_pool_reuses_connection_for_same_key(pool, integration_policy) -> None:
    """Second acquire on the same policy returns the same underlying conn."""
    conn_a = await pool.acquire(integration_policy)
    conn_b = await pool.acquire(integration_policy)
    assert conn_a is conn_b
