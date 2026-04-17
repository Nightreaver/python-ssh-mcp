"""E2E tests for the sudo tier. Opt-in via `SSH_E2E_SUDO_PASSWORD`.

Running as sudo against real hosts is genuinely risky (wrong pipe, wrong
host, wrong command -> rooted mutation). So this file skips every test
unless the operator has explicitly set ``SSH_E2E_SUDO_PASSWORD`` in the
environment. The password is read by the tool via ``fetch_sudo_password``
which accepts either ``SSH_SUDO_PASSWORD`` (the prod env) or a keychain /
command-based provider; the e2e-specific variable is a separate signal,
not a replacement.

Enable:

    export SSH_E2E_SUDO_PASSWORD='…'
    export SSH_SUDO_PASSWORD="$SSH_E2E_SUDO_PASSWORD"  # the tool reads this
    pytest -m e2e -v -k sudo

Each test is read-only (e.g. `sudo cat /etc/shadow` for the exec flavor,
`sudo id` for the script) so a misconfigured password doesn't mutate
anything. We still wrap everything in a try / best-effort so no state
leaks across runs.
"""
from __future__ import annotations

import os

import pytest

from ssh_mcp.ssh.errors import PlatformNotSupported
from ssh_mcp.tools.sudo_tools import ssh_sudo_exec, ssh_sudo_run_script

from .conftest import skip_if_no_sudo, skip_if_unreachable

pytestmark = pytest.mark.e2e


def pytest_generate_tests(metafunc):
    if "alias" not in metafunc.fixturenames:
        return
    from ssh_mcp.config import Settings
    from ssh_mcp.hosts import load_hosts

    from .conftest import HOSTS_FILE

    if not HOSTS_FILE.exists():
        metafunc.parametrize("alias", [], ids=[])
        return
    settings = Settings(SSH_HOSTS_FILE=HOSTS_FILE)
    hosts = load_hosts(HOSTS_FILE, settings)
    names = sorted(hosts.keys())
    metafunc.parametrize("alias", names, ids=names)


@pytest.fixture(autouse=True)
def _wire_sudo_env(monkeypatch):
    """Feed ``SSH_E2E_SUDO_PASSWORD`` into ``SSH_SUDO_PASSWORD`` for the tool.

    ``fetch_sudo_password`` is built to read prod env vars (SSH_SUDO_PASSWORD,
    SSH_SUDO_PASSWORD_CMD, OS keychain). We want the e2e suite to use a
    SEPARATE variable so nothing leaks between this suite and prod runs --
    so we mirror the opt-in var into the one the tool reads, scoped to each
    test via monkeypatch (auto-unset after the test).
    """
    pw = os.environ.get("SSH_E2E_SUDO_PASSWORD")
    if pw is not None:
        monkeypatch.setenv("SSH_SUDO_PASSWORD", pw)


async def test_sudo_exec_id(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """`ssh_sudo_exec("id")`: confirms effective uid is root. POSIX-only."""
    skip_if_no_sudo()
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_sudo_exec(host=alias, command="id", ctx=e2e_ctx)
        return
    result = await ssh_sudo_exec(host=alias, command="id", ctx=e2e_ctx)
    # ADR-0005: non-zero is data, not raised. Password errors show as non-zero.
    assert result.exit_code == 0, (
        f"sudo exec failed (exit {result.exit_code}): stderr={result.stderr!r} "
        f"-- is SSH_E2E_SUDO_PASSWORD correct for user {policy.user!r} on {policy.hostname}?"
    )
    assert "uid=0" in result.stdout or "root" in result.stdout


async def test_sudo_run_script(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """`ssh_sudo_run_script`: multi-line script under sudo via stdin."""
    skip_if_no_sudo()
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_sudo_run_script(host=alias, script="id", ctx=e2e_ctx)
        return
    script = """#!/bin/sh
set -e
id -u
whoami
"""
    result = await ssh_sudo_run_script(host=alias, script=script, ctx=e2e_ctx)
    assert result.exit_code == 0, result
    assert "0" in result.stdout  # uid line
    assert "root" in result.stdout
