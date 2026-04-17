"""End-to-end tests for the ``group:systemctl`` safe-tier tools.

Runs against every host declared in ``hosts.toml``. systemctl / journalctl
only make sense on Linux; Windows hosts are skipped at the top of each test.
``ssh_journalctl`` may return zero rows when the SSH user lacks membership in
the ``systemd-journal`` or ``adm`` group -- the test treats that as
informational rather than a failure. No test mutates host state.

Run with:
    pytest -m e2e -v -k systemctl
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from ssh_mcp.tools.systemctl_tools import (
    ssh_journalctl,
    ssh_systemctl_cat,
    ssh_systemctl_is_active,
    ssh_systemctl_is_enabled,
    ssh_systemctl_is_failed,
    ssh_systemctl_list_units,
    ssh_systemctl_show,
    ssh_systemctl_status,
)

from .conftest import skip_if_unreachable, skip_if_windows

pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------
# Alias parametrization  (same pattern as test_e2e_real_hosts.py)
# ---------------------------------------------------------------------------


def pytest_generate_tests(metafunc):
    """Parametrize ``alias`` over every host in hosts.toml at collection time."""
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
    aliases = sorted(hosts.keys())
    metafunc.parametrize("alias", aliases, ids=aliases)


# ---------------------------------------------------------------------------
# SSH unit-name resolution helper
# ---------------------------------------------------------------------------


async def _resolve_ssh_unit(alias: str, ctx: Any) -> str:
    """Return ``'ssh.service'`` or ``'sshd.service'``, whichever exists.

    Tries ``ssh.service`` first (Ubuntu/Debian default), then falls back to
    ``sshd.service`` (RHEL/Fedora/Arch). Calls ``pytest.skip`` when neither
    unit is found so the caller never has to handle a sentinel.
    """
    for candidate in ("ssh.service", "sshd.service"):
        r = await ssh_systemctl_is_enabled(host=alias, unit=candidate, ctx=ctx)
        if r["state"] != "not-found":
            return candidate
    pytest.skip("neither ssh.service nor sshd.service found on target")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_systemctl_status_sshd(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_status`` against the SSH daemon unit.

    Tries ``ssh.service`` first, then ``sshd.service`` -- whichever unit
    exists on the target. Skips if neither is present. Asserts that
    ``active_state`` is a non-empty string from the expected set; ``exit_code``
    is 0 (active) or 3 (inactive/dead) -- both are valid data, not errors.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    # Inline resolution: this test is *about* status so we want to see the
    # status output rather than delegate resolution to the helper.
    unit: str | None = None
    for candidate in ("ssh.service", "sshd.service"):
        probe = await ssh_systemctl_is_enabled(host=alias, unit=candidate, ctx=e2e_ctx)
        if probe["state"] != "not-found":
            unit = candidate
            break
    if unit is None:
        pytest.skip("neither ssh.service nor sshd.service found on target")

    result = await ssh_systemctl_status(host=alias, unit=unit, ctx=e2e_ctx)

    # exit_code 0 = active, 3 = inactive/dead — both are valid data returns.
    assert result["exit_code"] in {0, 3}, f"unexpected exit_code {result['exit_code']} for {unit}: {result}"
    active_state = result["active_state"]
    assert active_state is not None, f"active_state was None; stdout: {result['stdout']!r}"
    valid_states = {"active", "inactive", "failed", "activating", "deactivating", "reloading"}
    assert active_state in valid_states, f"active_state {active_state!r} not in expected set {valid_states}"
    assert result["unit"] == unit


async def test_systemctl_is_active_sshd(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_is_active`` against the SSH daemon unit.

    Because we are connected over SSH, the daemon must be active. Asserts
    ``state == "active"``.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    unit = await _resolve_ssh_unit(alias, e2e_ctx)
    result = await ssh_systemctl_is_active(host=alias, unit=unit, ctx=e2e_ctx)

    assert result["state"] == "active", (
        f"{alias}: {unit} is_active returned {result['state']!r}; "
        f"must be active -- we are connected over SSH: {result}"
    )
    assert result["exit_code"] == 0


async def test_systemctl_is_enabled_sshd(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_is_enabled`` against the SSH daemon unit.

    The SSH daemon is required to be permanently enabled (otherwise the host
    would not survive a reboot and we could not reconnect). Asserts that the
    state is one of the "effectively enabled" values.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    unit = await _resolve_ssh_unit(alias, e2e_ctx)
    result = await ssh_systemctl_is_enabled(host=alias, unit=unit, ctx=e2e_ctx)

    expected = {"enabled", "enabled-runtime", "static", "alias"}
    assert result["state"] in expected, (
        f"{alias}: {unit} is_enabled returned {result['state']!r}; "
        f"expected one of {expected} for a running SSH daemon"
    )


async def test_systemctl_is_failed_nonexistent(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_is_failed`` against a unit that certainly does not exist.

    A nonexistent unit is not failed. Asserts ``failed == False`` and that
    ``state`` is either ``"inactive"`` or ``"unknown"`` (systemd version
    dependent: older daemons print ``"inactive"`` for unknown units, newer
    ones exit 4 which the tool normalises to ``"unknown"``).
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    phantom = f"does-not-exist-{uuid.uuid4().hex[:8]}.service"
    result = await ssh_systemctl_is_failed(host=alias, unit=phantom, ctx=e2e_ctx)

    assert (
        result["failed"] is False
    ), f"{alias}: {phantom} reported failed=True; a nonexistent unit cannot be failed"
    assert result["state"] in {"inactive", "unknown", "not-found"}, (
        f"{alias}: {phantom} state={result['state']!r}; "
        "expected 'inactive', 'unknown', or 'not-found' for a nonexistent unit"
    )


async def test_systemctl_list_units_has_sshd(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_list_units`` with ``pattern='ssh*'`` finds the SSH daemon.

    Covers both ``ssh.service`` and ``sshd.service`` via the ``ssh*`` glob.
    Asserts that at least one returned entry has a ``unit`` field starting
    with ``"ssh"``.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    result = await ssh_systemctl_list_units(host=alias, ctx=e2e_ctx, pattern="ssh*", unit_type="service")

    assert result["exit_code"] == 0, f"list_units failed: {result}"
    units = result["units"]
    assert isinstance(units, list)
    ssh_units = [u for u in units if str(u["unit"]).startswith("ssh")]
    assert ssh_units, (
        f"{alias}: no unit starting with 'ssh' in list_units output; " f"got {[u['unit'] for u in units]!r}"
    )


async def test_systemctl_show_properties_filtering(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_show`` with an explicit property list.

    Calls with ``properties=["Id", "ActiveState", "SubState"]`` and asserts
    that the returned dict contains exactly those three keys and no others.
    Exercises the ``--property=Id,ActiveState,SubState`` filter code path.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    unit = await _resolve_ssh_unit(alias, e2e_ctx)
    wanted = ["Id", "ActiveState", "SubState"]
    result = await ssh_systemctl_show(host=alias, unit=unit, ctx=e2e_ctx, properties=wanted)

    assert result["exit_code"] == 0, f"systemctl show failed: {result}"
    props = result["properties"]
    assert isinstance(props, dict)

    # All requested keys must be present.
    for key in wanted:
        assert key in props, f"{alias}: property {key!r} missing from show output; got keys {list(props)!r}"

    # Only the requested keys should be present (the filter worked).
    extra = set(props.keys()) - set(wanted)
    assert not extra, (
        f"{alias}: unexpected extra properties returned: {extra!r}; "
        "the --property= filter should limit output to exactly the requested keys"
    )


async def test_systemctl_cat_sshd(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_systemctl_cat`` against the SSH daemon unit.

    ``systemctl cat`` prefixes each fragment with ``# /path/to/unit``.
    Asserts that stdout contains that prefix pattern AND at least one of
    ``[Service]`` or ``[Unit]`` (real unit-file section headers).
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    unit = await _resolve_ssh_unit(alias, e2e_ctx)
    result = await ssh_systemctl_cat(host=alias, unit=unit, ctx=e2e_ctx)

    assert result["exit_code"] == 0, f"systemctl cat failed: {result}"
    stdout = result["stdout"]
    assert isinstance(stdout, str), "stdout should be a string"
    assert stdout, "stdout should be non-empty"

    # systemctl cat always starts the output with "# /path/to/unit-file".
    assert "# /" in stdout, (
        f"{alias}: expected '# /' path-comment prefix in systemctl cat output; " f"got: {stdout[:200]!r}"
    )

    # Real unit files contain at least one section header.
    assert "[Service]" in stdout or "[Unit]" in stdout, (
        f"{alias}: neither '[Service]' nor '[Unit]' found in {unit} unit file; "
        f"output may be truncated or the unit file is unusual: {stdout[:200]!r}"
    )


async def test_journalctl_sshd_short_window(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """``ssh_journalctl`` against the SSH daemon over the last 30 days.

    Does NOT assert log content -- the SSH user may lack ``systemd-journal``
    or ``adm`` group membership, in which case journalctl returns an empty
    result or a permission message. The test passes as long as the tool
    returns successfully (no exception) and the result has valid shape:
    ``lines_returned >= 0`` and ``stdout`` is a string.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    unit = await _resolve_ssh_unit(alias, e2e_ctx)
    result = await ssh_journalctl(host=alias, unit=unit, ctx=e2e_ctx, lines=5, since="30d")

    assert isinstance(result["stdout"], str), f"stdout should be a string, got {type(result['stdout'])}"
    assert isinstance(
        result["lines_returned"], int
    ), f"lines_returned should be an int, got {type(result['lines_returned'])}"
    assert result["lines_returned"] >= 0, f"lines_returned must be >= 0; got {result['lines_returned']}"
    # Inform but do not fail when permission denied -- log at zero lines is
    # acceptable because many setups restrict journal access to root/adm.
