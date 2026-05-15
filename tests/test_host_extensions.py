"""ssh_host_info extension + ssh_host_network + ssh_user_info (INC-052).

Pure parser unit tests for the helpers (no Context, no SSH). The tools
themselves are exercised end-to-end by the e2e suite against real hosts.
"""

from __future__ import annotations

import pytest

from ssh_mcp.models.results import NetworkInterfaceAddress, NetworkInterfaceEntry
from ssh_mcp.tools.host_tools import (
    _parse_cpu_count,
    _parse_cpu_model,
    _parse_fqdn,
    _parse_ip_json,
    _parse_passwd_line,
)

# --- _parse_cpu_count ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("8\n", 8),
        ("1", 1),
        ("128\n\n", 128),
        ("", None),
        ("not a number", None),
        # `nproc` failure produces empty stdout via _run_capture; must NOT
        # fabricate a fake count from the empty string.
        ("\n", None),
    ],
)
def test_parse_cpu_count(raw: str, expected: int | None) -> None:
    assert _parse_cpu_count(raw) == expected


# --- _parse_cpu_model ---


def test_parse_cpu_model_intel_amd_format() -> None:
    raw = (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz\n"
        "cpu MHz\t\t: 2294.685\n"
    )
    assert _parse_cpu_model(raw) == "Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz"


def test_parse_cpu_model_arm_falls_back_to_model_or_hardware() -> None:
    """ARM /proc/cpuinfo lacks `model name`; uses `Model` or `Hardware`."""
    raw = (
        "processor\t: 0\n"
        "BogoMIPS\t: 108.00\n"
        "Hardware\t: BCM2835\n"
        "Model\t\t: Raspberry Pi 4 Model B Rev 1.4\n"
    )
    # Model takes priority over Hardware (test order in helper).
    assert _parse_cpu_model(raw) == "Raspberry Pi 4 Model B Rev 1.4"


def test_parse_cpu_model_returns_none_when_absent() -> None:
    assert _parse_cpu_model("processor\t: 0\nbogus\t: line\n") is None
    assert _parse_cpu_model("") is None


# --- _parse_fqdn ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("web01.example.com\n", "web01.example.com"),
        ("web01\n", "web01"),  # `hostname -f` falling back to short name
        ("", None),
        ("\n\n", None),
    ],
)
def test_parse_fqdn(raw: str, expected: str | None) -> None:
    assert _parse_fqdn(raw) == expected


# --- _parse_ip_json ---


def test_parse_ip_json_typical_eth_interface() -> None:
    raw = """[
      {
        "ifname": "eth0",
        "operstate": "UP",
        "address": "02:42:ac:11:00:02",
        "addr_info": [
          {"family": "inet",  "local": "10.0.0.42",  "prefixlen": 24},
          {"family": "inet6", "local": "fe80::42:acff:fe11:2", "prefixlen": 64}
        ]
      }
    ]"""
    out = _parse_ip_json(raw)
    assert out == [
        NetworkInterfaceEntry(
            name="eth0",
            state="UP",
            mac="02:42:ac:11:00:02",
            addresses=[
                NetworkInterfaceAddress(family="inet", address="10.0.0.42", prefix_length=24),
                NetworkInterfaceAddress(family="inet6", address="fe80::42:acff:fe11:2", prefix_length=64),
            ],
        )
    ]


def test_parse_ip_json_loopback_no_mac() -> None:
    raw = """[
      {
        "ifname": "lo",
        "operstate": "UNKNOWN",
        "addr_info": [
          {"family": "inet", "local": "127.0.0.1", "prefixlen": 8}
        ]
      }
    ]"""
    out = _parse_ip_json(raw)
    assert len(out) == 1
    assert out[0].name == "lo"
    assert out[0].mac is None


@pytest.mark.parametrize("raw", ["", "   ", "not json", "{}", "null"])
def test_parse_ip_json_tolerates_garbage(raw: str) -> None:
    """iproute2-less hosts (busybox, etc.) produce empty / malformed
    stdout via `_run_capture`. Surface as `[]` not as a raise."""
    assert _parse_ip_json(raw) == []


def test_parse_ip_json_drops_malformed_addr_entries() -> None:
    """Entries with missing / wrong-typed fields are dropped silently --
    one bad entry must not poison the rest."""
    raw = """[
      {
        "ifname": "eth0",
        "operstate": "UP",
        "addr_info": [
          {"family": "inet", "local": "10.0.0.1", "prefixlen": 24},
          {"family": "inet"},
          "not a dict",
          {"family": 42, "local": "10.0.0.2", "prefixlen": 24}
        ]
      }
    ]"""
    out = _parse_ip_json(raw)
    assert len(out) == 1
    assert len(out[0].addresses) == 1
    assert out[0].addresses[0].address == "10.0.0.1"


# --- _parse_passwd_line ---


def test_parse_passwd_line_standard_record() -> None:
    raw = "deploy:x:1000:1000:Deployment User:/home/deploy:/bin/bash\n"
    out = _parse_passwd_line(raw)
    assert out == {
        "name": "deploy",
        "uid": 1000,
        "gid": 1000,
        "gecos": "Deployment User",
        "home": "/home/deploy",
        "shell": "/bin/bash",
    }


def test_parse_passwd_line_empty_gecos_field() -> None:
    """System accounts often have empty GECOS; must parse cleanly."""
    raw = "nginx:x:33:33::/var/cache/nginx:/usr/sbin/nologin\n"
    out = _parse_passwd_line(raw)
    assert out is not None
    assert out["gecos"] == ""
    assert out["uid"] == 33


@pytest.mark.parametrize("raw", ["", "  \n", "name:x:foo:bar:gecos:home:shell", "too:few:fields"])
def test_parse_passwd_line_rejects_garbage(raw: str) -> None:
    """Empty stdout from getent (user not found) and non-numeric uid/gid
    must return None rather than raise -- the tool layer surfaces a
    clean ValueError on None."""
    assert _parse_passwd_line(raw) is None


# --- _dedupe_warnings -----------------------------------------------------


def test_dedupe_warnings_preserves_first_seen_order() -> None:
    from ssh_mcp.tools.host_tools import _dedupe_warnings

    a = ["NUL bytes stripped", "ANSI escape sequences stripped"]
    b = ["ANSI escape sequences stripped", "contains zero-width characters foo"]
    out = _dedupe_warnings(a, b)
    # First-seen order: NUL first, ANSI second, zero-width third.
    assert out == [
        "NUL bytes stripped",
        "ANSI escape sequences stripped",
        "contains zero-width characters foo",
    ]


def test_dedupe_warnings_empty_inputs_yield_empty_list() -> None:
    from ssh_mcp.tools.host_tools import _dedupe_warnings

    assert _dedupe_warnings() == []
    assert _dedupe_warnings([], [], []) == []
