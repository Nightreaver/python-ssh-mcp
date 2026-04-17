"""HostPolicy / AuthPolicy field validation. INC-013."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_mcp.models.policy import AuthPolicy, HostPolicy


def _base(**over: object) -> dict[str, object]:
    d: dict[str, object] = {
        "hostname": "web01.internal",
        "user": "deploy",
        "auth": AuthPolicy(method="agent"),
    }
    d.update(over)
    return d


def test_port_default_is_22() -> None:
    assert HostPolicy(**_base()).port == 22  # type: ignore[arg-type]


def test_port_accepts_valid_range() -> None:
    for port in (1, 22, 2222, 65535):
        HostPolicy(**_base(port=port))  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [0, -1, 65536, 100000])
def test_port_rejects_out_of_range(bad: int) -> None:
    with pytest.raises(ValidationError, match="out of range"):
        HostPolicy(**_base(port=bad))  # type: ignore[arg-type]


def test_port_coerces_numeric_string() -> None:
    # Pydantic v2 default coercion accepts "2222" -> 2222 for int fields.
    assert HostPolicy(**_base(port="2222")).port == 2222  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["abc", "22a", "", "  "])
def test_port_rejects_non_numeric_string(bad: str) -> None:
    with pytest.raises(ValidationError):
        HostPolicy(**_base(port=bad))  # type: ignore[arg-type]


def test_port_rejects_float() -> None:
    with pytest.raises(ValidationError):
        HostPolicy(**_base(port=22.5))  # type: ignore[arg-type]


def test_path_allowlist_must_be_absolute() -> None:
    with pytest.raises(ValidationError, match="must be absolute"):
        HostPolicy(**_base(path_allowlist=["relative/path"]))  # type: ignore[arg-type]


def test_fingerprint_shape_enforced() -> None:
    with pytest.raises(ValidationError, match="SHA256"):
        AuthPolicy(method="agent", identity_fingerprint="MD5:oldhash")
