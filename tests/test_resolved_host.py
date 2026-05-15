"""Pin the contract of `models.policy.ResolvedHost` (T1).

`ResolvedHost` is a frozen Pydantic value object that bundles the canonical
post-resolution `hostname` with the resolved `HostPolicy`. The point is to
encode "this host has cleared `host_policy.resolve()`" in the type system
so functions deeper in the call stack can take a `ResolvedHost` and know
they are not handling unresolved user input.

This file pins:
  - construction from a HostPolicy with explicit hostname
  - the wrapper's `hostname` mirrors the policy's `hostname`
  - frozen / immutable: mutation raises
  - extra="forbid": unknown fields rejected
  - equality: two ResolvedHost with the same fields compare equal
  - the policy round-trips identically (same object reference)
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from ssh_mcp.models.policy import AuthPolicy, HostPolicy, ResolvedHost


def _policy(host: str = "web01.internal", user: str = "deploy") -> HostPolicy:
    return HostPolicy(
        hostname=host,
        user=user,
        port=22,
        auth=AuthPolicy(method="agent"),
    )


class TestResolvedHostConstruction:
    def test_construction_with_explicit_hostname(self) -> None:
        policy = _policy()
        resolved = ResolvedHost(hostname=policy.hostname, policy=policy)
        assert resolved.hostname == "web01.internal"
        assert resolved.policy is policy

    def test_hostname_can_mirror_policy_hostname(self) -> None:
        """The canonical use: wrapper.hostname == policy.hostname.

        That mirror is what the wrapper documents -- the canonical post-
        resolution hostname. The type does not enforce this equality so
        tests can still construct synthetic mismatches if needed; the
        production helper `_context.resolve_host` always sets them equal.
        """
        policy = _policy(host="prod-db.internal")
        resolved = ResolvedHost(hostname=policy.hostname, policy=policy)
        assert resolved.hostname == resolved.policy.hostname

    def test_policy_reference_round_trips(self) -> None:
        """Pydantic copies model fields on validation by default. We rely on
        equality (not `is`) because the wrapper may revalidate the inner
        HostPolicy. The semantic guarantee is that `.policy` reproduces the
        input policy's fields."""
        policy = _policy()
        resolved = ResolvedHost(hostname="web01.internal", policy=policy)
        assert resolved.policy == policy
        assert resolved.policy.user == "deploy"
        assert resolved.policy.port == 22


class TestResolvedHostFrozen:
    def test_assigning_hostname_raises(self) -> None:
        policy = _policy()
        resolved = ResolvedHost(hostname=policy.hostname, policy=policy)
        with pytest.raises(ValidationError):
            resolved.hostname = "other.internal"

    def test_assigning_policy_raises(self) -> None:
        policy = _policy()
        resolved = ResolvedHost(hostname=policy.hostname, policy=policy)
        with pytest.raises(ValidationError):
            resolved.policy = _policy(host="other.internal")


class TestResolvedHostExtraForbid:
    def test_unknown_field_rejected(self) -> None:
        policy = _policy()
        with pytest.raises(ValidationError):
            ResolvedHost(  # type: ignore[call-arg]
                hostname=policy.hostname,
                policy=policy,
                bogus="not-a-real-field",
            )


class TestResolvedHostEquality:
    def test_same_fields_compare_equal(self) -> None:
        policy = _policy()
        a = ResolvedHost(hostname=policy.hostname, policy=policy)
        b = ResolvedHost(hostname=policy.hostname, policy=policy)
        assert a == b

    def test_different_hostname_not_equal(self) -> None:
        policy = _policy()
        a = ResolvedHost(hostname="web01.internal", policy=policy)
        b = ResolvedHost(hostname="web01.internal", policy=_policy(host="other.internal"))
        # Different inner policy hostname -> not equal even if wrapper hostname matches.
        assert a != b

    def test_different_policy_not_equal(self) -> None:
        a = ResolvedHost(hostname="web01.internal", policy=_policy(user="deploy"))
        b = ResolvedHost(hostname="web01.internal", policy=_policy(user="root"))
        assert a != b
