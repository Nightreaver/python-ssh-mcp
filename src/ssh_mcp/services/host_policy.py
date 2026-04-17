"""Host allowlist + blocklist resolution. One place, called by tools and the pool.

Rules (ADR-0015 revised by ADR-0019):

- Aliases are a **lookup mechanism only**. Allow/block rules evaluate on the
  canonical identifier: ``policy.hostname`` (the string we actually connect to).
- `SSH_HOSTS_BLOCKLIST` is matched against `policy.hostname` after resolution.
  Blocking by alias is no longer supported -- put the hostname in the blocklist.
- Allowlist = union of `hosts.toml` hostnames + `SSH_HOSTS_ALLOWLIST` entries.
  (hosts.toml aliases let you LOOK UP a policy; the resulting `hostname` is
  what the allowlist check considers.)
- Unknown (no matching alias, no matching hostname, not in env allowlist):
  `HostNotAllowed` -- even if the name happens to also be on the blocklist.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..models.policy import AuthPolicy, HostPolicy
from ..ssh.errors import HostBlocked, HostNotAllowed

if TYPE_CHECKING:
    from ..config import Settings


def resolve(
    name: str,
    hosts: dict[str, HostPolicy],
    settings: Settings,
) -> HostPolicy:
    """Resolve `name` to a HostPolicy, then evaluate policy on the canonical hostname.

    Resolution order:
      1. `name` matches a `hosts.<alias>` in hosts.toml -> that entry's policy.
      2. `name` matches `hosts.*.hostname` -> that entry's policy.
      3. `name` is in `SSH_HOSTS_ALLOWLIST` -> minimal policy built from env defaults.
      4. Otherwise: `HostNotAllowed`.

    Then `check_policy()` evaluates the blocklist against `policy.hostname`.
    """
    policy = _locate(name, hosts, settings)
    check_policy(policy, settings)
    return policy


def check_policy(policy: HostPolicy, settings: Settings) -> None:
    """Evaluate blocklist on the canonical `policy.hostname` only.

    Called both from `resolve()` and from the pool, so a HostPolicy constructed
    outside of resolve() still gets the blocklist check.
    """
    if policy.hostname in settings.SSH_HOSTS_BLOCKLIST:
        raise HostBlocked(
            f"host {policy.hostname!r} is on SSH_HOSTS_BLOCKLIST. "
            f"This is an intentional safety rail -- do not retry. If this "
            f"block looks wrong, escalate to a human operator."
        )


def _locate(
    name: str,
    hosts: dict[str, HostPolicy],
    settings: Settings,
) -> HostPolicy:
    if not hosts and not settings.SSH_HOSTS_ALLOWLIST:
        raise HostNotAllowed(
            "no hosts configured: add hosts.toml or set SSH_HOSTS_ALLOWLIST"
        )

    if name in hosts:
        return hosts[name]

    for policy in hosts.values():
        if policy.hostname == name:
            return policy

    if name in settings.SSH_HOSTS_ALLOWLIST:
        return HostPolicy(
            hostname=name,
            user=settings.SSH_DEFAULT_USER,
            port=22,
            auth=AuthPolicy(
                method="key" if settings.SSH_DEFAULT_KEY else "agent",
                key=settings.SSH_DEFAULT_KEY,
            ),
        )

    known = sorted(hosts.keys())
    raise HostNotAllowed(
        f"host {name!r} is not allowlisted. "
        f"Known aliases: {known!r}. Remediation: pick one of those, or ask "
        f"the operator to add this host to hosts.toml or SSH_HOSTS_ALLOWLIST."
    )
