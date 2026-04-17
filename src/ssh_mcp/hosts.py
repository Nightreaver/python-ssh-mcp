"""hosts.toml loader. See DESIGN.md §5.7 and ADR-0003 / ADR-0004."""
from __future__ import annotations

import logging
import os
import tomllib
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from .models.policy import AuthPolicy, HostPolicy

if TYPE_CHECKING:
    from pathlib import Path

    from .config import Settings

logger = logging.getLogger(__name__)


class HostsConfigError(ValueError):
    """Raised when hosts.toml is structurally or logically invalid."""


def load_hosts(path: Path | None, settings: Settings) -> dict[str, HostPolicy]:
    """Load hosts.toml and return resolved {name: HostPolicy}.

    Returns {} when path is None or the file does not exist (env-only mode).
    Raises HostsConfigError on any validation failure.
    """
    if path is None:
        return {}
    path = path.expanduser()
    if not path.exists():
        logger.info("hosts.toml not found at %s; running in env-only mode", path)
        return {}

    raw = _read_toml(path)
    defaults_raw = raw.get("defaults", {}) or {}
    hosts_raw = raw.get("hosts", {}) or {}

    if not isinstance(hosts_raw, dict):
        raise HostsConfigError("'hosts' must be a table in hosts.toml")

    env_fallbacks = _env_fallbacks(settings)
    policies: dict[str, HostPolicy] = {}
    for name, host_block in hosts_raw.items():
        if not isinstance(host_block, dict):
            raise HostsConfigError(f"hosts.{name} must be a table")
        merged = _merge_host(name, defaults_raw, host_block, env_fallbacks)
        try:
            policies[name] = HostPolicy(**merged)
        except ValidationError as exc:
            raise HostsConfigError(f"hosts.{name}: {exc}") from exc

    _validate_proxy_chains(policies)
    _validate_password_auth(policies, settings)
    _warn_on_risky_config(policies, settings)
    return policies


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise HostsConfigError(f"{path}: {exc}") from exc


def _env_fallbacks(settings: Settings) -> dict[str, Any]:
    """Defaults pulled from env when hosts.toml omits them."""
    fallbacks: dict[str, Any] = {"user": settings.SSH_DEFAULT_USER, "port": 22}
    if settings.SSH_DEFAULT_KEY is not None:
        fallbacks["auth"] = {"method": "key", "key": str(settings.SSH_DEFAULT_KEY)}
    return fallbacks


def _merge_host(
    name: str,
    defaults_raw: dict[str, Any],
    host_raw: dict[str, Any],
    env_fallbacks: dict[str, Any],
) -> dict[str, Any]:
    """Merge defaults + host block + env fallbacks. Host wins; then defaults; then env."""
    merged: dict[str, Any] = dict(env_fallbacks)
    merged.update(defaults_raw)
    merged.update(host_raw)

    if "hostname" not in merged:
        merged["hostname"] = name

    auth_defaults = defaults_raw.get("auth", {}) or {}
    auth_host = host_raw.get("auth", {}) or {}
    auth_env = env_fallbacks.get("auth", {}) or {}
    merged_auth: dict[str, Any] = {**auth_env, **auth_defaults, **auth_host}
    if merged_auth:
        merged["auth"] = _expand_auth(merged_auth)

    return merged


def _expand_auth(auth: dict[str, Any]) -> dict[str, Any]:
    """Expand ${VAR} / ~ in path-like auth fields."""
    out: dict[str, Any] = dict(auth)
    for field in ("identity_agent", "key"):
        v = out.get(field)
        if isinstance(v, str):
            out[field] = os.path.expandvars(os.path.expanduser(v))
    # Validate Pydantic shape up front so error messages reference the auth block.
    try:
        AuthPolicy(**out)
    except ValidationError as exc:
        raise HostsConfigError(f"auth block invalid: {exc}") from exc
    return out


def _validate_proxy_chains(policies: dict[str, HostPolicy]) -> None:
    """Every proxy_jump reference must exist; no cycles allowed."""
    for name, policy in policies.items():
        chain = policy.proxy_chain()
        if not chain:
            continue
        seen = {name}
        for hop in chain:
            if hop not in policies:
                raise HostsConfigError(
                    f"hosts.{name}.proxy_jump references unknown host {hop!r}"
                )
            if hop in seen:
                raise HostsConfigError(
                    f"circular proxy_jump chain detected starting at {name!r}"
                )
            seen.add(hop)
            hop_chain = policies[hop].proxy_chain()
            for deeper in hop_chain:
                if deeper in seen:
                    raise HostsConfigError(
                        f"circular proxy_jump chain detected starting at {name!r}"
                    )
                seen.add(deeper)


def _validate_password_auth(policies: dict[str, HostPolicy], settings: Settings) -> None:
    if settings.ALLOW_PASSWORD_AUTH:
        return
    for name, policy in policies.items():
        if policy.auth.method == "password":
            raise HostsConfigError(
                f"hosts.{name} uses password auth but ALLOW_PASSWORD_AUTH=false"
            )


# Defense-in-depth: when an operator opens path_allowlist to "*" / "/" we
# remind them that nothing carves out the obvious sensitive zones unless
# they list them in restricted_paths. This is a HINT, not a ban -- some
# hosts genuinely don't have these (containers, embedded), and the operator
# may have a different list in mind. See INCIDENTS.md INC-015 for the
# bvisible/mcp-ssh-manager#13 audit this was motivated by.
# Absolute paths only -- restricted_paths validator rejects "~/.ssh" etc.
# Per-user ssh dirs (`/root/.ssh`, `/home/<user>/.ssh`) need the operator
# to add them explicitly with their actual remote home; we can't know it.
_RECOMMENDED_RESTRICTED = (
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh",
)


def _warn_on_risky_config(policies: dict[str, HostPolicy], settings: Settings) -> None:
    env_restricted = set(settings.SSH_RESTRICTED_PATHS)
    # Always warn on path "*" / "/" -- these widen scope regardless of tier flags.
    for name, policy in policies.items():
        wildcard_entry = next(
            (root for root in policy.path_allowlist if root in ("*", "/")), None,
        )
        if wildcard_entry is None:
            continue
        logger.warning(
            "host %r uses wildcard path_allowlist (entry %r); every absolute "
            "path this SSH user can reach is accepted by MCP tools",
            name,
            wildcard_entry,
        )
        # Hint when none of the recommended sensitive zones are in either the
        # per-host or global restricted_paths.
        effective_restricted = set(policy.restricted_paths) | env_restricted
        missing = [
            r for r in _RECOMMENDED_RESTRICTED
            if not any(r == p or p.startswith(r) for p in effective_restricted)
        ]
        if missing:
            logger.warning(
                "host %r has wildcard path_allowlist but no restricted_paths "
                "covering %s -- consider adding them (per-host `restricted_paths` "
                "in hosts.toml or env SSH_RESTRICTED_PATHS) so low-access + "
                "sftp-read tools can't read credentials by accident.",
                name, missing,
            )

    if not settings.ALLOW_DANGEROUS_TOOLS:
        return
    for name, policy in policies.items():
        if "*" in policy.command_allowlist:
            logger.warning(
                "host %r uses wildcard command_allowlist (entry '*') with "
                "ALLOW_DANGEROUS_TOOLS=true; every command is accepted on this host",
                name,
            )
        elif not policy.command_allowlist and not settings.ALLOW_ANY_COMMAND:
            # Empty allowlist without ALLOW_ANY_COMMAND is fail-closed -- no warning
            # needed since check_command() will reject every call anyway.
            continue
        elif not policy.command_allowlist:
            logger.warning(
                "host %r has empty command_allowlist but ALLOW_DANGEROUS_TOOLS=true "
                "and ALLOW_ANY_COMMAND=true; exec tools will accept any command",
                name,
            )


def merged_host_allowlist(
    policies: dict[str, HostPolicy], settings: Settings
) -> set[str]:
    """Union of hosts.toml keys + SSH_HOSTS_ALLOWLIST env."""
    return set(policies.keys()) | set(settings.SSH_HOSTS_ALLOWLIST)
