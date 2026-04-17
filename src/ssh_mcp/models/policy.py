"""Per-host policy models loaded from hosts.toml. See DESIGN.md §5.7."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# `Path` MUST stay as a runtime import (not under `TYPE_CHECKING`): pydantic
# v2's model build calls `get_type_hints()` to resolve string annotations into
# actual types for validation, and `Path` is referenced in field annotations
# below. Moved here from a TYPE_CHECKING block when the ruff rule expansion
# (INC-045) tried to push it under there -- 131 tests broke with
# `PydanticUserError: AuthPolicy is not fully defined`.

# Windows absolute paths: `C:\foo`, `C:/foo`, case-insensitive drive letter.
# Matched in addition to POSIX `/...` so path_allowlist / restricted_paths can
# carry either flavour. Platform-specific matching (case-folding, separator
# normalization) happens in services/path_policy.
_WINDOWS_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _is_absolute_any_platform(p: str) -> bool:
    """True for POSIX `/foo` OR Windows `C:\\foo` / `C:/foo`."""
    return p.startswith("/") or bool(_WINDOWS_ABS_RE.match(p))


class AuthPolicy(BaseModel):
    """Auth configuration for a single host. See DESIGN.md §5.7a."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["agent", "key", "password"] = "agent"

    # method == "agent"
    identity_agent: Path | None = None
    identity_fingerprint: str | None = None
    identities_only: bool = False

    # method == "key"
    key: Path | None = None
    passphrase_cmd: str | None = None

    # method == "password" (refused unless ALLOW_PASSWORD_AUTH is set)
    password_cmd: str | None = None

    @field_validator("identity_fingerprint")
    @classmethod
    def _check_fingerprint_format(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v.startswith("SHA256:") or len(v) < len("SHA256:") + 16:
            raise ValueError("identity_fingerprint must look like 'SHA256:<base64>'")
        return v


class AlertsPolicy(BaseModel):
    """Per-host alerting thresholds evaluated by ``ssh_host_alerts``.

    All fields optional. When a threshold is unset, the corresponding metric
    is not evaluated and does not appear in the breaches list.
    """

    model_config = ConfigDict(extra="forbid")

    # Disk: breach when ANY mount's use_percent exceeds this value.
    disk_use_percent_max: int | None = None
    # Load average (1-minute): breach when load avg > this (Linux only).
    load_avg_1min_max: float | None = None
    # Memory: breach when free memory as % of total < this.
    mem_free_percent_min: int | None = None
    # Optional mount-path filter for disk check. Defaults to all real filesystems.
    disk_mounts: list[str] = Field(default_factory=list)


class HostPolicy(BaseModel):
    """Resolved policy for a single named host."""

    model_config = ConfigDict(extra="forbid")

    hostname: str
    user: str
    port: int = 22
    # `posix` covers linux, macos, and BSD -- we only branch on the POSIX/Windows
    # split because that's where behavior diverges (shell, path separator,
    # absence of `realpath` / `sudo`). Finer distinctions (`linux` vs `macos`)
    # can be added later if any tool actually needs them. The validator
    # accepts legacy aliases (`linux`, `macos`, `bsd`) and normalizes them
    # to `posix` for backward compatibility with existing hosts.toml files.
    platform: Literal["posix", "windows"] = "posix"
    default_dir: str | None = None
    sudo_mode: Literal["per-call", "persistent-su"] = "per-call"
    path_allowlist: list[str] = Field(default_factory=list)
    # Restricted zones inside the allowlist that low-access + sftp-read tools
    # refuse to touch. Typical use: an SMB-mounted /mnt/shared where you
    # allow the LLM full access to the host but not that shared data.
    # Operators who must reach these paths fall back to ssh_exec_run /
    # ssh_sudo_exec (subject to dangerous-tier gating).
    restricted_paths: list[str] = Field(default_factory=list)
    command_allowlist: list[str] = Field(default_factory=list)
    proxy_jump: str | list[str] | None = None
    auth: AuthPolicy = Field(default_factory=AuthPolicy)
    alerts: AlertsPolicy = Field(default_factory=AlertsPolicy)
    # Allow persistent shell sessions (`ssh_shell_open` / `_exec`) on this host.
    # Defaults to True -- the ALLOW_DANGEROUS_TOOLS tier flag is the primary
    # security gate. Set False per-host to allow arbitrary exec while
    # specifically denying stateful shells (e.g. production boxes where you
    # don't want an LLM tracking cwd across calls).
    persistent_session: bool = True
    # Override the Docker CLI for this host -- e.g. `podman` on a rootless
    # Podman box, `sudo docker` on a host that needs sudo for Docker access.
    # Shell-split at runtime. None = use the global SSH_DOCKER_CMD (default
    # `docker`). When set, the compose prefix derives from this (unless the
    # operator also sets SSH_DOCKER_COMPOSE_CMD explicitly).
    docker_cmd: str | None = None

    @field_validator("platform", mode="before")
    @classmethod
    def _normalize_platform(cls, v: object) -> object:
        """Backward compat: `linux` / `macos` / `bsd` -> `posix`."""
        if isinstance(v, str) and v.lower() in ("linux", "macos", "bsd", "darwin"):
            return "posix"
        return v

    @field_validator("port")
    @classmethod
    def _check_port(cls, v: int) -> int:
        if not 1 <= v <= 65535:
            raise ValueError(f"port {v} out of range 1..65535")
        return v

    @field_validator("path_allowlist")
    @classmethod
    def _check_absolute_paths(cls, v: list[str]) -> list[str]:
        # "*" and "/" are the documented "allow everything" sentinels -- see
        # services/path_policy._ALLOW_ALL_SENTINELS. Every other entry must be
        # an absolute path so prefix matching is unambiguous. Windows absolute
        # paths (`C:\foo`, `C:/foo`) are accepted in addition to POSIX `/foo`
        # so a host with `platform = "windows"` can express its allowlist in
        # native form; platform-specific matching happens in path_policy.
        for p in v:
            if p in ("*", "/"):
                continue
            if not _is_absolute_any_platform(p):
                raise ValueError(
                    f"path_allowlist entry must be absolute (or '*' / '/'): {p!r}"
                )
        return v

    @field_validator("restricted_paths")
    @classmethod
    def _check_restricted_paths_absolute(cls, v: list[str]) -> list[str]:
        # No sentinels here -- "*" or "/" as restricted would disable the entire
        # low-access + sftp-read tiers on the host. If that's really wanted,
        # the operator sets those tier flags to false instead; here we require
        # explicit absolute paths so the zone is unambiguous. Windows paths
        # accepted (see _check_absolute_paths).
        for p in v:
            if not _is_absolute_any_platform(p):
                raise ValueError(f"restricted_paths entry must be absolute: {p!r}")
        return v

    def proxy_chain(self) -> list[str]:
        """Normalize proxy_jump to a list (possibly empty)."""
        if self.proxy_jump is None:
            return []
        if isinstance(self.proxy_jump, str):
            return [self.proxy_jump]
        return list(self.proxy_jump)
