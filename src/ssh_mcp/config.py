"""Configuration loaded from environment variables / .env."""

from __future__ import annotations

import os as _os
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# SSH_MCP_DISABLE_DOTENV=1 skips .env file loading entirely. Set by
# tests/conftest.py so the operator's personal .env doesn't bleed into
# test assertions that check built-in defaults.
_ENV_FILE: str | None = None if _os.environ.get("SSH_MCP_DISABLE_DOTENV") else ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- SSH transport ---
    SSH_CONFIG_FILE: Path | None = None
    SSH_KNOWN_HOSTS: Path = Path.home() / ".ssh" / "known_hosts"
    SSH_DEFAULT_USER: str = "root"
    SSH_DEFAULT_KEY: Path | None = None
    SSH_HOSTS_FILE: Path | None = Path("hosts.toml")
    ALLOW_PASSWORD_AUTH: bool = False
    SSH_SKILLS_DIR: Path | None = Path("skills")

    # Workflow runbooks — multi-tool procedures (incident response, deploy +
    # verify, integrity audit, ...). Distinct from per-tool skills. Mounted
    # as a separate `SkillsDirectoryProvider` so operators can toggle them
    # off for tool-execution-only assistants that don't need narrative
    # guidance. See [skills vs runbooks] split in README.
    SSH_RUNBOOKS_DIR: Path | None = Path("runbooks")
    # Set to false to skip mounting `SSH_RUNBOOKS_DIR` entirely -- useful
    # for context-constrained clients or tool-execution-only deployments.
    # Per-tool skills under `SSH_SKILLS_DIR` stay unaffected.
    #
    # Note: there's no symmetric `SSH_ENABLE_SKILLS` toggle. Per-tool skills
    # are near-free context (client pulls them on demand, not preloaded) and
    # are load-bearing for how LLMs use the catalog. Runbooks are heavier
    # (full procedures, typically several pages) and optional for clients
    # that only want direct tool calls. Asymmetry is deliberate.
    SSH_ENABLE_RUNBOOKS: bool = True

    # Explicit opt-in for unrestricted exec when no command_allowlist is set.
    # Empty allowlist now DENIES — this flag is the only way to run any command.
    ALLOW_ANY_COMMAND: bool = False

    # Docker CLI invocation. Default `docker`; set to `podman` for Podman
    # hosts (API-compatible CLI + JSON output). Shell-split so operators
    # can prefix with `sudo`, `env`, wrappers, etc. Per-host override:
    # `docker_cmd = "podman"` in hosts.toml.
    SSH_DOCKER_CMD: str = "docker"

    # Docker compose invocation. Modern Docker uses `docker compose` (a
    # subcommand of the `docker` binary). Empty = derive at runtime as
    # `{SSH_DOCKER_CMD} compose` (so `SSH_DOCKER_CMD=podman` automatically
    # yields `podman compose`). Set explicitly only for legacy hosts with
    # the standalone `docker-compose` / `podman-compose` binary. Shell-split.
    SSH_DOCKER_COMPOSE_CMD: str = ""

    # INC-022: `ssh_docker_run` rejects known host-escape flags
    # (--privileged, --cap-add, --pid=host, --net=host, --volume=/:, etc.)
    # by default, even under ALLOW_DANGEROUS_TOOLS. Set this to true to
    # permit them -- equivalent to granting root on the target host.
    ALLOW_DOCKER_PRIVILEGED: bool = False

    # Dotted import path of an operator-supplied module exposing
    #   def register_hooks(registry: HookRegistry) -> None: ...
    # Loaded in the lifespan; missing module or missing function is a warning,
    # not a startup failure. See services/hooks.py.
    SSH_HOOKS_MODULE: str | None = None

    # Global gate for persistent shell sessions (ssh_shell_open / ssh_shell_exec).
    # Default True. When False, those two tools are hidden from tools/list via a
    # Visibility transform; ssh_shell_list and ssh_shell_close stay available so
    # operators can still audit / clean up pre-existing sessions.
    # Per-host override: `persistent_session = false` in hosts.toml rejects
    # specific hosts at call time. BOTH must pass (AND semantics).
    ALLOW_PERSISTENT_SESSIONS: bool = True

    # Which tool groups are visible to the LLM (subject to tier gates).
    # Empty = all groups enabled; see ADR-0016.
    SSH_ENABLED_GROUPS: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- Allowlists / blocklists ---
    # Exact-match hostnames. Blocklist wins over allowlist.
    # `NoDecode` bypasses pydantic-settings' automatic JSON decoding of list
    # fields so our `_accept_csv` field validator sees the raw string (e.g.
    # "" from `SSH_HOSTS_ALLOWLIST=` in a .env file). Without this, an empty
    # string for a complex-type field crashes the DotEnvSettingsSource before
    # any field validator runs.
    SSH_HOSTS_ALLOWLIST: Annotated[list[str], NoDecode] = Field(default_factory=list)
    SSH_HOSTS_BLOCKLIST: Annotated[list[str], NoDecode] = Field(default_factory=list)
    SSH_PATH_ALLOWLIST: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Restricted zones applied on top of path_allowlist. Low-access + sftp-read
    # tools refuse these paths; exec/sudo unaffected. Unions with per-host
    # `restricted_paths` in hosts.toml.
    SSH_RESTRICTED_PATHS: Annotated[list[str], NoDecode] = Field(default_factory=list)
    SSH_COMMAND_ALLOWLIST: Annotated[list[str], NoDecode] = Field(default_factory=list)

    @field_validator("SSH_CONFIG_FILE", mode="before")
    @classmethod
    def _empty_path_to_none(cls, v: Any) -> Any:
        """Treat `SSH_CONFIG_FILE=` (blank in .env) as unset.

        Without this, pydantic coerces "" into Path(""), which is truthy and
        sends an empty config path through to asyncssh. Operators leaving the
        field blank in `.env.example` expect "off", not "parse the empty path".
        """
        if isinstance(v, str) and not v.strip():
            return None
        return v

    @field_validator(
        "SSH_HOSTS_ALLOWLIST",
        "SSH_HOSTS_BLOCKLIST",
        "SSH_PATH_ALLOWLIST",
        "SSH_RESTRICTED_PATHS",
        "SSH_COMMAND_ALLOWLIST",
        "SSH_ENABLED_GROUPS",
        "SSH_BM25_ALWAYS_VISIBLE",
        mode="before",
    )
    @classmethod
    def _accept_csv(cls, v: Any) -> Any:
        """Allow comma-separated env vars (`A,B,C`) in addition to JSON arrays."""
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            if s.startswith("["):
                import json

                return json.loads(s)
            return [item.strip() for item in s.split(",") if item.strip()]
        return v

    # --- Caps / timeouts ---
    SSH_CONNECT_TIMEOUT: int = 10
    SSH_COMMAND_TIMEOUT: int = 60
    SSH_IDLE_TIMEOUT: int = 300
    SSH_KEEPALIVE_INTERVAL: int = 30
    SSH_MAX_CONNECTIONS_PER_HOST: int = 4
    SSH_STDOUT_CAP_BYTES: int = 1 << 20
    SSH_STDERR_CAP_BYTES: int = 1 << 20
    SSH_EDIT_MAX_FILE_BYTES: int = 10 << 20
    SSH_UPLOAD_MAX_FILE_BYTES: int = 256 << 20
    SSH_FIND_MAX_DEPTH: int = 10
    SSH_FIND_MAX_RESULTS: int = 10_000
    SSH_DELETE_FOLDER_MAX_ENTRIES: int = 10_000

    # --- Access tiers (default-deny) ---
    ALLOW_LOW_ACCESS_TOOLS: bool = False
    ALLOW_DANGEROUS_TOOLS: bool = False
    ALLOW_SUDO: bool = False
    SSH_ALLOW_KNOWN_HOSTS_WRITE: bool = False

    # --- Sudo ---
    SSH_SUDO_PASSWORD_CMD: str | None = None
    SSH_SUDO_MODE: Literal["per-call", "persistent-su"] = "per-call"

    # --- Tool discovery (BM25 search transform) ---
    # With 52+ tools the full tools/list schema is ~15-25k tokens per turn.
    # BM25SearchTransform replaces the catalog with two synthetic tools --
    # `search_tools(query)` and `call_tool(name, args)` -- plus any names in
    # SSH_BM25_ALWAYS_VISIBLE. The LLM searches for what it needs. Default OFF;
    # flip ON when context pressure outweighs the extra hop.
    SSH_ENABLE_BM25: bool = False
    SSH_BM25_MAX_RESULTS: int = 8
    # Tools that stay in tools/list regardless of BM25 -- give the LLM a
    # discoverability anchor so it knows the server exists. Keep small.
    SSH_BM25_ALWAYS_VISIBLE: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "ssh_host_ping",
            "ssh_host_info",
            "ssh_session_list",
            "ssh_shell_list",
        ]
    )

    # --- Observability ---
    VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"
    OTEL_ENABLED: bool = True


settings = Settings()
