"""Configuration loaded from environment variables / .env."""

from __future__ import annotations

import os as _os
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
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

    # Per-host agent-written memory (INC-055). Sidecar markdown files at
    # `<dir>/<alias>.md` that the LLM appends to via ssh_host_notes_append /
    # replaces via ssh_host_notes_set. Distinct from `hosts.toml`'s `notes`
    # field, which is the OPERATOR's hard-rule baseline -- the LLM reads
    # both via ssh_host_notes but only writes the sidecar. Set to None to
    # disable agent-side notes (read-only operator layer remains).
    SSH_HOST_NOTES_DIR: Path | None = Path("notes")
    # Cap on a single agent-notes sidecar file. Default 256 KiB -- generous
    # for accumulated memory but small enough that an LLM that goes wild
    # appending can't fill the operator's disk in one session.
    SSH_HOST_NOTES_MAX_BYTES: int = 256 * 1024

    # INC-059: when True (default), `ssh_host_ping` auto-injects the host's
    # operator-baseline notes (from hosts.toml's `notes` field) into its
    # result. Ping is the canonical "I'm starting work on this host" probe;
    # surfacing hard-rule constraints there means the LLM sees them without
    # needing to remember an explicit `ssh_host_notes` call -- enforcement
    # by ergonomics. Set False for tool-execution-only deployments where
    # ping should stay minimal.
    SSH_PING_INCLUDES_NOTES: bool = True
    # INC-060: parallel toggle for the agent layer (the LLM's own
    # session-spanning sidecar at <SSH_HOST_NOTES_DIR>/<alias>.md).
    # Default True so the LLM gets its past self's learned facts on
    # ping too -- without needing an explicit `ssh_host_notes` call.
    # Trade-off: agent sidecars can grow to SSH_HOST_NOTES_MAX_BYTES
    # (default 256 KiB) -- if your fleet's notes are large and ping
    # context inflation matters, set this False and rely on the
    # explicit tool. Independent of `SSH_PING_INCLUDES_NOTES` so an
    # operator can toggle the two layers separately.
    SSH_PING_INCLUDES_AGENT_NOTES: bool = True

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

    # Default-on rejection of `ssh_exec_run` / `_streaming` / `ssh_sudo_exec`
    # commands that match the cheatsheet (services/exec_cheatsheet.py).
    # Cheatsheet patterns are command shapes that have a dedicated native MCP
    # tool -- heredoc / tee / echo > path file-writes, leading `docker`,
    # `systemctl <verb>`, `journalctl`, `apt(-get) install|remove|upgrade|...`,
    # single mkdir/cp/mv/rm, output redirection to a real file. When False
    # (default), matching commands are refused with `CommandIsCheatsheetMatch`
    # and a hint pointing to the native tool. Set True to temporarily disable
    # for legacy automation; the intent is that operators fix the automation
    # to use the wrapper rather than relying on this opt-out long-term.
    SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS: bool = False

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

    # --- Secret-redaction policy (v1.4.0) ---
    # Glob-aware sibling to SSH_RESTRICTED_PATHS. Prefix-based ``restricted_paths``
    # stays as-is (cheap, simple); these globs are unioned on the deny side and
    # match via ``pathlib.PurePosixPath.match`` (POSIX semantics; Windows hosts
    # still flow through path_policy's Platform parameter). Example:
    #   SSH_RESTRICTED_GLOBS=**/.env,**/secrets/*,**/private*
    SSH_RESTRICTED_GLOBS: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Paths matching any of these globs are READABLE via ``ssh_read_redacted``
    # but trip the bypass-policy (block/warn/audit_only) when accessed via
    # ``ssh_sftp_download`` / other path-bearing tools that would return raw
    # bytes. Distinct from ``SSH_RESTRICTED_GLOBS`` -- that one is hard-deny.
    SSH_REDACT_PATHS_GLOBS: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Per-key redaction list (case-insensitive substring match on the KEY name
    # in KEY=VALUE shapes). MUTUALLY EXCLUSIVE with SSH_REDACT_KEYS_REPLACE:
    # setting both at this scope raises a validation error. ADD appends to
    # the built-in defaults (PASSWORD, PASSWD, SECRET, TOKEN, KEY, PRIVATE,
    # CREDENTIAL[S], API_KEY, APIKEY, DSN, AUTH, BEARER, COOKIE, SESSION,
    # JWT, OAUTH, SSH_KEY -- see services/redact_policy._DEFAULT_REDACT_KEYS).
    SSH_REDACT_KEYS_ADD: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # REPLACE swaps out the defaults entirely. Use when the defaults include
    # something you specifically want to expose (e.g. a non-secret ``KEY``
    # field), or when you want a tight allowlist of exactly N tokens.
    SSH_REDACT_KEYS_REPLACE: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # HMAC-SHA256 key for hashed-output redaction. When set, the marker emitted
    # for a redacted value is ``<sha:abcdef123456 len:48>`` where the hex
    # prefix is deterministic across hosts (lets the LLM compare secrets by
    # identity without seeing them). When EMPTY (the default), the engine
    # falls back to plain SHA256 -- still deterministic, but an attacker with
    # a known plaintext can confirm it without the salt. Recommended >= 32
    # chars of random data; rejected at startup if set to <32 chars.
    SSH_REDACT_SALT: str = ""
    # When True (default), the redactor ALSO scans for high-entropy strings
    # outside KEY=VALUE shape (base64 >= 20 chars, hex >= 32 chars). PEM blocks
    # are ALWAYS redacted regardless. When False, only KEY=VALUE matches are
    # redacted -- hardcoded secrets in random scripts pass through.
    SSH_REDACT_ENTROPY_DETECTION: bool = True
    # What happens when a path-bearing tool (ssh_sftp_download, ssh_sftp_list,
    # ssh_find, ssh_file_hash, file-ops) touches a path matching
    # SSH_REDACT_PATHS_GLOBS. ``block``: refuse with RedactBypassBlocked
    # pointing at ssh_read_redacted. ``warn`` (default): deliver raw content
    # with a warning appended to output_warnings. ``audit_only``: deliver
    # silently with a flag in the audit line.
    SSH_REDACT_BYPASS_POLICY: Literal["block", "warn", "audit_only"] = "warn"
    # If non-zero, ssh_read_redacted's marker carries ``hint:<first-N>...<last-N>``
    # so humans can compare secrets across hosts at a glance. Leaks 2N chars
    # of plaintext per secret -- USE WITH CARE. Capped at 4 each side.
    SSH_REDACT_HINT_CHARS: int = 0

    # Local-disk allowlist for the `local_path` upload/download mode (v1.3.0).
    # When ``ssh_upload`` / ``ssh_deploy`` / ``ssh_sftp_download`` are called
    # with ``local_path=...`` the MCP server reads/writes that file directly
    # on its OWN filesystem instead of routing the bytestream through the
    # MCP JSON channel as base64. The LLM never sees the payload.
    #
    # Empty list (the default) ⇒ ``local_path`` mode is fully DISABLED. Any
    # call passing ``local_path=`` raises ``LocalPathPolicyError`` pointing at
    # this setting. No "smart" fallbacks (no cwd, no MCP-roots, no
    # ~/Downloads default) -- the operator must opt in explicitly.
    #
    # Each entry is an absolute path on the MCP host. The target file must
    # resolve (symlinks followed) to a child of one of these roots. Paths
    # are NOT validated at load time -- they may exist intermittently (mounted
    # volumes, removable media) and we don't want a transiently-missing root
    # to crash startup.
    SSH_LOCAL_TRANSFER_ROOTS: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Size cap for the `local_path` code path ONLY. Default 2 GiB. The
    # existing `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB) continues to apply to
    # `content_text` / `content_base64` uploads and to the base64-encoded
    # `ssh_sftp_download` response -- those still pass through the MCP
    # JSON channel and want a stricter envelope. `local_path` bypasses
    # that channel and can stream much larger files safely.
    SSH_LOCAL_TRANSFER_MAX_BYTES: int = 2 << 30

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
        "SSH_RESTRICTED_GLOBS",
        "SSH_REDACT_PATHS_GLOBS",
        "SSH_REDACT_KEYS_ADD",
        "SSH_REDACT_KEYS_REPLACE",
        "SSH_COMMAND_ALLOWLIST",
        "SSH_ENABLED_GROUPS",
        "SSH_BM25_ALWAYS_VISIBLE",
        "SSH_LOCAL_TRANSFER_ROOTS",
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

    # --- MCP transport ---
    # FastMCP transport. `stdio` (default) is what every MCP client launcher
    # expects. `http` / `streamable-http` / `sse` expose the server over HTTP;
    # there is NO built-in auth or TLS -- put it behind a reverse proxy with
    # a bearer token / mTLS before binding to anything other than loopback.
    MCP_TRANSPORT: Literal["stdio", "http", "streamable-http", "sse"] = "stdio"
    MCP_HTTP_HOST: str = "127.0.0.1"
    MCP_HTTP_PORT: int = 8000

    @model_validator(mode="after")
    def _check_redact_config(self) -> Settings:
        """Validate the secret-redaction knobs introduced in v1.4.0.

        Three checks:

        1. ``SSH_REDACT_KEYS_ADD`` and ``SSH_REDACT_KEYS_REPLACE`` are mutually
           exclusive -- ADD appends to the built-in defaults, REPLACE swaps
           them out, and combining the two is almost certainly an operator
           typo. Raise a clear error naming both knobs so the fix is obvious.
        2. ``SSH_REDACT_SALT`` is either empty (warned-but-allowed plain-SHA256
           mode) OR at least 32 chars of operator-chosen entropy. Sub-32 is
           almost certainly an accidental short string; we reject so the
           operator notices.
        3. ``SSH_REDACT_HINT_CHARS`` clamped to ``[0, 4]``. The hint deliberately
           leaks 2N raw characters per secret; capping at 4 each side limits
           the damage of an over-permissive operator value.
        """
        if self.SSH_REDACT_KEYS_ADD and self.SSH_REDACT_KEYS_REPLACE:
            raise ValueError(
                "SSH_REDACT_KEYS_ADD and SSH_REDACT_KEYS_REPLACE are mutually "
                "exclusive: ADD appends to the built-in defaults, REPLACE swaps "
                "them out. Set one or the other, not both."
            )
        if self.SSH_REDACT_SALT and len(self.SSH_REDACT_SALT) < 32:
            raise ValueError(
                f"SSH_REDACT_SALT must be at least 32 chars when set "
                f"(got {len(self.SSH_REDACT_SALT)}). Pick a strong random "
                "secret, or leave empty to use plain-SHA256 mode."
            )
        if not 0 <= self.SSH_REDACT_HINT_CHARS <= 4:
            raise ValueError(
                f"SSH_REDACT_HINT_CHARS must be in [0, 4] "
                f"(got {self.SSH_REDACT_HINT_CHARS}); the hint leaks 2N raw "
                "characters per secret, capping at 4 each side limits exposure."
            )
        return self

    # --- Observability ---
    VERSION: str = "1.5.2"
    LOG_LEVEL: str = "INFO"
    OTEL_ENABLED: bool = True


settings = Settings()
