# AGENTS.md — Python SSH MCP Server

Architecture, security model, and engineering conventions for `python-ssh-mcp` — a FastMCP 3 server exposing SSH / SFTP / Docker / systemd operations as MCP tools.

**Change-control:** any significant change in implementation, tooling, configuration, or docs must be reviewed against this document, and the document must be updated to reflect the new reality.

---

## 1. Architecture

### 1.1 Layered design

- **Tool layer** — [src/ssh_mcp/tools/](src/ssh_mcp/tools/): thin, typed FastMCP entry points. No SSH primitives here. Organized by domain and visibility tier (see §3.1).
- **Service layer** — [src/ssh_mcp/services/](src/ssh_mcp/services/): policy enforcement (host / path / exec allowlists, sudo gating), error normalization, correlation IDs, audit logging.
- **Transport layer** — [src/ssh_mcp/ssh/](src/ssh_mcp/ssh/): connection pool, channel lifecycle, SFTP primitives, host-key enforcement. Primary layer for `asyncssh`; [services/path_policy.py](src/ssh_mcp/services/path_policy.py) also uses it for remote path canonicalization.
- **Models** — [src/ssh_mcp/models/](src/ssh_mcp/models/): Pydantic types for tool inputs, results, policy, file metadata.
- **Runtime glue** — [server.py](src/ssh_mcp/server.py) (FastMCP instance + tool registration), [lifespan.py](src/ssh_mcp/lifespan.py) (pool + known_hosts + visibility transforms), [config.py](src/ssh_mcp/config.py) (env-sourced settings), [`__main__.py`](src/ssh_mcp/__main__.py) (entry point).

Benefits: tool layer tests against a mocked service; service layer tests against a fake transport; transport swaps are local to `ssh/`.

### 1.2 Configuration and docs files

Config:

- [pyproject.toml](pyproject.toml) — project and dependencies.
- [fastmcp.json](fastmcp.json) — FastMCP server manifest (command, args, env).
- [hosts.toml](hosts.toml) — allowlisted hosts + per-host policy (commands, paths, sudo, platform). Fields here win over `~/.ssh/config`.
- [.env.example](.env.example) — required + optional env vars; copy to `.env` for local dev.

Docs (source of truth — keep in sync with code; edits flow through `docs-keeper`):

- [AGENTS.md](AGENTS.md) — this file: architecture, security model, conventions.
- [README.md](README.md) — user-facing install/config docs.
- [TOOLS.md](TOOLS.md) — full tool catalog (names, tiers, inputs, outputs).
- [DESIGN.md](DESIGN.md) — feature spec + implementation sequence.
- [DECISIONS.md](DECISIONS.md) — architectural decision records (ADRs).
- [BACKLOG.md](BACKLOG.md) — phase tracking, work-in-flight.
- [INCIDENTS.md](INCIDENTS.md) — append-only security findings + resolutions.

---

## 2. Security model

The catalog is tiered: most tools are read-only (pings, stats, listings, logs, process/disk introspection, SFTP reads), and a smaller `dangerous` tier holds arbitrary-command exec, SFTP writes, session mutation, and sudo-wrapped operations. Defense in depth targets the dangerous tier — one `ssh_exec_run` on the wrong host can wipe it — and the gating is structured so the read-only surface stays available without ever enabling mutation.

### 2.1 Secure defaults

1. Host-key verification is **on**; `known_hosts` is mandatory. No `AutoAddPolicy` in prod.
2. Password auth is **off**; keys / agent / certs only.
3. Agent forwarding is **off**.
4. `ALLOW_DANGEROUS_TOOLS` and `ALLOW_SUDO` default to `false`.
5. `SSH_HOSTS_ALLOWLIST` must be non-empty in prod; all tools validate `host` against it before touching the network.
6. SFTP paths canonicalized (symlinks resolved, `..` collapsed) **before** allowlist check.
7. Least-privileged SSH accounts — one per deployment, scoped via forced commands or restricted shells where possible.

### 2.2 Six-layer defense for dangerous operations

| Layer | Mechanism | Where |
|---|---|---|
| 1. Config gate | `ALLOW_DANGEROUS_TOOLS=false` → `Visibility(False, tags={"dangerous"})` transform hides dangerous tools from `tools/list`. Same pattern for `ALLOW_SUDO` + `{"sudo"}` tag. | [lifespan.py](src/ssh_mcp/lifespan.py) |
| 2. Host allowlist | Every tool validates `host` against `SSH_HOSTS_ALLOWLIST` (plus per-host policy in [hosts.toml](hosts.toml)) before opening a connection. Wildcards rejected unless explicit. | [services/host_policy.py](src/ssh_mcp/services/host_policy.py) |
| 3. Host-key verification | `known_hosts` mandatory. Unknown / mismatched keys → surface fingerprint to operator out-of-band, never auto-accept from the LLM. | [ssh/known_hosts.py](src/ssh_mcp/ssh/known_hosts.py) |
| 4. Command + path allowlists | `SSH_COMMAND_ALLOWLIST` (optional): `ssh_exec_run` matches first token + optional regex. `SSH_PATH_ALLOWLIST`: SFTP tools reject paths outside the configured roots after canonicalization. | [services/exec_policy.py](src/ssh_mcp/services/exec_policy.py), [services/path_policy.py](src/ssh_mcp/services/path_policy.py) |
| 5. Sudo / privilege | Separate `ALLOW_SUDO` flag — even with dangerous tools enabled, sudo-wrapped commands stay blocked until explicitly opted in. Never pass sudo passwords from tool arguments — rely on passwordless sudoers entries or a credential helper. | [ssh/sudo.py](src/ssh_mcp/ssh/sudo.py) |
| 6. Audit logging | Every dangerous invocation logs: tool, host, user, command/path, exit code, duration, correlation ID. Credentials, key material, stdin payloads redacted. | [services/audit.py](src/ssh_mcp/services/audit.py) |

### 2.3 Command-injection and argument handling

- **Do not concatenate untrusted strings into shell commands inside the server.** Accept the full command from the caller as a single string — the caller (the LLM) owns quoting.
- For synthesized commands, build a fixed argv list and pre-quote with `shlex.join` before handing the string to `conn.create_process` (see [ssh/exec.py](src/ssh_mcp/ssh/exec.py)). Never string-interpolate caller input into the command.
- For `ssh_exec_run_script`, stream the script body via stdin to `sh -s` — do not embed it in the command line.
- Never pass user input through `os.system`, `subprocess` with `shell=True`, or string-interpolated SSH arguments locally.

### 2.4 Credential handling

1. **SSH agent** (`SSH_AUTH_SOCK`) — preferred; no key material touches the server process.
2. **Key file on disk** — ed25519 preferred, then ECDSA, then RSA ≥ 3072 bits. Verify mode `0600`; warn otherwise. Passphrase via OS keychain or agent, never plaintext env var.
3. **Certificate-based auth** — CA-signed user certs where infra supports it.
4. **Password auth** — disabled by default; legacy hosts only, behind explicit flag.

Never log key material, passphrases, passwords, or raw auth banners. Never pass credentials as tool arguments. In-memory key handles stay confined to the transport layer.

### 2.5 Error mapping

Normalized MCP errors — exception details are sanitized to avoid leaking sensitive info:

| Source | MCP error | Notes |
|---|---|---|
| Connection refused / timeout | `HostUnreachable` | Include host, port, elapsed |
| Auth failure | `AuthenticationFailed` | Do NOT include which auth method failed |
| Host key mismatch | `HostKeyMismatch` | Include expected + actual fingerprint; security incident |
| Unknown host (not in known_hosts) | `UnknownHost` | Requires operator approval, not model approval |
| Command non-zero exit | **Not an error** | Return `exit_code`; caller decides |
| Command timeout | `CommandTimeout` | Include partial stdout/stderr if available |
| SFTP permission denied | `PermissionDenied` | Include path |
| SFTP no such file | `NotFound` | Include path |
| Path outside allowlist | `PathNotAllowed` | Security event, WARNING level |
| Host not allowlisted | `HostNotAllowed` | Security event |
| Dangerous tool disabled | `DangerousToolsDisabled` | Point to the env var |

---

## 3. Tool design

### 3.1 Naming and organization

Pattern: `ssh_<domain>_<operation>`. Domains currently registered (from `group:` tags): `host`, `session`, `sftp-read`, `file-ops`, `shell`, `exec`, `sudo`, `docker`.

Illustrative names per tier (see [TOOLS.md](TOOLS.md) for the full catalog):

- **safe**: `ssh_host_ping`, `ssh_sftp_list`, `ssh_sftp_download`, `ssh_docker_ps`, `ssh_known_hosts_verify`
- **low-access**: `ssh_mkdir`, `ssh_upload`, `ssh_edit`, `ssh_docker_compose_start`, `ssh_docker_cp`
- **dangerous**: `ssh_exec_run`, `ssh_exec_script`, `ssh_shell_open`, `ssh_docker_run`, `ssh_docker_rm`
- **sudo**: `ssh_sudo_exec`, `ssh_sudo_run_script`

Rules: lowercase `[a-z0-9_-]`, no dots, descriptive but concise.

### 3.2 Visibility tiers (FastMCP tags)

Risk classification uses **tags** on each `@mcp_server.tool(...)` registration. `Visibility` transforms in [lifespan.py](src/ssh_mcp/lifespan.py) filter tiers out of `tools/list` when the corresponding env var is `false`. Precedence: `sudo > dangerous > low-access > safe`.

| Tag | Operation type | Gate | Examples |
|---|---|---|---|
| `safe` | Read-only observability — TCP/SSH handshake, fixed-argv reads, SFTP reads | always visible | `ssh_host_ping`, `ssh_host_disk_usage`, `ssh_sftp_list`, `ssh_sftp_stat`, `ssh_docker_ps`, `ssh_known_hosts_verify` |
| `low-access` | Scoped writes / lifecycle ops — additive, no arbitrary exec, no destructive deletes | `ALLOW_LOW_ACCESS_TOOLS=true` | `ssh_mkdir`, `ssh_upload`, `ssh_cp`, `ssh_mv`, `ssh_edit`, `ssh_patch`, `ssh_shell_exec`, `ssh_docker_compose_start`, `ssh_docker_cp` |
| `dangerous` | Arbitrary command exec, destructive ops, persistent shells | `ALLOW_DANGEROUS_TOOLS=true` | `ssh_exec_run`, `ssh_exec_script`, `ssh_shell_open`, `ssh_docker_run`, `ssh_docker_rm`, `ssh_docker_prune`, `ssh_docker_compose_down` |
| `sudo` (always combined with `dangerous`) | Privileged escalation | `ALLOW_SUDO=true` **and** `ALLOW_DANGEROUS_TOOLS=true` | `ssh_sudo_exec`, `ssh_sudo_run_script` |

Governance:

- **Tag every tool** — `Visibility` relies on explicit tags; no tool is implicitly safe.
- Any tool accepting a free-form `command` or `path` targeting write operations is `dangerous`, full stop.
- When gated out, tools are filtered from `tools/list` — not just hidden; structurally uninvokable via MCP.
- All `dangerous` and `sudo` invocations emit audit logs with correlation IDs.

A tool that internally executes a fixed command (`uptime`, `df -h`, `uname -a`) may carry `safe` **only if** the full argv is hard-coded and free of caller interpolation.

### 3.3 Contract rules

- Typed inputs (Pydantic). Typical shape: `host: str, command: str, path: str, timeout: int | None`.
- Validate `host` against the allowlist before any network activity.
- For SFTP, resolve and canonicalize paths before the allowlist check; reject `..` traversal after resolution.
- Return stable JSON-friendly structures. Bytes are base64-encoded with a `content_encoding` field.
- A tool is only complete when it produces a correct result end-to-end against a real SSH target (a containerized sshd counts).

### 3.4 Output handling

Exec and file-read outputs stream and cap; list tools paginate inside the response.

- Cap `stdout` / `stderr` from `ssh_exec_run` at a configurable byte limit (default 1 MiB each). Report truncation in the response (`"stdout_truncated": true`).
- Provide a streaming variant (`ssh_exec_run_streaming`) for long-running commands, using the MCP progress/notification channel.
- For SFTP `list`, paginate with `offset` / `limit` / `has_more` (directories can contain thousands of entries).
- Always return structured metadata: `exit_code`, `duration_ms`, `bytes_stdout`, `bytes_stderr`, `truncated`.

### 3.5 Response patterns

```python
# Command execution
{"result": {"host": "...", "exit_code": 0, "stdout": "...", "stderr": "",
            "stdout_truncated": False, "stderr_truncated": False, "duration_ms": 142}}

# SFTP list (paginated inside the response)
{"result": {"path": "/var/log", "entries": [{"name": "syslog", "size": 12345,
            "mode": "0640", "mtime": "2026-04-14T10:00:00Z", "type": "file"}],
            "offset": 0, "limit": 100, "has_more": False}}

# Write confirmation
{"result": {"success": True, "host": "...", "path": "...", "bytes_written": 10485760}}
```

---

## 4. FastMCP 3 conventions

The canonical patterns this project uses. The source files are the authoritative reference; what follows is the rule, not the sample code.

### 4.1 Lifespan

- Manages the SSH connection pool, loads `known_hosts`, installs `Visibility` transforms for `dangerous` / `sudo` tags.
- Runs exactly once at startup and once at shutdown, regardless of client connections.
- Teardown via `try/finally` so connections close even on cancellation.
- Tools access the pool via the `pool_from(ctx)` helper in [tools/_context.py](src/ssh_mcp/tools/_context.py) (similarly `settings_from(ctx)`, `resolve_host(ctx, host)`).

See [lifespan.py](src/ssh_mcp/lifespan.py).

### 4.2 Tasks (long-running operations)

- Any SSH operation that may exceed ~30 s uses `task=TaskConfig(...)` (SEP-1686 background task protocol).
- Requires `pip install "fastmcp[tasks]"` (already in [pyproject.toml](pyproject.toml)).
- Backend: Redis docket (`FASTMCP_DOCKET_URL=redis://...`) in production; in-memory for local dev only.

Task-mode matrix (target policy — only `ssh_exec_run_streaming` currently uses `TaskConfig`; other rows guide future additions):

| Tool category | Target mode | Rationale |
|---|---|---|
| Fast reads (`ssh_host_ping`, `ssh_session_list`, `ssh_sftp_stat`, `ssh_host_disk_usage`) | `forbidden` (default) | Fixed-cost sync |
| `ssh_exec_run`, long SFTP transfers, `ssh_docker_compose_up` | `TaskConfig(mode="optional")` | Most calls fast; client opts in for slow ones |
| `ssh_exec_run_streaming` | `TaskConfig(mode="required")` | Long-running by contract — already in place |

Constraints: task-enabled tools must be async and registered at startup (no dynamic registration).

### 4.3 Pagination

`list_page_size` on the server paginates `tools/list`, `resources/list`, `prompts/list` uniformly. Enable only when catalog exceeds ~100 components. Cursors are opaque base64 per MCP spec.

This is **list-level pagination**, not data-level. For SFTP directory listings, continue using in-response `offset` / `limit` / `has_more` (§3.4).

### 4.4 Telemetry

OpenTelemetry ships native with FastMCP 3. Spans auto-generated for `tools/call`, `resources/read`, `prompts/get`, mounted-server delegations. Custom spans wrap SSH connect/auth/exec in the transport layer ([ssh/connection.py](src/ssh_mcp/ssh/connection.py), [ssh/exec.py](src/ssh_mcp/ssh/exec.py)).

**Redaction rules:**

- Never record full command strings as span attributes — flags may include secrets.
- Never record SFTP file contents, stdin payloads, or environment variables.
- Do record: host, user (not password/key), exit code, duration, bytes transferred, error class.

Enable with `OTEL_SERVICE_NAME=ssh-mcp` + `OTEL_EXPORTER_OTLP_ENDPOINT=...` + `opentelemetry-instrument python -m ssh_mcp`.

### 4.5 Versioning

- **Per-tool `version=`** supports controlled migration: clients request a specific version via `_meta.fastmcp.version`. Rule: either version *every* tool sharing an identifier or *none*. FastMCP raises `ValueError` at registration on mixed versioning.
- **Server `VERSION`** (in [config.py](src/ssh_mcp/config.py)) follows strict semver `MAJOR.MINOR.PATCH`: bump PATCH for fixes, MINOR for backwards-compatible additions, MAJOR for breaking changes. Must match `version` in [pyproject.toml](pyproject.toml).

### 4.6 Skills (operator runbooks)

Runbooks live in [runbooks/](runbooks/) and are exposed via FastMCP's Skills provider (`SkillsDirectoryProvider`) under the `skill://` URI scheme. Each runbook has a `SKILL.md` with YAML frontmatter (`description:`) and per-skill `_manifest` JSON.

This is a separate concept from our risk `tags` — do not conflate.

---

## 5. SSH integration

### 5.1 Connection model

- **Connection pool** keyed by `(user, host, port)`. Reuse across tool calls within ~60 s idle window.
- Enforce keepalives (`SSH_KEEPALIVE_INTERVAL`) to detect stale NAT/firewall entries.
- Use per-command channels on a shared connection — don't reconnect per call.
- Long-running commands stream stdout/stderr in chunks — never buffer unbounded output in memory.
- Clean teardown on shutdown; never leak file descriptors.

See [ssh/pool.py](src/ssh_mcp/ssh/pool.py).

### 5.2 Host resolution

- Honor `~/.ssh/config` when `SSH_CONFIG_FILE` is set (ProxyJump, user overrides). [hosts.toml](hosts.toml) fields take precedence; OpenSSH config only fills gaps (most useful for `IdentityFile`, `ProxyJump`, host aliases, legacy crypto overrides).
- Treat host keys as trusted only when present in `known_hosts`. Surface TOFU decisions to the operator, not the model.
- Bastion/jump host support via `ProxyJump` or explicit chaining.

### 5.3 Tool domains

Full registered catalog (names, tiers, inputs, outputs) lives in [TOOLS.md](TOOLS.md). Domain groups are identified via `group:<domain>` tags on each `@mcp_server.tool(...)` registration — see §3.1 for the list.

---

## 6. Python conventions

### 6.1 Style

- PEP 8 baseline: 4-space indent, 110-char lines (per [pyproject.toml](pyproject.toml)).
- `snake_case` functions/vars, `PascalCase` classes, `UPPER_CASE` constants.
- Import order stdlib / third-party / local, enforced by ruff.
- Docstrings on every public module, class, function.

### 6.2 Type safety

- Type hints on every public function.
- Pydantic models for tool I/O where structure is non-trivial.
- `typing.Literal` for enum-like choices.
- Avoid bare `except Exception`; catch `asyncssh.Error`, `OSError`, `asyncio.TimeoutError` explicitly.
- Ruff strict (`E,F,W,I,B,UP,S,SIM,RUF,ASYNC,PERF,PT,PLE,TCH`).
- Mypy strict on the `ssh_mcp` package.

### 6.3 Logging

- Structured, leveled, correlation-ID per tool invocation propagated into transport logs.
- Events emitted: `tool.request`, `tool.response`, `tool.error`, `ssh.connect`, `ssh.disconnect`, `ssh.exec`, `sftp.op`.
- Never log secrets, key material, passphrases, or argument values after `--password=` / `--token=` patterns.
- `LOG_LEVEL` via env; INFO in prod, DEBUG only for explicit troubleshooting.

### 6.4 Testing

- Unit tests against a fake transport.
- `@pytest.mark.integration` for tests needing a containerized sshd ([tests/integration/docker-compose.yml](tests/integration/docker-compose.yml)).
- `@pytest.mark.e2e` for tests against real hosts in `hosts.toml`.
- Cover explicitly: host-key mismatch, auth failure, command timeout, stdout truncation, SFTP path-traversal rejection, allowlist enforcement.
- **Never run integration tests against production hosts from CI.**
- **Always invoke through `uv run ...`**.

### 6.5 Runtime + dependencies

- Python: `>=3.11,<3.13`
- Build backend: `hatchling>=1.24.0`

Core dependencies:

| Package | Version | Purpose |
|---|---|---|
| `fastmcp` | `>=3.0.0,<4.0.0` | MCP server framework |
| `asyncssh` | `>=2.17.0,<3.0.0` | Async SSH/SFTP |
| `pydantic` | `>=2.8.0,<3.0.0` | Typed I/O |
| `pydantic-settings` | `>=2.3.0,<3.0.0` | Env-based config |
| `tenacity` | `>=8.3.0,<10.0.0` | Retry on transient connect failures (not on command failures) |

Dev dependencies: `pytest`, `pytest-asyncio`, `docker` (for sshd fixtures), `ruff`, `mypy`.

Version policy: bounded ranges in `pyproject.toml`, exact pins in lock files for CI/deploy. Revalidate FastMCP, asyncssh, and Pydantic major-version bumps together.

If `paramiko` is ever required for features asyncssh lacks, wrap it behind the same transport interface so higher layers stay transport-agnostic.

---

## 7. Boy Scout rule

Leave the codebase cleaner than you found it. Every change:

- Improves naming, readability, or structure in touched code.
- Removes dead code / obvious duplication when safe.
- Adds or refines tests for touched behavior — especially security-sensitive paths (allowlist checks, path canonicalization, host-key verification).
- Keeps scope tight — many small cleanups beat one sweeping refactor.
