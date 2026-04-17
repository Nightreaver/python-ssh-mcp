# Python SSH MCP

[![Python](https://img.shields.io/badge/python-3.11--3.13-blue)](https://www.python.org/)
[![FastMCP](https://img.shields.io/badge/fastmcp-3.x-blue)](https://gofastmcp.com/)
[![License](https://img.shields.io/badge/license-GPL--3-green)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-457%20passing-brightgreen)](CONFIGURATION.md#testing)

An SSH MCP server built in Python on top of FastMCP. The goal: give an LLM real SSH access to many hosts while keeping fine-grained control over what it can and can't do. The configuration surface is deliberately broad — probably overkill if you just want a single `ssh_exec` tool, but it pays off once you start connecting more than one host or locking the agent down to specific paths, commands, and visibility tiers. If a tool you need isn't here, open an issue.

Currently implemented:
57 tools across 8 groups, 457 passing unit tests + 6 dockerized-sshd integration tests + an opt-in `tests/e2e/` suite that drives every tool against the operator's real `hosts.toml`. Strict `known_hosts` by default, path-allowlist confinement on every path-bearing tool, SHA-256-hashed audit log, operator-pluggable hooks. Most tools return typed Pydantic results so MCP clients see real schemas in `tools/list` (not generic `object`); the few that legitimately produce merged or bimodal payloads stay as `dict[str, Any]` with the rationale documented at the function. POSIX SSH targets supported end-to-end; Windows SSH targets supported for SFTP + file-ops + `ssh_file_hash` via PowerShell `-EncodedCommand` (see [ADR-0023](DECISIONS.md)); Docker CLI swappable for Podman via `SSH_DOCKER_CMD` / per-host `docker_cmd`.

## Contents

In this file:

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [Walkthrough — your first host in 5 minutes](#walkthrough--your-first-host-in-5-minutes)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) python-ssh-mcp
- Write your first `hosts.toml` entry ([Walkthrough §3](#3-write-hoststoml))
- [Set up](#client-setup) your MCP Client (Claude Desktop, Claude Code, Cursor, ...)
- Ask the LLM to run `ssh_host_ping` against your target — verifies agent + `known_hosts` + pool end-to-end
- Flip the tier flags you need (`ALLOW_LOW_ACCESS_TOOLS`, `ALLOW_DANGEROUS_TOOLS`, `ALLOW_SUDO`) and the LLM unlocks file ops, exec, sudo — see [CONFIGURATION.md → Access tiers](CONFIGURATION.md#access-tiers)

**[CONFIGURATION.md](CONFIGURATION.md)** — configuring more hosts, access tiers, allowlist/blocklist, tool groups, Docker/Podman, per-host SSH identity, `known_hosts` management, sudo.
**[ADVANCED.md](ADVANCED.md)** — runbooks (FastMCP Skills), hooks, observability, testing, key rotation, architecture, contributing.

## Features

- **MCP-compliant server** exposing SSH over stdio (or HTTP if you prefer); transport speaks MCP directly, no shim.
- **Four-tier access model** — `read` / `low-access` / `dangerous` / `sudo`. Each tier is toggled with its own env flag and enforced via FastMCP `Visibility` transforms. Default: read-only.
- **Nine tool groups** orthogonal to tiers (`host`, `session`, `sftp-read`, `file-ops`, `exec`, `sudo`, `shell`, `docker`, `systemctl`). `SSH_ENABLED_GROUPS` trims the catalog to what a given assistant actually needs.
- **67 tools**: see [TOOLS.md](TOOLS.md) for the complete per-tool reference. Highlights:
  - Read-only probes (ping, host info, disk usage, processes, alerts, known-hosts verify)
  - SFTP reads (list, stat, download, find) with remote-realpath confinement
  - Low-access file ops (cp, mv, mkdir, delete, delete_folder, edit, patch, upload, deploy) — SFTP-first, atomic writes
  - Exec tier with per-call timeout, streaming variant, and TTY-need hint in results
  - Sudo tier (password piped via stdin, never argv; env passwords hard-rejected at startup)
  - 22 Docker tools (ps, logs, inspect, stats, images, compose up/down/logs/..., container lifecycle, exec, run)
  - Persistent shell sessions with cwd tracking (no remote PTY, sentinel-based state)
- **Strict `known_hosts`** — no auto-accept; unknown or mismatched keys fail closed.
- **Path confinement on everything** — each path-bearing tool canonicalizes via remote `realpath` (or SFTP realpath on Windows) and checks the allowlist, with `restricted_paths` carve-outs for sensitive zones.
- **Per-host policy** in `hosts.toml` — users, keys, allowlists, sudo mode, platform, proxy chains, alert thresholds, persistent-session opt-out.
- **Windows SSH target support** for SFTP + file-ops (see [ADR-0023](DECISIONS.md)); POSIX-only tools refuse Windows targets with a clean `PlatformNotSupported` that names the missing capability.
- **Audit log** — one JSON line per mutating call, paths/commands SHA-256-hashed, `error` field is exception class only (full text stays at DEBUG locally).
- **Operator hooks**: import any module via `SSH_HOOKS_MODULE` for `STARTUP` / `SHUTDOWN` / `PRE_TOOL_CALL` / `POST_TOOL_CALL` events. Bounded per-hook timeout, exception isolation, backlog warning when pending tasks pile up.
- **Runbooks via FastMCP Skills** — per-tool `SKILL.md` files give the LLM scoped how-to docs on demand.
- **BM25 tool search** (optional) — replaces `tools/list` with `search_tools` + `call_tool` once 50+ schemas start eating context.
- **Tool catalog overview** logged at startup (per-tier and per-group counts) so operators can see exactly what the LLM will be offered.

## Installation

Python SSH MCP is a standard PEP 621 Python package (hatchling build backend). Use
whichever installer you prefer — [uv](https://docs.astral.sh/uv/) is the
recommended path:

```bash
uv sync                      # create .venv + install runtime deps + dev extras
uv run ssh-mcp               # start the server on stdio

# Or without syncing a venv first — build + run in an ephemeral environment:
uvx --from . ssh-mcp

# Plain pip also works (PEP 517):
pip install -e ".[dev]"
ssh-mcp

# FastMCP shortcuts (once the package is installed):
fastmcp dev inspector        # dev UI: MCP Inspector + hot reload; auto-finds fastmcp.json
fastmcp run                  # run the server; auto-finds fastmcp.json
fastmcp run -t http -p 8000  # HTTP transport instead of stdio
```

Optional dependency groups:

- `.[tasks]` — adds the **Redis client** (`redis>=5.0.0`) for a production task backend. The FastMCP tasks runtime itself (`docket`, in-memory by default) is a hard dep via `fastmcp[tasks]` and ships regardless — install this extra only when pointing `FASTMCP_DOCKET_URL` at a real Redis (task-loss on restart matters in prod with `ALLOW_DANGEROUS_TOOLS=true`; see [`_warn_task_backend`](src/ssh_mcp/lifespan.py#L25)).
- `.[telemetry]` — OpenTelemetry distro + OTLP exporter.
- `.[dev]` — pytest, ruff, mypy.

MCP clients (Claude Desktop, Claude Code, Cursor) discover the server via [fastmcp.json](fastmcp.json).

## Client Setup

Every major MCP client accepts a JSON snippet that tells it how to spawn the
server. The shape is standardized around an `mcpServers` object — only the
file path differs per client. Pick your client, paste the snippet into the
right file, restart the client so the subprocess is respawned.

> **Heads-up:** `fastmcp.json`'s `deployment.env` block (if you keep one in
> the project) overrides the client env unconditionally — keep tier flags
> out of that block and let them come from the client config or your
> `.env`. If the client appears to hold a stale subprocess after code
> changes, see [Troubleshooting](#troubleshooting) — most clients spawn
> and own the server subprocess, so a terminal-side restart is not enough.

The base snippet (used by Claude Desktop, Cursor, Windsurf, Kilocode — most
clients speak this dialect):

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Nightreaver/python-ssh-mcp", "ssh-mcp"],
      "env": {
        "LOG_LEVEL": "INFO",
        "ALLOW_LOW_ACCESS_TOOLS": "false",
        "ALLOW_DANGEROUS_TOOLS": "false",
        "ALLOW_SUDO": "false"
      }
    }
  }
}
```

`uvx --from <path> ssh-mcp` builds and runs the server in an ephemeral
`uv`-managed environment; no persistent venv needed on the client side.
Alternative: replace with `"command": "fastmcp"`, `"args": ["run",
"<path-to-clone>/fastmcp.json"]` if you already have a venv
with `fastmcp` on PATH.

Flip the `ALLOW_*` flags as you grant capability to the assistant. Keep
read-only as the default and open the exec/sudo tiers only where you need
them.

### Claude Desktop

Config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Paste the base snippet. Fully quit Claude Desktop (tray icon → Quit) and
relaunch — reload does NOT re-spawn MCP subprocesses.

### Claude Code

CLI command, no JSON editing needed:

```bash
claude mcp add --transport stdio ssh-mcp -- uvx --from git+https://github.com/Nightreaver/python-ssh-mcp ssh-mcp
```

For scope control: `--scope user` (global), `--scope project` (commits
`.mcp.json` to the current repo), `--scope local` (default, this project
only). Env vars via repeated `--env KEY=VALUE` flags, or by editing
`~/.claude/mcp.json` after the fact.

### Cursor

Config file:

- **Global**: `~/.cursor/mcp.json`
- **Per-workspace**: `<workspace>/.cursor/mcp.json`

Same `mcpServers` shape as the base snippet. Cursor picks up config
changes on the next chat session — no full restart needed.

### VS Code (GitHub Copilot Chat / Agent Mode)

VS Code's MCP support (1.102+) uses a slightly different key. Config file:

- **Per-workspace**: `<workspace>/.vscode/mcp.json`
- **Global user settings**: `settings.json` → `"mcp.servers"`

Workspace `.vscode/mcp.json`:

```json
{
  "servers": {
    "ssh-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": ["--from", "git+https://github.com/Nightreaver/python-ssh-mcp", "ssh-mcp"],
      "env": {
        "LOG_LEVEL": "INFO",
        "ALLOW_LOW_ACCESS_TOOLS": "false",
        "ALLOW_DANGEROUS_TOOLS": "false",
        "ALLOW_SUDO": "false"
      }
    }
  }
}
```

Note the top-level key is `servers` (not `mcpServers`) and each entry
carries a `"type": "stdio"` discriminator. Reload the VS Code window
(`Developer: Reload Window`) to respawn.

### Windsurf (Codeium)

Config file: `~/.codeium/windsurf/mcp_config.json`. Same `mcpServers`
shape as the base snippet. Restart Windsurf after editing.

### Kilocode

Config file: `~/.kilocode/mcp.json` (or the equivalent in your Kilocode
install — the extension docs list the exact path). Same `mcpServers`
shape as the base snippet. Reload the VS Code window after editing.

### Continue.dev

Config file: `~/.continue/config.json`. Continue uses a nested key:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "transport": {
          "type": "stdio",
          "command": "uvx",
          "args": ["--from", "git+https://github.com/Nightreaver/python-ssh-mcp", "ssh-mcp"]
        }
      }
    ]
  }
}
```

Note: list-of-objects, not a named map. Env vars go inside the
`transport` block.

### Zed

Config via the Command Palette: `assistant: configure context servers`,
or edit `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "ssh-mcp": {
      "source": "custom",
      "command": {
        "path": "uvx",
        "args": ["--from", "git+https://github.com/Nightreaver/python-ssh-mcp", "ssh-mcp"],
        "env": {}
      }
    }
  }
}
```

### MCP Inspector (dev UI)

For debugging the server before wiring it into a real client:

```bash
fastmcp dev inspector
```

Auto-detects `fastmcp.json`, launches the web UI with a live MCP
Inspector attached. Hot-reload on source changes.

---

## Walkthrough — your first host in 5 minutes

The fastest path: **agent auth + one host + read-only tier**. Five steps:

### 1. Load your key into an agent

- **Linux/macOS:** `ssh-add ~/.ssh/id_ed25519`
- **Windows:** start **Pageant** and load your `.ppk` (or run `ssh-agent` + `ssh-add`)

Verify the agent is reachable:

```bash
uv run python -c "import asyncio; from ssh_mcp.ssh.agent import list_agent_fingerprints; print(asyncio.run(list_agent_fingerprints()))"
```

You should see one or more `SHA256:...` lines. Copy the one you intend to use — you'll reference it below.

### 2. Pin the target's host key (verify BEFORE you trust)

Strict `known_hosts` verification is on by default (no auto-accept). **Pinning is a three-step flow — never append `ssh-keyscan` output directly into `known_hosts`.**

```bash
# 2a. Scan to a scratch file. This does NOT trust anything yet.
ssh-keyscan -t ed25519,ecdsa,rsa web01.example.com > /tmp/web01.hostkey

# 2b. Print the fingerprint and compare OUT-OF-BAND.
ssh-keygen -lf /tmp/web01.hostkey
# → 256 SHA256:abc123... web01.example.com (ED25519)
```

Compare that `SHA256:...` against a source you trust that is not the network you just scanned over: the host's provisioner output, a console session, a terraform output, the sysadmin's Signal message. **If they don't match, stop.** A typo or MITM would pin a hostile key as trusted.

```bash
# 2c. Only after the out-of-band fingerprint matches, append and clean up.
cat /tmp/web01.hostkey >> ~/.ssh/known_hosts
rm /tmp/web01.hostkey
```

The MCP server refuses to connect if `known_hosts` is missing, empty, or doesn't match.

### 3. Write `hosts.toml`

Copy the annotated starter template and edit:

```bash
cp hosts.toml.example hosts.toml
# Replace the SHA256:REPLACE-WITH-... fingerprints with yours from step 1.
```

Or write from scratch — the minimum viable block:

```toml
[defaults]
user = "deploy"

[defaults.auth]
method = "agent"
identity_fingerprint = "SHA256:<paste-your-fingerprint-here>"
identities_only = true

[hosts.web01]
hostname = "web01.example.com"
path_allowlist = ["/opt/app", "/var/log"]
```

See [hosts.toml.example](hosts.toml.example) for bastion / proxy-jump, per-host key overrides, and the on-disk-key + keychain passphrase pattern. For multi-host recipes (bastions, per-role keys, legacy hosts) see [CONFIGURATION.md → Configuring more hosts](CONFIGURATION.md#configuring-more-hosts).

#### Inheriting from `~/.ssh/config`

If you already maintain a populated `~/.ssh/config` (host aliases, `ProxyJump`, `IdentityFile`, `Ciphers`/`MACs` overrides for legacy gear), point `SSH_CONFIG_FILE` at it and skip restating those fields in `hosts.toml`:

```bash
SSH_CONFIG_FILE=~/.ssh/config
```

Precedence: `hosts.toml` always wins. `~/.ssh/config` only fills in fields you didn't set per-host — the OpenSSH config can't broaden what `path_allowlist`, `command_allowlist`, or the host blocklist permit. Startup logs `ssh_config: honoring <abs-path>` (or a WARNING if the file is missing) so misconfiguration surfaces immediately.

### 4. Write `.env`

```bash
# Start locked down — only read-only tools are active.
ALLOW_LOW_ACCESS_TOOLS=false
ALLOW_DANGEROUS_TOOLS=false
ALLOW_SUDO=false

# Optional safety rail
SSH_HOSTS_BLOCKLIST=
```

### 5. Verify end-to-end

```bash
uv run ssh-mcp
```

From an MCP client (or from a quick Python shell), call:

```python
from ssh_mcp.server import mcp_server
# tools: ssh_host_ping, ssh_host_info, ssh_sftp_list, ssh_find, ...
```

`ssh_host_ping(host="web01")` should return `{reachable: true, auth_ok: true, latency_ms: N, ...}`.

If it fails, see [Troubleshooting](#troubleshooting).

---

## Troubleshooting

### `no SSH agent reachable`

The agent resolution order is: explicit `identity_agent` in `hosts.toml` → `SSH_AUTH_SOCK` env var → Windows auto-detect (Pageant / OpenSSH pipe). Check:

```bash
# Unix / macOS
echo $SSH_AUTH_SOCK
ssh-add -l

# Windows (PowerShell)
Get-Process Pageant -ErrorAction SilentlyContinue
uv run python -c "import asyncio; from ssh_mcp.ssh.agent import list_agent_fingerprints; print(asyncio.run(list_agent_fingerprints()))"
```

### `identity 'SHA256:...' not found in agent`

The fingerprint in `hosts.toml` doesn't match any key the agent exposes. List what's actually loaded:

```bash
uv run python -c "import asyncio; from ssh_mcp.ssh.agent import list_agent_fingerprints; [print(fp) for fp in asyncio.run(list_agent_fingerprints())]"
```

Copy one of the reported fingerprints into `identity_fingerprint`.

### `HostKeyMismatch` / `UnknownHost`

Either the host key changed (rotation or MITM) or `known_hosts` is missing the entry. Do **not** bypass this from the LLM, and do **not** `>>` a scan directly into `known_hosts` without verification. Use the three-step flow from [Walkthrough §2](#2-pin-the-targets-host-key-verify-before-you-trust):

```bash
ssh-keyscan -t ed25519,ecdsa <host> > /tmp/h.hostkey
ssh-keygen -lf /tmp/h.hostkey                     # compare fingerprint out-of-band
cat /tmp/h.hostkey >> ~/.ssh/known_hosts && rm /tmp/h.hostkey
```

### `HostNotAllowed`

The host isn't in `hosts.toml` and isn't in `SSH_HOSTS_ALLOWLIST`. Resolution tries the input first as a `hosts.<alias>` key, then against `hosts.*.hostname`, then against the env allowlist. Add a `hosts.toml` entry or add the literal hostname to `SSH_HOSTS_ALLOWLIST`.

### `HostBlocked`

Deny wins — check `SSH_HOSTS_BLOCKLIST`. This is intentional; remove the entry if the block was a mistake, but first confirm with the operator who added it.

### `PathNotAllowed`

The resolved (canonicalized) path is outside every root in `path_allowlist`. Check:

- Is the path correct? Low-access tools resolve symlinks before checking, so a symlink pointing out of `/opt/app` will be rejected even if the link itself lives there.
- Does `hosts.<name>.path_allowlist` cover the target?

### `command_allowlist is empty but ALLOW_DANGEROUS_TOOLS=true`

The loader warns if you enable exec without scoping what commands are allowed. Either set `SSH_COMMAND_ALLOWLIST` or an empty `command_allowlist` per host (explicit = no restriction).

### Tools not visible in the MCP client

- Check the tier: `ALLOW_LOW_ACCESS_TOOLS` / `ALLOW_DANGEROUS_TOOLS` / `ALLOW_SUDO` are default-deny.
- Check the group: `SSH_ENABLED_GROUPS` (empty = all; explicit = filter).
- Restart the MCP client — tool lists are cached per MCP server version.

---

## Disclaimer

Python SSH MCP is local infrastructure that grants an LLM (or any MCP client) the
ability to execute commands on remote systems over SSH. **Use at your own
risk.** Default-deny tier flags and strict `known_hosts` enforcement protect
against the obvious footguns, but no software can protect against an operator
who flips every flag to `true` without understanding the blast radius.

Read [DECISIONS.md](DECISIONS.md) before enabling the dangerous or sudo tier
in production. Audit the `ssh_mcp.audit` JSON lines on a regular basis. When
in doubt, leave a tier off.

This project is not affiliated with or endorsed by any SSH, FastMCP, or MCP
provider.

---

## Support

Building and maintaining this MCP server takes real time and effort, even with AI
assistance. If this SSH MCP has made your workflow and life easier, please consider supporting me:

- ❤️ [GitHub Sponsors](https://github.com/sponsors/Nightreaver)
- [Buy me a coffee on Ko-fi](https://ko-fi.com/nightreaver)
- [One-time PayPal tip](https://paypal.me/sbarthen/10)

Issues, questions, and feedback: open a GitHub issue. If you find **Python SSH MCP** useful,
consider starring the repo — it genuinely helps.
