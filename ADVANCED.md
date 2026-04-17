# Advanced topics

Runbooks, hooks, observability, testing, key rotation, architecture, contributing.

For getting started, see the [README](README.md). For configuration (hosts, tiers, allowlists, Docker, sudo), see [CONFIGURATION.md](CONFIGURATION.md).

## Contents

- [Runbooks (FastMCP Skills)](#runbooks-fastmcp-skills)
- [Extending with hooks](#extending-with-hooks)
- [Observability](#observability)
- [Testing](#testing)
- [Key rotation](#key-rotation)
- [Architecture](#architecture)
- [Contributing](#contributing)

---

## Runbooks (FastMCP Skills)

Two directories, each mounted as a separate FastMCP `SkillsDirectoryProvider` at startup (see [lifespan.py `_mount_skills`](src/ssh_mcp/lifespan.py#L176)):

- **`skills/ssh-<tool>/SKILL.md`** — one per registered tool. Names exactly match the tool ID with `_` → `-`. 57 currently, enforced by CI.
- **`runbooks/ssh-<workflow>/SKILL.md`** — multi-tool workflow procedures. Toggle-able via `SSH_ENABLE_RUNBOOKS` (default `true`); flip to `false` for tool-execution-only assistants that don't need narrative guidance in `resources/list`. Per-tool skills are unaffected.

```text
skills/                                 # mounted unconditionally
├── ssh-docker-top/SKILL.md             # per-tool
├── ssh-docker-cp/SKILL.md              # per-tool
├── ssh-host-ping/SKILL.md              # per-tool
├── ...                                 # one per tool, enforced by CI
runbooks/                               # mounted only if SSH_ENABLE_RUNBOOKS=true
├── ssh-incident-response/SKILL.md      # workflow
├── ssh-deploy-verify/SKILL.md          # workflow
└── ...
```

### Canonical workflow runbooks

- [runbooks/ssh-host-healthcheck/](runbooks/ssh-host-healthcheck/) — standard "is this host OK right now" pass: identity + alerts + disk + processes + uptime, interpreted as green/yellow/red. Read-only; safe to schedule.
- [runbooks/ssh-incident-response/](runbooks/ssh-incident-response/) — host-level incident response: disk-full triage, host-dark diagnosis, escalation. Read-only tier.
- [runbooks/ssh-docker-incident-response/](runbooks/ssh-docker-incident-response/) — container / compose-stack failures: restart loops, OOM kills, `inspect`-first exit-code reading, healthcheck drift, disk-pressure prune path, and the "when NOT to prune volumes" boundary.
- [runbooks/ssh-disk-cleanup/](runbooks/ssh-disk-cleanup/) — investigate before pruning. `find`+`stat` the actual consumers, branch on logs vs Docker vs app data, and the "never volume-prune from the LLM" rule.
- [runbooks/ssh-deploy-verify/](runbooks/ssh-deploy-verify/) — upload with backup, hash-verify the remote, `compose_up`, tail logs, and roll back via the `.bak-<ts>` sibling when verification fails.
- [runbooks/ssh-container-rollout/](runbooks/ssh-container-rollout/) — standalone `docker run` container rollout: capture config, pre-pull, stop+rm, re-run on the new tag, verify via `inspect.State.Health`, roll back to the previous image on failure.
- [runbooks/ssh-integrity-audit/](runbooks/ssh-integrity-audit/) — scheduled audit pass: identity pinning, file-hash drift against an out-of-band manifest, signature verify of deployed artifacts, SUID / world-writable delta against a baseline.
- [runbooks/ssh-verify-signature/](runbooks/ssh-verify-signature/) — GPG / cosign / minisign verify of a deployed artifact via `ssh_exec_run` + command-allowlist. Covers pubkey-distribution-vs-artifact-channel separation, the "sign where, verify where" boundary, and per-tool gotchas (pinentry hangs, untrusted-key warnings, Rekor network deps).

### Policy enforced by CI

- **Every `ssh_*` tool must have a matching skill.** Adding a tool without one fails [test_every_tool_has_a_matching_skill](tests/test_skills_ascii.py#L45). Slug rule: underscores in the tool name become dashes (`ssh_docker_top` → `skills/ssh-docker-top/`).
- **SKILL.md must be pure ASCII.** FastMCP 3.2.4's `SkillsDirectoryProvider` reads with the platform default encoding (cp1252 on Windows) and crashes on any non-ASCII byte. Guarded by [test_skill_is_ascii](tests/test_skills_ascii.py#L23). Use `--` or `->` instead of en-dashes/arrows.

### Per-tool skill template

```markdown
---
description: One-line summary shown in the MCP resource listing
---

# `ssh_<tool_name>`

**Tier:** read-only | **Group:** `docker` | **Tags:** `{safe, read, group:docker}`

<what it does in 2-3 sentences>

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| ... | ... | ... | ... | ... |

## Returns
## When to call it
## When NOT to call it
## Example
## Common failures
## Related
- [`ssh_other_tool`](../ssh-other-tool/SKILL.md)
```

Workflow runbooks are freer-form — a narrative procedure with tool calls woven in. See [runbooks/ssh-incident-response/SKILL.md](runbooks/ssh-incident-response/SKILL.md) for the canonical example.

### Config

- `SSH_SKILLS_DIR` — directory to mount (default: `./skills`). Missing directories log an info line and are skipped; provider errors log a warning but do not brick startup.

---

## Extending with hooks

The server exposes a lightweight hook registry for operator-written side-effect
handlers (notifications, metrics exporters, custom audit bridges). The registry
is wired and fires events, but no hooks are registered by default. You add them.

### Events

| Event | Fired | Blocking |
|---|---|---|
| `STARTUP` | once after the pool + host registry are ready | yes (lifespan waits) |
| `SHUTDOWN` | once before the pool closes | yes |
| `PRE_TOOL_CALL` | before every `@audited` tool (mutating tier) | no |
| `POST_TOOL_CALL` | after every `@audited` tool (includes errors + duration) | no |

Non-blocking events are scheduled as background tasks; the main flow returns
immediately. Every hook runs under a 5-second timeout; exceptions are logged
and do not disrupt other hooks or the server.

### Wiring a hook module

1. Write a Python module anywhere on your `PYTHONPATH`:

```python
# my_ops/hooks.py
from ssh_mcp.services.hooks import HookEvent, HookContext, HookRegistry

async def notify_slack(ctx: HookContext) -> None:
    if ctx.result == "error":
        # send to slack via your preferred client
        ...

def register_hooks(registry: HookRegistry) -> None:
    registry.register(HookEvent.POST_TOOL_CALL, notify_slack)
```

2. Point the server at it via env:

```bash
SSH_HOOKS_MODULE=my_ops.hooks
```

A missing or broken module logs a warning and the server starts with zero
hooks; it does not crash. See [src/ssh_mcp/services/hooks.py](src/ssh_mcp/services/hooks.py)
for the full registry API.

### Deliberate limits

- **Side-effect only.** Hooks cannot reject a tool call yet. Blocking pre-
  hooks with veto semantics need a return-value contract; defer until a
  concrete use case appears.
- **Python only.** No shell-command hooks (Claude Code style) yet. A
  `ShellCommandHook` adapter over `asyncio.create_subprocess_exec` would slot
  into the same registry later.
- **Mutating tools only.** `PRE/POST_TOOL_CALL` emit from the `@audited`
  decorator, which only wraps low-access/dangerous/sudo tools. Read-only tools
  don't fire hooks; extend to all tools if you need full observability.

---

## Observability

### Audit log

The `ssh_mcp.audit` logger emits **one JSON line per mutating tool call**:

```json
{
  "ts": 1744646123.42,
  "correlation_id": "a3f1b2c9d4e50678",
  "tool": "ssh_edit",
  "tier": "low-access",
  "host": "web01",
  "path_hash": "sha256:abc123...",
  "duration_ms": 142,
  "result": "ok"
}
```

Paths and command bodies are reduced to a short SHA-256 prefix. **This supports aggregation/dedup, not privacy** — a common path or command is trivially rainbow-tableable. If your audit sink needs confidentiality, enforce it with transport encryption and access control on the log backend.

**The `error` field is the exception class name only** (e.g. `"PathNotAllowed"`, `"AuthenticationFailed"`). Full exception text — which can include remote stderr, sudo prompts, and file paths — stays on the same logger at DEBUG level, correlated by `correlation_id`. That way forensic context is available locally without leaking into whatever shared backend you ship audit to.

Route via Python's standard logging config:

```python
# logging.ini (or equivalent)
[logger_ssh_mcp_audit]
level = INFO
handlers = audit_file
qualname = ssh_mcp.audit

[handler_audit_file]
class = FileHandler
args = ('/var/log/ssh-mcp/audit.jsonl', 'a')
```

### OpenTelemetry

FastMCP 3 auto-instruments MCP spans (`tools/call`, `resources/read`). Custom SSH spans are available:

```python
from ssh_mcp.telemetry import span, redact_argv

with span("ssh.exec", host=hostname, argv_len=len(argv)) as s:
    result = await conn.run(redact_argv(argv))
    s.set_attribute("ssh.exit_code", result.exit_status)
```

`redact_argv` replaces `--password=*`, `--token=*`, `--secret=*`, `--api-key=*` with `<redacted:N>` (length preserved for debugging).

Enable OTel via the standard environment variables:

```bash
export OTEL_SERVICE_NAME=ssh-mcp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317
opentelemetry-instrument uv run ssh-mcp
```

---

## Testing

```bash
uv run pytest                 # 457 unit tests, ~3s
uv run ruff check .
uv run mypy
```

### End-to-end tests (real hosts from `hosts.toml`)

Opt-in suite at `tests/e2e/` that drives every registered tool against the operator's actual hosts — the set declared in your `hosts.toml`. Unreachable hosts skip rather than fail, so you can run it against any subset of the fleet that's up.

```bash
uv run pytest -m e2e -v
```

The suite is split into four files:

- `test_e2e_real_hosts.py` — core tools (ping / host_info / sftp / file-ops / exec / sessions / shell) parametrized per alias, Windows/POSIX gating via `policy.platform`. Includes `test_platform_matches_banner` which flags a mismatch between the declared `platform` and the live SSH banner — catches `test_windows11` entries that forgot `platform = "windows"` without a confusing cascade of `realpath` failures downstream.
- `test_e2e_docker.py` — full container + compose lifecycle behind a `docker version` probe. Hosts without docker skip cleanly. Dangerous tools (`docker_run`, `docker_rm`, `docker_rmi`, `docker_prune`) run against a disposable `busybox:latest` container with a unique per-run name.
- `test_e2e_path_policy.py` — allowlist + `restricted_paths` enforcement. Each test rebuilds a **narrow** ctx because `effective_allowlist = policy.path_allowlist ∪ settings.SSH_PATH_ALLOWLIST` and a `"*"` wildcard in either tier would mask confinement; without the rebuild the operator's normal `["*"]` would defeat the test.
- `test_e2e_sudo.py` — sudo tier, skipped by default. Set `SSH_E2E_SUDO_PASSWORD` to opt in (separate from `SSH_SUDO_PASSWORD` so accidental prod env doesn't trigger mutation).

The e2e suite calls tool functions directly (not through the MCP wire), wiring `pool` / `settings` / `hosts` / `known_hosts` / `hooks` / `shell_sessions` into a stub `Context` that mirrors what the real lifespan builds. This exercises the production code paths without running a server.

### Integration tests (containerized sshd)

The integration suite spins a local sshd (linuxserver/openssh-server) on
`127.0.0.1:2222` and runs real SSH handshakes, SFTP reads, and remote exec
through our `ConnectionPool` and policy layer. The fixtures bootstrap
themselves — no keys are committed to the repo.

Bring the container up first (keys dir has to exist before the container
reads the public key into `authorized_keys`):

```bash
uv run pytest -m integration --collect-only   # triggers keypair generation
docker compose -f tests/integration/docker-compose.yml up -d
uv run pytest -m integration
```

On first run, `tests/integration/conftest.py` generates an ephemeral ed25519
keypair at `tests/integration/keys/test[.pub]`. The compose file mounts
`keys/` read-only into the container, which copies `test.pub` into the
tester user's `authorized_keys`. Subsequent runs reuse the same keypair.
The session's first actual SSH connect happens with `known_hosts=None` so
the fixture can pin the container's live host key into
`tests/integration/known_hosts`; every following call then runs under
strict known-hosts enforcement, just like production.

When you rebuild the container with `--force-recreate`, the server keys
roll and the pinned `known_hosts` goes stale — delete the file and let the
fixture re-pin:

```bash
rm tests/integration/known_hosts
uv run pytest -m integration
```

Everything in `tests/integration/keys/` and `tests/integration/known_hosts`
is gitignored.

### Live agent smoke test

```bash
uv run pytest tests/test_agent.py::test_live_agent_returns_well_formed_fingerprints -v
```

Passes if Pageant / `ssh-agent` is running with at least one loaded key; skips cleanly otherwise.

### MCP annotations smoke test

The MCP spec's `ToolAnnotations` (`readOnlyHint`, `destructiveHint`, ...) drive
whether MCP clients show an approval prompt for each tool call. We derive them
from our tier tags in the lifespan; the unit tests in
[tests/test_mcp_annotations.py](tests/test_mcp_annotations.py) assert the
derivation, and a helper script rounds-trips them through the stdio protocol
to catch serializer / FastMCP-version regressions that unit tests can't see:

```bash
uv run python scripts/check_annotations.py
```

Prints a `tool / readOnly / destructive` matrix for a dozen representative
tools and exits non-zero if any `safe` / `read` tool still shows up as
destructive. Cheap, fast, useful in CI. Run after any FastMCP upgrade.

---

## Key rotation

1. Generate a new keypair; add the public half to the target's `authorized_keys` **alongside** the old.
2. Load the new key into the agent (`ssh-add new_key`) or add it as a Pageant entry.
3. Update `hosts.<name>.auth.identity_fingerprint` in `hosts.toml` to the new `SHA256:...`.
4. Restart the MCP server. Startup validates the agent actually holds the new fingerprint.
5. Verify with `ssh_host_ping` against the host.
6. After a soak period, remove the old public key from `authorized_keys`.
7. In the audit log, filter `tool=ssh_host_ping host=<target>` around the rotation timestamp to confirm no failures.

---

## Architecture

- [DESIGN.md](DESIGN.md) — full architecture, data shapes, build phases
- [DECISIONS.md](DECISIONS.md) — ADR log
- [BACKLOG.md](BACKLOG.md) — implementation punch list + progress
- [INCIDENTS.md](INCIDENTS.md) — central security-finding log: internal reviews, external issue scans, audit reports, code reviews. Stable `INC-NNN` IDs with status + refs.
- [AGENTS.md](AGENTS.md) — FastMCP 3 coding conventions for this codebase
- [TOOLS.md](TOOLS.md) — per-tool reference, grouped by tier

---

## Contributing

Contributions welcome. Please read [AGENTS.md](AGENTS.md) for the coding
conventions this codebase follows and [DECISIONS.md](DECISIONS.md) for the
architectural invariants before opening a PR.

When adding a new tool:

- Tag it with both a **tier** (`safe` / `low-access` / `dangerous` / `sudo`)
  and a **group** (`group:<name>`).
- Wrap it with `@audited(tier=...)` if it mutates remote state or runs
  dangerous code.
- Write a `SKILL.md` runbook for it (pure ASCII — see
  `tests/test_skills_ascii.py`).
- Add it to [TOOLS.md](TOOLS.md) under its tier section.
- Add a regression test, ideally with a `FakeConn` / `FakeSFTP` shim rather
  than a live remote.
