# Design Decisions

Append-only log. One entry per decision, newest at the bottom. Format borrowed from lightweight ADRs: **Context → Decision → Consequences**. Decisions can be superseded; mark the old one and link forward.

---

## ADR-0001 — Three-tier access model

**Status:** Accepted (2026-04-14)

**Context:** A single on/off gate for privileged operations is the common default in SSH MCP servers, but LLM clients routinely need file edits without arbitrary shell, and granting `exec` for that job is disproportionate.

**Decision:** Gate tools in three independent tiers, each toggled by its own env flag and enforced via FastMCP `Visibility(False, tags={...})` transforms in the lifespan:
1. **read-only** (always on)
2. **low-access** — SFTP-mediated file mutation (`cp`, `mv`, `mkdir`, `delete`, `delete_folder`, `edit`, `patch`, `upload`). `ALLOW_LOW_ACCESS_TOOLS`.
3. **exec** — arbitrary command execution. `ALLOW_DANGEROUS_TOOLS`.
4. **sudo** — privileged execution. `ALLOW_SUDO` (implies `dangerous`).

**Consequences:** Operators can issue a "patch this config file" capability without also granting `curl | sh`. Tool authors must tag every tool correctly. Visibility is declarative; no per-tool runtime checks to get wrong.

---

## ADR-0002 — Tool groups orthogonal to tiers

**Status:** Accepted (2026-04-14)

**Context:** Large tool catalogs (we have 52 tools) choke small-context LLMs. Operators need a way to trim the catalog to domain-relevant subsets (e.g. "docker only", "host diagnostics only") without disabling whole tiers.

**Decision:** Every tool carries two tag dimensions: **tier** (risk) and **group** (domain, e.g., `group:host`, `group:file-ops`). Both are gated by separate `Visibility` transforms. Visibility is AND across both — a tool must pass tier AND group gates. Default groups when `SSH_ENABLED_GROUPS` is empty: `{host, session, sftp-read}`.

**Consequences:** Same mechanism serves security gating and context efficiency. No custom activation code. Search transforms (`BM25SearchTransform`) also respect `Visibility`, so catalog search stays consistent with gating.

---

## ADR-0003 — Per-host configuration via `hosts.toml`

**Status:** Accepted (2026-04-14, supersedes DESIGN.md §11 Q3 "env-only")

**Context:** Env vars cannot express per-host policy (different users, keys, allowlists, bastions). A structured file format with a clear priority chain is needed.

**Decision:** File-based host registry at `./hosts.toml` (path overridable via `SSH_HOSTS_FILE`). `tomllib` is stdlib in 3.11+, zero dependency. `[defaults]` block + per-host overrides; resolution chain: tool arg → per-host → defaults → env → built-in.

**Consequences:** Single-host users can still ignore the file and use env only (empty file or absent file is valid). Multi-host and ProxyJump users get a real schema. Validation runs at startup (proxy_jump references, circular chains, absolute paths).

**Rejected alternatives:** YAML (needs a dependency, more footguns), JSON (worse for humans), SQLite (overkill, opaque).

---

## ADR-0004 — Per-host SSH identity selection

**Status:** Accepted (2026-04-14)

**Context:** Production operators typically have many agent keys (ops, deploy, db). OpenSSH caps auth attempts at ~6; an agent with 10 keys hits `Too many authentication failures`. Offering every key to every host also leaks the operator's full fingerprint set.

**Decision:** Per-host `[hosts.<name>.auth]` block selects auth method and — for `method = "agent"` — a specific agent socket (`identity_agent`) and/or specific identity (`identity_fingerprint`, `identities_only`). Startup validation verifies fingerprints are present in the live agent. Fail-fast beats failing on first tool call.

**Consequences:** Three supported patterns: one agent with per-host fingerprint selection; multiple scoped agent sockets; on-disk key with passphrase from `passphrase_cmd`. Forbidden: passphrase literals in TOML, agent forwarding (confused-deputy risk).

---

## ADR-0005 — `stderr` is data, not failure

**Status:** Accepted (2026-04-14)

**Context:** Treating any bytes on stderr as failure (the naive default) rejects valid successes, because real commands emit benign stderr all the time (`curl` progress, `ssh` banners, `rsync` stats). Only the exit code tells you whether the command actually failed.

**Decision:** Exec tools return a structured result with `exit_code`, `stdout`, `stderr`, `stdout_truncated`, `stderr_truncated`, `duration_ms`, `timed_out`, `killed_by_signal`. Non-zero exit is **not** raised as an error; the caller decides. MCP errors are reserved for transport failures, policy rejections, and timeouts that exceeded the grace period.

**Consequences:** More information, fewer false failures. Callers must check `exit_code` themselves.

---

## ADR-0006 — SFTP-first for low-access file ops

**Status:** Accepted (2026-04-14)

**Context:** Any time we shell out to `cp`, `mv`, `rm`, we expose argv construction to injection risk. SFTP has native primitives for most ops.

**Decision:** Low-access tools use SFTP primitives when the protocol offers them. Shell fallback is allowed only when SFTP cannot do the job (e.g., recursive delete on huge trees, cross-filesystem `mv`). Fallback uses argv lists with `--` separators — never string interpolation. Pure-Python `unidiff` for patch application avoids shelling out to `patch(1)`.

**Consequences:** Zero shell for `mkdir`, `delete`, `upload`, `download`, `edit`, `patch`, intra-FS `mv`. Small shell surface for `cp`, cross-FS `mv`, recursive `rm`, each of which gets extra argv scrutiny.

---

## ADR-0007 — Argv-only command construction

**Status:** Accepted (2026-04-14)

**Context:** Embedding commands into shell strings with hand-escaping — or wrapping them in `sh -c` with quoted values — is the common pattern across SSH MCP servers, and every such pattern we've looked at has injection vectors.

**Decision:** Commands are built as argv lists via `ssh/argv.build_argv(...)`. Transport uses `asyncssh.create_process` with argv where supported; where the protocol needs a string, we serialize via `shlex.join(argv)`. Lint rule / review check bans `f"cmd {x}"`, `.format` on commands, `shell=True`, `os.system`.

**Consequences:** Untrusted values never touch the shell parser. One helper, one review rule, caught everywhere.

---

## ADR-0008 — Strict `known_hosts` by default

**Status:** Accepted (2026-04-14)

**Context:** SSH libraries commonly default to lax or auto-accept host-key policies (effectively TOFU without the operator being asked), and MCP servers built on them inherit that posture by default. That's MITM-prone.

**Decision:** `known_hosts` is loaded at startup and enforced. Unknown host → `UnknownHost` with operator-action message. Mismatch → `HostKeyMismatch` logged at WARNING (security event). Auto-accept is not available as a config option. An operator-only tool `ssh_known_hosts_add` for controlled first-connect pinning would require a fresh gate; the original `SSH_ALLOW_KNOWN_HOSTS_WRITE` flag was removed in v1.3.0 as it had no live caller.

**Consequences:** Slightly more friction on first-time host setup; much less MITM risk. Operators pin hosts via a human-in-the-loop path, not the LLM.

---

## ADR-0009 — Workflow tools out; Skills in

**Status:** Accepted (2026-04-14)

**Context:** It's tempting to bake backup, database, deploy, and monitoring workflows directly into the server as first-class MCP tools. That grows the audit surface quickly and makes the server harder to reason about — workflows are compositions, and composition belongs above the transport.

**Decision:** The MCP transport exposes primitives only. Workflow orchestration (incident response, backup/restore, deploy) lives as operator runbooks under `skills/*/SKILL.md`, exposed via the FastMCP Skills provider (AGENTS.md §PI-6). Tool-only clients can still use them via the `ResourcesAsTools` transform.

**Consequences:** Smaller, more auditable tool surface. Runbooks are versionable and operator-authored; they don't bloat the MCP server binary. Workflows that need state (scheduling, retry across sessions) can layer above the MCP via a separate orchestrator.

---

## ADR-0010 — Hooks deferred

**Status:** Deferred (2026-04-14)

**Context:** Hook systems (pre/post-connect, pre/post-command) are a common ask for side effects — notifications, audit bridges, env setup. They also widen the attack surface and complicate reasoning about the server's guarantees.

**Decision:** Defer. OTel spans + structured audit log cover the observability case. Anything more complex (Slack notify, PagerDuty, etc.) should be an external middleware on the MCP stream, not in-server Python. Revisit if operators ask with a concrete use case.

**Consequences:** Smaller surface, fewer ways to misuse. Accepted risk: some operators will want this and we'll need to add it later.

---

## ADR-0011 — Optional Redis for FastMCP tasks

**Status:** Accepted (2026-04-14)

**Context:** FastMCP 3's background tasks use Docket with either in-memory or Redis backends. In-memory loses tasks on restart and can't scale horizontally; Redis needs infra.

**Decision:** In-memory by default for dev. For production, Redis is strongly recommended — the server emits a **startup warning** when `ALLOW_DANGEROUS_TOOLS=true` and the Docket backend is in-memory (task loss on crash is bad for long-running `exec`).

**Consequences:** Zero-dep local dev. Clear deploy-time signal to wire up Redis before enabling dangerous tools in prod.

---

## ADR-0012 — Proactive idle-connection reaper

**Status:** Accepted (2026-04-14)

**Context:** Reactive "reap on next acquire" is the common pattern but leaks FDs when traffic stops — idle connections sit open until the next tool invocation forces a cleanup pass.

**Decision:** Background asyncio task runs every 60 s and closes connections idle > `SSH_IDLE_TIMEOUT`. Task lives in the lifespan and is cancelled on shutdown.

**Consequences:** Predictable FD cleanup. One extra background task per process.

---

## ADR-0023 — Windows SSH targets: SFTP + file-ops only (no shell parity)

**Status:** Accepted (2026-04-15)

**Context:** Operators run OpenSSH on Windows servers (Windows 10/11, Server 2019+) and want the same file-deployment / config-editing workflows they have on Linux. Two failure modes to avoid: (a) claim Windows support while everything is hardcoded POSIX — the server fails on every exec; (b) add a `platform=windows` flag that only skips the Linux timeout wrapper while leaving POSIX-shell assumptions (`cd && cmd`, `/`-separators) everywhere else. Neither is honest. We want Windows support that actually works — but not at the cost of doubling the tool catalog or writing a PowerShell exec path we can't test.

**Decision:** Explicit per-host `platform: Literal["posix", "windows"]` field on `HostPolicy` (default `posix`, legacy aliases `linux`/`macos`/`bsd`/`darwin` normalize to `posix`). On `platform="windows"`:

- **Supported**: every SFTP-mediated tool — `ssh_sftp_list`, `_stat`, `_download`, `ssh_mkdir`, `ssh_delete`, `ssh_delete_folder`, `ssh_upload`, `ssh_edit`, `ssh_patch`, `ssh_deploy`, `ssh_mv` (SFTP rename only; the `mv --` fallback is POSIX-gated), plus `ssh_find` via an SFTP-walk implementation (fnmatch glob, same `SSH_FIND_MAX_*` caps). `ssh_host_ping` and `ssh_known_hosts_verify` work (just SSH handshake). Session tools (`ssh_session_*`, `ssh_shell_list`/`_close`) work (in-memory, no remote dependency).
- **Refused** with `PlatformNotSupported`: `ssh_host_info` / `_disk_usage` / `_processes` / `_alerts` (parse `uname`, `/etc/os-release`, `df`, `ps`, `/proc/*`), `ssh_exec_*` (POSIX `sh` + `pkill`), `ssh_sudo_*` (no `sudo`), `ssh_shell_open`/`_exec` (sentinel relies on POSIX shell), `ssh_docker_*` (shell quoting + out-of-scope for now), `ssh_cp` (relies on `cp -a`).
- **Canonicalization**: `canonicalize()` routes to SFTP `realpath` extension (platform-agnostic) with a python-side `ntpath.normpath` fallback for non-existing paths. A subsequent SFTP `stat` enforces `must_exist=True` semantics so Windows has the same "this path really exists" guarantee as POSIX. Symlink-resolution for non-existing targets is weaker than POSIX `realpath -m` gives us — this is documented and acceptable for create/upload ops.
- **Allowlist matching on Windows**: backslash/forward-slash separators normalized to forward-slash, both sides case-folded before prefix compare. `C:\opt\app` equivalently matches `C:/OPT/APP/file.txt`. POSIX matching unchanged (case-sensitive, `/` only).
- **Naming**: no `*_win_*` tool variants. SFTP-based tools are protocol-level and have identical semantics on both platforms; doubling the catalog would bloat context for no gain. Future PowerShell-exec or `Get-ComputerInfo`-based host-info tools would get their own `ssh_pwsh_*` / `ssh_win_*` namespace since their semantics diverge.

**Consequences:** Windows support that matches what operators actually need (deploy / edit / read / find / manage files) without the maintenance tax of a full shell-parity layer. The gated tools fail loudly with a clean error message that names the missing capability and points at the SFTP alternative. Operators who need PowerShell exec add it as an explicit scope later. Regression tests in `tests/test_windows_target.py` cover the platform field, allowlist validation, require-posix gate, case/separator matching, and SFTP-realpath canonicalize (FakeConn + FakeSFTP shims, no live Windows host required).

---

## ADR-0022 — TTY-need detection in `ExecResult.hint`

**Status:** Accepted (2026-04-15)

**Context:** We deliberately do not allocate a remote PTY (see `services/shell_sessions.py` module docstring). That makes `top`, `htop`, `vim`, `passwd`, and any command that calls `tty -s` fail with stderr like `the input device is not a TTY` or `stdin: not a tty`. Same root cause as classfang/ssh-mcp-server#31. The LLM gets a bare exit-code-1 + stderr snippet and may or may not deduce why.

**Decision:** `ExecResult` carries an optional `hint: str | None` field. After every `run()` / `run_streaming()`, stderr is scanned for a small set of recognizable TTY-need markers. On a hit, `hint` is populated with a remediation suggestion (use batch flags like `top -bn1`, `htop -t`, `vim -es`, `chpasswd`; or pipe via `ssh_exec_script`). Null otherwise. The field is for the LLM, not for control flow — exit codes still drive correctness.

**Consequences:** No PTY support added; the architectural choice from `services/shell_sessions.py` (no PTY ever, to dodge prompt-boundary parsing and reconnect-state issues) stands. The hint shrinks the round-trip cost when a caller hits a TTY wall — faster recovery without inviting brittleness. Test guards in `tests/test_exec.py` cover positive (hint set) and negative (normal failure → hint null).

---

## ADR-0021 — Defense-in-depth hint when path_allowlist is wide-open

**Status:** Accepted (2026-04-15)

**Context:** Operators routinely set `path_allowlist=["*"]` ("*" sentinel) on dev / lab hosts — fine in spirit, but with no `restricted_paths` carve-out the LLM can SFTP-download `/etc/shadow`, `/etc/sudoers`, or `/etc/ssh/sshd_config` through the read tier. bvisible/mcp-ssh-manager#13's audit flagged the same shape: "secure-by-default" gaps when the operator opens the door.

**Decision:** When a host uses `path_allowlist=["*"]` or `["/"]` and **neither** the per-host `restricted_paths` **nor** `SSH_RESTRICTED_PATHS` covers `/etc/shadow`, `/etc/sudoers`, or `/etc/ssh`, `_warn_on_risky_config` emits a second WARNING line listing the missing entries and a one-line remediation (add them to either `restricted_paths` or `SSH_RESTRICTED_PATHS`). The list is **recommendations**, not an enforced ban — some hosts genuinely don't have these files (containers, embedded), and the operator may have a different list in mind.

**Consequences:** Operators who knew what they were doing see one extra log line; operators who didn't see a clear pointer at startup. No runtime cost, no behavior change for compliant configs. Per-user `~/.ssh` is **not** in the default recommendations because `restricted_paths` requires absolute paths and we can't know the remote user's home. Operators who care add `/root/.ssh` / `/home/<user>/.ssh` explicitly.

---

## ADR-0020 — BM25 search transform is opt-in, not default

**Status:** Accepted (2026-04-15, revisits BACKLOG line 139)

**Context:** When the catalog held 19 tools we skipped `BM25SearchTransform` per DESIGN.md §PI-8 ("revisit past 30"). After the docker (22), shell (4), alerts (1), and deploy (1) additions we're at 52 tools — past the threshold. The full `tools/list` payload runs ~15-25k tokens per turn; BM25 collapses it to two synthetic tools (`search_tools(query)`, `call_tool(name, args)`) plus a small pinned set, and the LLM searches.

**Decision:** Wire BM25 in lifespan behind `SSH_ENABLE_BM25=true` (default OFF). Tunables: `SSH_BM25_MAX_RESULTS=8` (top-K returned per search), `SSH_BM25_ALWAYS_VISIBLE` (pinned anchors so the LLM has a starting point — defaults to `ssh_host_ping`, `ssh_host_info`, `ssh_session_list`, `ssh_shell_list`). Applied AFTER the Visibility transforms so hidden tools also vanish from search.

**Consequences:** Two-step UX (search → call) is a real cognitive shift; default-off keeps the small-deployment case ergonomic. Operators with limited context windows or large catalogs flip it on; everyone else doesn't notice. Easy to A/B by toggling the env var. If the search/call indirection becomes the standard mode in our deployments, we revisit and flip the default to ON.

---

## ADR-0019 — Host allow/block matches the canonical hostname only

**Status:** Accepted (2026-04-14, tightens ADR-0015)

**Context:** The original blocklist check evaluated against the tool's input name (alias OR hostname), then again against the resolved `policy.hostname`. External review flagged the ambiguity: an operator reading `SSH_HOSTS_BLOCKLIST=prod-db` expects "block the thing labelled prod-db", but the rule actually matched both `prod-db` (alias) and `prod-db.internal` (hostname). Two subjects meant "what does this block, exactly?" had no single answer, and safety rails live or die by being obvious.

**Decision:** Aliases are a **lookup mechanism only**. `SSH_HOSTS_ALLOWLIST` and `SSH_HOSTS_BLOCKLIST` evaluate exclusively against `policy.hostname` — the string we actually open a connection to. Resolution order: `hosts.<alias>` → `hosts.*.hostname` → `SSH_HOSTS_ALLOWLIST` → `HostNotAllowed`. Blocklist is checked post-resolution, against the canonical hostname.

**Consequences:** To block a target, the operator writes its **hostname** into the blocklist, not its alias. This is a breaking change from ADR-0015 (which allowed blocklist-by-alias). An unknown host that happens to also be on the blocklist now reports `HostNotAllowed` (the most specific reason for the rejection) rather than `HostBlocked`. One subject, one rule, no ambiguity.

---

## ADR-0018 — Empty command allowlist fails closed

**Status:** Accepted (2026-04-14, supersedes the empty-allowlist-allows-anything convention)

**Context:** The original `services/exec_policy.check_command` returned early when no `command_allowlist` was configured (per-host or env). Operators reading "empty allowlist" naturally expect "nothing allowed" — not "everything allowed." The mismatch is a deployment footgun: an operator flipping `ALLOW_DANGEROUS_TOOLS=true` without also setting an allowlist gets an unrestricted exec server when they intended a locked-down one.

**Decision:** Empty allowlist now **denies every command**. To permit arbitrary commands, the operator sets `ALLOW_ANY_COMMAND=true` in the environment — an explicit, obvious, grep-able opt-in. The error message names the flag so misconfiguration surfaces with a concrete fix.

**Consequences:** Fail-closed by default; misconfigurations fail visibly rather than silently over-granting. Tests updated: `test_empty_allowlist_allows_anything` → `test_empty_allowlist_denies_by_default` + `test_empty_allowlist_allows_with_explicit_opt_in`. The same pattern (explicit flag beats implicit-by-empty) could be applied to other policy fields later if needed.

---

## ADR-0017 — Path confinement applies to reads AND writes

**Status:** Accepted (2026-04-14)

**Context:** Low-access tools (`cp`, `mv`, `edit`, `patch`, etc.) route every path through `services/path_policy.canonicalize_and_check`. Read tools (`ssh_sftp_list`, `ssh_sftp_stat`, `ssh_sftp_download`, `ssh_find`) did not. External review flagged this: "read-only" was being sold as "safe", but an LLM caller could still SFTP-download `/etc/shadow` or `/root/.ssh/id_ed25519` from any allowlisted host. "Read-only" means "no mutation"; it does **not** mean "no scope."

**Decision:** Every path-bearing tool — read or write — canonicalizes its `path` argument on the remote (`realpath -m -- <path>`) and verifies the resolved path is inside the per-host `path_allowlist` union-ed with `SSH_PATH_ALLOWLIST`. Single allowlist, one enforcement function, applied everywhere. We do not introduce separate read/write allowlists; operators who want asymmetric read/write scopes can express that by giving different SSH users different `hosts.toml` entries with different allowlists.

**Consequences:** Closes a read-exfiltration hole. Existing callers that worked by relying on implicit "reads are safe" will now get `PathNotAllowed` unless the path is explicitly scoped — that's the intent. Regression guard: `tests/test_read_tool_path_confinement.py` checks both the source references and the helper's behavior, so a future contributor can't silently drop the check.

---

## ADR-0016 — Tool groups default to all (permissive when empty)

**Status:** Accepted (2026-04-14, supersedes DESIGN.md §11 Q8 "minimal default")

**Context:** DESIGN.md §12 proposed that `SSH_ENABLED_GROUPS=""` (empty) should default to `{host, session, sftp-read}` — a minimal read-only surface. §11 Q8 left this open.

In practice this is surprising: an operator sets `ALLOW_LOW_ACCESS_TOOLS=true` to unlock file mutation, the `low-access` tier gate lifts, but the `file-ops` tools still don't appear because the group filter kept them hidden. Two flags, one desired outcome.

**Decision:** Empty `SSH_ENABLED_GROUPS` means **all groups visible** (subject to tier gates). Operators who want to trim the catalog set it explicitly. The tier flags (`ALLOW_LOW_ACCESS_TOOLS`, `ALLOW_DANGEROUS_TOOLS`, `ALLOW_SUDO`) remain the security knob; `SSH_ENABLED_GROUPS` remains the context-size knob.

Unknown group names are logged at WARNING and filtered out — they do not error.

**Consequences:** Ergonomic single-flag setup; tier flags alone determine what the LLM can do. Operators on small-context models can still shrink the catalog with an explicit list. This changes the behavior described in DESIGN.md §12; the doc should be updated to reflect this ADR.

---

## ADR-0015 — Host blocklist (deny wins over allow)

**Status:** Accepted (2026-04-14)

**Context:** DESIGN.md §2–§3 establishes an allowlist-only model: only hosts named in `hosts.toml` or `SSH_HOSTS_ALLOWLIST` can be reached. This is strict but offers no **explicit** "never touch this" signal. In practice operators want a safety rail that survives config merges — for example, forbidding `prod-*` even if someone later adds it to the allowlist for an experiment.

**Decision:** Introduce `SSH_HOSTS_BLOCKLIST` (exact hostnames, comma-separated or JSON). Resolution rule: **deny wins.** A host on the blocklist is refused as `HostBlocked` even when it is also on the allowlist, defined in `hosts.toml`, or reachable by alias. Resolution is centralized in `services/host_policy.py::resolve()`; the pool calls `check_policy()` as defense-in-depth for policies constructed outside the normal path.

As part of the same change, the list-valued env vars (`SSH_HOSTS_ALLOWLIST`, `SSH_HOSTS_BLOCKLIST`, `SSH_PATH_ALLOWLIST`, `SSH_COMMAND_ALLOWLIST`) now accept **either** a comma-separated string (`a,b,c`) **or** a JSON array (`["a","b"]`). Comma-separated is the ergonomic default; JSON remains available for values that legitimately contain commas.

**Consequences:** Belt-and-suspenders for high-risk hosts; clearer operator ergonomics. Glob / regex matching for either list remains out of scope (DESIGN.md §11 Q4) — exact strings only. A blocked **alias** is caught before resolution, so unknown-blocked entries still report `HostBlocked` (more informative than `HostNotAllowed`).

---

## ADR-0014 — `app.py` split from `server.py`

**Status:** Accepted (2026-04-14)

**Context:** `server.py` originally defined the `FastMCP` instance AND imported all tool modules for side-effect registration. Tool modules import `mcp_server` from `server`. Python initializes `server.py`, hits the tool imports, which try to re-import `server` mid-init → `ImportError: cannot import name 'mcp_server' from partially initialized module`.

**Decision:** The `FastMCP(...)` instance lives in `src/ssh_mcp/app.py`. `server.py` imports it from `app`, then performs the tool-module side-effect imports. Tool modules also import from `app`, not from `server`.

**Consequences:** Clean two-level import graph (`app` ← tool modules; `app` ← `server` ← `__main__`). No lazy/function-local imports needed. Future tool additions just `from ..app import mcp_server`.

---

## ADR-0013 — FastMCP 3 as the target

**Status:** Accepted (2026-04-14)

**Context:** FastMCP 3 introduces lifespan composition, per-tool versioning, native OTel, Skills provider, and `Visibility` transforms — all of which the design leans on.

**Decision:** Target `fastmcp>=3.0.0,<4.0.0`. Optional extras: `fastmcp[tasks]` for Docket/background tasks; `opentelemetry-distro` + OTLP exporter for telemetry. No attempt to maintain FastMCP 2 compatibility.

**Consequences:** Cleaner code, but tied to FastMCP 3 lifecycle. Major-version bumps require revalidation (AGENTS.md §5.5).

---

## ADR-0024 — `ResolvedHost` value type at the resolution boundary

**Status:** Accepted (2026-04-28)

**Context:** `host: str` flowing from MCP input through `resolve_host()` into `pool.acquire()` lost the canonical-vs-alias distinction in the type system. Functions deep in the call stack couldn't tell if they had a validated hostname or raw user input. INC-030 / INC-046 are representative of the bug class this prevents — a bare string slipping past the resolution boundary and being treated as if it were already canonical.

**Decision:** Introduce a frozen Pydantic `ResolvedHost(BaseModel)` (`extra="forbid"`) bundling `hostname: str` (canonical, post-alias-resolution) and `policy: HostPolicy`. `resolve_host(ctx, name) -> ResolvedHost` is the single resolution call site in [tools/_context.py](src/ssh_mcp/tools/_context.py). `pool.acquire(resolved: ResolvedHost)` unwraps to `_acquire_policy(policy)` at the pool boundary; `_check_allowed`, `open_connection`, and `_open_single` keep consuming `HostPolicy` directly. The stateless policy validators (`path_policy`, `exec_policy`, `host_policy`) keep `HostPolicy` — they have no need for the canonical-vs-alias distinction. Bastion hop paths use `_acquire_policy` directly because hop hosts come from the in-memory registry and are never raw user input. `require_posix(...)` was updated to accept `ResolvedHost` so it can surface the alias in its error messages. `multi_host_tools.py` stores `dict[str, ResolvedHost]` (alias → resolved). The double-resolve pattern at `systemctl` and SFTP helper sites was intentionally preserved to keep T1's scope tight; threading `resolved` through those helpers is a follow-up backlog item.

**Consequences:** MCP tool input signatures stay `host: str`; the value type lives downstream of the MCP boundary and is invisible to callers. The type system now enforces that anything operating on a validated hostname receives a `ResolvedHost`, not a raw string. Future cleanup: thread `resolved` through the eight `systemctl` wrapper sites and analogous patterns in `ssh_cp` / `ssh_mv` / `ssh_docker_exec` that currently double-resolve. Reviewer flagged this as a low-priority mechanical backlog item.

**References:** ArjanCodes patterns skill `[26/value]` + `[25/brittle]`. Sprint task T1 in `.claude/state/current-sprint.md`.

---

## ADR-0025 — Uniform `extra="forbid"` on all result models (incl. systemctl)

**Status:** Accepted (2026-04-30)

**Context:** INC-046 (2026-04-17) applied `extra="forbid"` + `_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")` to the 13 result models in `models/results.py`. The 9 systemctl result models in `models/systemctl.py` were authored after that review and were the only remaining model file missing the strictness config. A BACKLOG item captured this gap as a deferred follow-up.

**Decision:** Sprint 3 (v1.4.0) adds `_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")` to `models/systemctl.py` and applies it to all 9 systemctl result models (`SystemctlStatusResult`, `SystemctlIsActiveResult`, `SystemctlIsEnabledResult`, `SystemctlIsFailedResult`, `SystemctlListUnitsResult`, `SystemctlShowResult`, `SystemctlCatResult`, `JournalctlResult`, `SystemctlListUnitsEntry`). This mirrors the exact pattern used in `models/results.py` — one shared constant, applied to every model in the file.

**Consequences:** Construction-site typos on systemctl result models now raise `ValidationError` at the call site rather than silently dropping the field. The deferred BACKLOG item is closed. All `models/*.py` result classes now uniformly use `extra="forbid"` — no per-model exceptions remain.

---

## ADR-0026 — `local_path` bypass for the base64 LLM-channel bottleneck

**Status:** Accepted (2026-05-28)

**Context:** The default upload/download channel encodes file bytes as base64 inside tool-call arguments. Around 24 MiB the LLM began defensively chunking files into many small atomic-rename uploads — effectively serializing a large transfer into dozens of tool calls, each carrying a fragment. This made the channel unusable for real file transfer of anything non-trivial in size. The same problem applies in reverse: downloading a large file returns a base64 blob that occupies a significant fraction of the context window.

**Decision:** Add a `local_path` keyword-only parameter to `ssh_upload`, `ssh_deploy`, and `ssh_sftp_download`. When set, the bytestream is sourced from (or written to) the MCP host's own filesystem rather than encoded in the tool-call argument. Key design choices:

1. **Explicit opt-in with no fallbacks.** `SSH_LOCAL_TRANSFER_ROOTS` must be non-empty for the mode to activate; empty list = disabled. No fallback to cwd, MCP roots, or `~/Downloads`.
2. **Separate size cap.** `SSH_LOCAL_TRANSFER_MAX_BYTES` (default 2 GiB) governs the `local_path` code path exclusively. The existing `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB) still governs the base64 paths.
3. **Independent from `SSH_PATH_ALLOWLIST`.** The new `services/local_path_policy.py` governs MCP-host-side paths; `SSH_PATH_ALLOWLIST` governs remote SSH targets. Both must be configured separately.
4. **Three-way mutex.** `content_text`, `content_base64`, and `local_path` are mutually exclusive; exactly one must be set on upload, and `local_path` is optional on download.
5. **Atomic writes on both ends.** Upload streams from disk in 256 KiB chunks into the existing tmp+rename flow. Download writes to `<local_path>.ssh-mcp-tmp.<rand>` then `os.replace`.
6. **Symlink safety.** Read mode: strict-resolve (must exist + regular file). Write mode: strict-resolve of parent then canonical rebuild so symlinked parents are followed before the `is_relative_to` allowlist check.

**Consequences:** Large artifact deploys and snapshot downloads no longer require the LLM to hold or generate multi-MB base64 strings. Operators must explicitly configure `SSH_LOCAL_TRANSFER_ROOTS` — the default is safe (disabled). The `local_path_written` field on `WriteResult` and `DownloadResult` provides an audit trail back to the source/destination path on the MCP host.

---

## ADR-0027 — Secret-redaction layer: separate tool + HMAC markers + three-list policy (v1.5.0)

**Status:** Accepted (2026-05-30)

**Context:** The LLM routinely reads production config files (`.env`, docker compose, app YAML) to understand service configuration. These files mix structural information (which keys exist, how they relate) with secret values (passwords, tokens, API keys). `ssh_sftp_download` returns the raw bytes, putting plaintext secrets into the LLM context window -- a privacy concern even when the LLM itself is trusted, since context can be logged, sampled, or inadvertently reproduced in outputs.

**Decision:** Ship a separate `ssh_read_redacted` tool plus a three-list path policy. Key choices:

1. **Separate tool, not auto-redaction in `ssh_sftp_download`.** Auto-redaction inside `ssh_sftp_download` would be silent and surprising -- operators who read non-secret files would get markers they didn't ask for, and the intent ("I want to read this safely") would be invisible in the audit log. A dedicated tool makes the LLM's decision explicit and auditable. The tool name itself appears in the audit line; `ssh_sftp_download` remains semantically "raw bytes."

2. **HMAC-SHA256 with 12-character hex prefix.** A 12-char hex prefix is 48 bits of collision space -- more than adequate for any realistic secret set (even 100,000 unique secrets gives ~0.004% collision probability). At the same time, 12 hex chars is short enough that the inline marker `<sha:abcdef123456 len:48>` reads naturally and the LLM can copy it verbatim when cross-referencing across hosts. Brute-force reversal of the original secret requires breaking HMAC-SHA256 with an unknown salt, not just matching the short prefix.

3. **Three-list distinction.** `restricted_paths` (prefix-deny), `restricted_globs` (glob-deny), and `redact_paths_globs` (bypass-policy route) serve different needs and must not collapse into one. `restricted_*` is a hard-deny regardless of what tool is used -- it defends against misconfigurations where the path allowlist is too wide. `redact_paths_globs` is a softer gate: the path is readable but only by `ssh_read_redacted`. Conflating them would force operators to choose between "totally blocked" and "raw bytes to LLM."

4. **`block` is the recommended default for `redact_bypass_policy`.** Fail-closed: if the operator hasn't explicitly opted into `warn` or `audit_only`, other tools simply refuse with an error naming the alternative. `warn` is appropriate for dev where the operator trusts the LLM not to leak. `audit_only` is for deployments where the policy must be invisible to the LLM but tracked by SIEM.

5. **Entropy detection on by default.** Key-name matching only catches known patterns. Scripts and compose files often carry base64-encoded secrets in values whose keys don't match `PASSWORD` or `TOKEN`. Default-on entropy detection (base64 >= 20 chars, hex >= 32 chars) catches the common shapes without operator configuration of every key. PEM blocks are always caught regardless of the toggle -- they are unambiguous private key / certificate material.

6. **Anchor escape hatch in `_key_matches`.** Bare substring `PASS` would over-match `BYPASS_*` / `COMPASS_*` / `PASSTHROUGH`. The anchor syntax (`^PREFIX_`, `_SUFFIX$`, `^EXACT$`) lets the built-in list use `^PASS_` and `_PASS$` for the common `DB_PASS` / `PASS_HEADER` cases while staying clean on the false-positive classes. Operators can use the same anchors in `redact_keys_add`.

**Consequences:** LLMs can reason about config file structure and compare secrets across hosts (same secret = same hash) without ever seeing plaintext. Operators gain a structured audit trail (`redact_bypass: true` on warn/audit_only) for SIEM. The raw-exec bypass gap (see INC-064) is a documented limitation, not a defect -- mitigation via `command_allowlist` is the correct layer.

**References:** [services/redact_policy.py](src/ssh_mcp/services/redact_policy.py), [services/redactor.py](src/ssh_mcp/services/redactor.py), [tools/sftp_read_tools.py:ssh_read_redacted](src/ssh_mcp/tools/sftp_read_tools.py), [models/results.py:RedactedReadResult](src/ssh_mcp/models/results.py), INC-064.

---

## ADR-0028 -- Sudo-tier path-bearing tools + path-aware cheatsheet (v1.5.0)

**Status:** Accepted (2026-05-30)

**Context:** After the v1.5.0 redact-policy layer landed, a gap remained on production-hardened hosts where the SSH service account has minimal rights. On those hosts the SFTP-layer path policy (allowlist + restricted_paths + restricted_globs + redact_paths_globs) was de facto unreachable for root-owned files: the only sudo path was `ssh_sudo_exec("cat /etc/...")` which takes a command string, not a path argument, and has no structural hook to apply per-path policy. A root-owned `.env` at `/docker/app/.env` could be read via `ssh_sudo_exec cat /docker/app/.env` while `ssh_sftp_download` on the same path would be blocked by `redact_bypass_policy=block`.

**Decision:** Ship five sudo-tier path-bearing tools that route through the same `resolve_path` / `resolve_path_for_redacted_read` policy chain as the SFTP-read tier. Key choices:

1. **Five-tool scope (read + read_redacted + write + edit + list).** A three-tool partial set (read + write + list) would have left the "edit an existing privileged file" use-case on `ssh_sudo_exec` with a heredoc -- which is the exact bypass we are trying to close. All five are needed for a complete operator workflow.

2. **Shell-script-body construction convention: inline operator values as shell variables.** The `sudo_atomic_write` helper constructs a `sudo sh -c '<script>'` body. The inner command becomes the body of an outer `sh -c <quoted_inner>` via `_run_sudo_bytes`. Trailing positional-arg tokens after the script body (`sh -c '<script>' _ <dest> <mode> <owner>`) are parsed as shell statements, not positional params -- this is the bug that surfaced on live runs as `sh: 1: Syntax error: word unexpected` at stage `cat>tmp`. Fix: inline values as shell variables (`dest=<quoted>; mode=<quoted>; owner=<quoted>`) at the top of the script body via `shlex.quote`, never as trailing positional args. Future shell-script helpers MUST use this pattern.

3. **Path-aware cheatsheet hybrid.** When the command shape allows unambiguous single-path extraction (`cat <path>`, `head -n N <path>`, `ls <path>`), the rejection hint is path-aware: if the extracted path matches `redact_paths_globs`, the hint names the `_redacted` variant. When the shape is too complex to extract a path reliably (`awk`, `sed`, `grep`, `file`), a generic `read-ambiguous` pattern refuses with a broad redirect. The arms-race against creative shell shapes (`awk '{print}' .env`) is explicitly not pursued -- the spec accepts that residual surface.

4. **`ssh_sudo_write(local_path=)` reads file into memory.** The `local_path` mode uses `resolve_local_path` from `services/local_path_policy.py` (same operator setup as `ssh_upload`'s `local_path` mode, `SSH_LOCAL_TRANSFER_ROOTS` required). The local file is read into MCP server memory, then piped via stdin into the sudo pipeline. This avoids the LLM having to generate large base64 payloads. True streaming (no in-memory buffer) is deferred.

5. **`ssh_sudo_edit` preserves both ownership AND mode.** Two `sudo stat` calls run before write-back: `stat -c '%U:%G'` for owner/group and `stat -c '%a'` for octal permission bits. A secrets file at `0o600` must not get widened to the write helper's `0o644` default. This is security-critical: the default is applied ONLY as a fallback when stat returns `None` (file vanished between read and write -- an edge case, not the normal path).

6. **`SudoFileOpError` as the new exception class.** Path-policy failures (`PathNotAllowed`, `PathRestricted`, `RedactBypassBlocked`) continue to be raised upstream in `services/path_policy.py` before any sudo invocation. `SudoFileOpError` covers failures inside the sudo pipeline itself (sudo refused, cat/ls/stat failed, parse failure, cap exceeded). Callers see a clean two-class failure surface.

**Consequences:** The `redact_paths_globs` policy boundary now extends to root-owned files on hardened hosts. Operators with `ALLOW_SUDO=true` and `redact_bypass_policy=block` get consistent behavior across ssh-user-readable and root-owned paths: `.env` files are refused by both `ssh_sftp_download` and `ssh_sudo_read`, and both redirect to the `*_redacted` variant. The cheatsheet catches the most common `sudo cat .env` shapes and surfaces the redirect before any sudo invocation. Residual bypass surface via creative shell expressions is documented as INC-064 (unchanged from v1.5.0).

**References:** [services/sudo_file_ops.py](src/ssh_mcp/services/sudo_file_ops.py), [tools/sudo_tools.py](src/ssh_mcp/tools/sudo_tools.py), [services/exec_cheatsheet.py](src/ssh_mcp/services/exec_cheatsheet.py), [ssh/errors.py](src/ssh_mcp/ssh/errors.py), INC-064.

---

## ADR-0029 -- Server-info as dual surface (resource primary + tool fallback)

**Date:** 2026-06-01 / **Version:** 1.14.0 / **Status:** Accepted

**Context.** Operators and LLMs occasionally need to know which MCP server version they are talking to -- for capability-discovery ("am I on v1.12+ so `ssh_read_redacted` is available?"), for debugging client-server mismatches, or for cross-fleet asset tracking. FastMCP already populates `serverInfo.version` in the MCP initialize handshake from the value we pass to `FastMCP(version=...)` in `app.py`, but no major MCP client surfaces `serverInfo` into the LLM context. The version is operator-visible only (in client debug panes); the LLM cannot see it.

**Decision.** Expose server identity + capability surface via TWO MCP surfaces sharing one builder function:

1. **MCP resource** `mcp://ssh-mcp/server-info` -- the PRIMARY discovery path. Resources are the semantically correct MCP shape for "what is this server" -- static-ish metadata, cache-friendly, doesn't cost a catalog slot per turn.

2. **`ssh_server_info` tool** (read-tier, `group:host`) -- the FALLBACK for clients that do not expose `resources/list` to the LLM. Same payload shape as the resource body; pick whichever surface the client supports.

Both call into one shared `_collect_server_info()` helper in `tools/server_info_tools.py` so the payloads stay in lockstep. Payload shape (`ServerInfoResult`):

- `name` -- always `"ssh-mcp"`.
- `version` -- the running server's SemVer.
- `total_tools` -- post-Visibility count (what the LLM actually sees in `tools/list`).
- `enabled_tiers` -- list of `read` / `low-access` / `dangerous` / `sudo` depending on the `ALLOW_*` flags.
- `enabled_groups` -- the operator's `SSH_ENABLED_GROUPS` filter verbatim (empty list = no filter = all visible).

**Alternatives considered.**

- *Just the resource, no tool.* Cleaner architecturally but leaves the LLM blind on Claude Code / Claude Desktop / Cursor's current resource-handling story. Rejected because LLM-side capability discovery is the primary use-case.
- *Just the tool, no resource.* Costs one catalog slot per turn for metadata that doesn't change. Rejected because the resource is free per turn on supporting clients.
- *Piggy-back on `ssh_host_ping` or `ssh_host_list`.* Considered, but requires an arbitrary host alias to be configured even when the LLM only wants server metadata, and entangles host-level concerns with server-level metadata. Rejected.

**Consequences.** One new read-tier tool (~150 B catalog cost per turn -- worth it for the LLM-reachable fallback) plus one new resource entry. The tool is intentionally NOT decorated with `@audited`: server-meta queries don't need a security signal, and noising the audit log with them buys nothing. Capability-discovery via `ssh_server_info` is equivalent to checking `tools/list` for a tool name; both are cheap, and the LLM picks whichever surface its client exposes. No new env vars, no security boundary shift.

**References:** [tools/server_info_tools.py](src/ssh_mcp/tools/server_info_tools.py), [models/results.py::ServerInfoResult](src/ssh_mcp/models/results.py), [skills/ssh-server-info/SKILL.md](skills/ssh-server-info/SKILL.md), [app.py](src/ssh_mcp/app.py) (where the FastMCP `version=` field is set from `settings.VERSION`).
