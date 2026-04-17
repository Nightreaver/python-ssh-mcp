# INCIDENTS — Security review and findings log

Central log of security-relevant findings. Every check performed against
this codebase (internal review, external issue scan, code review) lands
here with a stable ID, a status, and links to the fix + tests +
documentation trail.

Consolidates security-review bookkeeping into a single append-only
ledger. Entries that originated before the 2026-04-16 consolidation keep
their historical IDs in the **Legacy ID** column (e.g. `C1`, `H3`, `N2`,
`W1`) as a migration aid; the `INC-NNN` identifier is canonical going
forward.

## Conventions

- **ID**: `INC-NNN`, issued in order, never reused.
- **Source**:
  - `internal-review` — we found it ourselves scanning the codebase.
  - `external-issue` — public issue in another SSH-MCP project.
  - `audit-report` — external security audit (e.g. AgentWard).
  - `code-review` — post-merge review of a specific PR / change.
- **Severity**: `Critical` / `High` / `Medium` / `Low` / `N/A` (the `N/A`
  case is for external issues that don't apply to our architecture).
- **Status**: `resolved` / `open` / `deferred` / `n/a`.
- **Refs**: BACKLOG progress entry date, DECISIONS ADR, source file + line,
  regression test path.

## How to use this file

- **Before opening a new finding**: grep here first. If the issue class was
  already evaluated, add a comment to the existing row rather than opening
  a new one.
- **When resolving**: change `Status` to `resolved`, add the fix commit /
  test / ADR to `Refs`, keep the original context block intact. Don't
  delete entries — the audit trail is the whole point.
- **When deferring**: change `Status` to `deferred`, add a `Deferred until:`
  line with a trigger condition ("when `ssh_shell_exec` grows complexity",
  "when we have a live Windows OpenSSH test target").

---

## Status index

Newest at the top.

| ID | Legacy | Date | Severity | Status | Source | Title |
|---|---|---|---|---|---|---|
| INC-051 | — | 2026-04-17 | Medium | resolved | external-issue | `classfang/ssh-mcp-server#22` — `SSH_CONFIG_FILE` was declared + documented but never consumed; now wired to `asyncssh.connect(config=[...])` with empty-string normalization + startup log |
| INC-050 | — | 2026-04-17 | N/A | n/a (covered) | external-issue | `bvisible/mcp-ssh-manager#16` — hardcoded `__dirname/.env` path; Python equivalent uses CWD-relative resolution + sync lifespan load |
| INC-048 | — | 2026-04-17 | Low | resolved | code-review | `services/audit.py` now type-checks both `kwargs["host"]` and `args[0]`; non-string falls through to "?" |
| INC-047 | — | 2026-04-17 | Medium | resolved | code-review | Shell-session `session.lock` is the only guard on `cwd`; added `exec_scope()` + `set_cwd()` that asserts lock-held at runtime |
| INC-046 | — | 2026-04-17 | Low | resolved | code-review | Step 1: `extra="forbid"` on all 13 result models. Step 2: 22 tools now return their `BaseModel` directly; MCP advertises real schemas; all test assertions converted to attr-access |
| INC-045 | — | 2026-04-17 | Low | resolved | code-review | Cleanup pass (104 → 0) + ruff `select` expanded with `ASYNC`/`PERF`/`PT`/`PLE`/`TCH`; runtime-import gotchas pinned via per-file ignores |
| INC-044 | — | 2026-04-17 | Low | open | code-review | No `.pre-commit-config.yaml`, no `.github/workflows/*.yml`, no `.python-version`; mypy-strict + custom ruff need CI gates |
| INC-043 | — | 2026-04-17 | Medium | resolved | code-review | `tools/docker_tools.py` 1020 lines split into `docker/_helpers` + `read_tools` + `lifecycle_tools` + `dangerous_tools` subpackage; facade preserves public imports |
| INC-042 | — | 2026-04-17 | Medium | resolved | code-review | `tools/_context.py` accessors use `# type: ignore[no-any-return]`; defined `LifespanContext` `TypedDict` + single `cast` |
| INC-041 | — | 2026-04-17 | Low | resolved | code-review | `tenacity` declared in pyproject but never imported — removed |
| INC-040 | — | 2026-04-17 | Medium | resolved | code-review | `_docker_prefix` / `_compose_prefix` typed `policy: Any, settings: Any`; now `HostPolicy` / `Settings` under `TYPE_CHECKING` |
| INC-039 | — | 2026-04-17 | Medium | resolved | code-review | `_atomic_write` catch `except Exception:` swallowed `CancelledError` / `MemoryError`; narrowed to `(asyncssh.Error, OSError)` |
| INC-038 | — | 2026-04-17 | Medium | resolved | code-review | `ssh_host_info` / `_alerts` used `asyncio.gather` without `return_exceptions=True`; one failing probe cancelled siblings |
| INC-037 | — | 2026-04-17 | Medium | resolved | code-review | `HostKeyMismatch` raised with literal `"<received>"` placeholder; replaced with explicit "unknown (asyncssh didn't expose it)" wording |
| INC-036 | — | 2026-04-17 | High | resolved | code-review | `ConnectionPool._reap_once()` iterated `self._entries.items()` while concurrent `acquire` could mutate → `RuntimeError`; snapshotted |
| INC-035 | — | 2026-04-17 | High | resolved | code-review | `ssh/exec.py` cancelled pump tasks on timeout without awaiting them; "Task exception was never retrieved" + lingering refs to closed channel |
| INC-034 | — | 2026-04-17 | High | resolved | e2e-test | Windows SFTP `realpath` returns Cygwin form `/C:/...`; canonicalizer rejected every Windows path |
| INC-033 | — | 2026-04-16 | Medium | resolved | code-review | `ssh_docker_volumes(name=...)` exit_code semantics undocumented (I2) |
| INC-032 | — | 2026-04-16 | Low | resolved | code-review | `_DOCKER_TIME_RE` accepts `d` but Go rejects it (I1) |
| INC-031 | — | 2026-04-16 | Critical | resolved | code-review | `ssh_file_hash` Windows branch used POSIX `shlex.join` quoting (B1) |
| INC-030 | — | 2026-04-16 | High | resolved | code-review | `ssh_file_hash` timeout docstring lie + no param (B1) |
| INC-029 | — | 2026-04-16 | High | resolved | code-review | `ssh_docker_cp` missing `effective_restricted_paths`/`check_not_restricted` imports → NameError (B1) |
| INC-028 | W1 | 2026-04-16 | Medium | resolved | internal-review | `ssh_file_hash` now supports Windows via PowerShell `-EncodedCommand` (base64-UTF16LE of a `Get-FileHash` script) |
| INC-027 | N3b | 2026-04-15 | Low | n/a (superseded) | internal-review | Shell-session lock has no end-to-end test — superseded by INC-047 (`set_cwd` now asserts lock-held; bypass-the-lock regression class eliminated) |
| INC-026 | N3a | 2026-04-15 | Low | resolved | internal-review | Tautological assertion in shell-session lock test |
| INC-025 | N2b | 2026-04-15 | Low | resolved | internal-review | Container-namespace join flags not covered (`--pid=container:<id>`) |
| INC-024 | N2a | 2026-04-15 | Medium | resolved | internal-review | `--mount` bypassed docker-run escalation deny-list |
| INC-023 | N3 | 2026-04-15 | Low | resolved | internal-review | Shell-session state caller-serialized, not locked |
| INC-022 | N2 | 2026-04-15 | Medium | resolved | internal-review | `ssh_docker_run` accepts arbitrary docker flags (--privileged, --cap-add, ...) |
| INC-021 | N1 | 2026-04-15 | Medium | resolved | internal-review | Unbounded fire-and-forget hook tasks |
| INC-020 | — | 2026-04-16 | N/A | n/a | code-review | Commit-message-style review: SSRF / hardcoded fallbacks / typos / stray `}` |
| INC-019 | — | 2026-04-15 | N/A | n/a | external-issue | `classfang/ssh-mcp-server#31` — `the input device is not a TTY` |
| INC-018 | — | 2026-04-15 | N/A | n/a | external-issue | `tufantunc/ssh-mcp#44` — newline injection via `description` metadata field |
| INC-017 | — | 2026-04-15 | N/A | n/a | external-issue | `tufantunc/ssh-mcp#42` — credentials in process argv / `ps` |
| INC-016 | — | 2026-04-15 | N/A | n/a | external-issue | `tufantunc/ssh-mcp#2` — no default command timeout |
| INC-015 | — | 2026-04-15 | N/A | n/a | audit-report | `bvisible/mcp-ssh-manager#13` — AgentWard audit (37 tools, unrestricted SSH, SOCKS5, no path allowlist) |
| INC-014 | L2 | 2026-04-14 | Low | resolved | internal-review | SFTP magic error codes (should use `asyncssh.sftp.FX_*`) |
| INC-013 | L1 | 2026-04-14 | Low | resolved | internal-review | Host policy lacked port-range / type / absolute-path validation |
| INC-012 | M5 | 2026-04-14 | Medium | resolved | internal-review | Absolute-path `command_allowlist` entries basename-matched (shadow-binary risk) |
| INC-011 | M1 | 2026-04-14 | Medium | resolved | internal-review | Streaming `chunk_cb` received more bytes than buffer captured |
| INC-010 | H4 | 2026-04-14 | High | resolved | internal-review | `ssh_edit` / `ssh_patch` crash on non-UTF-8 files |
| INC-009 | H3 | 2026-04-14 | High | resolved | internal-review | `SSH_SUDO_PASSWORD` env-var accepted (should be rejected at startup) |
| INC-008 | H2 | 2026-04-14 | High | resolved | internal-review | Audit `error` field leaks full exception text (may carry remote stderr) |
| INC-007 | H1 | 2026-04-14 | High | resolved | internal-review | `UnknownHost` vs `HostKeyMismatch` disambiguated by exception text substring |
| INC-006 | C4 | 2026-04-15 | Critical | resolved | internal-review | `KnownHosts.fingerprint_for` silently returned `None` (wrong tuple unpack) |
| INC-005 | C3 | 2026-04-14 | Critical | resolved | internal-review | Streaming `_pump` byte counters not updated per chunk → `stdout_truncated` wrong on timeout |
| INC-004 | C2 | 2026-04-14 | Critical | resolved | internal-review | `assert` before `rm -rf` stripped under `python -O` |
| INC-003 | C1 | 2026-04-14 | Critical | resolved | internal-review | `SSH_ENABLED_GROUPS` field missing from `Settings` — startup crash |
| INC-002 | — | 2026-04-14 | N/A | n/a | external-issue | External review: path confinement must apply to reads (ADR-0017 triggering event) |
| INC-001 | — | 2026-04-14 | N/A | n/a | external-issue | External review: empty `command_allowlist` footgun (ADR-0018 triggering event) |

---

## Detailed entries

### INC-051 — `SSH_CONFIG_FILE` declared but never consumed (`classfang/ssh-mcp-server#22`)

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** external-issue ([github.com/classfang/ssh-mcp-server/issues/22](https://github.com/classfang/ssh-mcp-server/issues/22))
- **Refs:** [config.py:25,107-118](src/ssh_mcp/config.py#L25), [ssh/connection.py:68-78](src/ssh_mcp/ssh/connection.py#L68-L78), [lifespan.py:236-249](src/ssh_mcp/lifespan.py#L236-L249), [tests/test_ssh_config_file.py](tests/test_ssh_config_file.py)

External feature request on a sibling project asked for `~/.ssh/config` support. Cross-check revealed a doc/code drift in *this* codebase: `SSH_CONFIG_FILE: Path | None = None` was declared in [config.py:25](src/ssh_mcp/config.py#L25), surfaced in [.env.example](.env.example#L5), promised by [AGENTS.md:594](AGENTS.md#L594) ("Honor `~/.ssh/config` when `SSH_CONFIG_FILE` is set (ProxyJump, user overrides, etc.)"), echoed in [DESIGN.md:451](DESIGN.md#L451), and listed in [tests/conftest.py:26](tests/conftest.py#L26) — but the **only** consumer in the entire `src/` tree was the test conftest cleaning it out of the environment. The connect path in [_open_single](src/ssh_mcp/ssh/connection.py#L53) built kwargs purely from `HostPolicy` and never passed anything to asyncssh's `config=` parameter. Operators setting the field saw zero effect; ProxyJump/IdentityFile/host-alias from their personal SSH config were silently ignored.

**Fix (3 small edits + test):**

1. [ssh/connection.py:68-78](src/ssh_mcp/ssh/connection.py#L68-L78) — `_open_single` now appends `kwargs["config"] = [str(settings.SSH_CONFIG_FILE.expanduser())]` when the field is set. asyncssh treats config-file values as fallbacks for kwargs not explicitly passed, so our explicit `host`/`port`/`username`/`known_hosts` still win — `~/.ssh/config` only fills in fields hosts.toml omitted (most usefully `IdentityFile`, `ProxyCommand`, `Host alias → HostName real.example.com`, and `Ciphers`/`MACs`/`KexAlgorithms` for legacy gear). `expanduser()` is called explicitly because pydantic's `Path` coercion does not.
2. [config.py:107-118](src/ssh_mcp/config.py#L107-L118) — added `_empty_path_to_none` field validator. `.env.example` ships `SSH_CONFIG_FILE=` (blank); without the validator pydantic would coerce `""` to `Path("")` (truthy, points at CWD) and every connection would smuggle a bogus config path into asyncssh.
3. [lifespan.py:236-249](src/ssh_mcp/lifespan.py#L236-L249) — startup logs `ssh_config: honoring <abs-path>` when set+exists, or WARNING when set+missing. asyncssh tolerates a missing config file silently, which makes "I set the env var but ProxyJump still doesn't apply" debug sessions miserable; the explicit log line gives the operator the resolved absolute path up front. Mirrors the same pattern used for `hosts.toml` ([hosts.py:35](src/ssh_mcp/hosts.py#L35)).

**Test ([tests/test_ssh_config_file.py](tests/test_ssh_config_file.py)):** 5 tests pinning the contract — `config` kwarg appears when set, absent when unset, `~` expanded before forwarding, blank env string normalized to None, whitespace-only env string normalized to None. Pattern: monkeypatch `asyncssh.connect` with a fake that captures kwargs and raises `_StopHere` to abort before networking. 462 unit tests green; mypy strict + ruff clean on the touched files.

Filing as Medium because the field was load-bearing for any operator with non-trivial SSH client config, and the silent failure mode (no warning, no error, no effect) is exactly the class of bug INC-016/INC-019 logging was meant to surface for adjacent code paths.

### INC-050 — `bvisible/mcp-ssh-manager#16` — hardcoded `__dirname/.env` path

- **Date:** 2026-04-17 · **Severity:** N/A · **Status:** n/a (covered)
- **Source:** external-issue ([github.com/bvisible/mcp-ssh-manager/issues/16](https://github.com/bvisible/mcp-ssh-manager/issues/16))
- **Refs:** [config.py:14](src/ssh_mcp/config.py#L14), [config.py:29](src/ssh_mcp/config.py#L29), [hosts.py:34-36](src/ssh_mcp/hosts.py#L34-L36), [lifespan.py:222-230](src/ssh_mcp/lifespan.py#L222-L230)

External report against `bvisible/mcp-ssh-manager`: `index.js` builds `path.join(__dirname, '..', '.env')`, which under global npm install resolves to `node_modules/mcp-ssh-manager/.env` and never matches the user's actual `.env`. Secondary bug: `configLoader.load().then(...)` runs without `await`, so the server boots before configs finish loading and reports "No SSH server configurations found." Three failure modes total: wrong base path, race window, silent miss.

Cross-check against this codebase:

1. **Hardcoded module-relative path.** Doesn't apply. `_ENV_FILE = ".env"` ([config.py:14](src/ssh_mcp/config.py#L14)) is a bare relative string; pydantic-settings resolves it against the **process CWD**, not the package install dir. Same for `SSH_HOSTS_FILE: Path | None = Path("hosts.toml")` ([config.py:29](src/ssh_mcp/config.py#L29)) and `SSH_SKILLS_DIR` / `SSH_RUNBOOKS_DIR`. Global install via `uv tool install` / `pipx` works — the launcher's CWD is honored.
2. **Async load race.** Doesn't apply. `Settings()` instantiation is synchronous; `load_hosts(...)` ([lifespan.py:222](src/ssh_mcp/lifespan.py#L222)) is a synchronous call inside the lifespan startup before any tool registration completes. No window where the server is up but configs aren't.
3. **Silent miss.** Already mitigated. [hosts.py:35](src/ssh_mcp/hosts.py#L35) emits `logger.info("hosts.toml not found at %s; running in env-only mode", path)` with the resolved absolute path (after `expanduser`). Lifespan startup line ([lifespan.py:226-230](src/ssh_mcp/lifespan.py#L226-L230)) prints `hosts_file=<path> named_hosts=<n> allowlisted=<n>` so the operator confirms the right file even on success.

One small gap remains symmetric to their UX complaint: pydantic-settings doesn't log which `.env` it loaded (or whether it found one at all). Trivial polish — emit a `dotenv: <abs-path-or-"absent">` line at lifespan start — but not a bug. Not opening a separate INC for it; tracked here for future cleanup if anyone hits the confusion in the wild.

Filing as `N/A` rather than `resolved` because no code changed. Documented for the audit trail and to avoid re-evaluating the same external report later.

### INC-048 — `audit.py` extracts `host` from `args[0]` without type-checking

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [services/audit.py:94-103](src/ssh_mcp/services/audit.py#L94-L103), [tests/test_audit.py](tests/test_audit.py) (`test_audited_host_type_checks_args_zero`)

`audited` decorator extracted `host = kwargs.get("host") or (args[0] if args else "?")` — `args[0]` was blindly trusted to be the host string. Any tool signature that put a non-string first (Context, int, arbitrary object) would smear whatever `__repr__` landed into the audit line. **Fix (option a):** type-check both sides — `kwargs["host"]` must be `str`, `args[0]` must be `str`, otherwise fall through to the `"?"` sentinel. Kept option (a) over requiring `host` keyword-only on every tool (option b) because (b) ripples across the whole tool surface for a Low-severity audit-quality issue. A regression test `test_audited_host_type_checks_args_zero` passes a `_NotAHost()` instance with a distinctive `__repr__` as `args[0]` and asserts the audit line carries `"host": "?"`, not the repr text.

### INC-047 — Shell-session `cwd` has no async-safe update API

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [services/shell_sessions.py:38-87](src/ssh_mcp/services/shell_sessions.py#L38-L87), [tools/shell_tools.py:86-109](src/ssh_mcp/tools/shell_tools.py#L86-L109), [tests/test_shell_sessions.py:210-262](tests/test_shell_sessions.py#L210-L262)

INC-023 added `session.lock` to serialize concurrent `ssh_shell_exec` calls on the same `session_id`. The lock was correct where used but discipline-only — any caller who wrote `session.cwd = ...` without acquiring `session.lock` first would observe a torn update, no test caught a misuser, no invariant raised if the lock wasn't held. **Fix:** added `ShellSession.exec_scope()` async context manager (the one approved way to hold the lock) + `ShellSession.set_cwd(new_cwd)` method that asserts `self.lock.locked()` at the write site. `ssh_shell_exec` rewritten to use both. Any future caller that forgets the `exec_scope` wrapper trips `RuntimeError: ShellSession.set_cwd called without holding exec_scope()` in the first test run. Three new regression tests pin the behavior: `test_set_cwd_outside_exec_scope_raises` (runtime assertion), `test_set_cwd_inside_exec_scope_succeeds` (happy path), `test_exec_scope_serializes_like_raw_lock` (mirrors the INC-023 serialization invariant through the new API so refactoring the scope implementation can't silently break concurrency). Supersedes INC-027: the "bypass the lock" regression class is eliminated by construction, so the end-to-end test INC-027 worried about becomes moot. 451 unit tests green.

### INC-046 — Result models lack `extra="forbid"`; tools return dicts instead of `BaseModel`

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [src/ssh_mcp/models/results.py](src/ssh_mcp/models/results.py), [src/ssh_mcp/tools/](src/ssh_mcp/tools/), [pyproject.toml:lint](pyproject.toml)

Policy models had `ConfigDict(extra="forbid")`; result models didn't, so typos in field construction silently succeeded. Separately, most tools built a `BaseModel` and immediately called `.model_dump()` before returning — FastMCP serializes `BaseModel` directly and preserves the MCP schema, but the tools were advertising `dict[str, Any]`. Two-step fix executed in the same release window before shipping.

**Step 1 (resolved):** added `model_config = ConfigDict(extra="forbid")` to every result model in `models/results.py` (13 classes). Pulled into a module-level `_RESULT_MODEL_CONFIG` constant so a future config switch lands in one place. Construction-site typos like `HashResult(digets=...)` now raise `ValidationError` at the call site.

**Step 2 (resolved):** dropped `.model_dump()` at the tool boundaries for 22 tools that return a single typed shape:

- `host_tools`: `ssh_host_ping` → `PingResult`, `ssh_host_info` → `HostInfoResult`, `ssh_host_disk_usage` → `DiskUsageResult`, `ssh_host_processes` → `ProcessListResult`
- `sftp_read_tools`: `ssh_sftp_list` → `SftpListResult`, `ssh_sftp_stat` → `StatResult`, `ssh_sftp_download` → `DownloadResult`, `ssh_find` → `FindResult`, `ssh_file_hash` → `HashResult`
- `low_access_tools` (8): `ssh_mkdir`, `ssh_delete`, `ssh_cp`, `ssh_mv`, `ssh_upload`, `ssh_edit`, `ssh_patch` → `WriteResult`
- `exec_tools` (3): `ssh_exec_run`, `ssh_exec_script`, `ssh_exec_run_streaming` → `ExecResult`
- `sudo_tools` (2): `ssh_sudo_exec`, `ssh_sudo_run_script` → `ExecResult`

MCP clients now see typed schemas in `tools/list` instead of generic `object`. Tools that legitimately produce merged or bimodal dicts stay as `dict[str, Any]` with that intent documented at the function: every `ssh_docker_*` (extends `_run_docker`'s ExecResult dict with parsed `containers`/`events`/`volumes` keys), `ssh_shell_exec` (adds `session_id` + `cwd` to the exec payload), `ssh_host_alerts` (custom breaches/metrics), `ssh_known_hosts_verify` (custom dict), `ssh_session_list`/`_stats` (custom dict), `ssh_shell_open`/`_close`/`_list` (custom dict), `ssh_delete_folder` (bimodal: `WriteResult` payload OR `dry_run` dict), `ssh_deploy` (extends `WriteResult` with `backup_path`).

Test sweep: ~60 assertions converted from `result["field"]` to `result.field` across `tests/test_file_hash.py` and 4 e2e files (`test_e2e_real_hosts.py`, `test_e2e_path_policy.py`, `test_e2e_sudo.py`, plus a few in `test_e2e_docker.py` that were already correct). Per-file ruff ignore extended from `["TC002"]` to `["TC001", "TC002"]` on `src/ssh_mcp/tools/**` because the new return types reference first-party result models that FastMCP must resolve at runtime via `get_type_hints()` — moving them under `if TYPE_CHECKING:` would break tool registration the same way INC-045 found earlier.

**Validation:** 457 unit tests pass, ruff clean. Pydantic now catches construction typos at model build, MCP advertises real schemas, and tool bodies stop lying about their return types.

### INC-045 — Ruff `select` missing async + perf rule groups

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [pyproject.toml](pyproject.toml) `[tool.ruff.lint]`, [src/ssh_mcp/models/policy.py:1-15](src/ssh_mcp/models/policy.py#L1-L15)

Two-step fix executed in one session.

**Step 1 (cleanup):** ran `ruff check --fix` (safe + unsafe). 104 → 18 manual fixes. Manual sweep covered: 4× `E501` line-too-long (reflowed), 4× `RUF012` mutable class attrs in test stub Contexts (annotated `ClassVar[dict[str, Any]]`), 3× `B017` `pytest.raises(Exception)` (tightened to `ValidationError`), 2× `B008` (one noqa for FastMCP `Progress` DI sentinel, one moved out of default arg), 2× `SIM117` nested `with` (combined), 1× `SIM108` (ternary), 1× `RUF002` ambiguous Unicode `∪` in docstring (replaced with literal "UNION-ed"), 1× `E402` (removed redundant `import pytest as _pytest`), 1× orphan helper-import block in docker_tools facade (added `# noqa: F401` to keep test re-exports). 104 → 0.

**Step 2 (rule expansion):** added `ASYNC`/`PERF`/`PT`/`PLE`/`TCH` to `select`. Ignored `ASYNC109` globally (every tool intentionally exposes `timeout=` for per-call MCP override; project convention, not a bug) and `PT011` (`pytest.raises(ValueError)` doesn't always need `match=` — too noisy). The `--unsafe-fixes` pass for `TCH002` then moved every `from fastmcp import Context` and `from pathlib import Path` into `if TYPE_CHECKING:` blocks. **131 tests broke** because:
- FastMCP's `@mcp_server.tool` decorator calls `get_type_hints()` at registration, which evaluates string annotations against runtime globals — `NameError: name 'Context' is not defined`.
- Pydantic v2's `model_rebuild()` does the same for field annotations — `PydanticUserError: AuthPolicy is not fully defined; you should define Path`.

Fix: restored the runtime imports in 10 tool modules + `models/policy.py`, then added per-file ignores so `TCH002`/`TCH003` can't push them back: `"src/ssh_mcp/tools/**" = ["TC002"]` and `"src/ssh_mcp/models/**" = ["TC003"]`. Both per-file blocks have inline comments naming the FastMCP and pydantic gotchas so the next contributor doesn't re-run the unsafe-fix.

**Counter-evidence the new rules pull weight:** `ASYNC109` would have flagged INC-035's pattern in advance. `PT018` caught 3 composite assertions auto-fixed cleanly. `TCH001`/`TCH002`/`TCH003` correctly pushed pure-typing imports under `TYPE_CHECKING` everywhere they were safe. 457 unit tests pass, ruff clean.

### INC-044 — No CI / pre-commit / `.python-version`

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** open
- **Source:** code-review (project review)
- **Refs:** missing `.github/workflows/*.yml`, `.pre-commit-config.yaml`, `.python-version`

Project uses mypy-strict + custom ruff config + pytest marker discipline — none of it runs on PR. Any contributor (human or agent) can land regressions that pass locally because their Python version / extras / lock state differs. **Action:** scaffold a minimal GHA workflow (`ruff check` + `mypy` + `pytest` unit, matrix on Python 3.11–3.13 since `target-version = "py311"`), a pre-commit config mirroring the workflow, and a `.python-version` pinning the default local interpreter. Integration + e2e suites stay out of CI (need fixtures / live hosts).

### INC-043 — `tools/docker_tools.py` is 1016 lines; needs splitting

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [src/ssh_mcp/tools/docker_tools.py](src/ssh_mcp/tools/docker_tools.py) (facade, 103 lines), [src/ssh_mcp/tools/docker/](src/ssh_mcp/tools/docker/) (subpackage)

Split into a `docker/` subpackage with four files: `_helpers.py` (360 — regex constants, name validation, escalation deny-list `_reject_escalation_flags`, `_docker_prefix` / `_compose_prefix`, `_run_docker`, `_compose_project_op`, NDJSON parsers), `read_tools.py` (361 — 10 read-tier tools), `lifecycle_tools.py` (155 — start/stop/restart factory + `ssh_docker_cp` + 3 compose lifecycle), `dangerous_tools.py` (228 — exec, run, pull, rm, rmi, prune, compose up/down/pull). `docker_tools.py` itself becomes a 103-line facade that imports the subpackage (triggering tool registration) and re-exports every public + private name existing callers import. No tool behavior change; pure reorg.

**Monkeypatch migration:** tool bodies resolve `_run_docker` in their OWN module's namespace, so `monkeypatch.setattr(docker_tools, "_run_docker", ...)` no longer intercepts them. Two test files updated (`test_docker_events_volumes.py` → targets `read_tools`; `test_docker_top_cp.py` → targets `lifecycle_tools`) with an explanatory comment on each. Pattern documented at the top of the facade module so future contributors know where to point patches. 448 unit tests green.

### INC-042 — `_context.py` accessors use `# type: ignore[no-any-return]`

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [src/ssh_mcp/tools/_context.py](src/ssh_mcp/tools/_context.py), [src/ssh_mcp/lifespan.py:307-315](src/ssh_mcp/lifespan.py#L307-L315)

Every `pool_from` / `settings_from` / `known_hosts_from` returned `ctx.lifespan_context[<key>]` typed as `Any` with a `# type: ignore[no-any-return]` suppression. Mypy didn't narrow; no IDE hint on what keys existed. **Fix:** defined `class LifespanContext(TypedDict)` with the exact seven keys `ssh_lifespan` populates (`pool`, `settings`, `hosts`, `host_allowlist`, `known_hosts`, `shell_sessions`, `hooks`). One helper `_lifespan(ctx) -> LifespanContext` does a single `cast` — all accessors read from the narrowed view and drop the `# type: ignore`. Adding a new key now requires updating the TypedDict first (single source of truth), so lifespan ↔ accessor drift surfaces at mypy time rather than runtime. Docstring on the TypedDict explicitly names the "update here first, lifespan second" rule. mypy clean on `_context.py` + `lifespan.py`; 448 unit tests green.

### INC-041 — Unused `tenacity` dependency

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [pyproject.toml](pyproject.toml) (removed), `grep -rn tenacity src/ tests/` returns nothing

Declared `"tenacity>=8.3.0,<10.0.0"` in `[project].dependencies`, never imported anywhere. Removed; `uv sync` confirms the package uninstalled cleanly. `uv.lock` (untracked, intentional per operator note) regenerates on next sync without tenacity.

### INC-040 — `_docker_prefix` / `_compose_prefix` typed `Any`

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [tools/docker_tools.py:174-197](src/ssh_mcp/tools/docker_tools.py#L174-L197)

Helpers took `policy: Any, settings: Any`; every `docker_cmd` / `SSH_DOCKER_CMD` field access was invisible to mypy. Tightened to `HostPolicy` / `Settings` imported under `TYPE_CHECKING:` so the types are real-at-lint but no runtime cycle is introduced.

### INC-039 — `_atomic_write` catch-all swallowed `CancelledError` / `MemoryError`

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [tools/low_access_tools.py:96-101](src/ssh_mcp/tools/low_access_tools.py#L96-L101)

`except Exception:` caught and re-raised after cleanup — but it also swallowed the `asyncio.CancelledError` lifecycle (Python 3.8+ `BaseException`, but pre-3.8 `Exception`), plus real programming errors (`MemoryError`, transient OOM). Narrowed to `(asyncssh.Error, OSError)` — the actual failure surface of SFTP write + chmod + rename. Comment on the catch explains why the narrow form is correct.

### INC-038 — `asyncio.gather` without `return_exceptions=True` in host tools

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [tools/host_tools.py:73-87](src/ssh_mcp/tools/host_tools.py#L73-L87), [:134-149](src/ssh_mcp/tools/host_tools.py#L134-L149)

`ssh_host_info` parallel-gathered `uname` / `os-release` / `uptime`; one failure (e.g. `uptime` missing on minimal containers) cancelled the siblings and lost the parts we could read. Same in `ssh_host_alerts` (df / loadavg / meminfo). Added `return_exceptions=True`; failures downgrade to empty string which the parsers already treat as "unavailable". Behavior change: partial diagnostics now succeed instead of raising.

### INC-037 — `HostKeyMismatch` raised with `"<received>"` literal

- **Date:** 2026-04-17 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [ssh/connection.py:87-94](src/ssh_mcp/ssh/connection.py#L87-L94)

Mismatch message surfaced the placeholder string `"<received>"` because asyncssh's `HostKeyNotVerifiable` doesn't expose the server's offered key. Looked like a broken f-string to operators chasing a real mismatch. Replaced with `"unknown (asyncssh did not expose the received key)"` and a comment naming `ssh-keyscan -p <port> <host>` as the OOB fetch path.

### INC-036 — `ConnectionPool._reap_once()` iterated dict during concurrent mutation

- **Date:** 2026-04-17 · **Severity:** High · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [ssh/pool.py:151-181](src/ssh_mcp/ssh/pool.py#L151-L181)

`for key, entry in self._entries.items():` ran in a background reaper task; concurrent `pool.acquire` / `release` from tool calls could insert/drop entries during the scan and raise `RuntimeError: dictionary changed size during iteration`. Race was narrow (reap loop fires every 60s) but real — intermittent prod crashes on busy pools. Snapshotted via `list(self._entries.items())`; comment names the race. Second pass (by-key lookup with `get`) already handled missing entries correctly.

### INC-035 — `ssh/exec.py` cancelled pump tasks on timeout without awaiting

- **Date:** 2026-04-17 · **Severity:** High · **Status:** resolved
- **Source:** code-review (project review)
- **Refs:** [ssh/exec.py:225-248](src/ssh_mcp/ssh/exec.py#L225-L248)

Timeout path called `pump_out.cancel()` / `pump_err.cancel()` and moved on without `await`. Two symptoms: (1) "Task exception was never retrieved" warning if a pump raised during cancel teardown (reader error mid-read), (2) lingering task references to the closing SSH channel. Added `await asyncio.gather(pump_out, pump_err, return_exceptions=True)` immediately after the cancels; comment explains why `return_exceptions=True` swallows the `CancelledError` + any secondary error cleanly.

### INC-034 — Windows SFTP `realpath` returns Cygwin form `/C:/...`

- **Date:** 2026-04-17 · **Severity:** High · **Status:** resolved
- **Source:** e2e-test (first full-catalog run against a real Windows OpenSSH target)
- **Refs:** [path_policy.py:245-262](src/ssh_mcp/services/path_policy.py#L245-L262), [tests/test_windows_target.py:266-304](tests/test_windows_target.py#L266-L304), [tests/e2e/](tests/e2e/), [BACKLOG entry 2026-04-17](BACKLOG.md)

OpenSSH-for-Windows' SFTP subsystem returns `realpath` results in Cygwin/WSL form — `C:\Users` comes back as `/C:/Users` (leading slash before the drive letter). `_canonicalize_windows` checked `_is_windows_absolute` on the raw result, which matches `C:\`, `C:/`, and UNC forms but not the Cygwin one, so every SFTP read / stat / upload against a Windows target raised `PathNotAllowed: canonicalized path is not absolute: '/C:/Users'`. ADR-0023 ships Windows as a first-class target, so this broke the whole SFTP path on the target class the ADR was written for. Fix: strip the single-character prefix when `path[0] == "/" and path[2:4] in (":/", ":\\") and path[1].isalpha()` — a predicate tight enough to leave UNC (`//host/share`) alone, since UNC starts with `//` and never has `:/` at offset 2. Surfaced by the new e2e suite on the first run against test_windows11; post-fix code review (2026-04-17) flagged that the fix shipped without a regression unit test — closed by [tests/test_windows_target.py::test_sftp_realpath_cygwin_form_is_normalized + test_unc_realpath_is_not_stripped](tests/test_windows_target.py#L266-L304), pinning both the Cygwin normalization and the UNC-pass-through contract.

### INC-033 — `ssh_docker_volumes(name=...)` exit_code semantics undocumented

- **Date:** 2026-04-16 · **Severity:** Medium · **Status:** resolved
- **Source:** code-review (docker events+volumes review, I2)
- **Refs:** [docker_tools.py:499-515](src/ssh_mcp/tools/docker_tools.py#L499-L515), [BACKLOG entry 2026-04-16](BACKLOG.md)

`ssh_docker_volumes(name="missing")` returned `{"volumes": [], "exit_code": 1, "stderr": "No such volume..."}`. Parity with `ssh_docker_inspect` but the docstring didn't call out that `[]` on non-zero exit means "lookup failed", not "genuinely empty". LLM callers could silently misread a lookup failure. Docstring now explicit: "caller MUST read `exit_code` and `stderr` to distinguish". No behavior change.

### INC-032 — `_DOCKER_TIME_RE` accepts `d` but Go rejects it

- **Date:** 2026-04-16 · **Severity:** Low · **Status:** resolved
- **Source:** code-review (docker events+volumes review, I1)
- **Refs:** [docker_tools.py:394-408](src/ssh_mcp/tools/docker_tools.py#L394-L408), [tests/test_docker_events_volumes.py](tests/test_docker_events_volumes.py)

`docker events --since 7d` routes through Go's `time.ParseDuration`, which recognizes `ns`/`us`/`ms`/`s`/`m`/`h` but NOT `d`. Our regex accepted `7d` and the daemon would have returned `time: unknown unit "d"`. Regex now restricts to `s`/`m`/`h`; docstring explains and suggests `168h` for 7 days. Two `d`-smuggling cases (`7d`, `1d2h`) added to the reject-parametrize.

### INC-031 — `ssh_file_hash` Windows branch used POSIX `shlex.join` quoting

- **Date:** 2026-04-16 · **Severity:** Critical · **Status:** resolved
- **Source:** code-review (file-hash + docker review, B1)
- **Refs:** [sftp_read_tools.py:245-310](src/ssh_mcp/tools/sftp_read_tools.py#L245-L310), **also INC-028 (open Windows item)**

`_hash_windows` assembled `powershell -NoProfile -NonInteractive -Command '(...)'` via `shlex.join`. POSIX `shlex.join` emits the `'"'"'` three-char dance for embedded apostrophes — POSIX-shell-only. Windows OpenSSH's default shell (cmd.exe) would land the entire first token as a literal string; PowerShell's own parser doesn't match this escape form either. First real Windows call would have crashed loudly. Test `test_path_with_single_quote_escaped` only verified `shlex.join` round-trips through `shlex.split` — proved nothing about the remote parser. Gated via `require_posix`; Windows branch + `_WINDOWS_HASH_ALGO` removed; see INC-028 for the open Windows-support item.

### INC-030 — `ssh_file_hash` timeout docstring lie + no param

- **Date:** 2026-04-16 · **Severity:** High · **Status:** resolved
- **Source:** code-review (file-hash review, B1)
- **Refs:** [sftp_read_tools.py:245-355](src/ssh_mcp/tools/sftp_read_tools.py#L245-L355), [tests/test_file_hash.py](tests/test_file_hash.py)

Docstring claimed "bump the env var or the per-call timeout if you need", but no `timeout` parameter existed and `conn.run(...)` was called without `timeout=`. Added `timeout: int | None = None` to the signature, wired through to both hash helpers matching the project's existing `effective_timeout = float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT)` pattern. Plus test gaps: canonical-vs-raw path, stat-failure → `-1` sentinel, timeout propagation through to `conn.run`.

### INC-029 — `ssh_docker_cp` missing `effective_restricted_paths`/`check_not_restricted` imports → NameError

- **Date:** 2026-04-16 · **Severity:** High · **Status:** resolved
- **Source:** code-review (post-merge review after INC-022 follow-ups, B1)
- **Refs:** [docker_tools.py:34-39](src/ssh_mcp/tools/docker_tools.py#L34-L39), [tests/test_docker_top_cp.py](tests/test_docker_top_cp.py), **AGENTS-MCP §21** (upstream lesson)

`ssh_docker_cp` referenced `effective_restricted_paths` + `check_not_restricted` but the import only brought in `canonicalize_and_check` + `effective_allowlist`. Pre-validation tests short-circuited on `_validate_name` / direction check before reaching the path-policy block, so the missing imports never showed up. Every real call would have `NameError`'d. Imports added; three happy-path argv-shape tests added that drive past validation with stubbed I/O; verified the new tests would have caught the bug by temporarily deleting the imports. This is the canonical example of the "pre-validation tests aren't enough" lesson now documented in AGENTS-MCP §21.

### INC-028 — `ssh_file_hash` has no Windows implementation

- **Date:** 2026-04-16 · **Severity:** Medium · **Status:** resolved · **Legacy:** W1
- **Source:** internal-review (triggered by INC-031 fix)
- **Refs:** [sftp_read_tools.py:323-378](src/ssh_mcp/tools/sftp_read_tools.py#L323-L378) (`_hash_windows`), [sftp_read_tools.py:290-326](src/ssh_mcp/tools/sftp_read_tools.py#L290-L326) (platform dispatch), [tests/test_file_hash.py](tests/test_file_hash.py) (`TestWindowsHashing`), [tests/e2e/test_e2e_real_hosts.py](tests/e2e/test_e2e_real_hosts.py) (`test_file_hash`)

After INC-031, `ssh_file_hash` gated Windows via `require_posix`. A proper implementation needed PowerShell's `-EncodedCommand <base64-UTF16LE>` (single opaque argv token, no shell quoting on the path) plus a way to ship it that cmd.exe can't mangle.

**Fix (2026-04-17):** added `_hash_windows(conn, canonical, algorithm, timeout)` which:

1. Builds a literal PowerShell script: `(Get-FileHash -Algorithm <ALGO> -LiteralPath '<escaped-path>').Hash` — the path is escaped using PowerShell's single-quote literal rule (`'` → `''`), and `-LiteralPath` takes the value verbatim (no wildcard expansion).
2. Encodes the script as `base64(script.encode("utf-16-le"))` — a pure-ASCII token PowerShell's `-EncodedCommand` consumes unchanged.
3. Invokes `powershell.exe -NoProfile -NonInteractive -EncodedCommand <b64>` as a single command line. All outer tokens are safe ASCII, so cmd.exe's parser doesn't get a chance to misquote anything.

`ssh_file_hash` body dispatches on `policy.platform` (`_hash_windows` vs `_hash_posix`); `require_posix` is dropped entirely. `Get-FileHash` returns uppercase hex — the parser lowercases to match POSIX. Regression tests in `tests/test_file_hash.py::TestWindowsHashing`:

- `test_invokes_powershell_encoded_command` — parametrized over MD5/SHA1/SHA256/SHA512; base64-decodes the captured command and checks the inner script names the right algorithm + LiteralPath.
- `test_windows_path_with_single_quote_is_ps_escaped` — a path like `O'Brien.txt` shows up as `'O''Brien.txt'` inside the script. The "operator has a file with an apostrophe" scenario would otherwise inject unquoted script.
- `test_windows_non_zero_exit_raises_HashError` — same error-surface contract as POSIX.

The e2e suite's `test_file_hash_posix` renamed to `test_file_hash` and now exercises both platforms; on `test_windows11` it hashes `C:\Windows\System32\drivers\etc\hosts` and asserts 64-char lowercase-hex SHA-256. 456 unit tests green.

### INC-027 — Shell-session lock has no end-to-end test

- **Date:** 2026-04-15 · **Severity:** Low · **Status:** n/a (superseded by INC-047) · **Legacy:** N3b
- **Source:** internal-review (post-fix review)
- **Refs:** [INC-047](INCIDENTS.md#inc-047--shell-session-cwd-has-no-async-safe-update-api), [services/shell_sessions.py:38-87](src/ssh_mcp/services/shell_sessions.py#L38-L87)

Original concern: the INC-023 regression test exercised the `asyncio.Lock` primitive but didn't drive `ssh_shell_exec` end-to-end, so a future refactor that bypassed `session.lock` before writing `session.cwd` wouldn't trip.

**Superseded by INC-047 (2026-04-17).** INC-047 replaced the discipline-only lock contract with a runtime-enforced one: `ShellSession.set_cwd` now asserts `self.lock.locked()` at the write site and `exec_scope()` is the single approved way to hold the lock. The "caller forgot to acquire the lock" regression class is eliminated by construction — any bypass raises `RuntimeError` the first time it's exercised, in any code path. The end-to-end test this entry proposed is no longer necessary: the `test_set_cwd_outside_exec_scope_raises` unit test in INC-047 catches the same failure mode cheaper and without mocking `exec_run`.

### INC-026 — Tautological assertion in shell-session lock test

- **Date:** 2026-04-15 · **Severity:** Low · **Status:** resolved · **Legacy:** N3a
- **Refs:** [tests/test_shell_sessions.py:203-205](tests/test_shell_sessions.py#L203-L205)

`assert (entered[0], exited[0]) == (entered[0], entered[0])` reduced to `exited[0] == entered[0]`, which was re-asserted on the next line. Tautology removed; the remaining `exited[i] == entered[i]` pair pins the serialization invariant.

### INC-025 — Container-namespace join flags not covered

- **Date:** 2026-04-15 · **Severity:** Low · **Status:** resolved · **Legacy:** N2b
- **Source:** internal-review (post-fix review of INC-022)
- **Refs:** [docker_tools.py:109-129](src/ssh_mcp/tools/docker_tools.py#L109-L129), [tests/test_docker_run_escalation.py](tests/test_docker_run_escalation.py)

After INC-024 closed `--mount source=/`, the namespace-share checker still only rejected literal `host`. `--pid=container:<id>` forms join another container's namespace — weaker than host escape but still an isolation break. Now rejects `=container:<id>` prefix form AND two-token form for all six namespace flags.

### INC-024 — `--mount` bypassed docker-run escalation deny-list

- **Date:** 2026-04-15 · **Severity:** Medium · **Status:** resolved · **Legacy:** N2a
- **Source:** internal-review (post-fix review of INC-022)
- **Refs:** [docker_tools.py:76-166](src/ssh_mcp/tools/docker_tools.py#L76-L166), [tests/test_docker_run_escalation.py](tests/test_docker_run_escalation.py)

`_reject_escalation_flags` from INC-022 covered `--volume=/:` but not `--mount type=bind,source=/,target=/host`. New `_mount_source_is_host_root` parses the KV value format and rejects host-root source. Handles `//`, `/./`, trailing-slash edge cases via `posixpath.normpath`.

### INC-023 — Shell-session state caller-serialized, not locked

- **Date:** 2026-04-15 · **Severity:** Low · **Status:** resolved · **Legacy:** N3
- **Refs:** [shell_sessions.py:42-49](src/ssh_mcp/services/shell_sessions.py#L42-L49), [shell_tools.py:84-104](src/ssh_mcp/tools/shell_tools.py#L84-L104)

Two concurrent `ssh_shell_exec` calls with the same `session_id` raced on the `cwd` update after sentinel parsing. Per-session `asyncio.Lock` added; `ssh_shell_exec` wraps exec + cwd update under the lock. Cheap when uncontended.

### INC-022 — `ssh_docker_run` accepts arbitrary docker flags

- **Date:** 2026-04-15 · **Severity:** Medium · **Status:** resolved · **Legacy:** N2
- **Refs:** [docker_tools.py:56-114](src/ssh_mcp/tools/docker_tools.py#L56-L114), [config.py:50](src/ssh_mcp/config.py#L50), [SKILL.md](skills/ssh-docker-run/SKILL.md)

Under `ALLOW_DANGEROUS_TOOLS=true`, `args: list[str]` was appended verbatim to `docker run`. Flags like `--privileged`, `--cap-add`, `--network=host`, `--volume=/:` granted root on the target host. Operators who flipped the tier for "one-shot run" unknowingly granted host escape. New `_reject_escalation_flags` deny-list + `ALLOW_DOCKER_PRIVILEGED` opt-in. Docstring + SKILL spell out the capability-escalation surface. Follow-ups INC-024 (`--mount`) and INC-025 (`container:<id>`) closed gaps found in post-fix review.

### INC-021 — Unbounded fire-and-forget hook tasks

- **Date:** 2026-04-15 · **Severity:** Medium · **Status:** resolved · **Legacy:** N1
- **Refs:** [hooks.py:80-89](src/ssh_mcp/services/hooks.py#L80-L89), [tests/test_hooks.py:189-258](tests/test_hooks.py#L189-L258)

`HookRegistry.emit(blocking=False)` spawned tasks via `asyncio.create_task(...)` without tracking. A hook that re-scheduled itself or ran slower than the event cadence could pile up pending tasks unboundedly. Now tracks tasks in a `set[Task]` with a `discard` done-callback; warns once when pending crosses a threshold (default 100).

### INC-020 — Commit-message-style review: SSRF / hardcoded fallbacks / typos / stray `}`

- **Date:** 2026-04-16 · **Severity:** N/A · **Status:** n/a (partial-applied)
- **Source:** code-review
- **Refs:** [connection.py:22-28](src/ssh_mcp/ssh/connection.py#L22-L28), [sudo.py:41-46](src/ssh_mcp/ssh/sudo.py#L41-L46)

Four-bullet review from an unrelated Node/TS project applied against our codebase:
- **SSRF bypass** — **N/A**, we have no URL-parser or HTTP-fetch surface. SSH hostnames route through `hosts.toml` + `SSH_HOSTS_ALLOWLIST` + strict `known_hosts`, not an IP-classifier.
- **Hardcoded fallback defaults** — minor hit: two `timeout=10` literals in `_run_command_for_secret` + `_run_secret_cmd`. Extracted to named `_SECRET_CMD_TIMEOUT_SECONDS = 10` module constants with rationale comment. Behavior unchanged.
- **Typos** — grep pass clean.
- **Stray `}` in template literal** — N/A, Python f-strings are compiler-checked.

### INC-019 — `classfang/ssh-mcp-server#31` — the input device is not a TTY

- **Date:** 2026-04-15 · **Severity:** N/A · **Status:** n/a (hardening-added)
- **Source:** external-issue
- **Refs:** [exec.py:42-65](src/ssh_mcp/ssh/exec.py#L42-L65), [DECISIONS.md ADR-0022](DECISIONS.md)

External report: tools that require a TTY (`sudo`, `top`, `passwd`) fail against stdio-based SSH. We deliberately don't allocate a remote PTY (see `services/shell_sessions.py` docstring). Added `ExecResult.hint` field that populates on recognizable `is not a tty` / `must be run from a terminal` stderr markers, pointing the LLM at batch-mode alternatives (`top -bn1`, `chpasswd`, etc.). ADR-0022 records the decision to keep the no-PTY posture + use the hint field.

### INC-018 — `tufantunc/ssh-mcp#44` — newline injection via `description` metadata field

- **Date:** 2026-04-15 · **Severity:** N/A · **Status:** n/a (not applicable)
- **Source:** external-issue

External report: a `description` parameter on the exec tool was interpolated into the shell command; newlines in the field injected arbitrary commands. **N/A for us**: we have no "metadata field that secretly becomes shell". Shell-bound fields (`command`, `script`) are explicit, allowlist-checked, and caller-owned. Identifier fields (container/image/service names) are regex-validated at the tool boundary. `wrap_command` in shell_sessions uses `shlex.quote` on the cwd. See conversation record in BACKLOG for the full comparison matrix.

### INC-017 — `tufantunc/ssh-mcp#42` — credentials in process argv / `ps`

- **Date:** 2026-04-15 · **Severity:** N/A · **Status:** n/a (covered)
- **Source:** external-issue
- **Refs:** [sudo.py:166-177](src/ssh_mcp/ssh/sudo.py#L166-L177) (INC-009 fix), [connection.py:131](src/ssh_mcp/ssh/connection.py#L131)

External report: server launched with `--password=...` in argv exposes credentials via `ps` / `/proc`. **Already covered**: `SSH_SUDO_PASSWORD` env var rejected at startup (INC-009); sudo password piped over stdin, never argv; `password_cmd` / `passphrase_cmd` subprocess helpers never receive secrets as argv. Indirect risk: an operator-configured `password_cmd = "echo MyPass"` would leak via `ps` — that's operator misconfiguration, documented in [skills/ssh-exec-run/SKILL.md](skills/ssh-exec-run/SKILL.md) / README.

### INC-016 — `tufantunc/ssh-mcp#2` — no default command timeout

- **Date:** 2026-04-15 · **Severity:** N/A · **Status:** n/a (covered)
- **Source:** external-issue
- **Refs:** [config.py:109-113](src/ssh_mcp/config.py#L109-L113), [exec.py:42-70](src/ssh_mcp/ssh/exec.py#L42-L70)

External report: LLM clients forget to pass a timeout, hang forever. **Already covered** since Phase 1: `SSH_COMMAND_TIMEOUT=60` default enforced via `asyncio.wait_for`. Plus `SSH_CONNECT_TIMEOUT=10`, `SSH_IDLE_TIMEOUT=300`, `SSH_KEEPALIVE_INTERVAL=30`, per-call `timeout` parameter on every exec tool.

### INC-015 — `bvisible/mcp-ssh-manager#13` — AgentWard audit

- **Date:** 2026-04-15 · **Severity:** N/A · **Status:** n/a (hardening-added)
- **Source:** audit-report
- **Refs:** [DECISIONS.md ADR-0021](DECISIONS.md), [hosts.py:150-186](src/ssh_mcp/hosts.py#L150-L186)

External audit of `mcp-ssh-manager`: 37 tools granting unrestricted SSH access, `ssh_execute` with zero filtering, `ssh_execute_sudo` plaintext password in argv/ps, `ssh_tunnel_create` unrestricted SOCKS5, no path allowlist, SQL-keyword-based query validation. Comparison against our architecture:
- ✓ Command allowlist + fail-closed when empty (ADR-0018)
- ✓ Sudo password via `-S` + stdin (INC-009 / INC-017)
- N/A Tunnel / SOCKS: not implemented (deferred in DECISIONS.md)
- ✓ Path allowlist + `restricted_paths` carve-outs + `canonicalize_and_check` (ADR-0017)
- N/A SQL query tool: not implemented
- ✓ Tiered approval gates via `Visibility` transforms (ADR-0001)

**Hardening added**: ADR-0021 — defense-in-depth WARNING at startup when `path_allowlist=["*"]` but `restricted_paths` doesn't cover `/etc/shadow`/`/etc/sudoers`/`/etc/ssh`. Operator gets a clear pointer at startup; not enforced (containers / embedded hosts genuinely don't have these).

### INC-014 — SFTP magic error codes

- **Date:** 2026-04-14 · **Severity:** Low · **Status:** resolved · **Legacy:** L2
- **Refs:** [low_access_tools.py:146](src/ssh_mcp/tools/low_access_tools.py#L146), [:329](src/ssh_mcp/tools/low_access_tools.py#L329)

Magic numbers like `exc.code == 2` scattered across SFTP error handling; brittle across asyncssh versions. Replaced with `asyncssh.sftp.FX_NO_SUCH_FILE` / `FX_FAILURE` / `FX_OP_UNSUPPORTED` / `FX_LINK_LOOP` constants.

### INC-013 — Host policy lacked port-range / type / absolute-path validation

- **Date:** 2026-04-14 · **Severity:** Low · **Status:** resolved · **Legacy:** L1
- **Refs:** [tests/test_host_policy_validation.py](tests/test_host_policy_validation.py)

Field validators on `HostPolicy` for port (1..65535), type (no negative ints as port), and absolute path enforcement on `path_allowlist` were missing. Regression tests added. Field validators on `HostPolicy` at [models/policy.py:94-117](src/ssh_mcp/models/policy.py#L94-L117).

### INC-012 — Absolute-path `command_allowlist` entries basename-matched

- **Date:** 2026-04-14 · **Severity:** Medium · **Status:** resolved (tightened) · **Legacy:** M5
- **Refs:** [exec_policy.py:61-81](src/ssh_mcp/services/exec_policy.py#L61-L81)

Allowlist entry `/usr/bin/systemctl` would match program `/opt/rogue/systemctl` via basename — shadow-binary bypass for operators who intentionally wrote absolute allowlist entries. Now: absolute entries require EXACT match; basename fallback retained for bare entries (`systemctl`) so `$PATH`-style usage still works.

### INC-011 — Streaming `chunk_cb` received more bytes than buffer captured

- **Date:** 2026-04-14 · **Severity:** Medium · **Status:** resolved · **Legacy:** M1
- **Refs:** [exec.py:194-197](src/ssh_mcp/ssh/exec.py#L194-L197)

`chunk_cb` was called with the full incoming chunk even when the output-cap clipped part of it. Consumers saw bytes that `stdout` discarded. Now: callback only receives the captured slice, matching the buffer.

### INC-010 — `ssh_edit` / `ssh_patch` crash on non-UTF-8 files

- **Date:** 2026-04-14 · **Severity:** High · **Status:** resolved · **Legacy:** H4
- **Refs:** [edit_service.py](src/ssh_mcp/services/edit_service.py), [low_access_tools.py:276](src/ssh_mcp/tools/low_access_tools.py#L276)

UnicodeDecodeError surfaced as a traceback. Now `errors="replace"` throughout the edit path; non-UTF-8 content surfaces as a clean `WriteError`.

### INC-009 — `SSH_SUDO_PASSWORD` env-var accepted

- **Date:** 2026-04-14 · **Severity:** High · **Status:** resolved · **Legacy:** H3
- **Refs:** [sudo.py:166-177](src/ssh_mcp/ssh/sudo.py#L166-L177), [lifespan.py:81](src/ssh_mcp/lifespan.py#L81)

Env vars leak into child processes, crash dumps, and `/proc/self/environ`. Passing a sudo password through an env var is footgunny even if the immediate code doesn't leak. `reject_env_password()` now raises at startup if `SSH_SUDO_PASSWORD` is set; operator is directed to `SSH_SUDO_PASSWORD_CMD` (subprocess) or OS keyring.

### INC-008 — Audit `error` field leaks full exception text

- **Date:** 2026-04-14 · **Severity:** High · **Status:** resolved · **Legacy:** H2
- **Refs:** [services/audit.py](src/ssh_mcp/services/audit.py)

Exception text in audit records could carry remote stderr — sudo prompts, paths, internal errors. Audit pipes often ship to shared log backends. Now: `error` field records the exception class name only; full `str(exc)` stays at DEBUG on the same logger locally, correlated via `correlation_id`.

### INC-007 — `UnknownHost` vs `HostKeyMismatch` disambiguated by exception text substring

- **Date:** 2026-04-14 · **Severity:** High · **Status:** resolved · **Legacy:** H1
- **Refs:** [connection.py:74-79](src/ssh_mcp/ssh/connection.py#L74-L79)

Both conditions surfaced as `asyncssh.HostKeyNotVerifiable` with different message substrings. Substring-sniffing for security-class errors is brittle and version-dependent. Now: `known_hosts.fingerprint_for()` lookup determines which case applies — if there's no pinned fingerprint, it's `UnknownHost`; if there is and it doesn't match, it's `HostKeyMismatch` (which carries both expected and actual fingerprints).

### INC-006 — `KnownHosts.fingerprint_for` silently returned `None`

- **Date:** 2026-04-15 · **Severity:** Critical · **Status:** resolved · **Legacy:** C4
- **Refs:** [known_hosts.py:99-114](src/ssh_mcp/ssh/known_hosts.py#L99-L114), [tests/test_known_hosts.py:94-119](tests/test_known_hosts.py#L94-L119)

`KnownHosts.fingerprint_for` unpacked 3 values from asyncssh's 7-tuple `match()` return, caught the resulting `ValueError`, and silently returned `None`. Impact:
- `ssh_host_ping` never reported the pinned fingerprint.
- `ssh_known_hosts_verify` always reported `expected_fingerprint=None`.
- INC-007 silently degraded to "always `UnknownHost`" — a real MITM / key rotation would have been mislabeled.

Fix: use indexing (`result[0]`) + stop swallowing `ValueError`. Regression guard generates a real ed25519 key via `asyncssh.generate_private_key` and round-trips through the full match path. Discovered during Pageant end-to-end verification on Windows.

### INC-005 — Streaming `_pump` byte counters not updated per chunk

- **Date:** 2026-04-14 · **Severity:** Critical · **Status:** resolved · **Legacy:** C3
- **Refs:** [exec.py:174-197](src/ssh_mcp/ssh/exec.py#L174-L197)

On timeout, the streaming exec returned `stdout_truncated=False` even if output had grown past the cap. Byte counters were set only on clean EOF; cancellation bypassed that. Now: counters update nonlocal per chunk, truncation flag is correct on timeout path.

### INC-004 — `assert` before `rm -rf` stripped under `python -O`

- **Date:** 2026-04-14 · **Severity:** Critical · **Status:** resolved · **Legacy:** C2
- **Refs:** [low_access_tools.py:219-221](src/ssh_mcp/tools/low_access_tools.py#L219-L221)

`assert re_canonical == canonical` guarded `rm -rf -- <canonical>` from a TOCTOU race. `python -O` strips asserts at compile time; the server would silently remove the rail. Replaced with explicit `raise WriteError(...)`.

### INC-003 — `SSH_ENABLED_GROUPS` field missing from `Settings`

- **Date:** 2026-04-14 · **Severity:** Critical · **Status:** resolved · **Legacy:** C1
- **Refs:** [config.py:62](src/ssh_mcp/config.py#L62), `test_config_has_every_field_lifespan_reads`

The lifespan read `settings.SSH_ENABLED_GROUPS` to apply group-visibility transforms. The field was missing from `Settings`. Every server startup crashed with `AttributeError`. Added with `default_factory=list`; regression test ensures future code splits don't drop the field without updating the lifespan consumer.

### INC-002 — External review: path confinement must apply to reads (ADR-0017 trigger)

- **Date:** 2026-04-14 · **Severity:** N/A · **Status:** n/a (hardening-added)
- **Source:** external-issue (external-review feedback pass)
- **Refs:** [DECISIONS.md ADR-0017](DECISIONS.md), [tests/test_read_tool_path_confinement.py](tests/test_read_tool_path_confinement.py)

External review flagged that "read-only" tools (`ssh_sftp_list`, `_stat`, `_download`, `ssh_find`) skipped `canonicalize_and_check`. "Read-only" means no mutation, NOT no scope — an LLM could still SFTP-download `/etc/shadow` or `/root/.ssh/id_ed25519` from any allowlisted host. ADR-0017 records the decision to apply path confinement to every path-bearing tool, read or write, via the same helper. Regression guard in the test file prevents future contributors from silently dropping the check.

### INC-001 — External review: empty `command_allowlist` footgun (ADR-0018 trigger)

- **Date:** 2026-04-14 · **Severity:** N/A · **Status:** n/a (hardening-added)
- **Source:** external-issue (external-review feedback pass)
- **Refs:** [DECISIONS.md ADR-0018](DECISIONS.md), [exec_policy.py:42-49](src/ssh_mcp/services/exec_policy.py#L42-L49)

External review flagged the convention "empty `command_allowlist` = no restriction" as a deployment footgun: operators reading "empty allowlist" naturally expect "nothing allowed". An operator flipping `ALLOW_DANGEROUS_TOOLS=true` without also setting an allowlist got an unrestricted exec server when they intended a locked-down one. ADR-0018 records the decision to fail closed; `ALLOW_ANY_COMMAND=true` is the only way to permit arbitrary commands with an empty allowlist.

---

## Triggering sources — quick index

- **Internal review passes** (2026-04-14, 2026-04-15): INC-003..INC-014, INC-021..INC-023
- **Internal post-fix review** (2026-04-15): INC-024..INC-027
- **External code review** (2026-04-16, two separate batches): INC-029, INC-030, INC-031, INC-032, INC-033
- **External project scans**: INC-015 (audit), INC-016, INC-017, INC-018, INC-019
- **External feedback pass**: INC-001, INC-002
- **Commit-message-style review** (2026-04-16): INC-020
- **Live-verification findings**: INC-006 (discovered during Pageant end-to-end)
