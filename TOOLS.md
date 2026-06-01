# Tool Reference

Tools are grouped by **tier** (which `ALLOW_*` flag they require) and within each tier by **group** (the `group:*` tag — used by `SSH_ENABLED_GROUPS` filtering).

For a full per-tool runbook, follow the **skill** link on each entry — the SKILL.md files cover `When to call`, `When NOT to call`, examples, common failures, and related tools.

- 100 tools total
- 10 tool groups: `host`, `session`, `sftp-read`, `file-ops`, `exec`, `sudo`, `shell`, `docker`, `systemctl`, `pkg`
- 4 tiers: read (always on) · low-access · dangerous · sudo
- See [README.md](README.md) for tier flags, host config, restricted paths, BM25 search, and `SSH_ENABLED_GROUPS` examples.

## Context cost per group

How many bytes each group adds to the `tools/list` response every MCP turn — so operators can decide what to trim via `SSH_ENABLED_GROUPS`. Measured by serializing each tool's wire schema (`name`, `description`, `inputSchema`, `annotations`) as it is sent to the client. Tokens are a bytes/4 heuristic — directional, not exact (JSON tokenises slightly denser on Claude / GPT-4-family).

Regenerate via `uv run python .claude/scripts/catalog-size.py` (or `.venv/Scripts/python` on Windows if `uv` is blocked by a running server). Re-run after any change to a tool's signature, docstring, or tag — and at every sprint that adds, removes, or modifies tools.

| Group | Tools | Bytes | ~Tokens | Avg / tool |
|---|---:|---:|---:|---:|
| `docker` | 27 | 20,053 | ~5,013 | 743 B |
| `host` | 14 | 11,640 | ~2,910 | 831 B |
| `file-ops` | 11 | 10,898 | ~2,724 | 990 B |
| `systemctl` | 17 | 8,290 | ~2,072 | 487 B |
| `sftp-read` | 6 | 7,737 | ~1,934 | 1,289 B |
| `sudo` | 7 | 6,943 | ~1,735 | 992 B |
| `pkg` | 9 | 4,479 | ~1,119 | 497 B |
| `exec` | 4 | 3,979 | ~994 | **994 B** (densest -- rich input schemas) |
| `shell` | 4 | 1,377 | ~344 | 344 B |
| `session` | 1 | 154 | ~38 | 154 B |
| **Total** | **100** | **75,550** | **~18,887** | — |

**Savings from common `SSH_ENABLED_GROUPS` trims:**

- Drop `docker` only → ~13,874 tok (saves **~5,013 tok / 27%** -- biggest single win)
- Drop `systemctl` only → ~16,815 tok (saves **~2,072 tok / 11%**)
- Drop both → ~11,802 tok (saves **~7,085 tok / 38%**)
- Keep only `host,sftp-read,docker` (observability + container triage) → ~9,857 tok (saves **~9,030 tok / 48%**)
- Keep only `host,session,systemctl` (systemd-triage persona) → ~5,020 tok (saves **~13,867 tok / 73%**)
- Drop `sudo` (no privileged ops needed) → ~17,152 tok (saves **~1,735 tok / 9%**)

## Contents

- [Platform compatibility matrix](#platform-compatibility-matrix)
- [How to read each entry](#how-to-read-each-entry)
- [Read tier (always on)](#read-tier-always-on) — 42 tools
- [Low-access tier](#low-access-tier-allow_low_access_toolstrue) — 22 tools (`ALLOW_LOW_ACCESS_TOOLS=true`)
- [Dangerous tier](#dangerous-tier-allow_dangerous_toolstrue) — 29 tools (`ALLOW_DANGEROUS_TOOLS=true`)
- [Sudo tier](#sudo-tier-allow_sudotrue) — 7 tools (`ALLOW_SUDO=true`)
- [Cross-cutting safeguards](#cross-cutting-safeguards)

## Platform compatibility matrix

Tools tagged **POSIX-only** refuse Windows targets with `PlatformNotSupported` (see [ADR-0023](DECISIONS.md)). Set `platform = "windows"` on the host in `hosts.toml` to enable Windows-target mode.

| Group | POSIX | Windows | Notes |
|---|---|---|---|
| `host` (ping / known_hosts_verify) | yes | yes | Pure SSH handshake |
| `host` (info / disk / processes / alerts) | yes | **no** | Parse POSIX outputs |
| `session` | yes | yes | In-memory pool / session state |
| `sftp-read` (list / stat / download) | yes | yes | SFTP protocol |
| `sftp-read` (find) | yes | yes | POSIX uses `find`; Windows uses SFTP-walk |
| `file-ops` (mkdir / delete / delete_folder / upload / edit / patch / deploy / mv / transfer) | yes | yes | SFTP-first |
| `file-ops` (`ssh_cp`) | yes | **no** | Uses `cp -a` |
| `file-ops` (`ssh_link`) | yes | partial | Symbolic + hard-`-L` via SFTP (cross-platform); hard-`-P` shells out to `ln -P` (POSIX-only) |
| `exec` | yes | **no** | POSIX `sh` + pkill |
| `sudo` | yes | **no** | No `sudo` |
| `shell` (open / exec) | yes | **no** | Cwd sentinel relies on POSIX shell |
| `shell` (list / close) | yes | yes | In-memory |
| `docker` | yes | **no** | Scope deferred — see ADR-0023 |
| `systemctl` | yes | **no** | systemd is Linux-only; no explicit platform gate (clean non-zero exit on Windows targets) |
| `pkg` | yes (Debian/Ubuntu) | **no** | APT binary probe gates all three tools; non-Debian POSIX hosts return `PlatformNotSupported` |

---

## Sections by group

- [Read tier](#read-tier-always-on) — 42 tools, no flag needed
  - [Host & connection](#host--connection-grouphost) (11)
  - [Sessions](#sessions-groupsession) (1)
  - [SFTP reads](#sftp-reads-groupsftp-read) (6)
  - [Docker (read)](#docker-read-groupdocker) (11)
  - [systemctl (read)](#systemctl-read-groupsystemctl) (8)
  - [Package management (read)](#package-management-read-grouppkg) (4)
  - [Persistent shell (read)](#persistent-shell-read-groupshell) (1)
- [Low-access tier](#low-access-tier-allow_low_access_toolstrue) — 22 tools (`ALLOW_LOW_ACCESS_TOOLS=true`)
  - [Host policy reload + notes](#host-policy-reload-grouphost-low-access) (3)
  - [File operations](#file-operations-groupfile-ops) (11)
  - [Docker (lifecycle)](#docker-lifecycle-groupdocker) (7)
  - [Persistent shell (close)](#persistent-shell-close-groupshell) (1)
- [Dangerous tier](#dangerous-tier-allow_dangerous_toolstrue) — 29 tools (`ALLOW_DANGEROUS_TOOLS=true`)
  - [Arbitrary execution](#arbitrary-execution-groupexec) (4)
  - [Docker (mutating)](#docker-mutating-groupdocker) (9)
  - [systemctl (mutating)](#systemctl-mutating-groupsystemctl) (9)
  - [Package management (mutating)](#package-management-mutating-grouppkg) (5)
  - [Persistent shell (open + exec)](#persistent-shell-open--exec-groupshell) (2)
- [Sudo tier](#sudo-tier-allow_sudotrue) — 7 tools (`ALLOW_SUDO=true`, also requires dangerous)
- [Cross-cutting safeguards](#cross-cutting-safeguards)

---

## How to read each entry

Every tool entry has the same shape — a single bullet:

- **`tool_name`** — one-line summary. Inputs: `host`, `<key inputs>`. [skill](skills/<name>/SKILL.md)
  - Optional notes (caps, allowlist behavior, related tool) on a nested bullet.

`host` is always required and accepts an alias from `hosts.toml` or any name in `SSH_HOSTS_ALLOWLIST`.

---

## How to use this reference

1. **Pick a tier** for what the assistant actually needs: read (always on) → low-access (file mutation) → dangerous (arbitrary commands) → sudo (on top of dangerous).
2. **Flip the tier flag** in the server env: `ALLOW_LOW_ACCESS_TOOLS=true` / `ALLOW_DANGEROUS_TOOLS=true` / `ALLOW_SUDO=true`. Default is read-only.
3. **Find the tool** by scanning the tier section below, or jump via [Sections by group](#sections-by-group).
4. **Open the linked skill** — the per-tool SKILL.md has `When to call`, `When NOT to call`, worked examples, and common failures.
5. **Smoke-test with `ssh_host_ping`** against your target before anything else — verifies agent, `known_hosts`, and the pool end-to-end.

**Quick "I want to..." recipes:**

| Goal | Tool | Tier |
| --- | --- | --- |
| Check if a host is reachable | `ssh_host_ping` | read |
| See what's running on a host | `ssh_host_processes` / `ssh_docker_ps` | read |
| Read a remote file | `ssh_sftp_download` | read |
| Edit a config file in place | `ssh_edit` or `ssh_patch` | low-access |
| Drop a new file atomically | `ssh_upload` (or `ssh_deploy` with backup) | low-access |
| Restart a container | `ssh_docker_restart` | low-access |
| Tail docker logs | `ssh_docker_logs` | read |
| Run an arbitrary command | `ssh_exec_run` (prefer a dedicated tool if one fits) | dangerous |
| Track cwd across calls | `ssh_shell_open` + `ssh_shell_exec` | dangerous |
| Run under sudo | `ssh_sudo_exec` | sudo |

**If a tool doesn't show up in your client:** check (1) the tier flag is set, (2) the group is in `SSH_ENABLED_GROUPS` (empty = all), (3) the host is in `SSH_HOSTS_ALLOWLIST` and not in `SSH_HOSTS_BLOCKLIST`. Startup logs a catalog summary — grep for `tools registered:`.

---

# Read tier (always on)

No flag required. These never mutate remote state. Path-bearing reads are still confined by `path_allowlist` and `restricted_paths` ([ADR-0017](DECISIONS.md)).

```toml
# hosts.toml
[hosts.prod-web]
hostname = "prod-web.internal"
user = "ops"
path_allowlist = ["/var/log", "/opt/app"]          # scope for sftp-read + find
# restricted_paths = ["/var/log/sensitive"]        # optional carve-outs
# No env flag needed — read tier is always on.
```

## Host & connection (`group:host`)

- **`ssh_server_info`** — Server identity (name + version) + capability surface (enabled tiers + `SSH_ENABLED_GROUPS` filter + post-Visibility tool count). No inputs. Companion to the `mcp://ssh-mcp/server-info` resource -- the resource is the primary discovery path; this tool is the fallback for clients that don't surface resources to the LLM (most current ones don't). Same payload shape on both surfaces. (v1.5.0) [skill](skills/ssh-server-info/SKILL.md)
- **`ssh_host_ping`** — TCP + SSH handshake probe. Returns reachability, auth status, latency, server banner, and the pinned known_host fingerprint. **Auto-injects BOTH note layers**: `operator_notes` (hard-rule baseline from `hosts.toml`'s `notes` field, [INC-059](INCIDENTS.md)) when `SSH_PING_INCLUDES_NOTES=True` (default), AND `agent_notes` (the LLM's own session-spanning sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md`, [INC-060](INCIDENTS.md)) when `SSH_PING_INCLUDES_AGENT_NOTES=True` (default). Independent toggles per layer. Makes ping the canonical "starting work on this host" probe that surfaces full host memory into LLM context for free. Trade-off for agent layer: sidecars can grow to `SSH_HOST_NOTES_MAX_BYTES` (default 256 KiB); flip `SSH_PING_INCLUDES_AGENT_NOTES=false` if context inflation matters. Inputs: `host`. [skill](skills/ssh-host-ping/SKILL.md)
- **`ssh_host_info`** — `uname -a`, `/etc/os-release`, `uptime`, `nproc`, `/proc/cpuinfo`, `hostname -f` parsed in parallel. Each probe runs independently (`return_exceptions=True`) so a missing one doesn't lose its siblings. Result includes `cpu_model`, `cpu_count`, `hostname_fqdn` ([INC-052](INCIDENTS.md)). Fixed argv, no shell interpolation. Inputs: `host`. [skill](skills/ssh-host-info/SKILL.md)
- **`ssh_host_disk_usage`** — `df -PTh` parsed into structured entries. Inputs: `host`. [skill](skills/ssh-host-disk-usage/SKILL.md)
- **`ssh_host_network`** — Per-interface state from `ip -j addr show`: name, oper-state, MAC, addresses (family + address + prefix length). Drops kernel-internal noise. Hosts without `iproute2` (busybox, etc.) get an empty list rather than a raise. POSIX-only. Inputs: `host`. [skill](skills/ssh-host-network/SKILL.md)
- **`ssh_host_processes`** — Top-N processes by CPU via `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu`. Inputs: `host`, `top_n` (default 25). [skill](skills/ssh-host-processes/SKILL.md)
- **`ssh_host_alerts`** — Evaluate per-host thresholds from `[hosts.<name>.alerts]` (disk %, load, mem free, optional disk-mount filter). Returns `breaches[]` + raw `metrics`. Inputs: `host`. [skill](skills/ssh-host-alerts/SKILL.md)
- **`ssh_user_info`** — Structured `/etc/passwd` row + group memberships for one user. Sourced from `getent passwd` + `id -Gn` + `id -gn`; no sudo. `username=None` queries the SSH user via `id -un`. Username validated against POSIX 3.437 before being passed to remote commands. Returns `{uid, gid, gecos, home, shell, primary_group, groups[]}`. POSIX-only. Inputs: `host`, `username` (optional). [skill](skills/ssh-user-info/SKILL.md)
- **`ssh_known_hosts_verify`** — Verify live server key matches `known_hosts` by attempting a real connect. Returns expected vs. actual fingerprints. Inputs: `host`. [skill](skills/ssh-known-hosts-verify/SKILL.md)
- **`ssh_host_list`** — Enumerate the hosts currently loaded from `hosts.toml` + `SSH_HOSTS_ALLOWLIST`. Returns `{alias, hostname, port, platform, user, auth_method, has_notes}` per entry — sanitized, no credentials. `has_notes: bool` is true when EITHER the operator baseline (`hosts.toml.notes`) or the agent sidecar (`<SSH_HOST_NOTES_DIR>/<alias>.md`) has content ([INC-055](INCIDENTS.md)) so callers know which hosts to drill into via `ssh_host_notes`. Inputs: *(none)*. [skill](skills/ssh-host-list/SKILL.md)
- **`ssh_host_notes`** — Read both layers of per-host memory: `operator_notes` (hard-rule baseline from `hosts.toml`'s `notes` field; READ-ONLY to the LLM) + `agent_notes` (the LLM's own working memory across sessions, sidecar markdown at `<SSH_HOST_NOTES_DIR>/<alias>.md`; READ-WRITE via the `_append` / `_set` tools). Pure in-memory + one local FS read; no SSH. Use BEFORE doing anything substantive on a host you haven't worked with this session — operator notes are hard rules, agent notes are your past self's hard-won lessons ([INC-055](INCIDENTS.md)). Inputs: `host`. [skill](skills/ssh-host-notes/SKILL.md)

## Host policy reload (`group:host`, low-access)

- **`ssh_host_reload`** — Re-read `hosts.toml` from disk and swap the in-memory policy atomically. Returns `{loaded, source, added, removed, changed}` so callers see what changed vs. the previous load. Validates the new file before swapping — on parse/validation failure the existing fleet stays intact. Does NOT invalidate pooled SSH connections; live sessions retain their original policy until they drop on keepalive. `ALLOW_LOW_ACCESS_TOOLS=true`. Inputs: *(none)*. [skill](skills/ssh-host-reload/SKILL.md)
- **`ssh_host_notes_append`** — Append a timestamped Markdown entry to the LLM's per-host memory sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md` ([INC-055](INCIDENTS.md)). Use to record durable lessons future sessions should inherit ("`deploy@` in docker group", "operator rejected `apt install apache2`", "logs go to `/var/log/myapp/access.log` NOT `.log.access`"). Atomic temp+rename on local FS; capped at `SSH_HOST_NOTES_MAX_BYTES`. `ALLOW_LOW_ACCESS_TOOLS=true`. Inputs: `host`, `entry`. [skill](skills/ssh-host-notes-append/SKILL.md)
- **`ssh_host_notes_set`** — Replace the entire agent-notes sidecar verbatim. Use to consolidate accumulated notes (read via `ssh_host_notes` first, prune stale entries, restructure, write back) or reset memory. Empty string clears the file to zero bytes. Atomic; same cap. `ALLOW_LOW_ACCESS_TOOLS=true`. Inputs: `host`, `content`. [skill](skills/ssh-host-notes-set/SKILL.md)

## Sessions (`group:session`)

- **`ssh_session_list`** — List open pooled SSH connections. Inputs: *(none)*. [skill](skills/ssh-session-list/SKILL.md)

## SFTP reads (`group:sftp-read`)

All paths canonicalized via remote `realpath -m` and verified inside `path_allowlist`; rejected by `restricted_paths` and `restricted_globs`. Paths that match `redact_paths_globs` trip the `redact_bypass_policy` — use `ssh_read_redacted` for those paths.

- **`ssh_sftp_list`** — List a directory with offset/limit pagination. Returns `entries[]` + `has_more`. Inputs: `host`, `path`, `offset` (0), `limit` (200). [skill](skills/ssh-sftp-list/SKILL.md)
- **`ssh_sftp_stat`** — File/dir metadata (kind, size, mode, mtime, owner, group, symlink target). Inputs: `host`, `path`. [skill](skills/ssh-sftp-stat/SKILL.md)
- **`ssh_sftp_download`** — Download a remote file. Default mode: base64-encoded content in the response, size-capped at `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB). `local_path` mode: streams to a path on the MCP host's filesystem (up to `SSH_LOCAL_TRANSFER_MAX_BYTES`, default 2 GiB; requires `SSH_LOCAL_TRANSFER_ROOTS`). Result includes `local_path_written` when `local_path` is used. Raises `RedactBypassBlocked` (default) when path matches `redact_paths_globs` and `redact_bypass_policy=block`; use `ssh_read_redacted` for those paths. Inputs: `host`, `path`, `local_path` (optional). [skill](skills/ssh-sftp-download/SKILL.md)
- **`ssh_find`** — `find <path> -maxdepth N -type T -name PATTERN`. Pattern regex-validated, results capped at `SSH_FIND_MAX_RESULTS`. Inputs: `host`, `root`, `name_pattern`, `kind` (`file`/`dir`/`symlink`/`any`), `max_depth`. [skill](skills/ssh-find/SKILL.md)
- **`ssh_file_hash`** — MD5 / SHA1 / SHA256 / SHA512 of a remote file. POSIX: `<algo>sum`. Windows: `Get-FileHash`. Returns lowercase hex digest + byte size. Use after `ssh_upload` / `ssh_deploy` / `ssh_docker_cp` to verify the transfer landed intact; MD5/SHA1 included for legacy checksums but NOT collision-resistant. Inputs: `host`, `path`, `algorithm` (default `sha256`). [skill](skills/ssh-file-hash/SKILL.md)
- **`ssh_read_redacted`** — Read a remote config file (`.env` / `.yml` / `.json` / `.ini` / generic) and pass it through the secret-redactor before delivering to the LLM. Secrets replaced by deterministic `<sha:abcdef123456 len:48>` markers (HMAC-SHA256, 12-char prefix). Three detection layers: key-name match (case-insensitive substring on default + configured keys), PEM blocks (always), entropy detection (base64 >= 20 chars / hex >= 32 chars, default on). Format auto-detected from extension. Exempt from `redact_bypass_policy=block` — this IS the operator-blessed path for redact-listed files. Still respects `restricted_paths` / `restricted_globs`. Returns `RedactedReadResult` with `content`, `redactions[]`, `format_detected`. Inputs: `host`, `path`, `format` (optional; auto-detected). [skill](skills/ssh-read-redacted/SKILL.md)

## Docker (read) (`group:docker`)

- **`ssh_docker_ps`** — List containers. `Labels` field stripped by default to protect LLM context (set `include_labels=True` to keep). Filter kwargs map to `--filter`: `name` (substring match, `[A-Za-z0-9][A-Za-z0-9_.-]*`), `status` (`created`/`running`/`paused`/`restarting`/`exited`/`dead`), `label` (bare key or `key=value`; k8s-style keys with `/` accepted), `ancestor` (image name, same regex as `name`). All filters validated before I/O. Inputs: `host`, `all_` (False), `include_labels` (False), `name` (None), `status` (None), `label` (None), `ancestor` (None). [skill](skills/ssh-docker-ps/SKILL.md)
- **`ssh_docker_logs`** — Container logs with aggressive context guards: `tail` default 50 (max 10000), `max_bytes` default 64 KiB (range 1 KiB..10 MiB). Inputs: `host`, `container`, `tail`, `since`, `timestamps`, `max_bytes`. [skill](skills/ssh-docker-logs/SKILL.md)
- **`ssh_docker_inspect`** — Inspect a docker object (`container`/`image`/`network`/`volume`). Inputs: `host`, `target`, `kind`. [skill](skills/ssh-docker-inspect/SKILL.md)
- **`ssh_docker_stats`** — One-shot resource snapshot via `docker stats --no-stream`. Inputs: `host`. [skill](skills/ssh-docker-stats/SKILL.md)
- **`ssh_docker_top`** — Process list inside a container (`docker top`). Plain `ps`-style text in `stdout` (no JSON format at the docker level). `ps_options` accepts extra argv (`-eo pid,user,comm`); shell metacharacters rejected. Inputs: `host`, `container`, `ps_options`. [skill](skills/ssh-docker-top/SKILL.md)
- **`ssh_docker_events`** — Daemon event stream over a bounded time window (`docker events --since <since> --until <until> --format '{{json .}}'`). Answers "what just happened?" in one call: OOM kills, restarts, health transitions, image pulls. `since` / `until` accept relative (`10m`), epoch, RFC3339, or `now`; `filters` = `["container=nginx", "event=die"]`. Inputs: `host`, `since` (default `"10m"`), `until` (default `"now"`), `filters`. [skill](skills/ssh-docker-events/SKILL.md)
- **`ssh_docker_volumes`** — List volumes (`docker volume ls --format '{{json .}}'`) or inspect one by name (`docker volume inspect -- <name>`). Use before any `ssh_docker_prune(scope="volume")` decision — named volumes often carry application state. Inputs: `host`, `name` (optional; None = list, set = inspect). [skill](skills/ssh-docker-volumes/SKILL.md)
- **`ssh_docker_system_df`** — Disk-usage summary across docker object types (`docker system df --format '{{json .}}'`). Returns 4 rows under `categories`: Images, Containers, Local Volumes, Build Cache — each with `TotalCount`, `Active`, `Size`, `Reclaimable` as Docker's human-readable strings (e.g. `"1.5GB (45%)"`). Run BEFORE `ssh_docker_prune` to estimate impact, or as the fast "why is `/var/lib/docker` getting full?" answer. Inputs: `host`. [skill](skills/ssh-docker-system-df/SKILL.md)
- **`ssh_docker_images`** — List local images. `Labels` stripped by default. Filter kwargs map to `--filter`: `reference` (glob-style image ref, supports `*`/`?`/digests, e.g. `ghcr.io/org/*:*`), `dangling` (bool; `True`=untagged only, `False`=tagged only), `label` (same form as `ssh_docker_ps`). All filters validated before I/O. Inputs: `host`, `include_labels` (False), `reference` (None), `dangling` (None), `label` (None). [skill](skills/ssh-docker-images/SKILL.md)
- **`ssh_docker_compose_ps`** — List compose-project services. `Labels` stripped by default. `compose_file` path-allowlist-checked. Filter kwargs: `service` (trailing positional, narrows to one compose service; same name regex as containers), `status` (`paused`/`restarting`/`removing`/`running`/`dead`/`created`/`exited`; note `removing` is compose-only). `--filter status=` is placed before the positional service name. Inputs: `host`, `compose_file`, `include_labels` (False), `service` (None), `status` (None). [skill](skills/ssh-docker-compose-ps/SKILL.md)
- **`ssh_docker_compose_logs`** — Compose logs with same context guards as `ssh_docker_logs`. Inputs: `host`, `compose_file`, `tail`, `service`, `max_bytes`. [skill](skills/ssh-docker-compose-logs/SKILL.md)

## systemctl (read) (`group:systemctl`)

Lifecycle ops (`start`, `stop`, `restart`, `reload`, `enable`, `disable`, `daemon-reload`) run via `ssh_sudo_exec systemctl ...` — see [runbooks/ssh-systemd-diagnostics/SKILL.md](runbooks/ssh-systemd-diagnostics/SKILL.md). Safe-tier tools listed here work on stock hosts without sudo.

All 8 tools carry `tags={"safe", "read", "group:systemctl"}` and `version="1.0"`. No `ALLOW_*` flag required. No `path_allowlist` interaction — these tools do not read or write SFTP paths. The SSH user must be in the `systemd-journal` or `adm` group for `ssh_journalctl` (see caveat below).

- **`ssh_systemctl_status`** — Full status block for one unit (`systemctl status <unit> --no-pager`). Returns `SystemctlStatusResult` (`{host, unit, stdout, exit_code, active_state}`). `active_state` parsed from the `Active:` line; `null` if absent. Exit code 3 (unit inactive/dead) is data, not an error. Inputs: `host`, `unit`. [skill](skills/ssh-systemctl-status/SKILL.md)
- **`ssh_systemctl_is_active`** — Lightweight active-state check. Returns `SystemctlIsActiveResult` (`{host, unit, state, exit_code}`). `state` in `active | inactive | failed | activating | deactivating | reloading | unknown`. Non-zero exit is normal — means unit is not active. Exit code 4 (no such unit) promoted to `state="unknown"`. Inputs: `host`, `unit`. [skill](skills/ssh-systemctl-is-active/SKILL.md)
- **`ssh_systemctl_is_enabled`** — Enablement state for a unit (survives reboot?). Returns `SystemctlIsEnabledResult` (`{host, unit, state, exit_code}`). `state` in `enabled | enabled-runtime | linked | linked-runtime | alias | masked | masked-runtime | static | indirect | disabled | generated | transient | bad | not-found | unknown`. Inputs: `host`, `unit`. [skill](skills/ssh-systemctl-is-enabled/SKILL.md)
- **`ssh_systemctl_is_failed`** — Failed-state check. Returns `SystemctlIsFailedResult` (`{host, unit, failed, state, exit_code}`). `failed=True` when the unit IS failed (exit code 0 from `systemctl is-failed` — consistent with systemctl's own convention). Inputs: `host`, `unit`. [skill](skills/ssh-systemctl-is-failed/SKILL.md)
- **`ssh_systemctl_list_units`** — List loaded units, optionally filtered. Returns `SystemctlListUnitsResult` (`{host, units, exit_code}`); each entry has `{unit, load, active, sub, description}`. Use `state="failed"` to surface all broken services in one call. Inputs: `host`, `pattern` (None), `state` (None), `unit_type` (`"service"`). [skill](skills/ssh-systemctl-list-units/SKILL.md)
- **`ssh_systemctl_show`** — Machine-readable properties as a `dict[str, str]`. Returns `SystemctlShowResult` (`{host, unit, properties, exit_code}`). Use `properties=["ActiveState", "Result", "NRestarts"]` to limit output — the full dump can be several hundred lines. Inputs: `host`, `unit`, `properties` (None). [skill](skills/ssh-systemctl-show/SKILL.md)
- **`ssh_systemctl_cat`** — Raw unit file contents (`systemctl cat <unit>`). Output is prefixed with `# /path/to/unit` per section. Useful for diffing unit drift between hosts without SFTP. Inputs: `host`, `unit`. [skill](skills/ssh-systemctl-cat/SKILL.md)
- **`ssh_journalctl`** — Bounded journal read (`journalctl -u <unit> --no-pager -n <lines>`). `since` / `until` accept systemd.time(7) vocabulary: relative (`10m`, `2h`, `30d`, `1w`, `6M`, `1y`), epoch, RFC3339, short date, or keywords (`yesterday`/`today`/`now`). `lines` capped at 1000. `grep` conservative-allowlist validated. **Caveat:** on hosts where the SSH user is not in `systemd-journal` or `adm`, the journal may be empty / permission-denied — fall through to `ssh_sudo_exec journalctl -u <unit>` when needed. Inputs: `host`, `unit`, `since` (None), `until` (None), `lines` (200), `grep` (None). [skill](skills/ssh-journalctl/SKILL.md)

## Package management (read) (`group:pkg`)

Read-tier apt tools probe for `apt` via `command -v apt` before invoking any APT binary. Hosts without `apt` (non-Debian distros, Windows targets) receive a clean `PlatformNotSupported` error. Pattern and package-name arguments are argv-validated — no shell metacharacters accepted. All read-tier tools carry `tags={"safe", "read", "group:pkg"}`. POSIX-only.

- **`ssh_apt_list`** — List APT packages filtered by mode and optional glob. `mode` ∈ `{"installed", "upgradable", "all"}`. Maps to `apt list --installed` / `--upgradable` / no flag. Narrow wide queries with `pattern` (e.g. `nginx*`) to avoid stdout-cap truncation. Returns `AptListResult` with `packages[]`, `total`, `truncated`, `output_warnings`. Inputs: `host`, `mode`, `pattern` (optional). [skill](skills/ssh-apt-list/SKILL.md)
- **`ssh_apt_search`** — Search package names AND descriptions via `apt-cache search`. Returns name + short description per match. Use when you know what a tool does but not what the package is called. Returns `AptSearchResult` with `results[]`, `output_warnings`. Inputs: `host`, `pattern`. [skill](skills/ssh-apt-search/SKILL.md)
- **`ssh_apt_show`** — Combined `apt-cache show` + `apt-cache policy` for one package in a single call. Returns `installed_version`, `candidate_version`, `repos[]`, `description`, `depends[]`, `recommends[]`, `suggests[]`, `conflicts[]`, `breaks[]`, `replaces[]`, `output_warnings`. Use for pre-upgrade audits and dependency-conflict diagnosis. Inputs: `host`, `package`. [skill](skills/ssh-apt-show/SKILL.md)
- **`ssh_apt_show_holds`** — Parse `apt-mark showhold` into a structured `held[]` list. Read-only sibling of the mutation tool `ssh_apt_mark`; no root needed. Returns `AptHoldsResult`. Inputs: `host`, `timeout` (optional). [skill](skills/ssh-apt-show-holds/SKILL.md)

## Persistent shell (read) (`group:shell`)

- **`ssh_shell_list`** — List open persistent sessions with cwd + idle age. Inputs: *(none)*. [skill](skills/ssh-shell-list/SKILL.md)

---

# Low-access tier (`ALLOW_LOW_ACCESS_TOOLS=true`)

SFTP-mediated mutations + bounded docker container lifecycle. Path-bearing tools route every path through `resolve_path` (which bundles `canonicalize_and_check` + `check_not_restricted`). Never invoke arbitrary shell.

```toml
# hosts.toml
[hosts.dev-box]
hostname = "dev.internal"
user = "dev"
path_allowlist = ["/opt/app", "/etc/app"]          # scope for file mutations
restricted_paths = ["/etc/app/secrets"]            # carve-outs inside allowlist
# docker_cmd = "sudo docker"                       # override if Docker needs sudo
# docker_cmd = "podman"                            # or rootless Podman
# Env: ALLOW_LOW_ACCESS_TOOLS=true
```

## File operations (`group:file-ops`)

All write paths use atomic `tmp + posix_rename`. Source / destination paths are allowlist-checked and refuse `restricted_paths`.

- **`ssh_mkdir`** — Create a directory. With `parents=True`, walks the path like `mkdir -p`. Inputs: `host`, `path`, `parents` (False). [skill](skills/ssh-mkdir/SKILL.md)
- **`ssh_delete`** — Delete a single file. Refuses directories — use `ssh_delete_folder`. Inputs: `host`, `path`. [skill](skills/ssh-delete/SKILL.md)
- **`ssh_delete_folder`** — Remove a directory. `recursive=False` requires empty (rmdir). `recursive=True` SFTP-walks with cap `SSH_DELETE_FOLDER_MAX_ENTRIES`, falls back to `rm -rf --` for huge trees. `dry_run=True` returns the would-delete list without touching anything. Inputs: `host`, `path`, `recursive`, `dry_run`. [skill](skills/ssh-delete-folder/SKILL.md)
- **`ssh_cp`** — Copy a file via `cp -a -- src dst` (fixed argv, no shell). Inputs: `host`, `src`, `dst`. [skill](skills/ssh-cp/SKILL.md)
- **`ssh_mv`** — Move/rename a file. SFTP `posix_rename` first; falls back to `mv --` for cross-filesystem. Inputs: `host`, `src`, `dst`. [skill](skills/ssh-mv/SKILL.md)
- **`ssh_link`** — Create a hard or symbolic link from `src` to `dst`. **Hard linking is O(1) — prefer over `ssh_cp` for big files on the same volume.** Three modes: (a) default `symbolic=False, follow_symlinks=True` (like `ln -L`) — pure SFTP `link()`, link points at src's resolved target if src is a symlink; (b) `symbolic=False, follow_symlinks=False` (like `ln -P --physical`) — hard link to the symlink itself; SFTP can't express this so it shells out to `ln -P -- <src> <dst>` (low-access tier; doesn't need `ln` allowlisted); (c) `symbolic=True` (like `ln -s`) — pure SFTP `symlink()`, src stored verbatim; `follow_symlinks` ignored per GNU `ln`. Both sides path-validated: dst canonicalized; hard-link-`-L` src canonicalized; hard-link-`-P` src parent-canonicalize + `lstat`; symbolic src validated as a path string (relative resolved against dst's parent, normalized via `posixpath.normpath`, then allowlist + restricted-paths check — dangling targets allowed, NUL bytes rejected). No `-f` (force) — use `ssh_delete` first to overwrite ([INC-056](INCIDENTS.md)). Inputs: `host`, `src`, `dst`, `symbolic` (False), `follow_symlinks` (True). [skill](skills/ssh-link/SKILL.md)
- **`ssh_upload`** — Create or replace a file atomically (`<path>.ssh-mcp-tmp.<hex>` + `posix_rename`). **Use this instead of `ssh_exec_run` for `cat > path <<EOF` / `tee` / `echo > path` / `printf > path`** — atomic, path-policy-checked, audited. Pass exactly one of `content_text` (plain UTF-8; configs/scripts/code), `content_base64` (binary-safe; capped at `SSH_UPLOAD_MAX_FILE_BYTES`, default 256 MiB), or `local_path` (stream from MCP-host disk; capped at `SSH_LOCAL_TRANSFER_MAX_BYTES`, default 2 GiB; requires `SSH_LOCAL_TRANSFER_ROOTS`). Use `local_path` for files larger than ~5 MiB to avoid base64 context overhead. Result includes `local_path_written` when `local_path` is used. Inputs: `host`, `path`, `content_text` (one-of), `content_base64` (one-of), `local_path` (one-of), `mode` (octal). [skill](skills/ssh-upload/SKILL.md)
- **`ssh_edit`** — Structured edit: replace `old_string` with `new_string` atomically. `mode="single"` (default) errors on duplicate or missing match; `mode="all"` replaces every occurrence. Inputs: `host`, `path`, `old_string`, `new_string`, `mode`. [skill](skills/ssh-edit/SKILL.md)
- **`ssh_patch`** — Apply a unified diff atomically. Rejects on context or removal mismatch (no fuzzy fallback). Inputs: `host`, `path`, `unified_diff`. [skill](skills/ssh-patch/SKILL.md)
- **`ssh_deploy`** — `ssh_upload` + auto-backup. If `backup=True` and the file exists, `posix_rename` to `<path>.bak-<UTC-iso8601>` before writing. Same three-way payload mutex as `ssh_upload`: `content_text`, `content_base64`, or `local_path`. Backup step runs before the new content is sourced from disk, regardless of payload mode. Inputs: `host`, `path`, `content_text` (one-of), `content_base64` (one-of), `local_path` (one-of), `mode`, `backup` (True). [skill](skills/ssh-deploy/SKILL.md)
- **`ssh_transfer`** — Copy a file from one remote host to another by streaming SFTP through the MCP server. Neither host needs outbound SSH to the other -- works in firewalled inter-host topologies where direct A->B SSH is blocked ([INC-052](INCIDENTS.md)). Both endpoints route through `resolve_path` (canonicalize + allowlist + restricted-zones) independently. Atomic write on the dst (temp + `posix_rename`). Size capped at `SSH_UPLOAD_MAX_FILE_BYTES`. Same-host call rejected -- use `ssh_cp` instead. Throughput bottlenecks at the slower of (src→MCP) and (MCP→dst); for inter-host gigabit when A and B already trust each other, an `scp` via `ssh_exec_run` is faster. Cross-platform via SFTP. Inputs: `src_host`, `src_path`, `dst_host`, `dst_path`, `overwrite` (False). [skill](skills/ssh-transfer/SKILL.md)

## Docker (lifecycle) (`group:docker`)

Container start/stop/restart and the parallel compose subcommands. Container names are regex-validated; compose file paths go through `resolve_path` (canonicalize + allowlist + restricted-zones).

- **`ssh_docker_start`** / **`ssh_docker_stop`** / **`ssh_docker_restart`** — `docker start|stop|restart -- <container>`. Inputs: `host`, `container`. [start](skills/ssh-docker-start/SKILL.md) · [stop](skills/ssh-docker-stop/SKILL.md) · [restart](skills/ssh-docker-restart/SKILL.md)
- **`ssh_docker_compose_start`** / **`ssh_docker_compose_stop`** / **`ssh_docker_compose_restart`** — `compose -f <file> start|stop|restart`. Inputs: `host`, `compose_file`. [start](skills/ssh-docker-compose-start/SKILL.md) · [stop](skills/ssh-docker-compose-stop/SKILL.md) · [restart](skills/ssh-docker-compose-restart/SKILL.md)
- **`ssh_docker_cp`** — Bidirectional `docker cp` between host and container. Host-side path canonicalized + allowlist + `restricted_paths` checked (same rules as `ssh_cp` / `ssh_upload`); container-side path not policy-checked (we don't manage policy inside containers). Direction explicit: `from_container` or `to_container`. Inputs: `host`, `container`, `container_path`, `host_path`, `direction`. [skill](skills/ssh-docker-cp/SKILL.md)

## Persistent shell (close) (`group:shell`)

- **`ssh_shell_close`** — Close a persistent session. No-op if the id is already gone. Stays available even when `ALLOW_PERSISTENT_SESSIONS=false`, so operators can drain pre-existing sessions. Inputs: `session_id`. [skill](skills/ssh-shell-close/SKILL.md)

---

# Dangerous tier (`ALLOW_DANGEROUS_TOOLS=true`)

Arbitrary command execution surface, container exec, container creation, and stateful shells. Audited (`ssh_mcp.audit` JSON line per call). Commands routed through `command_allowlist` (or `ALLOW_ANY_COMMAND=true`, [ADR-0018](DECISIONS.md)).

```toml
# hosts.toml
[hosts.prod-app]
hostname = "app.internal"
user = "ops"
command_allowlist = ["systemctl", "journalctl"]    # fail-closed if empty
persistent_session = true                          # default — false to deny stateful shells
# Env: ALLOW_DANGEROUS_TOOLS=true
# ALLOW_ANY_COMMAND=true                           # for open command access
# ALLOW_PERSISTENT_SESSIONS=true                   # for ssh_shell_open / _exec
# ALLOW_DOCKER_PRIVILEGED=true                     # only if you truly need --privileged / --cap-add / host-ns
```

## Arbitrary execution (`group:exec`)

- **`ssh_exec_run`** — **Last-resort tool.** Run an arbitrary command on the remote host. Caller owns quoting. Non-zero exit codes are data, not raised. Timeouts return `timed_out=True` plus best-effort pkill cleanup. The `ExecResult.hint` field surfaces a remediation note when stderr matches a known TTY-need pattern ([ADR-0022](DECISIONS.md)). Inputs: `host`, `command`, `timeout` (default `SSH_COMMAND_TIMEOUT=60`). [skill](skills/ssh-exec-run/SKILL.md)
  - **Prefer dedicated tools** when one fits — see the mapping table in the skill (`mkdir -p ... -> ssh_mkdir`, `cat ... -> ssh_sftp_download`, `docker ... -> ssh_docker_*`, `sudo ... -> ssh_sudo_exec`, ...). Wrappers are safer, faster, and audit cleaner.
- **`ssh_exec_script`** — Run a multi-line script body via stdin to `sh -s --`. Body never appears in argv, process listings, or audit lines. **No allowlist check** on the script body. Inputs: `host`, `script`, `timeout`. [skill](skills/ssh-exec-script/SKILL.md)
- **`ssh_exec_run_streaming`** — Long-running variant. Streams stdout/stderr tails to FastMCP's progress channel. Backed by `TaskConfig(mode="optional")` — clients may treat it synchronously for short commands or as a background task. Inputs: `host`, `command`, `timeout`. [skill](skills/ssh-exec-run-streaming/SKILL.md)
- **`ssh_broadcast`** — Run the same command on multiple pre-configured hosts in parallel. Each host's `command_allowlist` and `platform` are checked independently; one host's failure does NOT abort the others. Hard cap of 50 hosts per call. Returns `{command, results{alias→ExecResult}, succeeded[], failed[], errors{alias→exc-class}, elapsed_ms}`. Unknown / blocked aliases raise up front; per-host transport / allowlist / platform errors are captured in `errors`. Audit line records `host="?"` (fan-out); the result body is the durable record of what ran where. Inputs: `hosts[]`, `command`, `timeout`. [skill](skills/ssh-broadcast/SKILL.md)

## Docker (mutating) (`group:docker`)

Container exec, image pulls, container/image creation + removal, prune.

- **`ssh_docker_exec`** — Run a command inside a container. `command` is allowlist-checked like `ssh_exec_run`. Container name argv-validated. Inputs: `host`, `container`, `command`, `interactive` (False), `timeout`. [skill](skills/ssh-docker-exec/SKILL.md)
- **`ssh_docker_run`** — Create + start a new container from an image. **Capability-escalation surface:** flags that grant host-level control are **rejected by default** even under `ALLOW_DANGEROUS_TOOLS` — `--privileged`, `--cap-add`, `--security-opt`, `--device`, `--group-add`, host-namespace flags (`--pid=host`, `--network=host`, ...), another-container namespace joins (`--pid=container:<id>`), host-root bind mounts in both `-v /:/host` and `--mount source=/,target=/...` forms. Set `ALLOW_DOCKER_PRIVILEGED=true` to permit ([INC-022](INCIDENTS.md) / [INC-024](INCIDENTS.md) / [INC-025](INCIDENTS.md)). Image + optional name argv-validated. Inputs: `host`, `image`, `args[]`, `name`, `remove` (True), `detached` (False), `timeout`. [skill](skills/ssh-docker-run/SKILL.md)
- **`ssh_docker_pull`** — Pull an image. Bump `timeout` for slow networks. Inputs: `host`, `image`, `timeout`. [skill](skills/ssh-docker-pull/SKILL.md)
- **`ssh_docker_rm`** — Remove a container. `force=True` kills running containers first. Inputs: `host`, `container`, `force` (False). [skill](skills/ssh-docker-rm/SKILL.md)
- **`ssh_docker_rmi`** — Remove an image. `force=True` removes dependents. Inputs: `host`, `image`, `force` (False). [skill](skills/ssh-docker-rmi/SKILL.md)
- **`ssh_docker_prune`** — Prune unused docker resources. `scope` ∈ `{container, image, volume, network, system}`. `all_=True` adds `--all` for image/system scopes. Inputs: `host`, `scope` (`container`), `all_` (False). [skill](skills/ssh-docker-prune/SKILL.md)
- **`ssh_docker_compose_up`** — Bring up a compose project. Defaults to `-d` (detached). `build=True` rebuilds images first. Inputs: `host`, `compose_file`, `detached`, `build`, `timeout`. [skill](skills/ssh-docker-compose-up/SKILL.md)
- **`ssh_docker_compose_down`** — Tear down a compose project. `volumes=True` also removes named volumes (**destructive — data loss**). Inputs: `host`, `compose_file`, `volumes` (False), `timeout`. [skill](skills/ssh-docker-compose-down/SKILL.md)
- **`ssh_docker_compose_pull`** — Pull images for a compose project without starting services. Inputs: `host`, `compose_file`, `timeout`. [skill](skills/ssh-docker-compose-pull/SKILL.md)

## systemctl (mutating) (`group:systemctl`)

Lifecycle mutations on systemd units. **All require root** — use a sudoers-enabled SSH account (passwordless `systemctl`) or call via `ssh_sudo_exec` if you have the sudo tier. All carry `tags={"dangerous", "group:systemctl"}` and route through the same `_run_unit_action` helper that validates the unit name (POSIX-safe argv) and surfaces a `unit_hash` audit field. Non-zero exit codes are data, not raised. POSIX-only.

- **`ssh_systemctl_start`** — `systemctl start <unit>`. Starts the unit if not running. Idempotent — already-active units exit 0. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-start/SKILL.md)
- **`ssh_systemctl_stop`** — `systemctl stop <unit>`. Stops the unit. Idempotent — already-inactive units exit 0. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-stop/SKILL.md)
- **`ssh_systemctl_restart`** — `systemctl restart <unit>`. Stop-then-start in one call; preferred over manual stop+start for atomicity. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-restart/SKILL.md)
- **`ssh_systemctl_reload`** — `systemctl reload <unit>`. **Fails (non-zero exit) on units without `ExecReload=`** — use `ssh_systemctl_restart` for those. Use when the unit supports live config reload (nginx, systemd-journald, sshd). Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-reload/SKILL.md)
- **`ssh_systemctl_enable`** — `systemctl enable <unit>`. Creates symlinks so the unit starts at boot. **Does NOT start the unit** — call `ssh_systemctl_start` separately if you want it running now. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-enable/SKILL.md)
- **`ssh_systemctl_disable`** — `systemctl disable <unit>`. Removes the boot-time symlinks. **Does NOT stop the unit** — call `ssh_systemctl_stop` separately. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-disable/SKILL.md)
- **`ssh_systemctl_mask`** — `systemctl mask <unit>`. Links the unit to `/dev/null` — nothing can start it (boot, dependency, manual `systemctl start`) until unmasked. Use to forcibly prevent an unwanted service from coming up. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-mask/SKILL.md)
- **`ssh_systemctl_unmask`** — `systemctl unmask <unit>`. Reverses `ssh_systemctl_mask` — removes the `/dev/null` symlink so the unit can start again. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-unmask/SKILL.md)
- **`ssh_systemctl_reset_failed`** — `systemctl reset-failed <unit>`. Clears the failed state of one unit (no all-failed mode in v1). Pair with `ssh_journalctl` to first capture what failed, then reset so monitoring stops alarming. Inputs: `host`, `unit`, `timeout` (optional). [skill](skills/ssh-systemctl-reset-failed/SKILL.md)

## Package management (mutating) (`group:pkg`)

Dangerous-tier counterparts to the read-tier `ssh_apt_*` tools. All require root (use a sudoers-enabled SSH account or run via `ssh_sudo_exec`). Package names are validated against the Debian shape `^[a-z0-9][a-z0-9.+-]{0,127}$` before reaching argv; argv is built list-style and joined via `shlex.join`. All carry `tags={"dangerous", "group:pkg"}`. POSIX-only.

- **`ssh_apt_install`** — `apt-get -y install -- <packages...>`. Optionally runs `apt-get update` first via `update_first=True`. Returns `AptMutationResult` with `exit_code`, `stdout`, `stderr`, `duration_ms`, `output_warnings`. Inputs: `host`, `packages[]`, `update_first` (False), `timeout` (optional). [skill](skills/ssh-apt-install/SKILL.md)
- **`ssh_apt_upgrade`** — `apt-get -y upgrade`. Operator should typically run `ssh_apt_install([], update_first=True)` or refresh the index via `ssh_exec_run 'apt-get update'` first. Does NOT cover `do-release-upgrade` (intentional — release-upgrades stay an explicit `ssh_exec_run` decision). Inputs: `host`, `timeout` (optional). [skill](skills/ssh-apt-upgrade/SKILL.md)
- **`ssh_apt_remove`** — `apt-get -y remove -- <packages...>`. With `purge=True` uses the `purge` verb (also removes config files). Inputs: `host`, `packages[]`, `purge` (False), `timeout` (optional). [skill](skills/ssh-apt-remove/SKILL.md)
- **`ssh_apt_autoremove`** — `apt-get -y autoremove`. Removes packages installed as dependencies that are no longer needed. Inputs: `host`, `timeout` (optional). [skill](skills/ssh-apt-autoremove/SKILL.md)
- **`ssh_apt_mark`** — `apt-mark hold|unhold -- <packages...>`. Pins (or releases) packages at their current version. `action` ∈ `{"hold", "unhold"}`; the read-only `showhold` variant lives in the read-tier sibling `ssh_apt_show_holds`. Inputs: `host`, `action`, `packages[]`, `timeout` (optional). [skill](skills/ssh-apt-mark/SKILL.md)

## Persistent shell (open + exec) (`group:shell`)

`cwd` is tracked across calls via the `__SSHMCP_STATE__` sentinel; no remote PTY. Per-session `asyncio.Lock` serializes concurrent callers ([INC-023](INCIDENTS.md)). Hidden when `ALLOW_PERSISTENT_SESSIONS=false`. Per-host opt-out via `persistent_session = false` in `hosts.toml`.

- **`ssh_shell_open`** — Create a persistent session. Returns `session_id`. Inputs: `host`. [skill](skills/ssh-shell-open/SKILL.md)
- **`ssh_shell_exec`** — Run a command inside a session. `cwd` restored at start, updated from sentinel before return. Allowlist-checked like `ssh_exec_run`. Inputs: `session_id`, `command`, `timeout`. [skill](skills/ssh-shell-exec/SKILL.md)

---

# Sudo tier (`ALLOW_SUDO=true`)

Implies dangerous. Password sources, in priority order: `SSH_SUDO_PASSWORD_CMD` (subprocess) → OS keyring (`ssh-mcp-sudo` / `default`) → passwordless. `SSH_SUDO_PASSWORD` env is **rejected at startup** ([INC-009](INCIDENTS.md)).

```toml
# hosts.toml
[hosts.prod-db]
hostname = "db.internal"
user = "ops"
sudo_mode = "per-call"                             # or "persistent-su"
command_allowlist = ["systemctl", "postgresql"]    # also applies to sudo_exec
# Env: ALLOW_SUDO=true (implies ALLOW_DANGEROUS_TOOLS=true)
# Password: SSH_SUDO_PASSWORD_CMD=... / OS keyring / passwordless (see Sudo section in README)
```

- **`ssh_sudo_exec`** — Run a command under `sudo -S -p '' --`. Allowlist-checked like `ssh_exec_run`. Password piped over stdin, never appears in argv. Path-aware cheatsheet (v1.5.0) intercepts `sudo cat`/`sudo ls`/`sudo tee`/`sudo vi` etc. and redirects to the dedicated path tools below. Inputs: `host`, `command`, `timeout`. [skill](skills/ssh-sudo-exec/SKILL.md)
- **`ssh_sudo_run_script`** — Run a multi-line script under `sudo -S sh -s --`. Body on stdin after the password line; no allowlist check (same rationale as `ssh_exec_script`). Inputs: `host`, `script`, `timeout`. [skill](skills/ssh-sudo-run-script/SKILL.md)
- **`ssh_sudo_read`** — Read a root-owned file via `sudo cat --`; returns base64 bytes (`DownloadResult`). Full policy chain: allowlist + restricted_paths/globs + redact_bypass_policy (fires before sudo). Use `ssh_sudo_read_redacted` when `redact_bypass_policy=block` applies. Cap: `SSH_UPLOAD_MAX_FILE_BYTES` (256 MiB). Inputs: `host`, `path`. [skill](skills/ssh-sudo-read/SKILL.md)
- **`ssh_sudo_read_redacted`** — Sudo-elevated counterpart to `ssh_read_redacted`. Reads via `sudo cat`, runs the secret-redactor, returns `RedactedReadResult` with HMAC-SHA256 markers. Bypass-exempt (this IS the allowed alternative to `redact_bypass_policy=block`). Inputs: `host`, `path`, `format`. [skill](skills/ssh-sudo-read-redacted/SKILL.md)
- **`ssh_sudo_write`** — Atomic sudo write via tmp+chmod+chown+mv. Three-way payload mutex: `content_text` / `content_base64` / `local_path` (reads MCP-host file into memory; requires `SSH_LOCAL_TRANSFER_ROOTS`). Ownership preserved via pre-stat; new files default to root:root + warning. Caps: 256 MiB inline, 2 GiB local_path. Inputs: `host`, `path`, `content_text`, `content_base64`, `local_path`, `mode`, `chown_user`, `chown_group`. [skill](skills/ssh-sudo-write/SKILL.md)
- **`ssh_sudo_edit`** — Sudo-elevated structured edit: sudo read + `apply_edit` + sudo atomic write-back. Preserves both ownership AND mode (stat-first -- a 0o600 secrets file stays 0o600). Same `single`/`all` occurrence semantics as `ssh_edit`. Cap: `SSH_EDIT_MAX_FILE_BYTES` (10 MiB). Inputs: `host`, `path`, `old_string`, `new_string`, `occurrence`. [skill](skills/ssh-sudo-edit/SKILL.md)
- **`ssh_sudo_sftp_list`** — List a root-owned directory via `sudo ls -la --time-style=full-iso`; parsed into `SftpListResult.entries` (same shape as `ssh_sftp_list`). Pagination post-parse. BusyBox hosts: rows without `--time-style=full-iso` silently dropped. Inputs: `host`, `path`, `offset`, `limit`. [skill](skills/ssh-sudo-sftp-list/SKILL.md)

---

# Cross-cutting safeguards

These apply to all tools — worth knowing before you call anything.

| Safeguard | Where | What it does |
|---|---|---|
| **Tier flags** | `ALLOW_LOW_ACCESS_TOOLS` / `ALLOW_DANGEROUS_TOOLS` / `ALLOW_SUDO` | Hide whole tiers via FastMCP `Visibility` transforms ([ADR-0001](DECISIONS.md)). |
| **Group filter** | `SSH_ENABLED_GROUPS` | Trim catalog to specific `group:*` tags. Empty = all groups visible ([ADR-0016](DECISIONS.md)). |
| **Host allow + block** | `hosts.toml` keys / `SSH_HOSTS_ALLOWLIST` / `SSH_HOSTS_BLOCKLIST` | Resolve names to canonical hostname; deny wins ([ADR-0019](DECISIONS.md)). |
| **Path allowlist** | per-host `path_allowlist` ∪ `SSH_PATH_ALLOWLIST` | Every path-bearing tool (read or write) verifies via remote `realpath` ([ADR-0017](DECISIONS.md)). |
| **Restricted paths** | per-host `restricted_paths` ∪ `SSH_RESTRICTED_PATHS` | Carve-outs inside the allowlist; low-access + sftp-read tools refuse them. Exec/sudo unaffected. |
| **Command allowlist** | per-host `command_allowlist` ∪ `SSH_COMMAND_ALLOWLIST` | Empty = fail-closed unless `ALLOW_ANY_COMMAND=true` ([ADR-0018](DECISIONS.md)). |
| **Docker host-escape** | `ALLOW_DOCKER_PRIVILEGED` (default false) | `ssh_docker_run` rejects `--privileged`, `--cap-add`, host-namespace flags, host-root volume mounts ([INC-022](INCIDENTS.md)). |
| **Docker CLI binary** | `SSH_DOCKER_CMD` (default `docker`) + per-host `docker_cmd` in hosts.toml | Switch to `podman` (or any Docker-compatible CLI) globally or per-host. `SSH_DOCKER_COMPOSE_CMD` derives as `{docker_cmd} compose` unless explicitly overridden. |
| **Persistent sessions** | `ALLOW_PERSISTENT_SESSIONS` + per-host `persistent_session` | Both must be true to allow `ssh_shell_open` / `ssh_shell_exec`. |
| **Audit log** | `ssh_mcp.audit` logger | One JSON line per tool call (all tiers: `read` / `low-access` / `dangerous` / `sudo`). Paths + commands SHA-256 hashed; `error` field is exception class only ([INC-008](INCIDENTS.md)). |
| **Hooks** | `SSH_HOOKS_MODULE` | Operator-supplied module exposing `register_hooks(registry)`. Events: STARTUP / SHUTDOWN / PRE_TOOL_CALL / POST_TOOL_CALL. Side-effect only. |
| **BM25 search** | `SSH_ENABLE_BM25` | Replace tools/list with `search_tools` + `call_tool` for large catalogs ([ADR-0020](DECISIONS.md)). |
| **Output caps** | `SSH_STDOUT_CAP_BYTES` / `SSH_STDERR_CAP_BYTES` (1 MiB) | Truncate at the cap; `*_truncated` flag flips true. Docker logs default to a tighter 64 KiB. |
| **TTY hint** | `ExecResult.hint` | Populated when stderr matches `is not a tty` etc. — suggests batch flags ([ADR-0022](DECISIONS.md)). |

---

For environment-variable docs see [.env.example](.env.example). For per-tool runbooks see [skills/](skills/).
