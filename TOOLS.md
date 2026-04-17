# Tool Reference

Tools are grouped by **tier** (which `ALLOW_*` flag they require) and within each tier by **group** (the `group:*` tag — used by `SSH_ENABLED_GROUPS` filtering).

For a full per-tool runbook, follow the **skill** link on each entry — the SKILL.md files cover `When to call`, `When NOT to call`, examples, common failures, and related tools.

- 67 tools total
- 9 tool groups: `host`, `session`, `sftp-read`, `file-ops`, `exec`, `sudo`, `shell`, `docker`, `systemctl`
- 4 tiers: read (always on) · low-access · dangerous · sudo
- See [README.md](README.md) for tier flags, host config, restricted paths, BM25 search, and `SSH_ENABLED_GROUPS` examples.

## Context cost per group

How many bytes each group adds to the `tools/list` response every MCP turn — so operators can decide what to trim via `SSH_ENABLED_GROUPS`. Measured by serializing each tool's wire schema (`name`, `description`, `inputSchema`, `annotations`) as it is sent to the client. Tokens are a bytes/4 heuristic — directional, not exact (JSON tokenises slightly denser on Claude / GPT-4-family).

| Group | Tools | Bytes | ~Tokens | Avg / tool |
|---|---:|---:|---:|---:|
| `docker` | 26 | 15,337 | ~3,834 | 589 B |
| `systemctl` | 8 | 4,501 | ~1,125 | 562 B |
| `file-ops` | 9 | 4,062 | ~1,015 | 451 B |
| `exec` | 3 | 3,189 | ~797 | **1,063 B** (densest — rich input schemas) |
| `sftp-read` | 5 | 3,187 | ~796 | 637 B |
| `host` | 6 | 2,275 | ~568 | 379 B |
| `shell` | 4 | 1,377 | ~344 | 344 B |
| `sudo` | 2 | 1,339 | ~334 | 669 B |
| `session` | 2 | 324 | ~81 | 162 B |
| **Total** | **65** | **35,591** | **~8,897** | — |

**Savings from common `SSH_ENABLED_GROUPS` trims:**

- Drop `docker` only → ~5,063 tok (saves **43%** — biggest single win)
- Drop `systemctl` only → ~7,772 tok (saves **12%**)
- Drop both → ~3,938 tok (saves **55%**)
- Keep only `host,sftp-read,docker` (observability + container triage) → ~5,200 tok (saves ~42%)
- Keep only `host,session,systemctl` (systemd-triage persona) → ~1,774 tok (saves ~80%)

## Contents

- [Platform compatibility matrix](#platform-compatibility-matrix)
- [How to read each entry](#how-to-read-each-entry)
- [Read tier (always on)](#read-tier-always-on) — 33 tools
- [Low-access tier](#low-access-tier-allow_low_access_toolstrue) — 18 tools (`ALLOW_LOW_ACCESS_TOOLS=true`)
- [Dangerous tier](#dangerous-tier-allow_dangerous_toolstrue) — 14 tools (`ALLOW_DANGEROUS_TOOLS=true`)
- [Sudo tier](#sudo-tier-allow_sudotrue) — 2 tools (`ALLOW_SUDO=true`)
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
| `file-ops` (mkdir / delete / delete_folder / upload / edit / patch / deploy / mv) | yes | yes | SFTP-first |
| `file-ops` (`ssh_cp`) | yes | **no** | Uses `cp -a` |
| `exec` | yes | **no** | POSIX `sh` + pkill |
| `sudo` | yes | **no** | No `sudo` |
| `shell` (open / exec) | yes | **no** | Cwd sentinel relies on POSIX shell |
| `shell` (list / close) | yes | yes | In-memory |
| `docker` | yes | **no** | Scope deferred — see ADR-0023 |
| `systemctl` | yes | **no** | systemd is Linux-only; no explicit platform gate (clean non-zero exit on Windows targets) |

---

## Sections by group

- [Read tier](#read-tier-always-on) — 33 tools, no flag needed
  - [Host & connection](#host--connection-grouphost) (7)
  - [Sessions](#sessions-groupsession) (2)
  - [SFTP reads](#sftp-reads-groupsftp-read) (5)
  - [Docker (read)](#docker-read-groupdocker) (9)
  - [systemctl (read)](#systemctl-read-groupsystemctl) (8)
  - [Persistent shell (read)](#persistent-shell-read-groupshell) (1)
  - [Alerts](#alerts-grouphost) (covered above)
- [Low-access tier](#low-access-tier-allow_low_access_toolstrue) — 18 tools (`ALLOW_LOW_ACCESS_TOOLS=true`)
  - [Host policy reload](#host-policy-reload-grouphost-low-access) (1)
  - [File operations](#file-operations-groupfile-ops) (9)
  - [Docker (lifecycle)](#docker-lifecycle-groupdocker) (7)
  - [Persistent shell (close)](#persistent-shell-close-groupshell) (1)
- [Dangerous tier](#dangerous-tier-allow_dangerous_toolstrue) — 14 tools (`ALLOW_DANGEROUS_TOOLS=true`)
  - [Arbitrary execution](#arbitrary-execution-groupexec) (3)
  - [Docker (mutating)](#docker-mutating-groupdocker) (9)
  - [Persistent shell (open + exec)](#persistent-shell-open--exec-groupshell) (2)
- [Sudo tier](#sudo-tier-allow_sudotrue) — 2 tools (`ALLOW_SUDO=true`, also requires dangerous)
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

- **`ssh_host_ping`** — TCP + SSH handshake probe. Returns reachability, auth status, latency, server banner, and the pinned known_host fingerprint. Inputs: `host`. [skill](skills/ssh-host-ping/SKILL.md)
- **`ssh_host_info`** — `uname -a`, `/etc/os-release`, and `uptime`, parsed. Fixed argv, no shell interpolation. Inputs: `host`. [skill](skills/ssh-host-info/SKILL.md)
- **`ssh_host_disk_usage`** — `df -PTh` parsed into structured entries. Inputs: `host`. [skill](skills/ssh-host-disk-usage/SKILL.md)
- **`ssh_host_processes`** — Top-N processes by CPU via `ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu`. Inputs: `host`, `top_n` (default 25). [skill](skills/ssh-host-processes/SKILL.md)
- **`ssh_host_alerts`** — Evaluate per-host thresholds from `[hosts.<name>.alerts]` (disk %, load, mem free, optional disk-mount filter). Returns `breaches[]` + raw `metrics`. Inputs: `host`. [skill](skills/ssh-host-alerts/SKILL.md)
- **`ssh_known_hosts_verify`** — Verify live server key matches `known_hosts` by attempting a real connect. Returns expected vs. actual fingerprints. Inputs: `host`. [skill](skills/ssh-known-hosts-verify/SKILL.md)
- **`ssh_host_list`** — Enumerate the hosts currently loaded from `hosts.toml` + `SSH_HOSTS_ALLOWLIST`. Returns `{alias, hostname, port, platform, user, auth_method}` per entry — sanitized, no credentials. Inputs: *(none)*. [skill](skills/ssh-host-list/SKILL.md)

## Host policy reload (`group:host`, low-access)

- **`ssh_host_reload`** — Re-read `hosts.toml` from disk and swap the in-memory policy atomically. Returns `{loaded, source, added, removed, changed}` so callers see what changed vs. the previous load. Validates the new file before swapping — on parse/validation failure the existing fleet stays intact. Does NOT invalidate pooled SSH connections; live sessions retain their original policy until they drop on keepalive. `ALLOW_LOW_ACCESS_TOOLS=true`. Inputs: *(none)*. [skill](skills/ssh-host-reload/SKILL.md)

## Sessions (`group:session`)

- **`ssh_session_list`** — List open pooled SSH connections. Inputs: *(none)*. [skill](skills/ssh-session-list/SKILL.md)
- **`ssh_session_stats`** — Pool-level stats: open count, per-key idle time. Inputs: *(none)*. [skill](skills/ssh-session-stats/SKILL.md)

## SFTP reads (`group:sftp-read`)

All paths canonicalized via remote `realpath -m` and verified inside `path_allowlist`; rejected by `restricted_paths`.

- **`ssh_sftp_list`** — List a directory with offset/limit pagination. Returns `entries[]` + `has_more`. Inputs: `host`, `path`, `offset` (0), `limit` (200). [skill](skills/ssh-sftp-list/SKILL.md)
- **`ssh_sftp_stat`** — File/dir metadata (kind, size, mode, mtime, owner, group, symlink target). Inputs: `host`, `path`. [skill](skills/ssh-sftp-stat/SKILL.md)
- **`ssh_sftp_download`** — Download a remote file. Size-capped at `SSH_EDIT_MAX_FILE_BYTES`; content base64-encoded. Inputs: `host`, `path`. [skill](skills/ssh-sftp-download/SKILL.md)
- **`ssh_find`** — `find <path> -maxdepth N -type T -name PATTERN`. Pattern regex-validated, results capped at `SSH_FIND_MAX_RESULTS`. Inputs: `host`, `root`, `name_pattern`, `kind` (`file`/`dir`/`symlink`/`any`), `max_depth`. [skill](skills/ssh-find/SKILL.md)
- **`ssh_file_hash`** — MD5 / SHA1 / SHA256 / SHA512 of a remote file. POSIX: `<algo>sum`. Windows: `Get-FileHash`. Returns lowercase hex digest + byte size. Use after `ssh_upload` / `ssh_deploy` / `ssh_docker_cp` to verify the transfer landed intact; MD5/SHA1 included for legacy checksums but NOT collision-resistant. Inputs: `host`, `path`, `algorithm` (default `sha256`). [skill](skills/ssh-file-hash/SKILL.md)

## Docker (read) (`group:docker`)

- **`ssh_docker_ps`** — List containers. `Labels` field stripped by default to protect LLM context (set `include_labels=True` to keep). Inputs: `host`, `all_` (False), `include_labels` (False). [skill](skills/ssh-docker-ps/SKILL.md)
- **`ssh_docker_logs`** — Container logs with aggressive context guards: `tail` default 50 (max 10000), `max_bytes` default 64 KiB (range 1 KiB..10 MiB). Inputs: `host`, `container`, `tail`, `since`, `timestamps`, `max_bytes`. [skill](skills/ssh-docker-logs/SKILL.md)
- **`ssh_docker_inspect`** — Inspect a docker object (`container`/`image`/`network`/`volume`). Inputs: `host`, `target`, `kind`. [skill](skills/ssh-docker-inspect/SKILL.md)
- **`ssh_docker_stats`** — One-shot resource snapshot via `docker stats --no-stream`. Inputs: `host`. [skill](skills/ssh-docker-stats/SKILL.md)
- **`ssh_docker_top`** — Process list inside a container (`docker top`). Plain `ps`-style text in `stdout` (no JSON format at the docker level). `ps_options` accepts extra argv (`-eo pid,user,comm`); shell metacharacters rejected. Inputs: `host`, `container`, `ps_options`. [skill](skills/ssh-docker-top/SKILL.md)
- **`ssh_docker_events`** — Daemon event stream over a bounded time window (`docker events --since <since> --until <until> --format '{{json .}}'`). Answers "what just happened?" in one call: OOM kills, restarts, health transitions, image pulls. `since` / `until` accept relative (`10m`), epoch, RFC3339, or `now`; `filters` = `["container=nginx", "event=die"]`. Inputs: `host`, `since` (default `"10m"`), `until` (default `"now"`), `filters`. [skill](skills/ssh-docker-events/SKILL.md)
- **`ssh_docker_volumes`** — List volumes (`docker volume ls --format '{{json .}}'`) or inspect one by name (`docker volume inspect -- <name>`). Use before any `ssh_docker_prune(scope="volume")` decision — named volumes often carry application state. Inputs: `host`, `name` (optional; None = list, set = inspect). [skill](skills/ssh-docker-volumes/SKILL.md)
- **`ssh_docker_images`** — List local images. `Labels` stripped by default. Inputs: `host`, `include_labels` (False). [skill](skills/ssh-docker-images/SKILL.md)
- **`ssh_docker_compose_ps`** — List compose-project services. `Labels` stripped by default. `compose_file` path-allowlist-checked. Inputs: `host`, `compose_file`, `include_labels` (False). [skill](skills/ssh-docker-compose-ps/SKILL.md)
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

## Persistent shell (read) (`group:shell`)

- **`ssh_shell_list`** — List open persistent sessions with cwd + idle age. Inputs: *(none)*. [skill](skills/ssh-shell-list/SKILL.md)

---

# Low-access tier (`ALLOW_LOW_ACCESS_TOOLS=true`)

SFTP-mediated mutations + bounded docker container lifecycle. Path-bearing tools route every path through `canonicalize_and_check`. Never invoke arbitrary shell.

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
- **`ssh_upload`** — Atomic upload (`<path>.ssh-mcp-tmp.<hex>` + `posix_rename`). Payload base64-encoded, capped at `SSH_UPLOAD_MAX_FILE_BYTES`. Inputs: `host`, `path`, `content_base64`, `mode` (octal). [skill](skills/ssh-upload/SKILL.md)
- **`ssh_edit`** — Structured edit: replace `old_string` with `new_string` atomically. `mode="single"` (default) errors on duplicate or missing match; `mode="all"` replaces every occurrence. Inputs: `host`, `path`, `old_string`, `new_string`, `mode`. [skill](skills/ssh-edit/SKILL.md)
- **`ssh_patch`** — Apply a unified diff atomically. Rejects on context or removal mismatch (no fuzzy fallback). Inputs: `host`, `path`, `unified_diff`. [skill](skills/ssh-patch/SKILL.md)
- **`ssh_deploy`** — Atomic upload with optional pre-deploy backup. If `backup=True` and the file exists, `posix_rename` to `<path>.bak-<UTC-iso8601>` before writing. Inputs: `host`, `path`, `content_base64`, `mode`, `backup` (True). [skill](skills/ssh-deploy/SKILL.md)

## Docker (lifecycle) (`group:docker`)

Container start/stop/restart and the parallel compose subcommands. Container names are regex-validated; compose file paths go through `canonicalize_and_check`.

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

- **`ssh_sudo_exec`** — Run a command under `sudo -S -p '' --`. Allowlist-checked like `ssh_exec_run`. Password piped over stdin, never appears in argv. Inputs: `host`, `command`, `timeout`. [skill](skills/ssh-sudo-exec/SKILL.md)
- **`ssh_sudo_run_script`** — Run a multi-line script under `sudo -S sh -s --`. Body on stdin after the password line; no allowlist check (same rationale as `ssh_exec_script`). Inputs: `host`, `script`, `timeout`. [skill](skills/ssh-sudo-run-script/SKILL.md)

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
| **Audit log** | `ssh_mcp.audit` logger | One JSON line per dangerous / low-access / sudo call. Paths + commands SHA-256 hashed; `error` field is exception class only ([INC-008](INCIDENTS.md)). |
| **Hooks** | `SSH_HOOKS_MODULE` | Operator-supplied module exposing `register_hooks(registry)`. Events: STARTUP / SHUTDOWN / PRE_TOOL_CALL / POST_TOOL_CALL. Side-effect only. |
| **BM25 search** | `SSH_ENABLE_BM25` | Replace tools/list with `search_tools` + `call_tool` for large catalogs ([ADR-0020](DECISIONS.md)). |
| **Output caps** | `SSH_STDOUT_CAP_BYTES` / `SSH_STDERR_CAP_BYTES` (1 MiB) | Truncate at the cap; `*_truncated` flag flips true. Docker logs default to a tighter 64 KiB. |
| **TTY hint** | `ExecResult.hint` | Populated when stderr matches `is not a tty` etc. — suggests batch flags ([ADR-0022](DECISIONS.md)). |

---

For environment-variable docs see [.env.example](.env.example). For per-tool runbooks see [skills/](skills/).
