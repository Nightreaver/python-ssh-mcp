# Configuration

How to configure Python SSH MCP beyond the single-host walkthrough in the [README](README.md): multi-host setups, access tiers, allowlists, tool groups, Docker, per-host SSH identity, `known_hosts`, sudo.

For getting started, see the [README](README.md). For runbooks, hooks, observability, testing, and architecture, see [ADVANCED.md](ADVANCED.md).

## Contents

- [Configuring more hosts](#configuring-more-hosts)
- [Tiers vs groups — two knobs, different jobs](#tiers-vs-groups--two-knobs-different-jobs)
- [Access tiers](#access-tiers)
- [Allowlist + blocklist](#allowlist--blocklist)
- [Tool groups (context-size knob)](#tool-groups-context-size-knob)
- [Per-tool reference → TOOLS.md](TOOLS.md)
- [Per-host SSH identity](#per-host-ssh-identity)
- [`known_hosts` management](#known_hosts-management)
- [Sudo](#sudo)

---

## Configuring more hosts

`hosts.toml` supports unlimited `[hosts.<alias>]` blocks. Every entry can override anything from `[defaults]`. Common recipes:

### Bastion + many targets

```toml
[hosts.bastion]
hostname = "bastion.example.com"
user = "jumpuser"

[hosts.db01]
hostname = "db01.internal"
user = "dbadmin"
proxy_jump = "bastion"              # routes through hosts.bastion automatically
path_allowlist = ["/var/lib/postgresql/backups", "/etc/postgresql"]

[hosts.web01]
hostname = "web01.internal"
proxy_jump = "bastion"
path_allowlist = ["/var/www", "/etc/nginx"]
```

Chained bastions: `proxy_jump = ["bastion1", "bastion2"]`. Cycles rejected at startup.

### Different keys per role

```toml
[hosts.ops-box.auth]
method = "agent"
identity_fingerprint = "SHA256:ops-key-fingerprint"
identities_only = true

[hosts.db01.auth]
method = "agent"
identity_fingerprint = "SHA256:db-key-fingerprint"
identities_only = true
```

Now only the ops key is offered when connecting to `ops-box`, and only the db key is offered when connecting to `db01`. Prevents leaking your full identity set to every server you touch, and avoids OpenSSH's 6-auth-attempt cap.

### Legacy host without an agent

```toml
[hosts.legacy.auth]
method = "key"
key = "~/.ssh/id_legacy_rsa"
passphrase_cmd = "security find-generic-password -s ssh-legacy -w"   # macOS keychain
# Or: passphrase_cmd = "pass show ssh/legacy"                        # Unix `pass`
# Or: passphrase_cmd = "bw get password legacy-ssh"                  # Bitwarden CLI
```

**Never put passphrases or passwords literally in `hosts.toml`.** The loader will refuse password auth unless `ALLOW_PASSWORD_AUTH=true` is set (and even then, only via `password_cmd`).

### Recipe summary

| Scenario | What to put in `hosts.toml` |
|---|---|
| Single dev box, shared agent | one `[hosts.*]`, no `[defaults.auth]` |
| Bastion + N targets | `[hosts.bastion]` + each target has `proxy_jump = "bastion"` |
| Separate keys for separate roles | per-host `[hosts.<name>.auth]` with its own `identity_fingerprint` |
| Legacy box, on-disk key | `method = "key"` + `passphrase_cmd` from a keychain helper |
| Scoped Pageant / YubiKey-agent | per-host `identity_agent = "/path/to/scoped-agent.sock"` |

### Resolution precedence (highest → lowest)

1. Explicit tool argument (`host="..."` on a tool call)
2. Per-host `[hosts.<alias>.auth]`
3. Per-host top-level fields
4. `[defaults.auth]` + `[defaults]`
5. Env var (`SSH_DEFAULT_USER`, `SSH_DEFAULT_KEY`, etc.)
6. Built-in defaults

---

## Tiers vs groups — two knobs, different jobs

Two independent filters decide whether a given tool is visible to the LLM. Both must pass:

| Knob | Purpose | Default | Spellings |
|---|---|---|---|
| **Tier flag** (`ALLOW_LOW_ACCESS_TOOLS`, `ALLOW_DANGEROUS_TOOLS`, `ALLOW_SUDO`) | **Security gate.** Caps what the deployment is *permitted* to do. Fail-closed. | all `false` | env vars only |
| **Group filter** (`SSH_ENABLED_GROUPS`) | **Context-size / UX.** Trims what the LLM *sees* in its catalog. | empty = all visible | env var only |

The decision tree:

- **Do I want to make a capability impossible on this deployment?** → flip a **tier flag** off. No other knob can undo it (path allowlists, per-host config, LLM prompts — none of it overrides a closed tier).
- **Do I just want to hide some tools from the catalog to save context or focus the LLM?** → trim **`SSH_ENABLED_GROUPS`**. Doesn't change what's *possible* — just what's *offered*.

Example: you want a deployment that can read hosts and edit config files but **cannot** ever run arbitrary shell. Set `ALLOW_LOW_ACCESS_TOOLS=true`, keep `ALLOW_DANGEROUS_TOOLS=false`. No group knob would give you this — groups can only hide already-enabled tools.

Example: you enabled everything for your own use but want a tighter "diagnostics only" deployment sharing the same codebase. Leave the tiers as-is, set `SSH_ENABLED_GROUPS=host,session,sftp-read`. You still *could* call exec tools via a different client, but this catalog doesn't advertise them.

---

## Access tiers

Three independent env flags, all **default-deny**. These are the security gates referenced in the previous section:

| Flag | Unlocks |
|---|---|
| *(always on)* | Read-only tools: probes, SFTP reads, `find` |
| `ALLOW_LOW_ACCESS_TOOLS=true` | SFTP-mediated file mutation: `cp`, `mv`, `mkdir`, `delete`, `delete_folder`, `edit`, `patch`, `upload` |
| `ALLOW_DANGEROUS_TOOLS=true` | Arbitrary command execution. See also `ALLOW_ANY_COMMAND` below. |
| `ALLOW_SUDO=true` | Privileged execution (`sudo_exec`, `sudo_run_script`). Requires `ALLOW_DANGEROUS_TOOLS=true` too, since sudo tools carry both tags. |

Pick the narrowest tier for each deployment. A "diagnostics assistant" should stay read-only. A "config management assistant" gets low-access but not exec. Full-power access stays behind a separate deployment or a human operator.

**Tiers are the hard gate.** A tool hidden by a closed tier flag is invisible to the LLM no matter what `SSH_ENABLED_GROUPS` says. This is on purpose: a group filter is a UX affordance, not a security control.

**Path confinement applies to reads too.** `ssh_sftp_list`, `ssh_sftp_stat`, `ssh_sftp_download`, and `ssh_find` all canonicalize their `path` on the remote (following symlinks) and reject anything outside the per-host `path_allowlist` union-ed with `SSH_PATH_ALLOWLIST`. "Read-only" here means "no mutation" — not "no scope" (ADR-0017).

**Exec is fail-closed on command allowlist.** If `ALLOW_DANGEROUS_TOOLS=true` but neither `command_allowlist` (per host) nor `SSH_COMMAND_ALLOWLIST` (env) is set, every exec call is rejected as `CommandNotAllowed`. To permit arbitrary commands, set `ALLOW_ANY_COMMAND=true` explicitly (ADR-0018). This prevents the common misconfiguration where an operator reads "empty allowlist" as "nothing permitted" and then ships a server that actually permits everything.

**Command allowlist entries: bare = `$PATH`-style, absolute = exact match.** `["systemctl"]` matches `systemctl ARGS` **and** `/usr/bin/systemctl ARGS` **and** `/opt/custom/systemctl ARGS` (any binary of that name in any location). `["/usr/bin/systemctl"]` matches **only** `/usr/bin/systemctl ARGS` — it will reject `/opt/rogue/systemctl` on the same host. Use absolute paths when you care about shadow-binary risk.

**Allow/block evaluate on the canonical hostname.** `hosts.<alias>` in `hosts.toml` is a lookup key only — it resolves to `policy.hostname`, and `SSH_HOSTS_ALLOWLIST` / `SSH_HOSTS_BLOCKLIST` are matched against that hostname. To block a target, put its hostname in the blocklist, not its alias (ADR-0019).

---

## Allowlist + blocklist

```bash
# .env
SSH_HOSTS_ALLOWLIST=web01,db01,bastion        # union with hosts.toml keys
SSH_HOSTS_BLOCKLIST=prod-payments,prod-vault  # deny wins over allow
SSH_PATH_ALLOWLIST=/opt/app,/var/log          # unions with per-host path_allowlist
```

Both comma-separated strings and JSON arrays work (`["a","b"]`). Exact hostname matching only — globs/regex are out of scope ([ADR-0015](DECISIONS.md#L155)).

The blocklist runs **before** the allowlist. A host on the blocklist can never be reached, even if it's also allowlisted or defined in `hosts.toml`. Use this for "never touch production" safety rails.

### Restricted paths (carve-out inside the allowlist)

For hosts where you want broad low-access — cp, mv, edit, etc. — **except**
for specific paths (SMB-mounted shared data, backup volumes, anything you
don't want the LLM touching):

```toml
[hosts.docker1]
path_allowlist = ["*"]                                # full host access for low-access tier
restricted_paths = ["/mnt/smb-shared", "/mnt/backups"] # ... but NOT these
```

Env-level equivalent (unions with per-host):

```bash
SSH_RESTRICTED_PATHS=/mnt/fleet-shared
```

> **Defense-in-depth hint.** When `path_allowlist=["*"]` (or `["/"]`) and
> neither per-host `restricted_paths` nor `SSH_RESTRICTED_PATHS` covers
> `/etc/shadow`, `/etc/sudoers`, or `/etc/ssh`, startup logs a WARNING
> reminding you. Reads of those paths via low-access / sftp-read tools
> would otherwise expose hashed passwords, sudoer rules, or sshd config.
> The hint is a reminder, not a hard block.

Semantics:

- **low-access tools** (cp, mv, mkdir, delete, edit, patch, upload, deploy)
  refuse any source or destination path inside a restricted zone.
- **sftp-read tools** (list, stat, download, find) also refuse — reads of
  shared data can exfiltrate just as easily as writes can corrupt.
- **exec/sudo tools** are unaffected. They don't go through path policy;
  operators who truly need to touch a restricted path shell out to
  `ssh_exec_run` / `ssh_sudo_exec` with the usual exec-tier guards
  (command allowlist + `ALLOW_DANGEROUS_TOOLS`).

Error looks like:

```text
PathRestricted: path '/mnt/shared/customers.csv' is inside restricted zone
'/mnt/shared'; low-access and sftp-read tools refuse restricted paths.
Use ssh_exec_run / ssh_sudo_exec (requires ALLOW_DANGEROUS_TOOLS) if you
really need to touch this path.
```

**How enforcement works.** The check runs on the **canonical** path — `realpath -m` on the remote (SFTP `realpath` on Windows targets) resolves symlinks before the comparison, so a symlink inside the allowlist pointing into a restricted zone still rejects. On two-path operations (`ssh_cp`, `ssh_mv`, `ssh_docker_cp`) **both source and destination** are checked — you can't read *out* of a restricted zone either, not just write into one. When a path is rejected the tool raises `PathRestricted` before any remote I/O: nothing is created, read, or spawned on the target. The audit log records one line with `error="PathRestricted"`; the full message stays at DEBUG locally.

### Windows SSH targets

Set `platform = "windows"` on the host entry to enable Windows-target support.

```toml
[hosts.winbox]
hostname = "10.0.0.42"
user = "Administrator"
platform = "windows"
path_allowlist = ["C:\\opt\\app", "C:\\inetpub\\wwwroot"]
# or forward slashes; both are accepted and compared case-insensitively
```

**What works on Windows targets:**

- SFTP-based file ops: `ssh_mkdir`, `ssh_delete`, `ssh_delete_folder` (recursive via SFTP walk), `ssh_upload`, `ssh_edit`, `ssh_patch`, `ssh_deploy`, `ssh_mv` (SFTP rename only; no `mv` fallback on Windows). Note: `ssh_cp` is POSIX-only (uses `cp -a`) and refuses Windows targets.
- SFTP reads: `ssh_sftp_list`, `ssh_sftp_stat`, `ssh_sftp_download`
- `ssh_find` — backed by an SFTP-walk implementation (fnmatch `*.log` style patterns). Slower than POSIX `find` on big trees
- `ssh_host_ping`, `ssh_known_hosts_verify` — pure SSH handshake
- `ssh_session_*`, `ssh_shell_list`/`_close` — in-memory only

**What does NOT work (refused with `PlatformNotSupported`):**

- `ssh_host_info` / `_disk_usage` / `_processes` / `_alerts` — parse POSIX-only outputs (`uname`, `/etc/os-release`, `df`, `ps`, `/proc/*`)
- `ssh_exec_run` / `_script` / `_streaming` — POSIX `sh` wrapper
- `ssh_sudo_exec` / `_run_script` — no `sudo` on Windows
- `ssh_shell_open` / `_exec` — cwd sentinel relies on POSIX shell
- `ssh_docker_*` — out of scope for now
- `ssh_cp` — uses `cp -a` (use `ssh_sftp_download` + `ssh_upload` as an alternative)

**Path allowlist semantics on Windows:**

- Entries accepted in either form: `C:\\opt\\app` or `C:/opt/app`
- Matching is case-insensitive and separator-agnostic — `C:\opt\app` matches canonical `c:/opt/app/file.txt`
- Must be absolute with a drive letter (relative paths rejected at load time)
- UNC paths (`\\server\share`) accepted but untested; treat as experimental

**Path canonicalization:**

- Uses SFTP `realpath` extension (protocol-level, no remote binary needed)
- For non-existing paths (upload / mkdir targets), falls back to python-side `ntpath.normpath` — resolves `..` but not symlinks. Weaker than POSIX `realpath -m` but acceptable for create-time targets. See [ADR-0023](DECISIONS.md)
- OpenSSH-for-Windows' SFTP subsystem returns `realpath` results in Cygwin form (`C:\Users` comes back as `/C:/Users`); the canonicalizer strips the single leading `/` when the next two chars form a drive prefix, so both native and Cygwin-form inputs land on the same canonical path. UNC paths are left untouched (INC-034)

### "Allow everything" sentinels (path + command)

For dev boxes where you want MCP-side scoping fully open, per-host:

```toml
[hosts.devbox]
hostname = "devbox.internal"
path_allowlist = ["*"]        # or ["/"]  -- same thing, both accepted
command_allowlist = ["*"]     # allows any command
```

Same effect env-wide:

```bash
SSH_PATH_ALLOWLIST=/            # "/" and "*" both short-circuit to allow-all
ALLOW_ANY_COMMAND=true
```

Both paths log a startup WARNING naming the host, so the widened scope is grep-able in operator logs. Semantics:

| Spelling | Matches |
|---|---|
| `path_allowlist = ["*"]` or `["/"]` | every absolute path the SSH user can reach (OS file perms still apply) |
| `command_allowlist = ["*"]` | every command (symmetric with path) |
| `ALLOW_ANY_COMMAND=true` (env) | equivalent of `command_allowlist = ["*"]` but applied to any host with no explicit allowlist — broader blast radius |

> **`restricted_paths` still applies.** `*` / `/` widens the allowlist, it does not disable the deny-list. Per-host `restricted_paths` and `SSH_RESTRICTED_PATHS` continue to carve out sensitive zones (`/etc/shadow`, backup volumes, etc.) — see the [Restricted paths](#restricted-paths-carve-out-inside-the-allowlist) section above. The deny-list is the right place to keep "yes to everything *except*" semantics even on dev boxes.

Use the per-host sentinel on a single dev box; use the env flag only on a deployment that is intentionally unrestricted. Both surface the WARNING.

---

## Tool groups (context-size knob)

Independent from tiers. Every tool carries a `group:*` tag; the `SSH_ENABLED_GROUPS` env var filters which groups appear in the LLM's catalog. Empty = all groups visible (subject to tier gates — [ADR-0016](DECISIONS.md#L135)).

**Server-wide, not per-host.** `SSH_ENABLED_GROUPS` is applied once at startup as a single `Visibility` transform over the shared tool catalog — there is no `enabled_groups` field in `hosts.toml`. If you need different catalogs for different host sets, run separate server processes with different env.

For a per-tool reference (descriptions, inputs, skill links) see [TOOLS.md](TOOLS.md).

57 tools across 8 groups:

| Group | Count | Tools |
|---|---|---|
| `host` | 6 | `ssh_host_ping`, `ssh_host_info`, `ssh_host_disk_usage`, `ssh_host_processes`, `ssh_host_alerts`, `ssh_known_hosts_verify` |
| `session` | 2 | `ssh_session_list`, `ssh_session_stats` |
| `sftp-read` | 4 | `ssh_sftp_list`, `ssh_sftp_stat`, `ssh_sftp_download`, `ssh_find` |
| `file-ops` | 9 | `ssh_cp`, `ssh_mv`, `ssh_mkdir`, `ssh_delete`, `ssh_delete_folder`, `ssh_edit`, `ssh_patch`, `ssh_upload`, `ssh_deploy` |
| `exec` | 3 | `ssh_exec_run`, `ssh_exec_script`, `ssh_exec_run_streaming` |
| `sudo` | 2 | `ssh_sudo_exec`, `ssh_sudo_run_script` |
| `shell` | 4 | `ssh_shell_open`, `ssh_shell_exec`, `ssh_shell_close`, `ssh_shell_list` |
| `docker` | 26 | `ssh_docker_ps/logs/inspect/stats/top/events/volumes/images/...`, `ssh_docker_cp`, `ssh_docker_compose_up/down/logs/...`, `ssh_docker_exec/run/pull/rm/rmi/prune` |
| `keys` | 0 | *(reserved for future key-management tools)* |

Examples:

```bash
# Diagnostics assistant — smallest catalog, smallest context
SSH_ENABLED_GROUPS=host,session,sftp-read

# Config management assistant — reads + file ops, no shell
ALLOW_LOW_ACCESS_TOOLS=true
SSH_ENABLED_GROUPS=host,session,sftp-read,file-ops

# Docker-only assistant — container lifecycle across a fleet
ALLOW_LOW_ACCESS_TOOLS=true
ALLOW_DANGEROUS_TOOLS=true
SSH_ENABLED_GROUPS=host,session,docker

# Stateful troubleshooting — adds persistent shells on top of a standard dev config
ALLOW_DANGEROUS_TOOLS=true
SSH_ENABLED_GROUPS=host,session,sftp-read,file-ops,exec,shell
```

### Tool discovery via BM25 (optional, for large catalogs)

With every group enabled the LLM sees 50+ tool schemas per `tools/list`
response — roughly 15-25k tokens per turn. If that's eating your context
budget, switch on the BM25 search transform: `tools/list` shrinks to two
synthetic tools (`search_tools(query)` and `call_tool(name, args)`) plus
a small list of pinned anchors. The LLM searches for what it needs.

```bash
SSH_ENABLE_BM25=true
SSH_BM25_MAX_RESULTS=8
SSH_BM25_ALWAYS_VISIBLE=ssh_host_ping,ssh_host_info,ssh_session_list,ssh_shell_list
```

Default OFF — for fewer than ~30 visible tools the catalog fits comfortably
and the extra hop isn't worth it. Tradeoff: the LLM has to know to search.
With descriptive tool names + the pinned anchors that's usually fine.

### Podman hosts (or any Docker-compatible CLI)

Docker CLI name is configurable — default `docker`, switch to `podman` for
rootless Podman boxes or any Docker-compatible replacement. All 22 Docker
tools route through the same argv prefix:

```bash
# Globally (applies to every host without a per-host override):
SSH_DOCKER_CMD=podman
```

```toml
# Per-host, in hosts.toml (wins over SSH_DOCKER_CMD):
[hosts.rocky1]
hostname = "rocky1.internal"
user = "deploy"
docker_cmd = "podman"         # API-compatible; all tools work unchanged
```

`SSH_DOCKER_COMPOSE_CMD` is empty by default and derives from the docker cmd
at runtime — so `SSH_DOCKER_CMD=podman` automatically yields `podman compose`.
Only set it explicitly for legacy standalone binaries
(`docker-compose`, `podman-compose`). Shell-split, so you can wrap:

```bash
SSH_DOCKER_CMD="sudo docker"                # rootful docker via sudo
SSH_DOCKER_COMPOSE_CMD="podman-compose"     # legacy standalone
```

**Caveats on podman targets:**

- `ALLOW_DOCKER_PRIVILEGED` + the escalation deny-list (`--privileged`,
  `--cap-add`, `--network=host`, `--mount source=/`, `container:<id>`
  namespace joins, ...) apply unchanged. All of those flags exist in
  podman too, and they have the same blast radius.
- Rootless podman namespaces are not host namespaces — `--userns=host` means
  "host user" from podman's POV, which is already on the deny-list. If you
  actually *want* rootless-to-rootful, that's a different setup.
- JSON output fields are API-compatible at the `--format '{{json .}}'`
  level. Our parsing is tolerant of missing / renamed fields (e.g. podman
  sometimes emits `Names` as a list where docker emits a comma-joined string);
  result dicts surface what the host returned.

### Docker `--privileged` flags (always rejected by default)

`ssh_docker_run` accepts arbitrary `docker run` flags via `args`. Flags that
grant the container root on the host are **rejected by default** even under
`ALLOW_DANGEROUS_TOOLS=true`. The deny-list covers:

- Capability / security escalation: `--privileged`, `--cap-add`,
  `--security-opt`, `--device`, `--group-add`
- Host-namespace join: `--pid=host`, `--ipc=host`, `--uts=host`,
  `--userns=host`, `--network=host`, `--net=host` (and the two-token form
  `--pid host`, `--network host`, ...)
- Another-container namespace join: `--pid=container:<id>`,
  `--network=container:<id>`, etc. (weaker escape but still an isolation
  break)
- Host-root bind mounts in either flag style:
  - `-v /:/host` / `--volume=/:/host` / `--volume=/`
  - `--mount type=bind,source=/,target=/host` / `--mount=type=bind,source=/,...`
  - Includes `//`, `/./`, trailing-slash variants of the source path.

To permit them:

```bash
ALLOW_DOCKER_PRIVILEGED=true
```

That bypass is explicit and grep-able in audit logs.

### Tool catalog at startup

The lifespan logs a per-tier and per-group summary at INFO level so you
can see at a glance what the LLM will be offered:

```text
INFO ssh_mcp.lifespan tools registered: 52 total, 50 visible (after tier+group filters)
INFO ssh_mcp.lifespan   by tier:  safe=20/20 | low-access=16/16 | dangerous=14/14 | sudo=0/2
INFO ssh_mcp.lifespan   by group: docker=22/22 | exec=3/3 | file-ops=9/9 | host=6/6 | ...
```

Each cell is `visible/registered`. Sudo at `0/2` above means the two
`ssh_sudo_*` tools exist but are hidden because `ALLOW_SUDO=false`.

---

## Per-host SSH identity

Three auth methods, in order of preference:

### `method = "agent"` (default)

```toml
[hosts.db01.auth]
method = "agent"

# Optional: pin one specific identity by fingerprint so only this key is offered.
# Required on hosts with tight `MaxAuthTries` and many loaded keys.
identity_fingerprint = "SHA256:abc123..."
identities_only = true

# Optional: use a scoped agent on a different socket than SSH_AUTH_SOCK.
# Pattern: a short-lived agent unlocked only during the ops window.
identity_agent = "${XDG_RUNTIME_DIR}/ssh-agent-db.sock"
```

### `method = "key"`

```toml
[hosts.legacy.auth]
method = "key"
key = "~/.ssh/id_legacy_rsa"
passphrase_cmd = "pass show ssh/legacy"       # command that prints the passphrase
```

`passphrase_cmd` runs once per connect; output is never cached or logged.

### `method = "password"` (disabled by default)

Only honored if `ALLOW_PASSWORD_AUTH=true`. Even then, the password comes from `password_cmd`, not from a literal in `hosts.toml`.

```toml
[hosts.forced-legacy.auth]
method = "password"
password_cmd = "pass show ssh/legacy-password"
```

### Why pin by fingerprint?

- OpenSSH servers often cap auth attempts at 6. An agent with 10 keys hits `Too many authentication failures` before the right one is tried.
- Every key offered leaks its public half to the server. Compromised or hostile servers then have a map of your identities.
- `identities_only = true` + `identity_fingerprint` offers exactly one key, exactly once.

### Windows + PuTTY Pageant

On Windows, asyncssh talks to Pageant over the classic window-message protocol via `pywin32` (installed automatically). Verify it works:

```bash
uv run pytest tests/test_agent.py::test_live_agent_returns_well_formed_fingerprints -v
```

With Pageant running and at least one key loaded, this returns the live fingerprints. If Pageant is configured for the modern OpenSSH named pipe (`\\.\pipe\openssh-ssh-agent`, Pageant 0.78+), set `identity_agent = "\\\\.\\pipe\\openssh-ssh-agent"` in `hosts.toml`.

### What's rejected, always

- Passphrases in `hosts.toml` (any form)
- Password literals in `hosts.toml` (any form)
- SSH agent forwarding — confused-deputy risk on an MCP server

---

## `known_hosts` management

Strict verification is on by default ([ADR-0008](DECISIONS.md#L70)). The server never auto-trusts a new host from an LLM call. Management flow:

### First-time pinning (human-in-the-loop)

```bash
ssh-keyscan -t ed25519,ecdsa,rsa <hostname> | tee -a ~/.ssh/known_hosts
# Compare fingerprint out-of-band (console access, terraform output, host provisioner)
```

### Verify the current state

The `ssh_known_hosts_verify` tool reports:

```python
ssh_known_hosts_verify(host="web01")
# → {expected_fingerprint, live_fingerprint, matches_known_hosts, error}
```

`matches_known_hosts=true` means asyncssh's built-in verification passed. Anything else is a security event — stop and investigate.

### Host key rotation (server-side)

When a target rotates its host key, you'll get `HostKeyMismatch`:

1. Verify out-of-band that the rotation was intentional.
2. Remove the old line from `known_hosts`.
3. Re-run `ssh-keyscan` to pin the new key.
4. Restart the MCP (or just retry the tool — `known_hosts` is re-read on each connect).

### Alternate `known_hosts` location

```bash
SSH_KNOWN_HOSTS=/etc/ssh-mcp/known_hosts
```

If the file is missing, the server still starts but **every host will report as unknown** until the file exists and contains valid entries.

---

## Sudo

`ssh_sudo_exec` and `ssh_sudo_run_script` wrap commands with
`sudo -S -p '' -- ...` and pipe the sudo password on stdin. Both tools carry
`{dangerous, sudo, group:sudo}` — they require **both** `ALLOW_DANGEROUS_TOOLS=true`
and `ALLOW_SUDO=true` to be visible.

### Password source priority

Resolved per call, never cached:

1. `SSH_SUDO_PASSWORD_CMD` — a local shell command that prints the password
   (e.g. `pass show ops/sudo`, `bw get password ops-sudo`,
   `security find-generic-password -s ops-sudo -w`). Recommended.
2. OS keychain via the `keyring` package (service `ssh-mcp-sudo`, user `default`).
3. Passwordless sudoers entry — the tool uses `sudo -n` and no password is sent.

**`SSH_SUDO_PASSWORD` env var is rejected at startup.** Environment variables
leak via `/proc/self/environ`, child processes, and crash dumps — setting it
while `ALLOW_SUDO=true` makes the lifespan raise `AuthenticationFailed` and
the server refuses to start. Use `SSH_SUDO_PASSWORD_CMD` or keyring instead.

The password is never in argv, process listings, log lines, audit records, or
MCP return payloads. If your command's stdout happens to echo the password
back, that's on the command.

### Recommended deployment

For a host that actually needs to sudo, configure a scoped passwordless entry
on the target instead of shipping a password through the MCP:

```sudoers
# /etc/sudoers.d/ssh-mcp-deploy
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
```

Then the MCP never holds a password at all and `ssh_sudo_exec` falls through
to `sudo -n`.

### Persistent su-shell

`SSH_SUDO_MODE=persistent-su` is designed in DESIGN.md §11 Q1 but **not yet
implemented**. The lifespan logs a WARNING and falls back to per-call. Scoped
passwordless sudoers entries are the preferred alternative; revisit if repeated
sudo prompts become a bottleneck.
