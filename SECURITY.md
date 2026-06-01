# Security Policy

## Reporting a vulnerability

Email **nightreaver.b@gmail.com** with details. Do **not** open a public GitHub issue for security bugs.

This is a solo-maintained project. I aim to acknowledge reports within 7 days, but cannot guarantee a faster turnaround. Please set realistic expectations on response time.

## Project context

`python-ssh-mcp` is a FastMCP server that grants an LLM real SSH, SFTP, Docker, and systemd access to remote hosts. Permissions are organised into tiers (read-only / low-access / exec / sudo / dangerous-docker), each gated by environment flags and surfaced through FastMCP `Visibility` transforms.

For the full architecture — policy gates, audit logging, connection pool, tool tiers — see [AGENTS.md](./AGENTS.md).

## In scope

High-severity issues include, but are not limited to:

- Bypass of the policy gates: `host_policy`, `path_policy`, `exec_policy`, `redact_policy`, `local_path_policy` (in `src/ssh_mcp/services/`).
- Bypass of the `@audit_log` decorator chain — any tool action that should have been logged but wasn't.
- Command injection via tool parameters: path traversal, shell metacharacter escape, argv splitting flaws.
- Host key verification bypass or `known_hosts` handling flaws.
- Authentication flaws: key handling, agent forwarding, sudo password handling.
- Tier-flag bypass — for example, a dangerous tool callable when `ALLOW_DANGEROUS_TOOLS=0`.
- SFTP path-allowlist escape.
- **Secret-redaction layer (v1.4.1+)**: a path matching the configured `redact_paths_globs` returning unredacted bytes through any tool other than the documented raw-exec path (`ssh_exec_run` / `ssh_sudo_exec` — see "Out of scope" / INC-064). Includes bypass of `redact_bypass_policy=block`, of the `restricted_globs` hard-deny list, of the `SidecarSnapshot` CAS race-protection on `ssh_host_notes_append`, and hash-marker recovery techniques that reveal plaintext from a 12-char HMAC-SHA256 prefix where `SSH_REDACT_SALT` is set to a strong operator value.
- **Sudo-tier path policy enforcement (v1.4.1+)**: the five sudo-tier path-bearing tools (`ssh_sudo_read`, `ssh_sudo_read_redacted`, `ssh_sudo_write`, `ssh_sudo_edit`, `ssh_sudo_sftp_list`) all route through `resolve_path` / `resolve_path_for_redacted_read`. Any sudo-elevated file operation that lands on a path which should have been blocked by `restricted_paths`, `restricted_globs`, or `redact_paths_globs` is in scope.
- **Local-disk transfer allowlist (v1.10.0+)**: `local_path=` on `ssh_upload` / `ssh_deploy` / `ssh_sftp_download` / `ssh_sudo_write` reading or writing outside `SSH_LOCAL_TRANSFER_ROOTS` (including via symlink escape, parent-traversal, or empty-allowlist enablement).

## Out of scope

- Issues that require an attacker to already have full operator access to the MCP server's config, `.env`, or `hosts.toml`. That is the project's trust boundary — once the operator's environment is compromised, all bets are off.
- Known limitations documented in [CONFIGURATION.md](./CONFIGURATION.md), [AGENTS.md](./AGENTS.md), or [INCIDENTS.md](./INCIDENTS.md). In particular: **INC-064** — `ssh_exec_run` / `ssh_sudo_exec` taking a command body (not a path) cannot be policy-checked against `redact_paths_globs`. By-design; mitigation is operator `command_allowlist` discipline (do not allowlist `cat`, `less`, `head`, `tail` if any host has secrets behind a redact glob).
- Denial-of-service via expensive-but-permitted operations (e.g. `ssh_exec_run_streaming` invoked with a pathological command). Use operator-side rate limiting if this is a concern.

## Disclosure policy

Coordinated disclosure preferred. A fix or documented mitigation will land before public detail is published. Credit will be offered unless the reporter requests anonymity.
