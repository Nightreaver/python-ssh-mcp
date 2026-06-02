# Changelog

All notable changes to **python-ssh-mcp** are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions map 1:1 to annotated git tags on `main`.

## [Unreleased]

## [1.5.2] -- 2026-06-02

### Changed

- Release history extracted into this `CHANGELOG.md` (previously the "shipped milestones" block in `DESIGN.md`). `DESIGN.md` now points here. No behaviour changes.

## [1.5.1] -- 2026-06-01

### Changed

- `ssh_host_notes_set` skill gains a canonical sidecar-structure template: safety-first head sections (CRITICAL, At-a-glance, platform quirks, storage, workloads, access caveats) and an append-only Timeline tail. Marks `_set` as the structural owner and `_append` as the history-only writer so two agents don't fight over the same regions.
- `ssh_host_notes_append` and `ssh_host_notes` skills updated for the same contract.

## [1.5.0] -- 2026-06-01

### Added

- `ssh_server_info` read-tier tool + `mcp://ssh-mcp/server-info` resource. Dual surface (resource as primary discovery path, tool as fallback for clients that don't expose resources to the LLM) sharing one payload shape: `name`, `version`, `total_tools`, `enabled_tiers`, `enabled_groups`. Lives in the `host` group. Not `@audited` -- server-meta, no host touch.

## [1.4.1] -- 2026-06-01

### Changed

- Documentation polish across public docs, source docstrings, and skill files. No behaviour changes.

## [1.4.0] -- 2026-06-01

### Added

- **Secret-redaction policy** (ADR-0027). New service stack: `services/redact_policy.py` (config: key lists, glob lists, bypass policy, salt, entropy detection) + `services/redactor.py` (line-level redaction engine). New tool `ssh_read_redacted` routes through path policy then applies redaction before returning content. Operator knobs: `SSH_REDACT_KEYS_ADD` / `SSH_REDACT_KEYS_REPLACE`, `SSH_REDACT_PATHS_GLOBS`, `SSH_RESTRICTED_GLOBS`, `SSH_REDACT_SALT`, `SSH_REDACT_ENTROPY_DETECTION`, `SSH_REDACT_BYPASS_POLICY`, `SSH_REDACT_HINT_CHARS`. Audit line gains optional `redact_bypass: true` field. HMAC-SHA256 hash markers allow cross-host secret identity comparison without leaking plaintext.
- **Sudo-tier path-bearing tools** + path-aware cheatsheet (ADR-0028). Five new tools (`ssh_sudo_read`, `ssh_sudo_read_redacted`, `ssh_sudo_write`, `ssh_sudo_edit`, `ssh_sudo_sftp_list`) implemented via `services/sudo_file_ops.py`. Each routes through the same `resolve_path` / `resolve_path_for_redacted_read` policy chain as the SFTP-read tier, closing the gap where `ssh_sudo_exec("cat .env")` bypassed `redact_bypass_policy=block`. Path-aware cheatsheet extension: single-path `cat`, `head`, `ls` shapes resolve the path and redirect to the `*_redacted` variant when appropriate. INC-064 documents the residual raw-exec gap (complex shell shapes) as a known limitation.
- `ssh_docker_system_df` read-tier tool. Reports disk consumption by images, containers, volumes, and build cache. Added to the `docker` group.
- **CAS concurrent-writer safety** for `ssh_host_notes_append` (INC-065). Pure optimistic CAS -- no lock. `SidecarSnapshot` captures `(text, mtime_ns, size)` at read time via `read_sidecar_with_snapshot`; `atomic_write_sidecar_if_unchanged` re-stats the file immediately before `os.replace` and returns `False` (no write) if `mtime_ns` or `size` changed since the snapshot. `ssh_host_notes_append` wraps the full build+write in a 5-iteration retry loop; each retry takes a fresh snapshot and rebuilds content against the newer existing text. After 5 contention failures it raises `RuntimeError` instead of spinning unbounded. `ssh_host_notes_set` is deliberately left last-writer-wins; a CAS variant with `expected_etag` is deferred.

## [1.3.0] -- 2026-05-28

### Added

- **Local-disk transfer mode**. `ssh_upload`, `ssh_deploy`, `ssh_sftp_download`, and `ssh_sudo_write` gain an optional `local_path=` argument. The MCP server reads/writes a file directly on its own filesystem instead of routing the payload through the MCP JSON channel as base64. New service `services/local_path_policy.py` enforces an operator-configured allowlist (`SSH_LOCAL_TRANSFER_ROOTS`) and byte cap (`SSH_LOCAL_TRANSFER_MAX_BYTES`, default 2 GiB). Mode is fully disabled when the allowlist is empty (the default).

### Changed

- `low_access_tools.py` refactored into a `low_access/` subpackage (`_helpers`, `fs_tools`, `edit_tools`, `link_tools`, `upload_tools`), mirroring the docker subpackage split (INC-043). The top-level `low_access_tools` module is now a thin re-export facade; imports and test monkeypatch points are preserved.

## [1.2.0] -- 2026-05-28

### Added

- **`apt` mutation tier** (`group:pkg`): `ssh_apt_install` / `upgrade` / `remove` / `autoremove` / `mark`, plus read-tier `ssh_apt_show_holds`. Package names validated against the Debian shape in `models.apt` before argv; argv built list-style + `shlex.join`.
- **`systemctl` mutation tier** (`group:systemctl`): `start` / `stop` / `restart` / `reload` / `enable` / `disable` / `mask` / `unmask` / `reset-failed` via one `_run_unit_action` dispatcher with a frozenset verb tripwire. Unit names validated before argv.
- Exec-cheatsheet service: rejects `ssh_exec_run` / `_streaming` / `ssh_sudo_exec` invocations matching a native-tool cheatsheet shape (heredoc, `tee`, `echo > path`, leading `docker`, single `systemctl`/`journalctl`/`apt(-get)`, single `mkdir`/`cp`/`mv`/`rm`, output redirection to a real file). Default-on via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=false`; matches raise `CommandIsCheatsheetMatch` with a hint to the native tool.
- Host runbooks: `host-snapshot`, `long-running-job`, `os-upgrade` plus per-tool SKILLs for every new mutation.

### Changed

- All mutations are `{"dangerous"}`-tagged, `@audited(tier="dangerous")`, and do NOT auto-prepend sudo (matches read-tier convention).
- `_run_systemctl` now returns the resolved hostname so read tools drop a second `resolve_host` round-trip.
- `path_policy`, `pool`, `sudo`, and `errors` modules hardened.
- `snapshots/` added to `.gitignore`.

## [1.1.0] -- 2026-05-16

### Added

- `apt` read-tier tooling (`ssh_apt_list`, `ssh_apt_search`, `ssh_apt_show`) and broadcast / link / transfer surface.
- Host-notes layer (operator-baseline notes in `hosts.toml` + agent-written sidecars).
- Output sanitization across read tools.

## [1.0.0] -- 2026-04-18

### Added

- Initial public release. FastMCP 3 server exposing SSH / SFTP / Docker / systemd operations as MCP tools. Three independent access tiers (read-only always on, low-access via `ALLOW_LOW_ACCESS_TOOLS`, exec via `ALLOW_DANGEROUS_TOOLS`, sudo via `ALLOW_SUDO`). Multi-host via TOML registry. `known_hosts` enforcement, structured audit log, OTel tracing.

[Unreleased]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.5.2...HEAD
[1.5.2]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Nightreaver/python-ssh-mcp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Nightreaver/python-ssh-mcp/releases/tag/v1.0.0
