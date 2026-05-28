---
description: Copy a file from one remote host to another, transiting through the MCP server (works when A cannot SSH to B)
---

# `ssh_transfer`

**Tier:** low-access | **Group:** `file-ops` | **Tags:** `{low-access, group:file-ops}`

Stream a file from `src_host:src_path` to `dst_host:dst_path` via SFTP
channels on both connections. Neither host needs outbound SSH to the
other -- data transits through the MCP server. This is the whole point:
works in firewalled inter-host topologies where direct A->B SSH is blocked.

Disabled unless `ALLOW_LOW_ACCESS_TOOLS=true`. Both hosts resolve through
the normal policy stack (blocklist, allowlist). Both paths route through
`resolve_path` (which bundles canonicalize + allowlist + restricted-zones)
independently -- src must exist; dst must NOT exist unless `overwrite=True`.

## When to call it

- Copy a build artifact from the build host to a prod host when they
  don't have inter-host SSH trust (bastion topologies, separate VPCs).
- Move a database dump between hosts that only trust the MCP server.
- Relay a file between two hosts the operator already trusts via MCP.

## When NOT to call it

- Same host for source and dest -- use `ssh_cp` (cheaper, no SFTP relay).
- Host-to-host copy where A already has SSH to B (gigabit common) --
  `ssh_exec_run(host=A, command="scp B:dst ...")` via their direct link
  is faster and doesn't bottleneck at the MCP host's uplink.
- Binary larger than `SSH_UPLOAD_MAX_FILE_BYTES` (default 256 MiB) --
  the size check rejects up front.
- You need resumable / checkpointed transfers -- this streams end-to-end
  in one call and has no resume primitive.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `src_host` | str | yes | -- | Alias or hostname of the source |
| `src_path` | str | yes | -- | Absolute path on the source host |
| `dst_host` | str | yes | -- | Alias or hostname of the destination |
| `dst_path` | str | yes | -- | Absolute path on the destination host |
| `overwrite` | bool | no | False | Replace existing dst_path if present |

## Returns

```json
{
  "src_host": "build01.example.com",
  "src_path": "/build/artifacts/app-1.2.tar.gz",
  "dst_host": "prod01.example.com",
  "dst_path": "/opt/app/releases/app-1.2.tar.gz",
  "size": 18874368,
  "duration_ms": 412,
  "throughput_mb_s": 43.67
}
```

`throughput_mb_s` is derived convenience (size / duration). It is
bottlenecked by the slower of (src -> MCP) and (MCP -> dst) hops -- on a
residential MCP machine bridging two cloud hosts, this caps near the
operator's upload bandwidth.

## Atomic write

The destination is written to `<dst_path>.ssh-mcp-tmp.<rand>` and
`posix_rename`-d into place. A crash mid-transfer leaves the temp file
(harmless, gets garbage-collected by ops cleanup); the final path is
never observed partial. Same pattern as `ssh_upload`.

## Throughput note

For inter-host gigabit where A and B already trust each other, an
`scp`/`rsync` invoked via `ssh_exec_run` between the hosts will be faster
than `ssh_transfer` -- no transit through the MCP host. Use `ssh_transfer`
specifically for the firewalled / no-inter-host-SSH case.

## Common failures

- `ValueError: src_host and dst_host are both ...` -- same host; use
  `ssh_cp` instead.
- `ValueError: src file N bytes exceeds SSH_UPLOAD_MAX_FILE_BYTES=...` --
  raise the cap or split the file.
- `ValueError: destination ... already exists` -- pass `overwrite=True`
  or pick a different dst_path.
- `PathNotAllowed` / `PathRestricted` on either side -- the path isn't
  in that host's allowlist, or it's in a restricted zone.
- `ConnectError` / `AuthenticationFailed` -- one of the hosts can't be
  reached; check with `ssh_host_ping`.

## Example

```python
ssh_transfer(
    src_host="build01",
    src_path="/build/artifacts/app-1.2.tar.gz",
    dst_host="prod01",
    dst_path="/opt/app/releases/app-1.2.tar.gz",
)
```

## Related

- [`ssh_cp`](../ssh-cp/SKILL.md) -- single-host file copy (use this for
  same-host transfers).
- [`ssh_upload`](../ssh-upload/SKILL.md) -- upload content from the MCP
  host to a remote; `local_path` mode streams from MCP-host disk without
  base64 (the right choice when the file is already on the MCP host and
  you only need it on one remote, as opposed to two remotes).
- [`ssh_sftp_download`](../ssh-sftp-download/SKILL.md) -- download a
  remote file; `local_path` mode writes it to the MCP host instead of
  returning base64.
