---
description: Run the same command on multiple pre-configured hosts in parallel; per-host gated, partial-failure tolerant
---

# `ssh_broadcast`

**Tier:** dangerous | **Group:** `exec` | **Tags:** `{dangerous, group:exec}`

Fan out one command across N hosts, return a structured per-host result.
Each host's command is independently allowlist-checked and platform-gated;
one host's failure does NOT abort the others. Hard cap of 50 hosts per call.

Disabled unless `ALLOW_DANGEROUS_TOOLS=true`. Each host's per-host
`command_allowlist` (or `SSH_COMMAND_ALLOWLIST`) gates its branch
independently -- you can have one host accept the command and another
deny it within the same broadcast call.

## When to call it

- "What kernel runs on `web01..web10`?"
- "Show `systemctl is-active myapp` across the api tier."
- "Tail the last 5 nginx error lines on every edge node."
- Any read-only diagnostic across a known fleet.

## When NOT to call it

- One host -- use `ssh_exec_run` directly. The per-host result wrapper is
  noise for n=1.
- Long-running commands per host -- there is no streaming variant.
  `ssh_exec_run_streaming` covers single-host long jobs.
- Mutations you want serialized -- broadcast runs in parallel; if you
  need "stop on first failure" semantics, sequence the calls yourself.
- Sudo across the fleet -- there is no `ssh_sudo_broadcast` (yet).
  Loop `ssh_sudo_exec` per host if needed.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `hosts` | list[str] | yes | -- | Aliases or hostnames; deduplicated; max 50 |
| `command` | str | yes | -- | Shell command. You own quoting. |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` (60) | Per-host timeout in seconds |

## Returns

```json
{
  "command": "uname -r",
  "results": {
    "web01": {"host": "web01", "exit_code": 0, "stdout": "6.1.0-21-amd64\n", "...": "..."},
    "web02": {"host": "web02", "exit_code": 0, "stdout": "6.1.0-22-amd64\n", "...": "..."}
  },
  "succeeded": ["web01", "web02"],
  "failed": ["web03"],
  "errors": {"web03": "ConnectError"},
  "elapsed_ms": 412
}
```

- `results[alias]` -- full `ExecResult` for every host that produced one
  (the command ran, regardless of exit code). Same shape as
  `ssh_exec_run`'s return.
- `succeeded[alias]` -- exit_code == 0 AND not timed out.
- `failed[alias]` -- everything else: non-zero exit, timed out, or raised.
- `errors[alias]` -- exception class name for hosts that raised before
  producing an `ExecResult` (typically `CommandNotAllowed`,
  `PlatformNotSupported`, `ConnectError`, `AuthenticationFailed`,
  `UnknownHost`, `HostKeyMismatch`).
- `elapsed_ms` -- wall-clock time of the whole broadcast (not the sum of
  per-host times -- they ran in parallel).

## Pre-flight vs per-host failures

`ssh_broadcast` distinguishes two failure modes:

1. **Caller errors** (RAISE -- the whole call aborts):
   - Empty `hosts` list.
   - More than 50 hosts.
   - Any alias that resolves to `HostNotAllowed` or `HostBlocked` -- typos
     and policy denials are caller errors, not transient per-host issues.
     Fix the call rather than digging through `errors`.
2. **Per-host failures** (CAPTURED -- siblings still run):
   - `CommandNotAllowed` -- this host's allowlist denies the command.
   - `PlatformNotSupported` -- this host has `platform = "windows"`.
   - `ConnectError`, `AuthenticationFailed`, `UnknownHost`,
     `HostKeyMismatch` -- transport-layer issues for this host only.
   - Non-zero exit codes and `timed_out=true` -- these are data, the
     command ran. They land in `failed` (with full `ExecResult` in
     `results[alias]`), NOT in `errors`.

## Examples

```python
# Inventory: kernel version across the web tier.
ssh_broadcast(
    hosts=["web01", "web02", "web03"],
    command="uname -r",
)

# Mixed-platform fleet: the Windows host shows up in `errors`.
ssh_broadcast(
    hosts=["api01", "api02", "win01"],
    command="systemctl is-active myapp",
)
# -> errors == {"win01": "PlatformNotSupported"}
#    succeeded == ["api01", "api02"] (assuming both return exit 0)

# Repeated aliases are deduplicated.
ssh_broadcast(hosts=["web01", "web01", "web01"], command="uptime")
# -> one acquire, one ExecResult.
```

## Audit notes

The audit log records `host="?"` for the broadcast call (it's a fan-out;
no single host applies). The `command` is captured + hashed in the audit
line as usual. The `command` field is also echoed into the result body so
the broadcast call is self-describing -- the result IS the durable record
of what was run on whom.

## Common failures

- `ValueError: hosts cannot be empty` -- pass at least one alias.
- `ValueError: hosts list has N entries; max is 50` -- split across calls.
- `ValueError: unknown / blocked hosts in broadcast: ...` -- typo or
  blocklist hit. Check `hosts.toml` and your blocklist env var.
- Per-host `CommandNotAllowed` in `errors` -- that host's `command_allowlist`
  doesn't include the first token of `command`. Either widen the host's
  allowlist or drop it from the broadcast.
- Per-host `PlatformNotSupported` -- the broadcast hit a Windows host;
  drop it from the list or use a Windows-safe command via a different tool.

## Related

- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- single-host equivalent.
- [`ssh_host_list`](../ssh-host-list/SKILL.md) -- enumerate aliases known
  to the server before composing a broadcast.
- [`ssh_exec_run_streaming`](../ssh-exec-run-streaming/SKILL.md) -- single
  host, long-running, with progress.
