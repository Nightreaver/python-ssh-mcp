---
description: Diagnose and operate systemd services via SSH
---

# SSH Systemd Diagnostics

Safe-tier read tools for inspecting systemd services without root access, plus
dedicated mutation tools for lifecycle operations that require root.

All tools in Section 1 carry `tags={"safe", "read", "group:systemctl"}` and
work without any `ALLOW_*` flag. Lifecycle operations in Section 3 are
dangerous-tier wrappers (`ssh_systemctl_start` / `_stop` / `_restart` /
`_reload` / `_enable` / `_disable` / `_mask` / `_unmask` / `_reset_failed`)
that require `ALLOW_DANGEROUS_TOOLS=true` and root on the target (use a
sudoers-enabled SSH account or `ssh_sudo_exec` for the rare `daemon-reload`
case that has no dedicated wrapper).

## Default-on cheatsheet rejection (since v1.9.0)

`ssh_exec_run` refuses commands that have a native MCP tool -- see
`skills/ssh-exec-run/SKILL.md`. The native-tool flow below avoids
that. Composite scripts (where the script IS the artefact) opt out
via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` at the operator level.

---

## 1. Tools

### `ssh_systemctl_status`

Full status output for one unit, equivalent to `systemctl status <unit>
--no-pager`. Returns `{stdout, exit_code, active_state}` where `active_state`
is parsed from the `Active:` line. Exit code 3 (inactive/dead) is data, not
an error.

```python
ssh_systemctl_status(host="web01", unit="nginx.service")
```

### `ssh_systemctl_is_active`

Checks whether a unit is active. Returns `{state}` which is one of
`active | inactive | failed | activating | deactivating | reloading | unknown`.

```python
ssh_systemctl_is_active(host="web01", unit="nginx.service")
```

### `ssh_systemctl_is_enabled`

Checks the unit's enablement state. Returns `{state}` which is one of
`enabled | disabled | masked | static | indirect | linked | generated |
transient | bad | not-found | unknown` (and their `-runtime` variants).

```python
ssh_systemctl_is_enabled(host="web01", unit="nginx.service")
```

### `ssh_systemctl_is_failed`

Checks whether a unit is in a `failed` state. Returns `{failed, state,
exit_code}`. `failed=True` when the unit IS in a failed state (exit code 0
from `systemctl is-failed`).

```python
ssh_systemctl_is_failed(host="web01", unit="nginx.service")
```

### `ssh_systemctl_list_units`

Lists loaded units, optionally filtered by glob pattern, state, or unit type.
Parsed into `{units: [{unit, load, active, sub, description}, ...]}`.

```python
# All running services
ssh_systemctl_list_units(host="web01", state="running")

# Failed units of any type
ssh_systemctl_list_units(host="web01", state="failed", unit_type="service")

# Units matching a glob
ssh_systemctl_list_units(host="web01", pattern="nginx*")
```

### `ssh_systemctl_show`

Returns machine-readable properties for a unit as `{properties: dict[str,
str]}`. Use `properties=` to limit output to specific keys.

```python
# All properties
ssh_systemctl_show(host="web01", unit="nginx.service")

# Targeted diagnostic properties
ssh_systemctl_show(
    host="web01",
    unit="nginx.service",
    properties=["ActiveState", "ExecMainStatus", "Result", "NRestarts"],
)
```

### `ssh_systemctl_cat`

Returns the full unit file content (including drop-in overrides) as raw
stdout. Equivalent to `systemctl cat <unit>`.

```python
ssh_systemctl_cat(host="web01", unit="nginx.service")
```

### `ssh_journalctl`

Returns recent journal entries for a unit. Defaults to the last 200 lines.
Hard cap at 1000 lines per call; use `since=` to narrow instead of raising
the line count.

```python
# Last 200 lines (default)
ssh_journalctl(host="web01", unit="nginx.service")

# Last 15 minutes with a keyword filter
ssh_journalctl(host="web01", unit="nginx.service", since="15m", grep="error")

# Time-bounded window
ssh_journalctl(
    host="web01",
    unit="nginx.service",
    since="2026-04-16T10:00:00Z",
    until="2026-04-16T10:30:00Z",
    lines=500,
)
```

---

## 2. Common diagnostic flow

### Service failing or restarting unexpectedly

1. **Quick state check** - determine current state and failure history:

   ```python
   ssh_systemctl_is_active(host="web01", unit="nginx.service")
   ssh_systemctl_is_failed(host="web01", unit="nginx.service")
   ```

2. **Full status** - human-readable summary with recent journal tail:

   ```python
   ssh_systemctl_status(host="web01", unit="nginx.service")
   ```

3. **Machine-readable failure details** - get exit status, result code,
   and restart count:

   ```python
   ssh_systemctl_show(
       host="web01",
       unit="nginx.service",
       properties=["ExecMainStatus", "Result", "NRestarts", "ActiveEnterTimestamp"],
   )
   ```

   Key properties to look at:
   - `Result`: `success | exit-code | signal | core-dump | watchdog | start-limit-hit`
   - `ExecMainStatus`: the process exit code (if `Result=exit-code`)
   - `NRestarts`: how many times systemd has restarted this unit

4. **Recent logs** - fetch the last 15 minutes, optionally filter for errors:

   ```python
   ssh_journalctl(host="web01", unit="nginx.service", since="15m", grep="error")
   ```

5. **Check the unit file** - verify the configuration is what you expect:

   ```python
   ssh_systemctl_cat(host="web01", unit="nginx.service")
   ```

### Finding all failed services

```python
ssh_systemctl_list_units(host="web01", state="failed")
```

Then for each failed unit, loop through steps 2-4 above.

### Checking enablement before a reboot

```python
ssh_systemctl_is_enabled(host="web01", unit="nginx.service")
```

A unit that is `active` but `disabled` will not survive a reboot. Enable it
with `ssh_sudo_exec` (see Section 3).

---

## 3. Lifecycle ops via dedicated `ssh_systemctl_*` mutation tools

Lifecycle mutations have dedicated dangerous-tier wrappers. They require
`ALLOW_DANGEROUS_TOOLS=true` on the server. Each tool needs root on the
target -- use a sudoers-enabled SSH account, polkit, or `ssh_sudo_exec`
for the rare `daemon-reload` case that has no dedicated wrapper.

Each wrapper returns a structured `SystemctlUnitActionResult` (host, unit,
action, exit_code, stdout, stderr, duration_ms, output_warnings) instead of
the raw `ExecResult` you'd get from `ssh_exec_run`. Routing through these
tools also keeps the audit trail named after the action (`ssh_systemctl_restart`)
rather than a generic `ssh_exec_run` line.

### Start a unit

```python
ssh_systemctl_start(host="web01", unit="nginx.service")
```

### Stop a unit

```python
ssh_systemctl_stop(host="web01", unit="nginx.service")
```

### Restart a unit

```python
ssh_systemctl_restart(host="web01", unit="nginx.service")
```

### Reload (without full restart - requires ExecReload= in unit file)

```python
ssh_systemctl_reload(host="web01", unit="nginx.service")
```

### Enable a unit (survive reboot)

```python
ssh_systemctl_enable(host="web01", unit="nginx.service")
```

### Disable a unit

```python
ssh_systemctl_disable(host="web01", unit="nginx.service")
```

### Mask / unmask a unit

```python
ssh_systemctl_mask(host="web01", unit="nginx.service")
ssh_systemctl_unmask(host="web01", unit="nginx.service")
```

### Clear a failed-unit state

```python
ssh_systemctl_reset_failed(host="web01", unit="nginx.service")
```

### daemon-reload (required after unit file changes)

There is no dedicated wrapper for `daemon-reload` -- it is a daemon-wide
verb, not a per-unit action. Use `ssh_sudo_exec` (or root SSH) for it.
Run this before starting or restarting a unit whose file you just changed
via `ssh_upload` / `ssh_edit`:

```python
ssh_sudo_exec(host="web01", command="systemctl daemon-reload")
```

(`systemctl daemon-reload` does NOT trigger the cheatsheet rejection --
the matcher only covers per-unit verbs.)

### Combined: deploy + reload

```python
import base64

unit_bytes = open("myapp.service", "rb").read()

# 1. Upload the changed unit file (low-access tier).
#    Path must be in the host's path_allowlist.
ssh_upload(
    host="web01",
    path="/etc/systemd/system/myapp.service",
    content_base64=base64.b64encode(unit_bytes).decode("ascii"),
)

# 2. Reload the daemon to pick up the new file
ssh_sudo_exec(host="web01", command="systemctl daemon-reload")

# 3. Restart the service
ssh_systemctl_restart(host="web01", unit="myapp.service")

# 4. Verify it came up healthy
ssh_systemctl_is_active(host="web01", unit="myapp.service")
ssh_journalctl(host="web01", unit="myapp.service", since="1m")
```

---

## 4. Caveats

### Journal access permissions

`journalctl -u <unit>` (which backs `ssh_journalctl`) reads from the systemd
journal binary files. The SSH user must be a member of the `systemd-journal`
group (read-only access) or the `adm` group (broader log access), or be
running as root.

If `exit_code` is non-zero and `stderr` says `Permission denied` or
`No journal files were found`, the SSH user lacks the required group
membership. Add the user to `systemd-journal`:

```bash
usermod -aG systemd-journal <ssh-user>
```

Then re-connect (group membership changes only take effect on new logins).

### User units (`--user` scope)

`systemctl --user` operates on the per-user instance of systemd (session
scope). The dedicated tools in this runbook always target the system
instance. To inspect user units, use the generic `ssh_exec_run` (dangerous
tier). This call matches the `systemctl status` cheatsheet pattern; the
operator must enable `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` because
there is no `--user`-scoped wrapper:

```python
ssh_exec_run(
    host="web01",
    command="systemctl --user status myapp.service",
)
```

### Windows targets

None of these tools work on Windows targets. systemd is Linux-only.
The tools will call `resolve_host` which returns a `HostPolicy`; if the
policy sets `platform=windows`, the underlying `_run_systemctl` call will
reach the remote and simply fail because `systemctl` does not exist.
There is no explicit platform gate in the safe-tier systemctl tools
(unlike docker tools which call `require_posix`). This is intentional:
the failure mode is a clean non-zero exit with a clear stderr message,
which is less confusing than a local `PlatformNotSupported` exception
when the operator is exploring whether a host is Linux or not.

### Systemd version compatibility

`ssh_systemctl_list_units` uses simple text column parsing and makes no
assumptions about systemd version. The column order (`UNIT LOAD ACTIVE SUB
DESCRIPTION`) has been stable since systemd v32 (released 2013) and is
safe to parse on any modern distribution.

---

## Related runbooks

- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) - broad host
  health check including disk, load, and process visibility.
- [ssh-incident-response](../ssh-incident-response/SKILL.md) - host
  unreachable or SSH handshake failing.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  - incident response when the failing service is a Docker workload.
