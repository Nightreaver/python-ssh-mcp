---
description: Diagnose and operate systemd services via SSH
---

# SSH Systemd Diagnostics

Safe-tier read tools for inspecting systemd services without root access, plus
`ssh_sudo_exec` examples for lifecycle operations that require root.

All tools in Section 1 carry `tags={"safe", "read", "group:systemctl"}` and
work without any `ALLOW_*` flag. Lifecycle operations in Section 3 require
`ALLOW_SUDO=true` **and** `ALLOW_DANGEROUS_TOOLS=true`.

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

## 3. Lifecycle ops via `ssh_sudo_exec`

Lifecycle mutations require root. Use `ssh_sudo_exec` with both
`ALLOW_SUDO=true` **and** `ALLOW_DANGEROUS_TOOLS=true` set in the server
environment. polkit can relax the root requirement on a per-operation basis
if the operator configures it, but the server-side flags must still be set.

### Start a unit

```python
ssh_sudo_exec(host="web01", command="systemctl start nginx.service")
```

### Stop a unit

```python
ssh_sudo_exec(host="web01", command="systemctl stop nginx.service")
```

### Restart a unit

```python
ssh_sudo_exec(host="web01", command="systemctl restart nginx.service")
```

### Reload (without full restart - requires ExecReload= in unit file)

```python
ssh_sudo_exec(host="web01", command="systemctl reload nginx.service")
```

### Enable a unit (survive reboot)

```python
ssh_sudo_exec(host="web01", command="systemctl enable nginx.service")
```

### Disable a unit

```python
ssh_sudo_exec(host="web01", command="systemctl disable nginx.service")
```

### daemon-reload (required after unit file changes)

Always run this before starting or restarting a unit whose file you just
changed via `ssh_upload` / `ssh_edit`:

```python
ssh_sudo_exec(host="web01", command="systemctl daemon-reload")
```

### Combined: deploy + reload

```python
# 1. Upload the changed unit file (low-access tier)
ssh_upload(host="web01", path="/etc/systemd/system/myapp.service", content_base64=...)

# 2. Reload the daemon to pick up the new file
ssh_sudo_exec(host="web01", command="systemctl daemon-reload")

# 3. Restart the service
ssh_sudo_exec(host="web01", command="systemctl restart myapp.service")

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
tier):

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
