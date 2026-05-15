---
description: Structured /etc/passwd row plus group memberships for one user; no sudo required
---

# `ssh_user_info`

**Tier:** safe | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Query `/etc/passwd` (via `getent`) and group memberships (via `id`) for
one user. Returns a structured record: uid, gid, gecos, home, shell,
primary group, all groups. Read-only, no sudo.

`username=None` (the default) queries the SSH user that this connection
authenticates as -- `id -un` on the remote tells us the effective
identity, which may differ from `policy.user` in `sudo`/agent-forwarding
setups.

POSIX-only. Windows targets raise `PlatformNotSupported`.

## When to call it

- Audit: who is logged in as `deploy@`? What groups does it carry?
- Permission triage: why can `svc-app@` not read `/var/log/myapp`?
  (Check its `primary_group` + `groups`.)
- Onboarding / offboarding: does user `X` exist on host `Y`?

## When NOT to call it

- Enumerate ALL users on the host -- `getent passwd` dumps the full
  list via `ssh_exec_run` if you really need it. This tool returns ONE
  user at a time by design (`username=None` picks current user).
- Check password-aging (`chage -l`) -- that needs root; out of scope
  for the safe tier. Route through `ssh_sudo_exec` if you need it.
- Non-POSIX hosts -- use `net user <name>` on Windows via
  `ssh_exec_run` once `command_allowlist` permits it.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `username` | str | no | current SSH user | Validated against POSIX 3.437; shell metacharacters rejected |

## Returns

`UserInfoResult`:

| field | type | notes |
|---|---|---|
| `host` | `str` | canonical hostname |
| `username` | `str` | resolved username |
| `uid` | `int` | numeric user ID |
| `gid` | `int` | primary group ID |
| `gecos` | `str` | GECOS field (often empty on system accounts) |
| `home` | `str` | home directory |
| `shell` | `str` | login shell |
| `primary_group` | `str` | primary group name |
| `groups` | `list[str]` | all group memberships |
| `output_warnings` | `list[str]` | suspicious pattern warnings (see below) |

```json
{
  "host": "web01.example.com",
  "username": "deploy",
  "uid": 1000,
  "gid": 1000,
  "gecos": "Deployment User",
  "home": "/home/deploy",
  "shell": "/bin/bash",
  "primary_group": "deploy",
  "groups": ["deploy", "docker", "sudo"],
  "output_warnings": []
}
```

- `gecos` is often empty on system accounts; the field is still present
  (empty string).
- `groups` is space-separated in `id -Gn` output, returned as a list.
- `getent passwd` may consult LDAP / NSS backends on hosts configured
  with them; the result reflects the actual identity store.

### `output_warnings` and GECOS scanning

The `gecos` field is attacker-controllable on shared boxes: any user with
`chfn` access (or root) can write arbitrary content into it. After fetching
the record, `output_sanitizer.scan()` checks `gecos` for suspicious patterns
(ANSI escape sequences, terminal control codes, shell metacharacters, injection
payloads). The string is NOT modified -- original text is preserved verbatim for
binary safety (INC-058 pattern). Matches are reported in `output_warnings`.

If `output_warnings` is non-empty, treat the `gecos` value (and any field
it was derived from) with caution before rendering or passing to other tools.

## Username validation

Per POSIX 3.437: `^[a-z_][a-z0-9_-]{0,31}\$?$`. Anything else raises
`ValueError` before the arg ever reaches the remote -- shell
metacharacters can't smuggle through. If you have an actual user whose
name violates this (rare but possible on non-POSIX-strict systems),
query via `ssh_exec_run` + `getent passwd '<name>'` with your own quoting.

## Common failures

- `ValueError: username ... contains characters that POSIX usernames
  don't permit` -- validation rejected the arg. Fix or escape.
- `ValueError: user ... not found via getent on host ...` -- the user
  doesn't exist on that host (or the host's NSS chain doesn't know them).
- `PlatformNotSupported` -- Windows host.

## Related

- [`ssh_host_info`](../ssh-host-info/SKILL.md) -- hostname, os, CPU,
  uptime. General host posture.
- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- for arbitrary `id` /
  `getent` / `chage -l` queries outside this tool's narrow surface.
