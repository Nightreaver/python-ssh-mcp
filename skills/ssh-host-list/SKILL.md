---
description: List all host aliases currently loaded in the running server
---

# `ssh_host_list`

**Tier:** safe (read-only) | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Enumerates the named hosts loaded from `hosts.toml` (or the in-memory fleet
after a reload). Returns sanitized metadata only -- never exposes credentials
(key paths, passwords, passphrases, proxy-jump secrets).

## Inputs

None beyond `ctx`.

## Returns

`HostListResult`:

- `hosts`: list of `HostListEntry`, sorted by alias ascending
- `count`: number of entries

Each `HostListEntry` carries:

| field | type | notes |
|---|---|---|
| `alias` | str | Name from hosts.toml |
| `hostname` | str | Resolved hostname / IP |
| `port` | int | SSH port |
| `platform` | str | `"posix"` or `"windows"` |
| `user` | str | SSH login user |
| `auth_method` | str | `"agent"`, `"key"`, or `"password"` -- method label only, not the secret |

## When to call it

- Quick audit of which hosts are configured before pinging or SSHing.
- After `ssh_host_reload` to confirm the new fleet was applied.

## When NOT to call it

- You need to know whether a host is actually reachable -- use `ssh_host_ping`.

## Example

```python
ssh_host_list()
```

## Related

- [`ssh_host_ping`](../ssh-host-ping/SKILL.md)
- [`ssh_host_reload`](../ssh-host-reload/SKILL.md)
