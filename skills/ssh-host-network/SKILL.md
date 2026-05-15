---
description: Structured per-interface network state from `ip -j addr show`; iproute2-required, no sudo
---

# `ssh_host_network`

**Tier:** safe | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Parse `ip -j addr show` on the remote and return structured per-interface
JSON: name, oper-state, MAC, addresses (family + address + prefix length).

The raw `ip` output carries dozens of kernel-internal fields (broadcast,
valid_life_time, scope, link_index, ...) that bloat the schema with no
operational value -- those are deliberately stripped here. Use
`ssh_exec_run "ip -j addr show"` if you need the full payload.

POSIX-only and `iproute2`-required. Hosts without `ip` (busybox without
netlink, very old systems) get an empty `interfaces` list rather than a
raise -- consumers can fall back to `ssh_exec_run "ifconfig"` or whatever
the host supports.

## When to call it

- "What addresses are bound to `eth0` on `web01`?"
- "Which interfaces are UP across the api tier?" (combine with
  `ssh_broadcast`.)
- Network triage: confirm an interface that should be UP isn't DOWN.
- Audit: enumerate inet / inet6 addresses the host actually advertises.

## When NOT to call it

- Need routes -- this tool only returns interfaces. Use `ssh_exec_run
  "ip -j route show"` (or add an `ssh_host_routes` tool if this becomes
  a recurring ask).
- Need active connections / listening sockets -- use `ssh_exec_run "ss
  -tlnp"`.
- Hosts on busybox without `ip` -- empty result; pick a different tool.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |

## Returns

```json
{
  "host": "web01.example.com",
  "interfaces": [
    {
      "name": "lo",
      "state": "UNKNOWN",
      "mac": "00:00:00:00:00:00",
      "addresses": [
        {"family": "inet",  "address": "127.0.0.1", "prefix_length": 8},
        {"family": "inet6", "address": "::1",       "prefix_length": 128}
      ]
    },
    {
      "name": "eth0",
      "state": "UP",
      "mac": "02:42:ac:11:00:02",
      "addresses": [
        {"family": "inet",  "address": "10.0.0.42",      "prefix_length": 24},
        {"family": "inet6", "address": "fe80::42:acff:fe11:2", "prefix_length": 64}
      ]
    }
  ]
}
```

- `state` mirrors netlink `operstate`: typically `UP`, `DOWN`,
  `UNKNOWN`, `LOWERLAYERDOWN`. Older `ip` builds may omit it; the
  parser falls back to `UNKNOWN`.
- `mac` is None for software interfaces without a hardware address.
- Empty `interfaces` list = `ip` not installed or output not parseable.
  Fall back to `ssh_exec_run "ifconfig"`.

## Common failures

- `PlatformNotSupported` -- Windows host (no `ip` command); use
  `ssh_exec_run "ipconfig"` once allowlisted.
- Empty `interfaces` -- `ip` missing or output malformed. Try
  `ssh_exec_run "which ip"` to confirm.

## Related

- [`ssh_host_info`](../ssh-host-info/SKILL.md) -- general host posture
  including `hostname_fqdn`, `cpu_model`, etc.
- [`ssh_host_disk_usage`](../ssh-host-disk-usage/SKILL.md) -- mounted
  filesystems.
