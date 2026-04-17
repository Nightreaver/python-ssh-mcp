---
description: Probe a remote host's SSH reachability and auth status
---

# `ssh_host_ping`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Probe TCP reachability and the SSH handshake for a host. Does **not** run a
remote command. The cheapest thing to call when you need to confirm a target
is alive before reaching for heavier tools.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias from `hosts.toml` (`web01`) or hostname from `SSH_HOSTS_ALLOWLIST` |

## Returns

```json
{
  "host": "web01.example.com",
  "reachable": true,
  "auth_ok": true,
  "latency_ms": 42,
  "server_banner": "SSH-2.0-OpenSSH_9.6",
  "known_host_fingerprint": "SHA256:..."
}
```

- `reachable=false` -> TCP refused or DNS failed.
- `reachable=true, auth_ok=false` -> TCP succeeded but the SSH layer rejected us (host-key mismatch, unknown host, auth failure).

## When to call it

- First step of any host-targeted workflow -- confirm the box is up before
  spending time on deeper tools.
- Liveness checks in an incident-response flow.
- Before `ssh_known_hosts_verify` when you want a quick "is it even TCP-up?" signal.

## When NOT to call it

- As a general "ping" in a tight loop -- use infrastructure monitoring for that.
- To validate the host key specifically -- prefer `ssh_known_hosts_verify`,
  which explicitly compares expected vs. live fingerprints.

## Example

```python
ssh_host_ping(host="web01")
# -> {reachable: true, auth_ok: true, latency_ms: 42, ...}
```

## Common failures

- `HostNotAllowed` -- `host` isn't in `hosts.toml` or `SSH_HOSTS_ALLOWLIST`. Add it.
- `HostBlocked` -- deny wins over allow; remove from `SSH_HOSTS_BLOCKLIST` if the block was a mistake.

## Related

- [`ssh_known_hosts_verify`](../ssh-known-hosts-verify/SKILL.md) -- verify host key matches the pinned fingerprint.
- [`ssh_host_info`](../ssh-host-info/SKILL.md) -- follow-up call once `ping` confirms auth.
