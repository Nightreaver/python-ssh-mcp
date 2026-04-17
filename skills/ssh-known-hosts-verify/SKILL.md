---
description: Verify a host's live SSH fingerprint matches known_hosts
---

# `ssh_known_hosts_verify`

**Tier:** read-only | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Connect to the host via the normal pool (which enforces `known_hosts`) and
report whether the live server key matches the pinned fingerprint. Never
auto-trusts. If the tool reports a mismatch, treat it as a **security event**
and escalate -- don't silently re-pin.

## Inputs

| name | type | required | notes |
|---|---|---|---|
| `host` | str | yes | Alias or hostname |

## Returns

```json
{
  "host": "web01.example.com",
  "expected_fingerprint": "SHA256:abc...",
  "live_fingerprint": "SHA256:abc...",
  "matches_known_hosts": true,
  "error": null
}
```

On mismatch or unknown host:

```json
{
  "matches_known_hosts": false,
  "error": "UnknownHost: host key for web01 not in known_hosts; verify out-of-band"
}
```

## When to call it

- After a reported host key change -- confirm it's legitimate before doing anything else.
- Periodic audit across your fleet.
- Any time `ssh_host_ping` reports `auth_ok=false` with a host-key-related error.

## When NOT to call it

- As a regular health check -- `ssh_host_ping` is cheaper.
- To _add_ an unknown host's key -- this tool never pins; use `ssh-keyscan` and
  human verification out-of-band.

## Example

```python
ssh_known_hosts_verify(host="bastion")
# -> {matches_known_hosts: true, live_fingerprint: "SHA256:..."}
```

## Common failures

- `matches_known_hosts=false` + `error="UnknownHost: ..."` -- `known_hosts` has no
  entry for this host. Fix: pre-pin via `ssh-keyscan`.
- `matches_known_hosts=false` + `error="HostKeyMismatch: ..."` -- **security event**.
  Escalate before any further action.
- `matches_known_hosts=false` + `error="ConnectError: ..."` -- TCP or transport
  failure, not a key issue.

## Related

- [`ssh_host_ping`](../ssh-host-ping/SKILL.md) -- cheaper reachability probe.
- See [README -- known_hosts management](../../README.md#known_hosts-management).
