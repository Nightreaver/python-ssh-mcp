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
  "known_host_fingerprint": "SHA256:...",
  "operator_notes": "- NEVER install apache2 here -- nginx only.\n- Owner: platform-team@.",
  "agent_notes": "# Agent notes for `web01` ...\n\n## 2026-04-25T10:00:00Z\nlearned: deploy@ in docker group\n"
}
```

- `reachable=false` -> TCP refused or DNS failed.
- `reachable=true, auth_ok=false` -> TCP succeeded but the SSH layer rejected us (host-key mismatch, unknown host, auth failure).
- `operator_notes` (INC-059) -> the host's hard-rule baseline from
  `hosts.toml`'s `notes` field, auto-injected when
  `SSH_PING_INCLUDES_NOTES=True` (default) and the host has notes.
  Treat as constraints from the operator -- "don't install apache2",
  ownership, on-call routing -- and respect them in everything that
  follows. Null when the host has no notes or the operator opted out.
- `agent_notes` (INC-060) -> the LLM's own session-spanning sidecar
  at `<SSH_HOST_NOTES_DIR>/<alias>.md`, auto-injected when
  `SSH_PING_INCLUDES_AGENT_NOTES=True` (default) and the sidecar
  exists with content. Your past self's hard-won lessons -- respect
  them. Null when the sidecar is missing / empty / the agent layer
  is disabled.

The two layers toggle independently via their respective settings.
Both default ON: ping is the canonical "starting work on this host"
probe and surfacing both note layers there means the LLM gets full
host memory into context without remembering separate
`ssh_host_notes` / `ssh_host_notes_*` calls.

**Context budget caveat for `agent_notes`:** sidecars can grow to
`SSH_HOST_NOTES_MAX_BYTES` (default 256 KiB). If your fleet's notes
are large and ping context inflation matters, set
`SSH_PING_INCLUDES_AGENT_NOTES=false` and rely on the explicit
`ssh_host_notes` call when needed.

## When to call it

- **First step of any host-targeted workflow** -- confirm the box is up
  before spending time on deeper tools, AND get the operator's hard-rule
  notes for free (see `operator_notes` above). When notes are returned,
  read them before proposing a plan -- they may forbid the obvious
  approach you were about to take.
- Liveness checks in an incident-response flow.
- Before `ssh_known_hosts_verify` when you want a quick "is it even
  TCP-up?" signal.

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
