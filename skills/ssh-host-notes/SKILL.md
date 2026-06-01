---
description: Read both layers of per-host memory -- operator baseline (hosts.toml) + your own session-spanning notes (notes/<alias>.md). Call BEFORE working on a host
---

# `ssh_host_notes`

**Tier:** safe | **Group:** `host` | **Tags:** `{safe, read, group:host}`

Returns both layers of per-host memory in one call:

- **`operator_notes`** -- hard-rule baseline from `hosts.toml`'s `notes`
  field. READ-ONLY to you. Use this for the operator's "never install
  apache2 here", "logs ship to /var/log/myapp -- do NOT change rotation",
  ownership / on-call routing constraints.
- **`agent_notes`** -- your OWN working memory across sessions, stored as
  a markdown sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md` (default
  `notes/<alias>.md`). READ-WRITE by you via
  [`ssh_host_notes_append`](../ssh-host-notes-append/SKILL.md) (preferred
  -- timestamped entry) or
  [`ssh_host_notes_set`](../ssh-host-notes-set/SKILL.md) (replaces the
  whole file -- use to consolidate).

`has_notes` is True when EITHER layer is non-empty.

## When to call it

**By default, both layers ride on `ssh_host_ping` automatically** -- the
operator-baseline (INC-059) and the agent sidecar (INC-060) are both
auto-injected into the ping response when their respective settings are
on (defaults: both True). So the dedicated `ssh_host_notes` tool is
only strictly necessary when:

- The operator has disabled one of the auto-injection settings
  (`SSH_PING_INCLUDES_NOTES=false` or
  `SSH_PING_INCLUDES_AGENT_NOTES=false`).
- You want to re-read the notes mid-session after writing via
  `ssh_host_notes_append` / `_set` (ping caches nothing -- but
  re-pinging just to refresh the notes is wasteful when this tool is
  cheaper).
- You skipped ping entirely (e.g., the workflow started with a tool
  that resolves the host without pinging first).

Standard discovery flow:

1. `ssh_host_ping` -- liveness probe; result auto-includes BOTH
   `operator_notes` and `agent_notes` (defaults).
2. `ssh_host_list` -- enumerate the fleet; each entry has `has_notes:
   bool`.
3. For any host where you want a fresh re-read of notes after writes
   (or where ping injection is disabled), call
   `ssh_host_notes(host=<alias>)`.
4. Treat `operator_notes` as hard constraints -- don't paraphrase them
   away.
5. Treat `agent_notes` as your past self's hard-won lessons -- the
   operator may not see them but they exist for a reason.

After your work, when you've LEARNED something durable about the host
("deploy@ is in the docker group", "myapp.service has restart=always
without health checks"), append it via `ssh_host_notes_append` so future
sessions inherit the knowledge.

## Expected sidecar structure

The sidecar should follow the **canonical structure** documented in
[`ssh_host_notes_set`](../ssh-host-notes-set/SKILL.md#canonical-sidecar-structure).
Quick mental model:

- **Safety first**: `!!! CRITICAL` (only when there's a hard rule) and
  `DON'Ts` (smaller advisories) live near the top so they ride into
  context on every ping.
- **Facts**: At-a-glance / Platform quirks / Storage / Workloads /
  Access caveats / Cross-host dependencies / Operational heuristics
  -- include the sections that have real content for THIS host; skip
  the others. Host-specific subsections (e.g. "Cron-Spezifika") are
  fine when a recurring theme warrants it.
- **Action items**: Open TODOs (checkboxes, ticked rather than deleted).
- **History**: Known interventions (permanent state changes) and
  Timeline (append-only, oldest -> newest).

`_set` is the structural owner of the shape; `_append` only adds
Timeline rows.

### Diagnose what you read

After reading, classify the sidecar before deciding what to write:

- **`agent_notes is None`** -- fresh host, no sidecar yet. **Do NOT
  start with `ssh_host_notes_append`** -- that would create only the
  minimal bootstrap header (`# Agent notes for <alias>`) and skip the
  structured head entirely. The correct flow: gather facts via
  `ssh_host_info` / `ssh_host_disk_usage` / `ssh_host_network` /
  `ssh_host_processes` / `ssh_docker_ps` / `ssh_systemctl_list_units`
  as appropriate, then call `ssh_host_notes_set` ONCE with the full
  canonical skeleton (At-a-glance through Timeline). Subsequent
  durable lessons land via `_append`.

- **Bootstrap-only sidecar** -- file exists but starts directly with
  the minimal `# Agent notes for <alias>` header followed by Timeline
  entries; **no At-a-glance, no Platform quirks, no other head
  sections** at all. This means the initial structure step was skipped
  on first contact (someone went straight to `_append` instead of
  `_set`). **Remediate**: gather facts as above, then `_set` the full
  canonical body -- preserve every existing Timeline entry verbatim at
  the bottom, just add the relevant structured head sections at the
  top (At-a-glance always; the optional sections only where they have
  real content for this host).

- **Canonical structure present, content drifted** -- the head sections
  exist but values are stale (At-a-glance still says kernel 6.1 but
  host is on 6.6 now; Open TODOs has items the operator confirmed
  completed). **Normal evolution** -- refresh during the next
  consolidation `_set`. Drift in CONTENT is expected; the trigger to
  act is the next time you have fresh facts in hand.

- **Free-form drift / unknown shape** -- head sections missing or out
  of order; no recognizable canonical layout. Treat like the
  bootstrap-only case: gather facts, then `_set` the full canonical
  body, preserving any timestamped entries you can identify as
  Timeline rows (move them under `## Timeline (...)`).

**Rule of thumb:** if the file starts directly with the Timeline (or
has no structured head at all), the setup step was skipped and should
be done now. Content changes inside the head sections are normal --
absence of the head sections is the trigger for `_set` remediation.
Don't drop facts; consolidation is restructuring, not pruning.

## When NOT to call it

- The host has `has_notes: false` in `ssh_host_list` AND it's a host
  you've worked with this session (notes haven't changed).
- You're doing a pure read operation that wouldn't be affected by any
  guidance.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias from `hosts.toml` (or hostname from `SSH_HOSTS_ALLOWLIST`) |

## Returns

```json
{
  "alias": "web01",
  "hostname": "web01.example.com",
  "operator_notes": "- Static-asset web server. NEVER install apache2 ...\n",
  "agent_notes": "# Agent notes for `web01` ...\n\n## 2026-04-25T10:00:00Z\nlearned: ...\n",
  "agent_notes_path": "/abs/path/to/notes/web01.md",
  "has_notes": true
}
```

When neither layer is set:

```json
{
  "alias": "web02",
  "hostname": "web02.example.com",
  "operator_notes": null,
  "agent_notes": null,
  "agent_notes_path": "/abs/path/to/notes/web02.md",
  "has_notes": false
}
```

`agent_notes_path` is surfaced even when `agent_notes is None` so the
operator can `cat` the file path you'd write to. It's None only when
`SSH_HOST_NOTES_DIR` is unset (operator opted out of the agent layer
entirely).

## Common failures

- `HostNotAllowed` / `HostBlocked` -- standard host-policy rejection.

## Related

- [`ssh_host_notes_append`](../ssh-host-notes-append/SKILL.md) -- record
  a timestamped fact to your agent sidecar. **Use this after you learn
  something durable.**
- [`ssh_host_notes_set`](../ssh-host-notes-set/SKILL.md) -- replace the
  whole sidecar to consolidate or restart memory.
- [`ssh_host_list`](../ssh-host-list/SKILL.md) -- enumerate aliases;
  `has_notes` flag tells you which hosts have guidance worth reading.
- [`ssh_host_reload`](../ssh-host-reload/SKILL.md) -- re-read
  `hosts.toml` after the operator updates `operator_notes`.
