---
description: Replace your entire agent-notes sidecar for one host. Use to consolidate accumulated notes or reset memory.
---

# `ssh_host_notes_set`

**Tier:** low-access | **Group:** `host` | **Tags:** `{low-access, group:host}`

Replace `<SSH_HOST_NOTES_DIR>/<alias>.md` entirely with `content`.
`content` is written verbatim -- no automatic timestamp prefix; if you
want one, include it yourself.

Disabled unless `ALLOW_LOW_ACCESS_TOOLS=true`.

## When to call it

- **Consolidate:** the sidecar has accumulated 30+ timestamped entries,
  some now stale or redundant. Read it via `ssh_host_notes`, prune dead
  facts, restructure into thematic sections, write the cleaned version
  back.
- **Reset:** prior notes have become misleading (operator changed how
  the host works; old assumptions invalidated). Pass an empty string to
  clear the sidecar to zero bytes (file stays in place; future
  `ssh_host_notes` returns `agent_notes=None`).
- **Bulk import:** rare -- you have a curated block of facts to seed
  into a fresh sidecar in one shot.

## When NOT to call it

- You just want to add ONE new fact -- use `ssh_host_notes_append`.
  `_set` is for whole-file rewrites; `_append` is the everyday tool.
- You haven't read the current sidecar -- you'd overwrite useful prior
  knowledge by accident. ALWAYS `ssh_host_notes` first.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `content` | str | yes | -- | New sidecar content. Empty string clears to zero bytes. |

## Returns

```json
{
  "alias": "web01",
  "hostname": "web01.example.com",
  "agent_notes_path": "/abs/path/to/notes/web01.md",
  "bytes_written": 612,
  "was_created": false,
  "message": "replaced sidecar contents"
}
```

`was_created` distinguishes first-ever write (creates the file + parent
dir) from in-place replacement.

## Atomicity

Atomic: temp file + `os.replace`. The sidecar is never observed
half-written.

## Suggested consolidation pattern

```text
1. notes = ssh_host_notes(host="web01")
2. read notes.agent_notes; identify stale entries (about a feature
   that's been removed; superseded by a later entry; etc.)
3. compose a cleaned markdown body, structured by topic (Auth & users;
   Service quirks; Deployment; Debugging hints), preserving every entry
   that's still load-bearing.
4. ssh_host_notes_set(host="web01", content=<cleaned body>)
```

Don't lose information you can't easily re-derive. When in doubt, keep.

## Common failures

- `ValueError: SSH_HOST_NOTES_DIR is unset` -- operator disabled the
  agent layer; ask them to set the env var.
- `ValueError: content is N bytes; cap is SSH_HOST_NOTES_MAX_BYTES=...`
  -- the cleaned content still exceeds the cap. Drop more entries.
- `HostNotAllowed` / `HostBlocked` -- standard host-policy rejection.

## Related

- [`ssh_host_notes`](../ssh-host-notes/SKILL.md) -- read first;
  consolidation requires knowing what's there.
- [`ssh_host_notes_append`](../ssh-host-notes-append/SKILL.md) -- the
  everyday "I learned a thing" tool.
