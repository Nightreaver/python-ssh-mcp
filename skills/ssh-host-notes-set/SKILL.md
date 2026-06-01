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

## Canonical sidecar structure

This tool is the **structural owner** of the sidecar file shape. The
target layout below is operator scan-friendly: facts at the top,
history at the bottom. Structured head sections are **agent-maintained
via `_set` when content drifts**; the **Timeline is append-only** via
[`ssh_host_notes_append`](../ssh-host-notes-append/SKILL.md).

Most sections are **OPTIONAL** -- include the ones that have real
content for this host, skip the others. The two non-negotiables are
ordering (safety first, history last) and the append-only Timeline.

```markdown
# <alias> -- <one-line role / OS>
# e.g. "orangepi3 -- Armbian 25.8 + Pi-hole DNS + Homepage container"
# e.g. "james -- Synology DSM 7.3.2 NAS (172.20.31.26)"

## !!! CRITICAL (read first)         <!-- OPTIONAL -->
- 1-3 short bullets the LLM must see BEFORE doing anything else.
- Use for hard rules where a mistake causes real damage:
  data-loss-risk paths, single-point-of-failure services, sakrosankt
  user data, "do not stop unannounced".

## At-a-glance
- **OS:** <distro + version + kernel + init>
- **Hardware:** <CPU + cores + RAM + swap>
- **Disks:** <mount -> device, size, FS, %used> (1-3 lines, only relevant)
- **Network:** <primary IP/cidr + interface>
- **SSH user:** <user> (<sudo: passwordless for X / per-call / none>)
- **Role:** <one sentence: what this host does in the fleet>
- **Last verified:** YYYY-MM-DDTHH:MMZ

## Platform quirks (must-know)
- 3-7 short bullets: facts about the system that would surprise the
  next agent.
- e.g. "/etc/os-release empty on DSM", "PATH excludes /usr/local/bin",
  "busybox userland; use absolute paths".

## Storage layout
- one-liner per volume/mount: capacity, %used, type, convention.
- Sub-bullets for share lists, docker-compose conventions, dual-mount
  patterns. Cross-ref to other host notes when storage spans hosts.

## Workloads (active)
- systemd: nginx, postgres-16, ...
- docker: N containers across M compose stacks (list stack names).
- known broken: <service> (one-line + ref to Timeline date).

## Access caveats                    <!-- OPTIONAL -->
- Use when sudo / group membership / socket permissions aren't trivial.
- e.g. "no docker group on DSM; /var/run/docker.sock is root:root 0660;
  sudo only for /usr/bin/docker".

## Cross-host dependencies           <!-- OPTIONAL -->
- Use when this host serves another or depends on another.
- e.g. "supplies DNS to 172.20.0.0/16 via Pi-hole",
       "depends on james SMB share for /docker (CIFS, _netdev,nofail)".

## Operational heuristics            <!-- OPTIONAL -->
- Timing / behaviour expectations from past sessions. Distinct from
  Platform quirks (those are facts about the system); these are how
  operations on this system feel.
- e.g. "first-start of a fresh container takes minutes (slow SD + CIFS)",
       "docker pull 2-3 min for mid-size arm64 images -- timeout=600",
       "DNS-hang during 00:00-00:30 log-flush window".

## Open TODOs                        <!-- OPTIONAL -->
- [ ] open item
- [x] completed item -- left ticked as a record; sweep periodically via _set
- (Keep the list short. Long-lived done items move to Timeline.)

## DON'Ts                            <!-- OPTIONAL -->
- Consolidated negative rules, smaller scope than CRITICAL above.
- e.g. "don't edit /etc/cron.d/pihole -- pihole updater overwrites it",
       "don't `docker pull` during 00:00-00:30 log-flush phase".

## Known interventions               <!-- OPTIONAL -->
- Permanent state changes operators or agents have made -- distinct
  from Timeline observations because these affect future behaviour.
- e.g. "2026-05-19 opkg install coreutils 9.7 (busybox realpath
  doesn't support -e, broke path-policy)",
       "2026-05-24 hosts.toml docker_cmd switched to 'sudo /usr/local/bin/docker'".

## Timeline (append-only, oldest -> newest)
### 2026-04-25T10:00:00Z -- short title
learned: deploy@ in docker group, sudo not needed for docker commands.

### 2026-04-25T11:30:00Z -- operator preference
operator rejected `apt install apache2` here; nginx is the established
solution.
```

**Why this shape:**

- **Safety first.** `!!! CRITICAL` and `DON'Ts` are pulled to the top
  precisely because the operator's worst fear is "the LLM missed the
  warning and broke X". Putting them at the top maximises the chance
  they ride into LLM context on every ping (`SSH_PING_INCLUDES_AGENT_NOTES`).
- **Scan-friendly.** Operator can read top-to-bottom and get the host's
  identity + gotchas + active workload status in ~30 seconds. Past
  sessions' chronological trail lives at the bottom where it doesn't
  slow that scan.
- **Sections are optional.** A simple host might only have At-a-glance
  + Platform quirks + Timeline. A complex one (DNS-SPoF Pi, NAS,
  receiver with sakrosankt data) needs CRITICAL + Access caveats +
  Cross-host deps + Operational heuristics + DON'Ts. Use what's load-bearing.
- **Host-specific subsections welcome.** When a recurring theme
  warrants its own section (orangepi3's "Cron-Spezifika" /
  "armbian-ramlog" because cron drives the load curve here), break
  it out under a `##`-level heading between Storage and Timeline.
  The canonical names above are convention, not law.
- **TODOs tick (`- [x]`) instead of being deleted** -- preserves the
  audit trail. Sweep done items at the next `_set`; if the done item
  was durable knowledge, summarise it into Timeline or one of the
  fact-sections first.
- **Timeline grows oldest -> newest** because `ssh_host_notes_append`
  appends at the end. Operator reads top-of-Timeline for first-encounter
  context, bottom-of-Timeline for most-recent state.

### Distinguishing the three "negative rule" surfaces

| Section | When to use | Severity |
| --- | --- | --- |
| `!!! CRITICAL` (top) | Mistake causes real damage (data loss, fleet-wide outage, irreversible change). Operator's "if you only read one thing..." | High; demands LLM attention before action |
| `DON'Ts` (mid) | Don't-do-X advisories. Smaller blast radius, but still avoidable mistakes. | Medium; specific tactical patterns |
| Platform quirks | Facts about how the system behaves (not a rule, just reality). | Informational |

### Distinguishing operational from historical

| Section | Content | Tense |
| --- | --- | --- |
| Platform quirks | Facts about the system | Present-tense, undated |
| Operational heuristics | "How operations feel" -- timing, retry patterns, expected slowness | Present-tense, undated |
| Known interventions | Permanent state changes made by operator/agents | Past-tense, dated, durable |
| Timeline | Observations, decisions, lessons from one session | Past-tense, dated, append-only |

## Suggested consolidation pattern

The end-state must conform to the canonical structure above. The
structured head is the part `_set` maintains; the Timeline preserves
prior timestamped entries verbatim (you only prune stale ones).

```text
1. notes = ssh_host_notes(host="web01")
2. read notes.agent_notes; identify:
   - stale TIMELINE entries (about a removed feature / superseded by a
     later entry / one-off debugging notes that aged out)
   - structural drift (At-a-glance still says kernel 6.1 but host is on
     6.6 now; "Open TODOs" has items the operator confirmed completed)
3. compose a cleaned markdown body in the canonical structure:
   - update At-a-glance / Platform quirks / Storage / Workloads with
     today's known state (each one-liner -- not a sprawl)
   - tick done TODOs `- [x]`; drop very old done ones (>3 months); add
     new actionable ones
   - preserve every Timeline entry that's still load-bearing; drop only
     entries fully superseded by a later one
4. ssh_host_notes_set(host="web01", content=<cleaned body>)
```

## Initial setup pattern (first time on a host you'll work with)

When you'll spend real time on a host, lay down the canonical skeleton
on first contact instead of letting `ssh_host_notes_append` create the
minimal-header bootstrap:

```text
1. ssh_host_ping(host="web01") -- agent_notes likely None on first contact
2. gather facts via ssh_host_info / ssh_host_disk_usage / ssh_host_network /
   ssh_host_processes / ssh_docker_ps / ssh_systemctl_list_units etc.
3. compose a markdown body in the canonical structure with At-a-glance
   filled in from those calls, Workloads from ps/docker_ps, your initial
   TODOs (if any), and an empty Timeline section (or your first
   timestamped entry already at the bottom).
4. ssh_host_notes_set(host="web01", content=<skeleton with facts>)
5. continue your work; record durable lessons via ssh_host_notes_append
   -- they'll land in the Timeline section.
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
