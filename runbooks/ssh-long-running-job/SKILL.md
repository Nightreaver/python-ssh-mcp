---
description: Launch a multi-hour command in a detached tmux session, record it in host-notes, and poll for completion across sessions
---

# SSH Long-Running Job

Workflow runbook for "this command will run for hours and must survive
the MCP server, my conversation, and a flaky link". Pattern: run the
command in a detached `tmux` session on the remote, record the session
name + log path in [agent host-notes](../../skills/ssh-host-notes-append/SKILL.md),
poll until done. The motivating case is a multi-TB `rsync`, but the
same shape fits long `restic` backups, big `pg_dump`/`pg_restore`, mass
`apt` upgrades on slow boxes, dataset downloads, etc.

`ssh_exec_run_streaming` covers "minutes, not seconds" -- this runbook
covers "hours-to-days", where the job MUST be decoupled from the SSH
channel and the MCP process.

## Default-on cheatsheet rejection (since v1.9.0)

`ssh_exec_run` refuses commands that have a native MCP tool -- see
`skills/ssh-exec-run/SKILL.md`. The native-tool flow below avoids
that. Composite scripts (where the script IS the artefact) opt out
via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` at the operator level.

Every `ssh_exec_run` call in this runbook is a `tmux` / `tail` /
`grep` / `cat` / `command -v` invocation -- none of those have
native MCP wrappers and none are cheatsheet-matched. The launch
command (Section 2) wraps the long-running job inside `tmux new -d`;
that wrapper IS the long-job artefact (its detachment + rc-file
contract is what makes resume possible), so it intentionally runs
as a single exec under one audit correlation id.

## Why tmux and not the streaming tool

| Concern | `ssh_exec_run_streaming` | This runbook (tmux + notes) |
|---|---|---|
| Per-call timeout | bounded by `timeout` arg | none -- job outlives every call |
| Survives MCP restart | only with Redis docket | yes, unconditionally |
| Survives network blip | no (`ConnectError` aborts the stream) | yes |
| Resumable | no | yes (rsync `--partial`, restic checkpoints) |
| Future conversation can find it | no | yes (notes auto-injected on `ssh_host_ping`) |
| Live progress to the client | streaming chunks | poll `tail` of the log |

If any row in column 3 doesn't matter for your case, use the streaming
tool -- it's simpler.

## Sequence

1. Precheck source host (read)
2. Launch in detached tmux + log to disk (dangerous: `ssh_exec_run`)
3. Record job in host-notes (low-access: `ssh_host_notes_append`)
4. Poll until tmux session is gone (read)
5. Resume from a future session (read + low-access)
6. Verify exit code + finalize note (low-access)
7. Failure recovery (dangerous)

## 1. Precheck source host

The "host" the MCP server connects to is wherever the long-running
command *runs from* -- for an rsync push, that's the source. Confirm:

```python
# tmux installed?
ssh_exec_run(host="nas01", command="command -v tmux", timeout=10)
# disk for the log file
ssh_host_disk_usage(host="nas01")
# nothing already in flight under the same name (avoid clobbering a
# prior run)
ssh_host_notes(host="nas01")  # look for an existing [long-run] line
ssh_exec_run(host="nas01", command="tmux ls 2>/dev/null", timeout=10)
```

If tmux isn't installed, stop and ask the operator -- this runbook
does not silently fall back to `nohup` or `screen` because the
polling commands below are tmux-specific. (Replace the launch +
poll lines if you really need `screen`; the rest of the shape is
identical.)

## 2. Launch in detached tmux

Pick a stable, dated session name -- it doubles as the handle for
every subsequent poll AND the slug the future-you will grep for in
host-notes. Format: `<task>-<UTC-date>-<short-tag>`.

```python
from shlex import quote as shlex_quote

job = "xfer-2026-05-19-rsync-nas-to-dst"   # session name + log slug
log = f"/var/log/{job}.log"
rc  = f"/var/log/{job}.rc"

# wrap the command so its exit code lands in a known file when the
# session exits. without this you can tell "it's done" but not
# "it succeeded".
inner = (
    f"rsync -aP --partial --append-verify --log-file={log} "
    f"/data/ user@dst01:/data/ ; echo $? > {rc}"
)

ssh_exec_run(
    host="nas01",
    command=f"tmux new -d -s {job} {shlex_quote(inner)}",
    timeout=15,
)
```

Key flags:

- `tmux new -d -s <name>` -- detached; returns immediately, tmux owns
  the process. No PID juggling needed; the session name IS the handle.
- `--partial --append-verify` (rsync) -- a network blip or full restart
  resumes from the last good byte instead of retransferring TB.
- `--log-file=...` (rsync) -- progress is preserved even if no one is
  watching. Don't rely on `tmux capture-pane` for completeness; the
  scrollback is bounded.
- `echo $? > <rc>` -- the success signal. `tmux has-session` only
  tells you the session is GONE, not whether the job succeeded; an
  rsync that aborted with rc=23 (partial transfer) and one that
  finished cleanly look identical from tmux's perspective.

The MCP `ssh_exec_run` call returns in milliseconds because tmux
detached. The rsync is now uncoupled from the MCP channel.

## 3. Record the job in host-notes

```python
ssh_host_notes_append(
    host="nas01",
    entry=(
        f"[long-run] {job} | tmux:{job} | log:{log} | rc:{rc} | "
        f"started:2026-05-19T14:30Z | src:/data/ dst:dst01:/data/"
    ),
)
```

Why this exact shape:

- **Declarative, not imperative.** It states a fact ("there is a tmux
  session named X"); it does NOT say "come back and check on this".
  See the [hygiene section](../../skills/ssh-host-notes-append/SKILL.md#hygiene-what-is-safe-vs-unsafe-to-write)
  -- imperative entries become self-reinforcing prompt injection on
  every subsequent `ssh_host_ping`.
- **`[long-run]` prefix.** Greppable. A future session running
  `ssh_host_notes(host="nas01")` can spot in-flight jobs at a glance.
- **One line, pipe-separated fields.** Predictable for the LLM to
  parse on resume. The handbook's own host-notes auto-injection
  happens on every ping, so the line will be in your context without
  any extra read call.

What NOT to put in the note: rsync's verbose progress output, the
full inner command, secret-bearing flags. Summary only.

## 4. Poll until the tmux session is gone

The "done" signal is two-stage: tmux session disappears, THEN the rc
file exists. Polling cadence is a tradeoff -- check more often near
expected completion, less often for a transfer you know will run
12 hours.

```python
# fast progress glance (last 5 log lines, no decision)
ssh_exec_run(host="nas01",
             command=f"tail -n 5 {log}",
             timeout=10)

# completion check
result = ssh_exec_run(
    host="nas01",
    command=f"tmux has-session -t {job} 2>/dev/null; echo TMUX_EXIT=$?",
    timeout=10,
)
# TMUX_EXIT=0 -> still running
# TMUX_EXIT=1 -> session gone; check rc file in step 6
```

For very long jobs, schedule the next check with `/schedule` or a
`/loop` rather than tight-looping in a single conversation -- you'll
burn the prompt cache for nothing while the rsync grinds through
disk. The note + auto-inject means a brand-new session can pick up
polling from cold (see step 5).

A useful intermediate metric for rsync is `--info=progress2` (in the
launch step) or grepping the log for `to-check=<remaining>/<total>`:

```python
ssh_exec_run(
    host="nas01",
    command=(
        f"grep -oE 'to-check=[0-9]+/[0-9]+' {log} | tail -n 1"
    ),
    timeout=10,
)
# to-check=412/8439  -> ~95% remaining
```

## 5. Resume from a future session

This is the payoff. A new conversation, possibly hours later, with
no memory of the prior session:

```python
# triggers host-notes auto-injection (INC-060)
ssh_host_ping(host="nas01")
# you now see the [long-run] line in your context without any
# further read call. parse the fields:
#   tmux:<session>  log:<path>  rc:<path>  started:<iso>
```

From there: jump to step 4's polling. Same `tmux has-session` check,
same `tail -n 5 <log>`. No state was lost across the conversation
gap; the remote tmux session is the source of truth, the host-note
is the index.

If `ssh_host_ping` returns a sidecar without a `[long-run]` entry
matching the job you remember, treat that as "completed and cleaned
up" -- step 6 deletes the line when finalizing.

## 6. Verify exit code + finalize the note

Once `tmux has-session` returns 1 (session gone):

```python
result = ssh_exec_run(host="nas01", command=f"cat {rc}", timeout=10)
exit_code = int(result["stdout"].strip())
```

Decision table for rsync specifically (other tools have their own
codes):

| rc | Meaning | Action |
|---|---|---|
| 0 | clean transfer | finalize note: success |
| 23 | partial transfer (some files vanished, perms, etc.) | inspect `log` for per-file errors; may be acceptable |
| 24 | partial transfer (vanished source files) | usually safe to ignore for live trees |
| 30 / 35 | timeout | network died; rerun the same command, `--partial` resumes |
| other | hard failure | tail the log, investigate before retry |

Then update host-notes. Two paths:

```python
# A. quick completion entry (preferred for short-lived jobs)
ssh_host_notes_append(
    host="nas01",
    entry=(
        f"[long-run] {job} completed rc={exit_code} at "
        f"2026-05-19T22:14Z"
    ),
)

# B. consolidate -- if the sidecar has accumulated many [long-run]
# lines, rewrite the whole file to drop completed ones:
notes_text = ssh_host_notes(host="nas01")["agent_notes"]
cleaned = drop_long_run_lines(notes_text, job=job)  # caller-owned
ssh_host_notes_set(host="nas01", content=cleaned)
```

Path A is simpler and what you'll do 90% of the time. Path B keeps
the sidecar from growing unboundedly across many transfers; the
budget is `SSH_HOST_NOTES_MAX_BYTES` (default 256 KiB) and
`ssh_host_notes_append` will refuse if you blow past it.

You can also delete the rc + log files at this point if disk pressure
matters; the note already captured the outcome.

## 7. Failure recovery

**tmux session died but rc file is missing** -- the wrapper crashed
before `echo $? > <rc>` ran (host rebooted, OOM-killer, SIGKILL).
Treat as "outcome unknown"; inspect the log tail for the last rsync
line, decide whether to rerun. With `--partial --append-verify` a
rerun is cheap.

**tmux session still alive after the expected duration** -- get the
running PIDs and decide:

```python
ssh_exec_run(
    host="nas01",
    command=f"tmux list-panes -t {job} -F '#{{pane_pid}}' | "
            f"xargs -I{{}} ps -o pid,etime,cmd -p {{}}",
    timeout=15,
)
```

If it's genuinely stuck (no log progress for an hour), kill the
session and re-launch:

```python
ssh_exec_run(host="nas01", command=f"tmux kill-session -t {job}",
             timeout=10)
```

This is a dangerous operation. Confirm with the operator before
killing a job they may have been watching from another channel.

**Note says a job exists, tmux says it doesn't, rc file says success
on a much earlier timestamp** -- the note is stale (operator
finalized via a different path, or you skipped step 6 last time).
Update the note via `ssh_host_notes_set` and move on; don't relaunch.

## Boundaries

- This runbook needs `ALLOW_DANGEROUS_TOOLS=true` (exec) **and**
  `ALLOW_LOW_ACCESS_TOOLS=true` (host-notes).
- The MCP server must be able to reach the source host. The
  destination only needs to be reachable from the source -- it is
  not an MCP host.
- One job per session name. Two operators running this runbook with
  the same `job` slug will collide on the tmux session and the log
  path. The dated slug + per-host scoping makes collisions unlikely
  but not impossible; check step 1 before launching.
- Not a substitute for a real job queue (Nomad, systemd timers,
  Airflow, ...). Use this for one-shot operator-driven runs, not
  recurring scheduled work.
- If your shop already runs `systemd-run --user --unit=...` for
  detached jobs, prefer that -- you get journal logs + `is-active`
  for free. The note pattern (step 3) is unchanged; only the launch
  + poll commands shift.

## Related runbooks

- [`ssh-deploy-verify`](../ssh-deploy-verify/SKILL.md) -- if the
  long-running job is "upload + activate", do the deploy via that
  runbook synchronously instead.
- [`ssh-disk-cleanup`](../ssh-disk-cleanup/SKILL.md) -- if step 1
  shows the source or destination is tight on space, clean up first;
  rsync filling a partition mid-transfer is recoverable but ugly.
- [`ssh_exec_run_streaming`](../../skills/ssh-exec-run-streaming/SKILL.md)
  -- the right tool when the same job is "minutes" not "hours".
- [`ssh_host_notes_append`](../../skills/ssh-host-notes-append/SKILL.md)
  -- read the hygiene section before adapting the note shape; the
  imperative-vs-declarative distinction matters more than it looks.
