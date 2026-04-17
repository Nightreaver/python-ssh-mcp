---
description: Run a multi-line shell script via stdin to `sh -s --`
---

# `ssh_exec_script`

**Tier:** dangerous | **Group:** `exec` | **Tags:** `{dangerous, group:exec}`

The script body is **streamed via stdin** to `sh -s --` on the remote, so it
never appears in argv, process listings, or audit lines. This is the right
choice for anything multi-line or anything you'd rather not show in a `ps`
listing.

**No command allowlist check** is performed against the script body -- the
allowlist only inspects argv tokens, and the body is on stdin. Inspect what
you execute. Disabled unless `ALLOW_DANGEROUS_TOOLS=true`.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias or hostname |
| `script` | str | yes | -- | The script body. Sent verbatim to `sh -s --` stdin. |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` | Per-call timeout in seconds |

## Returns

Same `ExecResult` shape as `ssh_exec_run`.

## When to call it

- Multi-line shell logic (loops, conditionals, intermediate variables).
- A script that contains values you don't want logged in argv (paths, IDs, but **not** secrets -- they still get logged at the OS level if your script echoes them).
- You'd otherwise have to chain commands with `&& \\` and quote everything carefully.

## When NOT to call it

- A single command -- `ssh_exec_run` is simpler and cheaper.
- Long-running output -- use `ssh_exec_run_streaming`.
- Anything sudoy -- use `ssh_sudo_run_script` (Phase 4).

## Example

```python
script = """\
set -euo pipefail
for f in /var/log/nginx/*.log; do
    lines=$(wc -l < "$f")
    echo "$f: $lines"
done
"""
ssh_exec_script(host="web01", script=script, timeout=30)
```

## Quoting note

Because the script is on stdin, you don't have to escape `$`, backticks, or
quotes the way you would for `ssh_exec_run`. Write the script as you'd write
a `.sh` file. Prepend `set -euo pipefail` if you want strict failure semantics.

## Common failures

- `ConnectError` -- TCP, auth, or transport failure.
- `HostBlocked` / `HostNotAllowed` -- see host policy.
- `timed_out=true` -- script ran past the timeout. Pkill cleanup attempted on `sh -s --`.

## Related

- [`ssh_exec_run`](../ssh-exec-run/SKILL.md) -- single-command variant with allowlist enforcement.
- [`ssh_exec_run_streaming`](../ssh-exec-run-streaming/SKILL.md) -- for scripts that produce continuous output.
