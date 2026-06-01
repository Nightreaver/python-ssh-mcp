"""Per-host agent-notes tools (read + append + set).

Thin wrappers around :mod:`ssh_mcp.services.host_notes`: resolve the host,
compute the sidecar path, call the service helper, wrap the outcome in a
Pydantic result model. The filesystem mechanics live in the service module
so this layer stays focused on tool registration, audit decoration, and
size-cap enforcement (which depends on Settings).

INC-045: ``Context`` is imported at runtime because every function in this
module is decorated with ``@mcp_server.tool`` -- FastMCP introspects the
annotation at registration time, so a ``TYPE_CHECKING``-only import would
crash at server start.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastmcp import Context

from ..app import mcp_server
from ..models.results import HostNotesResult, HostNotesWriteResult
from ..services.audit import audited
from ..services.host_notes import (
    atomic_write_sidecar,
    atomic_write_sidecar_if_unchanged,
    read_sidecar,
    read_sidecar_with_snapshot,
    resolve_sidecar_path,
    try_resolve_sidecar_path,
)
from ._context import resolve_host, settings_from

if TYPE_CHECKING:
    from pathlib import Path


@mcp_server.tool(tags={"safe", "read", "group:host"}, version="1.0")
@audited(tier="read")
async def ssh_host_notes(host: str, ctx: Context) -> HostNotesResult:
    """Read both layers of per-host memory: operator baseline + agent sidecar.

    **Call this BEFORE doing anything substantive on a host you haven't
    worked with this session.** Two layers:

    - `operator_notes` -- hard-rule baseline from `hosts.toml`'s `notes`
      field. Operator-controlled, READ-ONLY. "Never install apache2",
      ownership / on-call routing, deployment conventions.
    - `agent_notes` -- your own working memory across sessions, stored as
      a markdown sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md`. Read here,
      WRITTEN by `ssh_host_notes_append` (preferred) or
      `ssh_host_notes_set` (replaces the whole file -- use to consolidate).

    `ssh_host_list` surfaces `has_notes: bool` per host (true when EITHER
    layer is non-empty) so you know which hosts to drill into.

    Cheap: in-memory lookup for operator notes; one local FS read for
    agent notes. No SSH.
    """
    policy = resolve_host(ctx, host).policy
    settings = settings_from(ctx)
    op = policy.notes.strip() if (policy.notes and policy.notes.strip()) else None
    sidecar_path: Path | None = try_resolve_sidecar_path(settings.SSH_HOST_NOTES_DIR, host)
    agent: str | None = None
    if sidecar_path is not None:
        agent = read_sidecar(sidecar_path)
    return HostNotesResult(
        alias=host,
        hostname=policy.hostname,
        operator_notes=op,
        agent_notes=agent,
        agent_notes_path=str(sidecar_path) if sidecar_path is not None else None,
        has_notes=op is not None or agent is not None,
    )


@mcp_server.tool(tags={"low-access", "group:host"}, version="1.0")
@audited(tier="low-access")
async def ssh_host_notes_append(host: str, entry: str, ctx: Context) -> HostNotesWriteResult:
    """Append a timestamped entry to this host's agent-notes sidecar.

    USE THIS to record things you've LEARNED about a host that future
    sessions should remember -- "deploy@ is in the docker group; sudo not
    needed for docker commands", "myapp.service has restart=always but no
    health check -- restart loops if config is bad", "operator rejected
    `apt install apache2` here on 2026-04-25; nginx is the established
    solution".

    Writes to `<SSH_HOST_NOTES_DIR>/<alias>.md` (default `notes/<alias>.md`
    relative to CWD). Atomic: temp file + os.replace. The new content is
    `existing\\n\\n## <UTC iso8601>\\n<entry>\\n`. Creates the file (and
    parent dir) on first call.

    Capped at `SSH_HOST_NOTES_MAX_BYTES` (default 256 KiB total file
    size). When you're approaching the cap, use `ssh_host_notes_set` to
    consolidate -- pick the entries that are still relevant and drop the
    rest. Don't let the sidecar grow unbounded.

    DO NOT use this to store secrets, credentials, or any data the
    operator hasn't explicitly told you to persist. The sidecar is a
    plain file on the operator's MCP host. Treat it as guidance for your
    future self, not as a database.

    **Concurrent writers (v1.5.0, INC-065):** when two MCP server
    processes both append to the same sidecar around the same time, the
    second writer used to silently clobber the first. This tool now uses
    optimistic CAS: capture (mtime, size) at read, re-stat before write,
    rebuild + retry if the file changed since. Up to 5 retries; if a
    concurrent writer beats us 5 times in a row the call raises -- caller
    should retry the whole tool call.
    """
    if not entry or not entry.strip():
        raise ValueError("entry must be non-empty (after stripping whitespace)")
    policy = resolve_host(ctx, host).policy
    settings = settings_from(ctx)
    sidecar = resolve_sidecar_path(settings.SSH_HOST_NOTES_DIR, host)
    timestamp = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = f"## {timestamp}\n{entry.rstrip()}\n"
    cap = settings.SSH_HOST_NOTES_MAX_BYTES

    # CAS retry loop. Each attempt: snapshot -> build content from THIS
    # snapshot -> write iff mtime+size still match. Concurrent writer
    # beats us -> snapshot changed on next read -> rebuild against the
    # newer existing content -> retry. Bounded at 5 iterations to avoid
    # unbounded spin under pathological contention; in practice 2 is
    # enough.
    last_was_created = False
    last_encoded_len = 0
    for _attempt in range(_NOTES_APPEND_MAX_RETRIES):
        snap = read_sidecar_with_snapshot(sidecar)
        existing = snap.text or ""
        last_was_created = existing == ""
        if existing:
            new_content = f"{existing.rstrip()}\n\n{suffix}"
        else:
            new_content = (
                f"# Agent notes for `{host}` ({policy.hostname})\n\n"
                f"Written by ssh-mcp's agent-notes tools. Free-form across "
                f"sessions. Operator can read these as plain Markdown.\n\n"
                f"{suffix}"
            )
        last_encoded_len = len(new_content.encode("utf-8"))
        if last_encoded_len > cap:
            raise ValueError(
                f"sidecar would be {last_encoded_len} bytes after append; cap is "
                f"SSH_HOST_NOTES_MAX_BYTES={cap}. Use ssh_host_notes_set to "
                f"consolidate the file (drop stale entries) before appending."
            )
        if atomic_write_sidecar_if_unchanged(
            sidecar,
            new_content,
            expected_mtime_ns=snap.mtime_ns,
            expected_size=snap.size,
        ):
            return HostNotesWriteResult(
                alias=host,
                hostname=policy.hostname,
                agent_notes_path=str(sidecar),
                bytes_written=last_encoded_len,
                was_created=last_was_created,
                message=(
                    "created sidecar with first entry" if last_was_created else "appended timestamped entry"
                ),
            )
        # else: concurrent writer beat us. Loop, rebuild from fresh snapshot.
    raise RuntimeError(
        f"sidecar {sidecar} changed by a concurrent writer "
        f"{_NOTES_APPEND_MAX_RETRIES} times in a row; another MCP server "
        "process appears to be hammering the same file. Retry the call."
    )


# Bounded retry count for the CAS loop in ssh_host_notes_append. 5 covers
# realistic agent contention; pathological hammering surfaces as a clear
# RuntimeError instead of an unbounded spin.
_NOTES_APPEND_MAX_RETRIES = 5


@mcp_server.tool(tags={"low-access", "group:host"}, version="1.0")
@audited(tier="low-access")
async def ssh_host_notes_set(host: str, content: str, ctx: Context) -> HostNotesWriteResult:
    """Replace the entire agent-notes sidecar for this host.

    USE THIS to consolidate accumulated notes -- read the current sidecar
    via `ssh_host_notes`, prune stale entries, restructure the markdown,
    and write the cleaned version back. Or to restart the memory from
    scratch when prior notes have become misleading.

    `content` is written verbatim (no automatic timestamp prefix; if you
    want one, include it in `content`). Pass an empty string to clear the
    sidecar without deleting the file (the file becomes 0 bytes; future
    `ssh_host_notes` returns `agent_notes=None`).

    Atomic: temp file + os.replace. Capped at `SSH_HOST_NOTES_MAX_BYTES`.
    Same caveats as `ssh_host_notes_append` -- no secrets, this is plain
    text on the operator's MCP host.

    **Concurrent writers (v1.5.0, INC-065):** unlike
    `ssh_host_notes_append`, `_set` is deliberately last-writer-wins.
    The caller already decided to replace the file wholesale; if a
    concurrent writer slipped an `_append` in between the caller's read
    and this call, that appended entry IS lost. If you need the safe
    flow, call `ssh_host_notes` immediately before `ssh_host_notes_set`
    and accept that other agents may still race. A CAS variant of `_set`
    (with an `expected_etag` argument) is a v1.14 candidate.
    """
    policy = resolve_host(ctx, host).policy
    settings = settings_from(ctx)
    sidecar = resolve_sidecar_path(settings.SSH_HOST_NOTES_DIR, host)

    cap = settings.SSH_HOST_NOTES_MAX_BYTES
    encoded_len = len(content.encode("utf-8"))
    if encoded_len > cap:
        raise ValueError(f"content is {encoded_len} bytes; cap is SSH_HOST_NOTES_MAX_BYTES={cap}.")

    was_created = not sidecar.is_file()
    atomic_write_sidecar(sidecar, content)
    return HostNotesWriteResult(
        alias=host,
        hostname=policy.hostname,
        agent_notes_path=str(sidecar),
        bytes_written=encoded_len,
        was_created=was_created,
        message=("created sidecar" if was_created else "replaced sidecar contents"),
    )
