"""Per-host memory: ssh_host_notes (read both layers) +
ssh_host_notes_append + ssh_host_notes_set + has_notes flag (INC-055).

Pinned contracts:
- HostPolicy.notes (operator-set, read-only) loaded from hosts.toml.
- Sidecar `<SSH_HOST_NOTES_DIR>/<alias>.md` (agent-written) read+write.
- ssh_host_notes returns BOTH layers; has_notes True iff either is set.
- ssh_host_notes_append writes a timestamped markdown entry; first call
  creates the file with a header.
- ssh_host_notes_set replaces the entire sidecar verbatim.
- Size cap (SSH_HOST_NOTES_MAX_BYTES) enforced on both write tools.
- Atomic write: temp + os.replace (cleanup on failure).
- Defensive: alias regex blocks path-traversal in sidecar filenames.
- Empty entry rejected; empty content allowed (clears sidecar to 0 bytes).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import host_notes_tools
from ssh_mcp.tools.host_notes_tools import (
    ssh_host_notes,
    ssh_host_notes_append,
    ssh_host_notes_set,
)
from ssh_mcp.tools.host_tools import ssh_host_list

if TYPE_CHECKING:
    from pathlib import Path


def _policy(alias: str, *, notes: str | None = None) -> HostPolicy:
    return HostPolicy(
        hostname=f"{alias}.example.com",
        user="deploy",
        port=22,
        platform="posix",
        auth=AuthPolicy(method="agent"),
        notes=notes,
    )


def _ctx(
    hosts: dict[str, HostPolicy],
    *,
    notes_dir: Path | None,
    max_bytes: int = 256 * 1024,
) -> Any:
    """Build a Context whose Settings has the per-test notes_dir."""
    settings = Settings(
        SSH_HOSTS_FILE=None,
        SSH_HOSTS_ALLOWLIST=[],
        SSH_HOST_NOTES_DIR=notes_dir,
        SSH_HOST_NOTES_MAX_BYTES=max_bytes,
    )

    class _Ctx:
        lifespan_context: dict[str, Any] = {  # noqa: RUF012  -- per-test instance, not shared
            "pool": MagicMock(),
            "settings": settings,
            "hosts": hosts,
            "host_allowlist": list(hosts.keys()),
            "known_hosts": MagicMock(),
            "shell_sessions": MagicMock(),
            "hooks": AsyncMock(),
        }

    return _Ctx()


# ---------------------------------------------------------------------------
# Operator layer: HostPolicy.notes
# ---------------------------------------------------------------------------


def test_policy_accepts_multiline_notes() -> None:
    body = "- Never install apache2.\n- Logs to /var/log/nginx.\n"
    p = _policy("web01", notes=body)
    assert p.notes == body


def test_policy_default_notes_is_none() -> None:
    assert _policy("web01").notes is None


# ---------------------------------------------------------------------------
# ssh_host_list: has_notes flag spans both layers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_host_list_flags_operator_notes(tmp_path: Path) -> None:
    hosts = {
        "with_op": _policy("with_op", notes="hello"),
        "without_op": _policy("without_op"),
    }
    out = await ssh_host_list(ctx=_ctx(hosts, notes_dir=tmp_path))
    by_alias = {e.alias: e for e in out.hosts}
    assert by_alias["with_op"].has_notes is True
    assert by_alias["without_op"].has_notes is False


@pytest.mark.asyncio
async def test_host_list_flags_agent_sidecar(tmp_path: Path) -> None:
    """has_notes is True when the sidecar exists and is non-empty, even
    if the operator field is empty."""
    (tmp_path / "agent_only.md").write_text("learned this last week", encoding="utf-8")
    (tmp_path / "blank.md").write_text("", encoding="utf-8")  # 0 bytes
    hosts = {
        "agent_only": _policy("agent_only"),
        "blank": _policy("blank"),
        "no_file": _policy("no_file"),
    }
    out = await ssh_host_list(ctx=_ctx(hosts, notes_dir=tmp_path))
    by_alias = {e.alias: e for e in out.hosts}
    assert by_alias["agent_only"].has_notes is True
    assert by_alias["blank"].has_notes is False  # 0-byte file = absent
    assert by_alias["no_file"].has_notes is False


@pytest.mark.asyncio
async def test_host_list_treats_whitespace_only_operator_notes_as_absent(tmp_path: Path) -> None:
    hosts = {
        "blank": _policy("blank", notes=""),
        "whitespace": _policy("whitespace", notes="   \n\t\n"),
    }
    out = await ssh_host_list(ctx=_ctx(hosts, notes_dir=tmp_path))
    by_alias = {e.alias: e for e in out.hosts}
    assert by_alias["blank"].has_notes is False
    assert by_alias["whitespace"].has_notes is False


@pytest.mark.asyncio
async def test_host_list_works_when_notes_dir_disabled() -> None:
    """SSH_HOST_NOTES_DIR=None disables the sidecar layer; has_notes
    only reflects the operator layer."""
    hosts = {
        "op": _policy("op", notes="hello"),
        "neither": _policy("neither"),
    }
    out = await ssh_host_list(ctx=_ctx(hosts, notes_dir=None))
    by_alias = {e.alias: e for e in out.hosts}
    assert by_alias["op"].has_notes is True
    assert by_alias["neither"].has_notes is False


# ---------------------------------------------------------------------------
# ssh_host_notes: returns both layers with clean separation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notes_returns_both_layers(tmp_path: Path) -> None:
    op_body = "- NEVER install apache2 -- nginx only.\n"
    agent_body = "## 2026-04-25T10:00:00Z\nlearned: deploy@ in docker group.\n"
    (tmp_path / "web01.md").write_text(agent_body, encoding="utf-8")
    hosts = {"web01": _policy("web01", notes=op_body)}

    out = await ssh_host_notes(host="web01", ctx=_ctx(hosts, notes_dir=tmp_path))
    assert out.operator_notes == op_body.strip()
    assert out.agent_notes == agent_body
    assert out.agent_notes_path == str(tmp_path / "web01.md")
    assert out.has_notes is True


@pytest.mark.asyncio
async def test_notes_returns_none_when_neither_layer_set(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    out = await ssh_host_notes(host="web01", ctx=_ctx(hosts, notes_dir=tmp_path))
    assert out.operator_notes is None
    assert out.agent_notes is None
    assert out.has_notes is False
    # Path is still surfaced so the operator can `cat` it if curious.
    assert out.agent_notes_path == str(tmp_path / "web01.md")


@pytest.mark.asyncio
async def test_notes_path_is_none_when_dir_disabled() -> None:
    """SSH_HOST_NOTES_DIR=None: agent_notes_path is None and the agent
    layer is unreadable. Operator layer still works."""
    hosts = {"web01": _policy("web01", notes="op only")}
    out = await ssh_host_notes(host="web01", ctx=_ctx(hosts, notes_dir=None))
    assert out.operator_notes == "op only"
    assert out.agent_notes is None
    assert out.agent_notes_path is None
    assert out.has_notes is True


# ---------------------------------------------------------------------------
# ssh_host_notes_append
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_creates_file_with_header_on_first_call(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    out = await ssh_host_notes_append(
        host="web01",
        entry="learned: deploy@ in docker group, sudo not needed for docker",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert out.was_created is True
    sidecar = tmp_path / "web01.md"
    assert sidecar.is_file()
    content = sidecar.read_text(encoding="utf-8")
    assert content.startswith("# Agent notes for `web01` (web01.example.com)\n")
    assert "## " in content  # timestamp header line
    assert "learned: deploy@ in docker group" in content


@pytest.mark.asyncio
async def test_append_to_existing_preserves_old_content(tmp_path: Path) -> None:
    sidecar = tmp_path / "web01.md"
    existing = "# Agent notes for `web01`\n\n## 2026-04-20T10:00:00Z\nfirst entry\n"
    sidecar.write_text(existing, encoding="utf-8")

    hosts = {"web01": _policy("web01")}
    out = await ssh_host_notes_append(
        host="web01",
        entry="second entry",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert out.was_created is False
    new_content = sidecar.read_text(encoding="utf-8")
    assert "first entry" in new_content
    assert "second entry" in new_content
    # Two distinct timestamp blocks present.
    assert new_content.count("## ") >= 2


@pytest.mark.asyncio
async def test_append_rejects_empty_entry(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    with pytest.raises(ValueError, match="non-empty"):
        await ssh_host_notes_append(
            host="web01",
            entry="   \n\t",
            ctx=_ctx(hosts, notes_dir=tmp_path),
        )


@pytest.mark.asyncio
async def test_append_enforces_size_cap(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    sidecar = tmp_path / "web01.md"
    sidecar.write_text("x" * 200, encoding="utf-8")

    # Cap of 250 bytes; appending 100+ bytes of header+entry would exceed it.
    with pytest.raises(ValueError, match="SSH_HOST_NOTES_MAX_BYTES"):
        await ssh_host_notes_append(
            host="web01",
            entry="y" * 200,
            ctx=_ctx(hosts, notes_dir=tmp_path, max_bytes=250),
        )


@pytest.mark.asyncio
async def test_append_raises_when_dir_disabled() -> None:
    hosts = {"web01": _policy("web01")}
    with pytest.raises(ValueError, match="SSH_HOST_NOTES_DIR is unset"):
        await ssh_host_notes_append(
            host="web01",
            entry="anything",
            ctx=_ctx(hosts, notes_dir=None),
        )


@pytest.mark.asyncio
async def test_append_creates_parent_dir(tmp_path: Path) -> None:
    """First-ever notes write should create the dir if missing."""
    nested = tmp_path / "deep" / "nested"
    assert not nested.exists()
    hosts = {"web01": _policy("web01")}
    await ssh_host_notes_append(
        host="web01",
        entry="first ever",
        ctx=_ctx(hosts, notes_dir=nested),
    )
    assert (nested / "web01.md").is_file()


# ---------------------------------------------------------------------------
# ssh_host_notes_append: CAS concurrent-writer safety (INC-065, v1.4.0)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_append_retries_on_concurrent_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """First CAS attempt sees a stale snapshot (another writer slipped in
    between our read and our write); the retry loop re-snapshots and the
    second attempt succeeds. Both the simulated concurrent entry AND our
    entry must be present at the end."""
    sidecar = tmp_path / "web01.md"
    initial = "# Agent notes for `web01`\n\n## 2026-04-20T10:00:00Z\noriginal\n"
    sidecar.write_text(initial, encoding="utf-8")

    real_write_if_unchanged = host_notes_tools.atomic_write_sidecar_if_unchanged
    call_count = 0

    def _flaky_write(
        path: Path,
        content: str,
        *,
        expected_mtime_ns: int | None,
        expected_size: int | None,
    ) -> bool:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Simulate a concurrent writer: rewrite the sidecar with extra
            # content BEFORE we attempt our write. The real CAS check
            # below will then see mtime+size mismatch and return False.
            path.write_text(
                initial.rstrip() + "\n\n## 2026-04-20T10:00:01Z\nconcurrent entry\n",
                encoding="utf-8",
            )
        return real_write_if_unchanged(
            path,
            content,
            expected_mtime_ns=expected_mtime_ns,
            expected_size=expected_size,
        )

    monkeypatch.setattr(host_notes_tools, "atomic_write_sidecar_if_unchanged", _flaky_write)

    hosts = {"web01": _policy("web01")}
    result = await ssh_host_notes_append(
        host="web01",
        entry="our new entry",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert result.was_created is False
    final = sidecar.read_text(encoding="utf-8")
    # The concurrent writer's entry survived (CAS prevented us from
    # silently overwriting it).
    assert "concurrent entry" in final
    # Our own entry was applied on the retry against the fresher snapshot.
    assert "our new entry" in final
    # We made exactly 2 write attempts (one failed CAS + one success).
    assert call_count == 2


@pytest.mark.asyncio
async def test_append_raises_when_concurrent_writers_exhaust_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a concurrent writer beats us every single retry, the call raises
    a clear RuntimeError naming the file. Prevents unbounded spin under
    pathological contention."""
    sidecar = tmp_path / "web01.md"
    sidecar.write_text("# pre\n", encoding="utf-8")

    def _always_loses(
        path: Path,
        content: str,
        *,
        expected_mtime_ns: int | None,
        expected_size: int | None,
    ) -> bool:
        # Simulate: another writer always commits between our snapshot
        # and our write attempt. CAS never succeeds.
        return False

    monkeypatch.setattr(host_notes_tools, "atomic_write_sidecar_if_unchanged", _always_loses)
    hosts = {"web01": _policy("web01")}
    with pytest.raises(RuntimeError, match="concurrent writer"):
        await ssh_host_notes_append(
            host="web01",
            entry="doomed",
            ctx=_ctx(hosts, notes_dir=tmp_path),
        )


@pytest.mark.asyncio
async def test_append_first_attempt_succeeds_in_uncontended_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanity: when no concurrent writer is present, the loop succeeds on
    the first iteration -- no wasted retries, no extra file I/O."""
    hosts = {"web01": _policy("web01")}
    real_write_if_unchanged = host_notes_tools.atomic_write_sidecar_if_unchanged
    call_count = 0

    def _counting(*args: Any, **kwargs: Any) -> bool:
        nonlocal call_count
        call_count += 1
        return real_write_if_unchanged(*args, **kwargs)

    monkeypatch.setattr(host_notes_tools, "atomic_write_sidecar_if_unchanged", _counting)
    await ssh_host_notes_append(
        host="web01",
        entry="single try",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert call_count == 1


# ---------------------------------------------------------------------------
# ssh_host_notes_set
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_writes_content_verbatim(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    body = "# Cleaned-up notes\n\nKnown facts:\n- deploy@ in docker group\n"
    out = await ssh_host_notes_set(
        host="web01",
        content=body,
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert out.was_created is True
    assert (tmp_path / "web01.md").read_text(encoding="utf-8") == body
    assert out.bytes_written == len(body.encode("utf-8"))


@pytest.mark.asyncio
async def test_set_replaces_existing_content(tmp_path: Path) -> None:
    sidecar = tmp_path / "web01.md"
    sidecar.write_text("old stale content here", encoding="utf-8")
    hosts = {"web01": _policy("web01")}

    out = await ssh_host_notes_set(
        host="web01",
        content="fresh content",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert out.was_created is False
    assert sidecar.read_text(encoding="utf-8") == "fresh content"


@pytest.mark.asyncio
async def test_set_empty_clears_sidecar(tmp_path: Path) -> None:
    """Empty string is a deliberate valid input -- clears the sidecar to
    zero bytes (without deleting the file)."""
    sidecar = tmp_path / "web01.md"
    sidecar.write_text("stuff", encoding="utf-8")
    hosts = {"web01": _policy("web01")}

    await ssh_host_notes_set(
        host="web01",
        content="",
        ctx=_ctx(hosts, notes_dir=tmp_path),
    )
    assert sidecar.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_set_enforces_size_cap(tmp_path: Path) -> None:
    hosts = {"web01": _policy("web01")}
    with pytest.raises(ValueError, match="SSH_HOST_NOTES_MAX_BYTES"):
        await ssh_host_notes_set(
            host="web01",
            content="x" * 1000,
            ctx=_ctx(hosts, notes_dir=tmp_path, max_bytes=500),
        )


# ---------------------------------------------------------------------------
# Defensive: unknown alias and resolve_host integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_alias_propagates_through_resolver(tmp_path: Path) -> None:
    from ssh_mcp.ssh.errors import HostNotAllowed

    hosts = {"web01": _policy("web01", notes="hi")}
    ctx = _ctx(hosts, notes_dir=tmp_path)
    with pytest.raises(HostNotAllowed):
        await ssh_host_notes(host="typo01", ctx=ctx)
    with pytest.raises(HostNotAllowed):
        await ssh_host_notes_append(host="typo01", entry="x", ctx=ctx)
    with pytest.raises(HostNotAllowed):
        await ssh_host_notes_set(host="typo01", content="x", ctx=ctx)
