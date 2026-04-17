"""services/audit — record() shape, hash(), audited() decorator around async tools."""
from __future__ import annotations

import json
import logging

import pytest

from ssh_mcp.services import audit


@pytest.fixture
def audit_sink(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
    return caplog


def _only_audit_event(caplog: pytest.LogCaptureFixture) -> dict:
    lines = [r.message for r in caplog.records if r.name == "ssh_mcp.audit"]
    assert len(lines) == 1, f"expected 1 audit line, got {len(lines)}: {lines}"
    return json.loads(lines[0])


def test_record_minimal(audit_sink: pytest.LogCaptureFixture) -> None:
    audit.record(
        tool="ssh_mkdir",
        tier="low-access",
        host="web01.internal",
        correlation_id="abc123",
        duration_ms=42,
        result="ok",
    )
    event = _only_audit_event(audit_sink)
    assert event["tool"] == "ssh_mkdir"
    assert event["tier"] == "low-access"
    assert event["host"] == "web01.internal"
    assert event["correlation_id"] == "abc123"
    assert event["result"] == "ok"
    assert "path_hash" not in event  # not provided
    assert "command_hash" not in event


def test_record_hashes_path_and_command(audit_sink: pytest.LogCaptureFixture) -> None:
    audit.record(
        tool="ssh_exec",
        tier="dangerous",
        host="web01.internal",
        correlation_id="x",
        duration_ms=1,
        result="ok",
        path="/etc/nginx/nginx.conf",
        command="nginx -t",
        exit_code=0,
    )
    event = _only_audit_event(audit_sink)
    assert event["path_hash"].startswith("sha256:")
    assert event["command_hash"].startswith("sha256:")
    assert event["exit_code"] == 0


@pytest.mark.asyncio
async def test_audited_records_ok(audit_sink: pytest.LogCaptureFixture) -> None:
    @audit.audited(tier="low-access")
    async def ssh_mkdir(host: str, path: str) -> dict:
        return {"host": host, "path": "/opt/app/new", "success": True}

    out = await ssh_mkdir(host="web01.internal", path="/opt/app/new")
    assert out["success"] is True
    event = _only_audit_event(audit_sink)
    assert event["tool"] == "ssh_mkdir"
    assert event["tier"] == "low-access"
    assert event["host"] == "web01.internal"
    assert event["result"] == "ok"
    assert event["path_hash"].startswith("sha256:")
    assert "error" not in event


@pytest.mark.asyncio
async def test_audited_records_error_and_reraises(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    @audit.audited(tier="low-access")
    async def ssh_delete(host: str, path: str) -> dict:
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError, match="nope"):
        await ssh_delete(host="web01.internal", path="/opt/app/f")

    # Only the exception CLASS name is recorded in the audit line (INC-008)
    # to keep potentially sensitive message text out of shipped audit logs.
    event = _only_audit_event(audit_sink)
    assert event["result"] == "error"
    assert event["error"] == "RuntimeError"
    assert "nope" not in event["error"]
    assert event["host"] == "web01.internal"


@pytest.mark.asyncio
async def test_audited_records_duration(audit_sink: pytest.LogCaptureFixture) -> None:
    import asyncio

    @audit.audited(tier="low-access")
    async def ssh_slow(host: str) -> dict:
        await asyncio.sleep(0.02)
        return {"host": host, "success": True}

    await ssh_slow(host="web01.internal")
    event = _only_audit_event(audit_sink)
    assert event["duration_ms"] >= 15  # account for scheduling jitter


@pytest.mark.asyncio
async def test_audited_host_type_checks_args_zero(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """INC-048: `host = args[0] if args else "?"` happily recorded whatever
    sat in the first positional slot -- a Context, an int, an object with
    a surprising __repr__. Now it must be a ``str`` to land in the audit
    line; a non-string positional falls through to "?" so the audit stream
    doesn't gain ambiguous entries from a misordered signature.
    """

    class _NotAHost:
        def __repr__(self) -> str:  # would otherwise have smeared into the audit line
            return "<ctx-like object>"

    @audit.audited(tier="low-access")
    async def weird_signature(first_positional, /) -> dict:
        return {"success": True}

    await weird_signature(_NotAHost())
    event = _only_audit_event(audit_sink)
    assert event["host"] == "?", (
        f"non-string positional should audit as '?'; got {event['host']!r}"
    )


def test_hash_summary_is_deterministic() -> None:
    assert audit._hash("foo") == audit._hash("foo")
    assert audit._hash(None) is None
    assert audit._hash("") is not None  # empty string is still hashed


def test_correlation_ids_are_unique() -> None:
    ids = {audit.new_correlation_id() for _ in range(100)}
    assert len(ids) == 100


# --- Secret redaction in audit lines (BACKLOG: ongoing/cross-cutting) --------


def test_record_redacts_secret_flags_before_hashing(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """`command_hash` must dedup by command shape, not by smuggled secret value.

    `sha256("foo --password=hunter2")` is a stable fingerprint of the actual
    secret -- trivially rainbow-tableable for any guessable password. After
    redaction, two calls with different secrets produce the SAME hash.
    """
    audit.record(
        tool="ssh_exec_run", tier="dangerous", host="h", correlation_id="a",
        duration_ms=1, result="ok",
        command="mysql -u root --password=hunter2 -e 'SELECT 1'",
    )
    audit.record(
        tool="ssh_exec_run", tier="dangerous", host="h", correlation_id="b",
        duration_ms=1, result="ok",
        command="mysql -u root --password=correcthorse -e 'SELECT 1'",
    )
    events = [json.loads(r.message) for r in audit_sink.records
              if r.name == "ssh_mcp.audit"]
    assert len(events) == 2
    assert events[0]["command_hash"] == events[1]["command_hash"], (
        "secret-only differences must NOT change the audit hash -- otherwise "
        "the hash leaks the secret value via brute-force lookup"
    )


@pytest.mark.asyncio
async def test_audited_captures_command_kwarg(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """`command: str` kwargs (ssh_exec_run, ssh_sudo_exec, etc.) must surface
    in the audit line as `command_hash` so operators can dedup invocations.
    """

    @audit.audited(tier="dangerous")
    async def ssh_exec_run(host: str, command: str) -> dict:
        return {"host": host}

    await ssh_exec_run(host="web01", command="systemctl status nginx")
    event = _only_audit_event(audit_sink)
    assert "command_hash" in event
    assert event["command_hash"].startswith("sha256:")


@pytest.mark.asyncio
async def test_audited_redacts_secrets_in_command_kwarg(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """End-to-end: a tool kwarg like `command="--password=hunter2"` must
    produce a hash equal to the redacted form, NOT the raw secret form.
    """
    from ssh_mcp.telemetry import redact_command_string

    @audit.audited(tier="dangerous")
    async def ssh_exec_run(host: str, command: str) -> dict:
        return {"host": host}

    raw = "mysql -u root --password=hunter2 -e SELECT"
    await ssh_exec_run(host="web01", command=raw)
    event = _only_audit_event(audit_sink)
    # `record()` runs redact_command_string AND strips the `:N` length suffix
    # so different secret lengths still dedup to the same command_hash.
    redacted = audit._REDACTED_LEN_SUFFIX_RE.sub(
        "<redacted>", redact_command_string(raw),
    )
    expected = audit._hash(redacted)
    assert event["command_hash"] == expected


@pytest.mark.asyncio
async def test_audited_captures_args_list_kwarg(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """`args: list[str]` (ssh_docker_run) must also flow into command_hash,
    joined and redacted via redact_argv. Per-element secret values stay
    confined to their own element so non-secret args remain readable.
    """

    @audit.audited(tier="dangerous")
    async def ssh_docker_run(host: str, image: str, args: list[str]) -> dict:
        return {"host": host}

    await ssh_docker_run(
        host="web01", image="nginx",
        args=["--env=PORT=80", "--token=abc123"],
    )
    event = _only_audit_event(audit_sink)
    assert "command_hash" in event


@pytest.mark.asyncio
async def test_audited_does_not_capture_script_kwarg(
    audit_sink: pytest.LogCaptureFixture,
) -> None:
    """`ssh_exec_script` pipes `script:` over stdin specifically so it never
    appears in argv, process listings, or audit lines. The decorator must
    honor that contract -- the script body is NOT a `command` field.
    """

    @audit.audited(tier="dangerous")
    async def ssh_exec_script(host: str, script: str) -> dict:
        return {"host": host}

    await ssh_exec_script(host="web01", script="echo secret-script-body")
    event = _only_audit_event(audit_sink)
    assert "command_hash" not in event, (
        "ssh_exec_script must not surface the script body in audit lines"
    )
