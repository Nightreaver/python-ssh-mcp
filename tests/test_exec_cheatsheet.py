"""Tests for the default-on cheatsheet rejection (B1).

Covers:
  1. ``match_cheatsheet`` per-pattern positive matches with correct
     ``pattern_id`` + ``suggested_tool``.
  2. ``match_cheatsheet`` per-pattern negative cases that must NOT match
     (legitimate composite scripts, append-redirects, /dev/null discard,
     read-tier apt commands, dpkg, daemon-reload, etc.).
  3. Heredoc shape variants (``<<EOF``, ``<<'EOF'``, ``<<"EOF"``, ``<<-EOF``,
     ``<< EOF``, ``<< -EOF``) all hit the heredoc pattern.
  4. Integration: ``ssh_exec_run`` raises ``CommandIsCheatsheetMatch`` for a
     matching command under the default setting.
  5. Integration: with ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true``, the
     cheatsheet pre-check itself does NOT raise (the call may still fail
     downstream at ``check_command`` -- that is out of scope here).
  6. ``ssh_exec_run_streaming`` has the same surface.
  7. ``match_cheatsheet`` returns ``None`` for empty / whitespace-only
     commands (the empty-command rejection belongs to ``check_command``).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from _helpers import make_ctx

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.services.exec_cheatsheet import CheatsheetMatch, match_cheatsheet
from ssh_mcp.ssh.errors import CommandIsCheatsheetMatch
from ssh_mcp.tools.exec_tools import ssh_exec_run, ssh_exec_run_streaming

# ---------------------------------------------------------------------------
# 1. Per-pattern positive matches
# ---------------------------------------------------------------------------


_POSITIVE_CASES: list[tuple[str, str, str]] = [
    # (command, expected_pattern_id, expected_suggested_tool)
    # --- docker ---
    ("docker ps", "docker", "ssh_docker_ps"),
    ("docker ps -a", "docker", "ssh_docker_ps"),
    ("  docker images", "docker", "ssh_docker_images"),
    ("docker logs nginx", "docker", "ssh_docker_logs"),
    ("docker run --rm alpine echo hi", "docker", "ssh_docker_run"),
    ("docker exec -it web bash", "docker", "ssh_docker_exec"),
    ("docker rm -f web", "docker", "ssh_docker_rm"),
    ("docker rmi alpine", "docker", "ssh_docker_rmi"),
    ("docker pull alpine", "docker", "ssh_docker_pull"),
    ("docker prune", "docker", "ssh_docker_prune"),
    ("docker cp web:/x /tmp/x", "docker", "ssh_docker_cp"),
    ("docker compose up -d", "docker", "ssh_docker_compose_up"),
    ("docker compose down", "docker", "ssh_docker_compose_down"),
    ("docker compose logs --tail 50", "docker", "ssh_docker_compose_logs"),
    # docker subcommand we don't have a 1:1 wrapper for -> family fallback
    ("docker network ls", "docker", "ssh_docker_* family"),
    # bare `docker` (no subcommand) -> family fallback
    ("docker", "docker", "ssh_docker_* family"),
    # --- systemctl ---
    ("systemctl status nginx", "systemctl", "ssh_systemctl_status"),
    ("systemctl is-active nginx", "systemctl", "ssh_systemctl_is_active"),
    ("systemctl restart nginx", "systemctl", "ssh_systemctl_restart"),
    ("systemctl reset-failed nginx", "systemctl", "ssh_systemctl_reset_failed"),
    ("systemctl list-units --type=service", "systemctl", "ssh_systemctl_list_units"),
    ("  systemctl   reload nginx", "systemctl", "ssh_systemctl_reload"),
    # --- journalctl ---
    ("journalctl -u nginx", "journalctl", "ssh_journalctl"),
    ("journalctl --since '5 min ago'", "journalctl", "ssh_journalctl"),
    ("  journalctl", "journalctl", "ssh_journalctl"),
    # --- apt mutation ---
    ("apt install nginx", "apt-mutation", "ssh_apt_install"),
    ("apt-get install -y nginx", "apt-mutation", "ssh_apt_install"),
    ("apt upgrade", "apt-mutation", "ssh_apt_upgrade"),
    ("apt-get remove nginx", "apt-mutation", "ssh_apt_remove"),
    ("apt purge nginx", "apt-mutation", "ssh_apt_remove"),
    ("apt autoremove", "apt-mutation", "ssh_apt_autoremove"),
    # --- heredoc / tee / echo > / printf > ---
    ("cat > /tmp/x <<EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("cat > /tmp/x <<'EOF'\nhi\nEOF", "heredoc", "ssh_upload"),
    ('cat > /tmp/x <<"EOF"\nhi\nEOF', "heredoc", "ssh_upload"),
    ("cat > /tmp/x <<-EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("cat > /tmp/x << EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("cat > /tmp/x << -EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("tee /tmp/x", "heredoc", "ssh_upload"),
    ("tee -a /tmp/x", "heredoc", "ssh_upload"),
    ('echo "hello" > /tmp/x', "heredoc", "ssh_upload"),
    ("printf '%s' hi > /tmp/x", "heredoc", "ssh_upload"),
    # --- single fileop ---
    ("mkdir /tmp/foo", "single-fileop", "ssh_mkdir"),
    ("mkdir -p /tmp/foo", "single-fileop", "ssh_mkdir"),
    ("rm /tmp/x", "single-fileop", "ssh_delete"),
    ("rm -rf /tmp/foo", "single-fileop", "ssh_delete_folder"),
    ("rm -fr /tmp/foo", "single-fileop", "ssh_delete_folder"),
    ("cp /tmp/x /tmp/y", "single-fileop", "ssh_cp"),
    ("cp -a /tmp/x /tmp/y", "single-fileop", "ssh_cp"),
    ("mv /tmp/x /tmp/y", "single-fileop", "ssh_mv"),
    # --- output-redirect (catches when no earlier pattern hit) ---
    ("uname -a > /tmp/hostinfo", "output-redirect", "ssh_upload"),
    (
        "tail -n 100 /var/log/syslog | grep error > /tmp/errors",
        "output-redirect",
        "ssh_upload",
    ),
]


@pytest.mark.parametrize(
    ("command", "pattern_id", "suggested_tool"),
    _POSITIVE_CASES,
    ids=[c[0][:50] for c in _POSITIVE_CASES],
)
def test_match_cheatsheet_positive(command: str, pattern_id: str, suggested_tool: str) -> None:
    match = match_cheatsheet(command)
    assert match is not None, f"expected match for {command!r}"
    assert match.pattern_id == pattern_id
    assert match.suggested_tool == suggested_tool


# ---------------------------------------------------------------------------
# 2. Per-pattern negative cases -- these must NOT match
# ---------------------------------------------------------------------------


_NEGATIVE_CASES: list[str] = [
    # Read-tier apt -- the wrapper exists but the matcher is deliberately
    # conservative; composites like `apt list --installed | grep ...` are
    # legitimate fall-through.
    "apt list --installed",
    "apt search nginx",
    "apt show nginx",
    "apt-cache search foo",
    # apt-get update is not a wrapper-covered verb.
    "apt-get update",
    # apt-mark: deliberately not matched (no clean wrapper for hold/unhold).
    "apt-mark hold nginx",
    # Different package frontend, no wrapper.
    "dpkg -l",
    "dpkg-query -W",
    # Append redirect -- intentional, not a file-replace.
    "cat /etc/passwd >> /tmp/all-passwds",
    # Stderr/stdout fd redirects -- not file-writes from cheatsheet POV.
    # (tee here would still hit heredoc pattern; this case asserts the
    # /dev/null special-case for `2>&1 >` chains.)
    "command 2>&1 > /dev/null",
    # Discard to /dev/null -- not a file-write.
    "command > /dev/null",
    "command > /dev/null 2>&1",
    # Composite snapshot script: multiple statements via `;`.
    "tar -czf /tmp/backup.tar.gz /etc; sha256sum /tmp/backup.tar.gz",
    # Composite: mkdir-then-curl chain.
    "mkdir -p /tmp/foo && curl https://example.com/file | tar -xz",
    # v1.4.0: ``cat /etc/hostname`` and ``ls /tmp`` now DO match -- they
    # route to ssh_sftp_download / ssh_sftp_list respectively (read-single
    # / list-single patterns). Kept in commit message for future audit.
    "uname -a",
    # systemctl verb not in matched list -- daemon-reload, reboot, etc.
    "systemctl daemon-reload",
    "systemctl reboot",
    # Read-tier systemctl that doesn't have an entry in our verb list still
    # passes; we only match the 16 enumerated verbs.
    "systemctl --version",
    # journalctl-LOOKING-but-not -- subtle: this is a different binary.
    "myjournalctl --foo",
    # Things that should fall through to ssh_exec_script-style usage.
    "for i in 1 2 3; do echo $i; done",
    # Bare `ps` / `df` -- no cheatsheet entry (those have wrappers, but the
    # matcher only covers the seven specified pattern classes; PR scope).
    "ps aux",
    "df -h",
]


@pytest.mark.parametrize("command", _NEGATIVE_CASES, ids=lambda c: c[:50])
def test_match_cheatsheet_negative(command: str) -> None:
    match = match_cheatsheet(command)
    assert match is None, (
        f"command {command!r} unexpectedly matched: {match!r}. " "False positive risk -- audit the matcher."
    )


# ---------------------------------------------------------------------------
# 3. Heredoc shape variants -- already in _POSITIVE_CASES, but pin separately
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat > /tmp/x <<EOF\nhi\nEOF",
        "cat > /tmp/x <<'EOF'\nhi\nEOF",
        'cat > /tmp/x <<"EOF"\nhi\nEOF',
        "cat > /tmp/x <<-EOF\nhi\nEOF",
        "cat > /tmp/x << EOF\nhi\nEOF",
        "cat > /tmp/x << -EOF\nhi\nEOF",
        "cat > /tmp/x <<_MARKER\nhi\n_MARKER",
        "cat > /tmp/x <<MARKER1\nhi\nMARKER1",
    ],
    ids=lambda c: c.split("<<", 1)[1].split("\n", 1)[0][:20],
)
def test_heredoc_shapes_all_match(command: str) -> None:
    match = match_cheatsheet(command)
    assert match is not None
    assert match.pattern_id == "heredoc"
    assert match.suggested_tool == "ssh_upload"


# ---------------------------------------------------------------------------
# 4. Empty / whitespace-only -> no match (check_command handles emptiness)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["", "   ", "\n", "\t\t"])
def test_empty_command_does_not_match(command: str) -> None:
    assert match_cheatsheet(command) is None


# ---------------------------------------------------------------------------
# 5. Integration: ssh_exec_run + ssh_exec_run_streaming raise
# ---------------------------------------------------------------------------


def _ctx_with_settings(**overrides: Any) -> Any:
    """Build a ``make_ctx``-style fake but with the supplied Settings
    overrides baked in. Used to flip ``SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS``
    (and any sibling toggles) per test.
    """
    from typing import ClassVar

    hostname = "testhost"
    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    base = {
        "SSH_HOSTS_ALLOWLIST": [hostname],
        "ALLOW_ANY_COMMAND": True,
    }
    base.update(overrides)
    settings = Settings(**base)  # type: ignore[arg-type]
    policy = HostPolicy(hostname=hostname, user="deploy", auth=AuthPolicy(method="agent"))

    class _Ctx:
        lifespan_context: ClassVar[dict] = {
            "pool": pool,
            "settings": settings,
            "hosts": {hostname: policy},
        }

    return _Ctx()


_INTEGRATION_REJECTION_CASES: list[tuple[str, str, str]] = [
    ("docker ps", "docker", "ssh_docker_ps"),
    ("systemctl restart nginx", "systemctl", "ssh_systemctl_restart"),
    ("journalctl -u nginx", "journalctl", "ssh_journalctl"),
    ("apt install nginx", "apt-mutation", "ssh_apt_install"),
    ("cat > /tmp/x <<EOF\nhi\nEOF", "heredoc", "ssh_upload"),
    ("mkdir /tmp/foo", "single-fileop", "ssh_mkdir"),
    ("echo hi > /tmp/x", "heredoc", "ssh_upload"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "pattern_id", "suggested_tool"),
    _INTEGRATION_REJECTION_CASES,
    ids=[c[0][:40] for c in _INTEGRATION_REJECTION_CASES],
)
async def test_ssh_exec_run_rejects_cheatsheet_by_default(
    command: str, pattern_id: str, suggested_tool: str
) -> None:
    ctx = make_ctx()
    with pytest.raises(CommandIsCheatsheetMatch) as exc_info:
        await ssh_exec_run(host="testhost", command=command, ctx=ctx)
    assert exc_info.value.pattern_id == pattern_id
    assert exc_info.value.suggested_tool == suggested_tool
    assert exc_info.value.command == command
    assert suggested_tool in str(exc_info.value)
    assert "SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS" in str(exc_info.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "pattern_id", "suggested_tool"),
    _INTEGRATION_REJECTION_CASES,
    ids=[c[0][:40] for c in _INTEGRATION_REJECTION_CASES],
)
async def test_ssh_exec_run_streaming_rejects_cheatsheet_by_default(
    command: str, pattern_id: str, suggested_tool: str
) -> None:
    ctx = make_ctx()
    with pytest.raises(CommandIsCheatsheetMatch) as exc_info:
        await ssh_exec_run_streaming(host="testhost", command=command, ctx=ctx)
    assert exc_info.value.pattern_id == pattern_id
    assert exc_info.value.suggested_tool == suggested_tool


# ---------------------------------------------------------------------------
# 5b. Rejection message names the actual tool that refused (not always exec_run)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rejection_message_names_exec_run() -> None:
    ctx = make_ctx()
    with pytest.raises(CommandIsCheatsheetMatch) as exc_info:
        await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)
    assert str(exc_info.value).startswith("ssh_exec_run refused:")


@pytest.mark.asyncio
async def test_rejection_message_names_exec_run_streaming() -> None:
    ctx = make_ctx()
    with pytest.raises(CommandIsCheatsheetMatch) as exc_info:
        await ssh_exec_run_streaming(host="testhost", command="docker ps", ctx=ctx)
    assert str(exc_info.value).startswith("ssh_exec_run_streaming refused:")


@pytest.mark.asyncio
async def test_rejection_message_names_sudo_exec() -> None:
    from ssh_mcp.tools.sudo_tools import ssh_sudo_exec

    ctx = make_ctx()
    with pytest.raises(CommandIsCheatsheetMatch) as exc_info:
        await ssh_sudo_exec(host="testhost", command="docker ps", ctx=ctx)
    assert str(exc_info.value).startswith("ssh_sudo_exec refused:")


# ---------------------------------------------------------------------------
# 6. Opt-out: SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true bypasses the cheatsheet
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [c[0] for c in _INTEGRATION_REJECTION_CASES],
    ids=[c[0][:40] for c in _INTEGRATION_REJECTION_CASES],
)
async def test_ssh_exec_run_opt_out_bypasses_cheatsheet(command: str) -> None:
    """With the opt-out on, the cheatsheet pre-check must NOT raise. The
    call may still fail downstream (require_posix, check_command, transport),
    but NOT with ``CommandIsCheatsheetMatch``.
    """
    ctx = _ctx_with_settings(SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=True)
    # Force the downstream path to fail fast (the fake pool's acquire returns
    # a MagicMock conn that doesn't speak asyncssh, so exec.run will explode).
    # We only care that the failure isn't CommandIsCheatsheetMatch.
    raised: BaseException | None = None
    try:
        await ssh_exec_run(host="testhost", command=command, ctx=ctx)
    except CommandIsCheatsheetMatch as exc:  # pragma: no cover - failure path
        pytest.fail(f"opt-out should bypass cheatsheet, got {exc!r}")
    except BaseException as exc:
        raised = exc
    # Either it raised something OTHER than CommandIsCheatsheetMatch, or it
    # completed (unlikely with the fake conn). Both are acceptable for this
    # test -- the contract is "cheatsheet doesn't fire".
    if raised is not None:
        assert not isinstance(raised, CommandIsCheatsheetMatch)


# ---------------------------------------------------------------------------
# 7. Exception payload shape
# ---------------------------------------------------------------------------


def test_exception_payload_attributes() -> None:
    match = match_cheatsheet("docker ps")
    assert isinstance(match, CheatsheetMatch)
    exc = CommandIsCheatsheetMatch(
        pattern_id=match.pattern_id,
        command="docker ps",
        suggested_tool=match.suggested_tool,
        message="hello",
    )
    assert exc.pattern_id == "docker"
    assert exc.command == "docker ps"
    assert exc.suggested_tool == "ssh_docker_ps"
    assert str(exc) == "hello"


# ---------------------------------------------------------------------------
# 8. Pattern-ordering preservation -- earlier patterns must always win
# ---------------------------------------------------------------------------
#
# Property under test: when a command satisfies the structural signature of
# more than one cheatsheet pattern, ``match_cheatsheet`` must return the
# EARLIER one (per the canonical 1..7 ordering documented in the matcher).
# Adding a new pattern at position N must not silently swallow commands that
# previously hit position M < N.
#
# We exercise this two ways:
#   (a) Overlap matrix: hand-built commands that legitimately satisfy two
#       patterns; the table pins which one wins.
#   (b) Noise robustness: each canonical positive case is permuted with
#       benign whitespace and trailing args; the pattern_id must NOT shift.


_ORDERING_OVERLAP_CASES: list[tuple[str, str, str]] = [
    # (command, expected_pattern_id, why_overlap)
    # docker + output-redirect -> docker wins (pattern 1 < 7)
    ("docker ps > /tmp/out", "docker", "docker prefix; also has > redirect"),
    ("docker logs nginx > /tmp/log", "docker", "docker prefix; also has > redirect"),
    # systemctl + output-redirect -> systemctl wins (2 < 7)
    ("systemctl status nginx > /tmp/st", "systemctl", "systemctl prefix; also has > redirect"),
    # journalctl + output-redirect -> journalctl wins (3 < 7)
    ("journalctl -u nginx > /tmp/jl", "journalctl", "journalctl prefix; also has > redirect"),
    # apt-mutation + output-redirect -> apt wins (4 < 7)
    ("apt install nginx > /tmp/apt", "apt-mutation", "apt prefix; also has > redirect"),
    # heredoc + output-redirect -> heredoc wins (5 < 7)
    # (cat > path <<EOF inherently contains a `>` -- without ordering this
    # would race to output-redirect.)
    ("cat > /tmp/x <<EOF\nhi\nEOF", "heredoc", "heredoc; also has > redirect"),
    ('echo "hi" > /tmp/x', "heredoc", "echo-redirect; also has generic > redirect"),
    ("printf 'x' > /tmp/x", "heredoc", "printf-redirect; also has generic > redirect"),
    ("tee /tmp/x", "heredoc", "tee; standalone fileop-shape"),
    # single-fileop + output-redirect: composite would have a `;` or `&&`,
    # which suppresses single-fileop. A bare mkdir/cp/mv/rm cannot legally
    # carry a `>` without being composite, so the only ordering we can
    # exercise here is: bare mkdir (no redirect) -> single-fileop, NOT
    # output-redirect.
    ("mkdir /tmp/foo", "single-fileop", "mkdir alone; no redirect"),
    ("rm /tmp/x", "single-fileop", "rm alone; no redirect"),
    # systemctl + heredoc would be malformed shell; not tested.
]


@pytest.mark.parametrize(
    ("command", "expected_pattern_id", "why_overlap"),
    _ORDERING_OVERLAP_CASES,
    ids=[c[0][:50] for c in _ORDERING_OVERLAP_CASES],
)
def test_pattern_ordering_overlap(command: str, expected_pattern_id: str, why_overlap: str) -> None:
    """Earlier pattern in the canonical 1..7 order must win every overlap.

    ``why_overlap`` is unused at runtime -- documents the overlap in the
    test ID so a regression failure points at which property was violated.
    """
    del why_overlap  # documentation only
    match = match_cheatsheet(command)
    assert match is not None, f"expected match for overlap case {command!r}"
    assert match.pattern_id == expected_pattern_id, (
        f"command {command!r}: expected pattern_id={expected_pattern_id!r}, "
        f"got {match.pattern_id!r} -- pattern ordering invariant violated; "
        "a later pattern is swallowing a command that an earlier one matches."
    )


# Permutations: prefix / suffix noise variants that must not change pattern_id.
# Keys are the canonical positive case; values are the (pattern_id,
# suggested_tool) the matcher must return for each permutation.
_NOISE_VARIANTS: list[tuple[str, str, str]] = [
    ("docker ps", "docker", "ssh_docker_ps"),
    ("systemctl restart nginx", "systemctl", "ssh_systemctl_restart"),
    ("journalctl -u nginx", "journalctl", "ssh_journalctl"),
    ("apt install nginx", "apt-mutation", "ssh_apt_install"),
    ("apt-get install -y nginx", "apt-mutation", "ssh_apt_install"),
    ("tee /tmp/x", "heredoc", "ssh_upload"),
    ("mkdir /tmp/foo", "single-fileop", "ssh_mkdir"),
]


def _whitespace_perturbations(cmd: str) -> list[str]:
    """Return ``cmd`` with a handful of benign whitespace mutations.

    Leading/trailing whitespace and intra-token spacing variations the LLM
    might produce -- each must resolve to the same pattern_id as the
    canonical form. We deliberately do NOT mutate case (regexes are
    case-sensitive by design for verb-disambiguation).
    """
    return [
        cmd,
        " " + cmd,
        "  " + cmd,
        "\t" + cmd,
        cmd + " ",
        cmd + "\n",
        cmd.replace(" ", "  ", 1) if " " in cmd else cmd,
    ]


@pytest.mark.parametrize(
    ("base", "pattern_id", "suggested_tool"),
    _NOISE_VARIANTS,
    ids=[c[0][:40] for c in _NOISE_VARIANTS],
)
def test_pattern_ordering_robust_to_whitespace_noise(base: str, pattern_id: str, suggested_tool: str) -> None:
    """Whitespace permutations must not shift which pattern fires.

    Catches regressions where a regex tightens its anchors and a benign
    whitespace variation suddenly falls through to a later pattern.
    """
    for variant in _whitespace_perturbations(base):
        match = match_cheatsheet(variant)
        assert match is not None, f"variant {variant!r} of {base!r} no longer matches"
        assert match.pattern_id == pattern_id, (
            f"variant {variant!r} of {base!r}: pattern_id shifted from "
            f"{pattern_id!r} to {match.pattern_id!r}"
        )
        assert match.suggested_tool == suggested_tool


# Trailing-arg permutations: adding flags/args after a canonical prefix must
# leave the pattern_id stable. (apt install nginx -> apt install nginx libx ...)
_TRAILING_ARG_VARIANTS: list[tuple[str, list[str], str]] = [
    # (base, extra_arg_lists_to_append, expected_pattern_id)
    ("docker ps", [["-a"], ["--filter", "name=web"], ["-q", "--no-trunc"]], "docker"),
    (
        "systemctl restart nginx",
        [["--now"], ["--no-block"]],
        "systemctl",
    ),
    ("journalctl -u nginx", [["-f"], ["--since", "1h ago"], ["-n", "100"]], "journalctl"),
    ("apt install nginx", [["libssl3"], ["-y"], ["--no-install-recommends"]], "apt-mutation"),
]


@pytest.mark.parametrize(
    ("base", "trailing_args", "pattern_id"),
    _TRAILING_ARG_VARIANTS,
    ids=[c[0][:40] for c in _TRAILING_ARG_VARIANTS],
)
def test_pattern_ordering_robust_to_trailing_args(
    base: str, trailing_args: list[list[str]], pattern_id: str
) -> None:
    """Appending plausible flags / extra args after the prefix must not
    shift which pattern fires.
    """
    for extra in trailing_args:
        variant = base + " " + " ".join(extra)
        match = match_cheatsheet(variant)
        assert match is not None, f"variant {variant!r} of {base!r} no longer matches"
        assert match.pattern_id == pattern_id, (
            f"variant {variant!r} of {base!r}: pattern_id shifted from "
            f"{pattern_id!r} to {match.pattern_id!r} on trailing-arg permutation"
        )


# ---------------------------------------------------------------------------
# 9. Audit-line suppression -- cheatsheet rejections must NOT hit the audit log
# ---------------------------------------------------------------------------
#
# The cheatsheet pre-check refuses the call BEFORE any host-side work happens
# (no pool acquire, no command_allowlist check, no exec). The exec_tools.py
# comment promises "no side-effect, no audit-line for the rejected attempt".
# This test pins that promise: the ``ssh_mcp.audit`` logger must see ZERO
# records when a tool raises ``CommandIsCheatsheetMatch``.
#
# Why this matters: operators ship the audit logger to shared log backends
# (SIEM, Loki, etc.). A ``result=error`` line for every cheatsheet-rejected
# attempt would be pure noise -- the LLM retrying a wrong tool 5 times would
# emit 5 audit lines that mean nothing operationally. We keep the local DEBUG
# trail (forensics) but suppress the structured INFO record.


@pytest.mark.asyncio
async def test_cheatsheet_rejection_emits_no_audit_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``ssh_exec_run`` raising ``CommandIsCheatsheetMatch`` must not emit
    any record on the ``ssh_mcp.audit`` logger.
    """
    import logging

    ctx = make_ctx()
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")

    with pytest.raises(CommandIsCheatsheetMatch):
        await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)

    audit_records = [r for r in caplog.records if r.name == "ssh_mcp.audit" and r.levelno >= logging.INFO]
    assert audit_records == [], (
        f"cheatsheet rejection emitted {len(audit_records)} audit line(s); "
        "expected zero (precheck happens before any side-effect). "
        f"Records: {[r.getMessage() for r in audit_records]}"
    )


@pytest.mark.asyncio
async def test_cheatsheet_rejection_audit_suppression_covers_all_three_tools(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The suppression must hold for every cheatsheet-aware tool, not just
    ssh_exec_run. Covers ssh_exec_run_streaming and ssh_sudo_exec too.
    """
    import logging

    from ssh_mcp.tools.sudo_tools import ssh_sudo_exec

    for tool_callable, tool_name in [
        (ssh_exec_run, "ssh_exec_run"),
        (ssh_exec_run_streaming, "ssh_exec_run_streaming"),
        (ssh_sudo_exec, "ssh_sudo_exec"),
    ]:
        ctx = make_ctx()
        caplog.clear()
        caplog.set_level(logging.INFO, logger="ssh_mcp.audit")
        with pytest.raises(CommandIsCheatsheetMatch):
            await tool_callable(host="testhost", command="docker ps", ctx=ctx)
        audit_records = [r for r in caplog.records if r.name == "ssh_mcp.audit" and r.levelno >= logging.INFO]
        assert audit_records == [], (
            f"{tool_name} cheatsheet rejection emitted {len(audit_records)} audit line(s); " "expected zero."
        )


@pytest.mark.asyncio
async def test_non_cheatsheet_error_still_audits(caplog: pytest.LogCaptureFixture) -> None:
    """Control: when a tool raises something OTHER than
    ``CommandIsCheatsheetMatch`` (here: a downstream exception from the
    fake pool), the audit line IS still emitted. Confirms the suppression
    is narrow -- only the cheatsheet class is silenced.
    """
    import logging

    ctx = _ctx_with_settings(SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=True)
    caplog.set_level(logging.INFO, logger="ssh_mcp.audit")

    # The MagicMock conn from _ctx_with_settings does not speak asyncssh,
    # so exec.run will explode somewhere downstream. We don't care WHICH
    # exception lands -- only that it is not CommandIsCheatsheetMatch AND
    # that an audit line was emitted for the attempted (non-cheatsheet) call.
    with pytest.raises(BaseException) as exc_info:
        await ssh_exec_run(host="testhost", command="docker ps", ctx=ctx)
    assert not isinstance(exc_info.value, CommandIsCheatsheetMatch)

    audit_records = [r for r in caplog.records if r.name == "ssh_mcp.audit" and r.levelno >= logging.INFO]
    assert audit_records, (
        "non-cheatsheet error path must still produce an audit line; "
        "the suppression accidentally caught the wrong exception class."
    )


# ---------------------------------------------------------------------------
# 9. v1.4.0: read / list / sudo-prefix patterns + path-aware suggestion.
# ---------------------------------------------------------------------------


def _policy_with_redact_globs(globs: list[str]) -> HostPolicy:
    return HostPolicy(
        hostname="testhost",
        user="deploy",
        auth=AuthPolicy(method="agent"),
        redact_paths_globs=globs,
    )


def _settings_default() -> Settings:
    return Settings(SSH_HOSTS_ALLOWLIST=["testhost"])  # type: ignore[call-arg]


_READ_POSITIVE: list[tuple[str, str]] = [
    ("cat /etc/hostname", "ssh_sftp_download"),
    ("head -n 100 /var/log/syslog", "ssh_sftp_download"),
    ("tail -n 50 /var/log/syslog", "ssh_sftp_download"),
    ("less /etc/hosts", "ssh_sftp_download"),
    ("more /etc/hosts", "ssh_sftp_download"),
    ("view /etc/hosts", "ssh_sftp_download"),
    ("xxd /bin/ls", "ssh_sftp_download"),
    ("strings /bin/ls", "ssh_sftp_download"),
    ("wc -l /etc/passwd", "ssh_sftp_download"),
]


@pytest.mark.parametrize(("command", "expected_tool"), _READ_POSITIVE)
def test_read_single_pattern_suggests_plain(command: str, expected_tool: str) -> None:
    """Path-aware fallback: no policy threaded -> plain ssh_sftp_download."""
    match = match_cheatsheet(command)
    assert match is not None
    assert match.pattern_id == "read-single"
    assert match.suggested_tool == expected_tool


def test_read_single_redact_match_suggests_redacted() -> None:
    policy = _policy_with_redact_globs(["**/.env"])
    settings = _settings_default()
    match = match_cheatsheet("cat /opt/app/.env", policy=policy, settings=settings)
    assert match is not None
    assert match.pattern_id == "read-single"
    assert match.suggested_tool == "ssh_read_redacted"
    assert "redact_paths_globs" in match.human_explanation


def test_read_single_non_redact_suggests_plain() -> None:
    policy = _policy_with_redact_globs(["**/.env"])
    settings = _settings_default()
    match = match_cheatsheet("cat /etc/hostname", policy=policy, settings=settings)
    assert match is not None
    assert match.suggested_tool == "ssh_sftp_download"


def test_read_ambiguous_falls_back_to_generic() -> None:
    for cmd in ("awk '{print}' /etc/passwd", "sed -i s/a/b/ /etc/foo", "grep root /etc/passwd"):
        match = match_cheatsheet(cmd)
        assert match is not None, cmd
        assert match.pattern_id == "read-ambiguous"
        assert match.suggested_tool == "ssh_sftp_download"


def test_list_single_pattern_suggests_sftp_list() -> None:
    match = match_cheatsheet("ls /tmp")
    assert match is not None
    assert match.pattern_id == "list-single"
    assert match.suggested_tool == "ssh_sftp_list"


def test_list_single_with_flags() -> None:
    match = match_cheatsheet("ls -la /tmp")
    assert match is not None
    assert match.pattern_id == "list-single"


def test_sudo_cat_suggests_sudo_read() -> None:
    match = match_cheatsheet("sudo cat /etc/shadow")
    assert match is not None
    assert match.pattern_id == "sudo-read-single"
    assert match.suggested_tool == "ssh_sudo_read"


def test_sudo_cat_redact_suggests_sudo_read_redacted() -> None:
    policy = _policy_with_redact_globs(["**/.env"])
    settings = _settings_default()
    match = match_cheatsheet(
        "sudo cat /docker/dev/modified_shop/.env",
        policy=policy,
        settings=settings,
    )
    assert match is not None
    assert match.pattern_id == "sudo-read-single"
    assert match.suggested_tool == "ssh_sudo_read_redacted"


def test_sudo_tee_suggests_sudo_write() -> None:
    match = match_cheatsheet("sudo tee /etc/myapp/config.toml")
    assert match is not None
    assert match.pattern_id == "sudo-write-single"
    assert match.suggested_tool == "ssh_sudo_write"


def test_sudo_sh_c_cat_suggests_sudo_write() -> None:
    match = match_cheatsheet("sudo sh -c 'cat > /etc/foo'")
    assert match is not None
    assert match.pattern_id == "sudo-write-single"
    assert match.suggested_tool == "ssh_sudo_write"


def test_sudo_vi_suggests_sudo_edit() -> None:
    for editor in ("vi", "vim", "nano", "emacs", "ed"):
        match = match_cheatsheet(f"sudo {editor} /etc/foo")
        assert match is not None, editor
        assert match.pattern_id == "sudo-edit-single"
        assert match.suggested_tool == "ssh_sudo_edit"


def test_sudo_ls_suggests_sudo_sftp_list() -> None:
    match = match_cheatsheet("sudo ls /root")
    assert match is not None
    assert match.pattern_id == "sudo-list-single"
    assert match.suggested_tool == "ssh_sudo_sftp_list"


def test_sudo_docker_still_routes_to_docker_pattern() -> None:
    """sudo-prefixed but the inner is docker -> falls through to docker
    pattern (legitimate use of sudo for docker on hardened hosts)."""
    match = match_cheatsheet("sudo docker ps")
    assert match is not None
    assert match.pattern_id == "docker"


def test_read_single_composite_does_not_match() -> None:
    """``cat /etc/x | grep root`` is a legitimate pipeline -- the matcher
    refuses to extract a path from it."""
    match = match_cheatsheet("cat /etc/passwd | grep root")
    # Not read-single (composite). Could fall through to other patterns; just
    # assert it's not the new read-single pattern.
    if match is not None:
        assert match.pattern_id != "read-single"
