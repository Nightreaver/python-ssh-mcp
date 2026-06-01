"""Default-on cheatsheet rejection for `ssh_exec_run` / `ssh_exec_run_streaming`.

The exec-tier tools are last-resort. When the LLM reaches for raw shell to do
something a dedicated MCP tool already covers (``docker ps``, ``systemctl
restart``, ``apt-get install``, heredoc file-writes, single ``mkdir`` /
``rm``, output redirection to a file), we want to reject the call and
redirect to the structured wrapper instead. The wrappers are safer (policy
gates + audit), cheaper (no command_allowlist round-trip), and produce
typed results instead of stdout the LLM has to re-parse.

This module is the **pattern matcher only**. The exec tools own the policy
decision (env opt-out toggles whether a match raises or is merely recorded).
Returning ``None`` means "no cheatsheet match found, continue to the next
gate". Each match carries a stable ``pattern_id`` (for analytics + tests)
and a ``suggested_tool`` name (for the rejection message).

The matcher is deliberately conservative: patterns must trigger only on
shapes the operator clearly meant as a single-purpose call. Composite
scripts (``mkdir -p ... && curl ... | tar -xz``, ``tar ...; sha256sum
...``), append redirects (``>>``), and discard-to-/dev/null are NOT
matches. INC false-positive surface is the chief risk here; see test
suite ``tests/test_exec_cheatsheet.py`` for the audited negative list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ssh.errors import CommandIsCheatsheetMatch

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import HostPolicy

__all__ = [
    "CheatsheetMatch",
    "build_cheatsheet_rejection_message",
    "cheatsheet_hint_warning",
    "cheatsheet_precheck",
    "match_cheatsheet",
]


@dataclass(frozen=True)
class CheatsheetMatch:
    """A single cheatsheet-pattern hit.

    ``pattern_id`` is stable across versions (used by tests, audit, and the
    forthcoming output_warnings wiring in B2). ``suggested_tool`` names the
    native MCP tool the LLM should reach for instead. ``human_explanation``
    is a one-line "why" suitable for the rejection message body.
    """

    pattern_id: str
    suggested_tool: str
    human_explanation: str


# ---------------------------------------------------------------------------
# Pattern regexes. Compiled at import; ordering matters -- the matcher
# returns on the FIRST hit so more-specific patterns must come first.
# ---------------------------------------------------------------------------

# 1. Anything starting with `docker ` (or just `docker` then EOS).
_DOCKER_RE = re.compile(r"^\s*docker(\s|$)")

# 2. `systemctl <verb>` where <verb> is one of the wrapper-covered actions.
_SYSTEMCTL_VERBS = (
    "is-active",
    "is-enabled",
    "is-failed",
    "status",
    "show",
    "cat",
    "list-units",
    "list-unit-files",
    "start",
    "stop",
    "restart",
    "reload",
    "enable",
    "disable",
    "mask",
    "unmask",
    "reset-failed",
)
_SYSTEMCTL_RE = re.compile(
    r"^\s*systemctl\s+(?P<verb>" + "|".join(re.escape(v) for v in _SYSTEMCTL_VERBS) + r")\b"
)

# 3. `journalctl ...` -- any invocation.
_JOURNALCTL_RE = re.compile(r"^\s*journalctl(\s|$)")

# 4. `apt` / `apt-get` mutation verbs (install/upgrade/remove/purge/autoremove).
#    Read verbs (apt list/search/show) and `apt-mark` are deliberately NOT
#    matched -- see module docstring.
_APT_MUTATION_VERBS = ("install", "upgrade", "remove", "purge", "autoremove")
_APT_MUTATION_RE = re.compile(r"^\s*apt(-get)?\s+(?P<verb>" + "|".join(_APT_MUTATION_VERBS) + r")\b")

# 5. Heredoc file-writes + tee + echo/printf-to-file. Each is a separate
#    expression so we can keep them readable.
#
#    Heredoc: `<<EOF`, `<< EOF`, `<<-EOF`, `<< -EOF`, `<<'EOF'`, `<<"EOF"`,
#    etc. The marker name is `[A-Za-z_][A-Za-z0-9_]*`. Optional dash for
#    indented heredocs, optional whitespace, optional surrounding quotes.
_HEREDOC_RE = re.compile(r"<<\s*-?\s*['\"]?[A-Za-z_][A-Za-z0-9_]*['\"]?")
#    `tee <path>` (any tee invocation that names a target).
_TEE_RE = re.compile(r"\btee\s+\S+")
#    `echo ... > path` and `printf ... > path`. We require something between
#    the command and the `>` so we don't double-match the same redirect that
#    pattern 7 would catch (those two patterns intentionally overlap, but
#    heredoc's earlier order means the redirect-bearing echo/printf gets
#    classified as "heredoc-family file-write" rather than generic redirect).
_ECHO_REDIRECT_RE = re.compile(r"^\s*echo\s+.*>\s*\S+")
_PRINTF_REDIRECT_RE = re.compile(r"^\s*printf\s+.*>\s*\S+")

# 6. Single-statement file operations. Match must be at the start AND the
#    full command must contain no shell separators (``|``, ``&&``, ``;``,
#    ``||``) and no command substitution (``$(`` or backtick) -- those
#    indicate a composite pipeline that the operator is intentionally
#    running as a one-liner.
_FILEOP_START_RE = re.compile(r"^\s*(?P<op>mkdir|cp|mv|rm)\s")
_COMPOSITE_TOKENS = ("|", "&&", "||", ";", "$(", "`")

# 7. Output redirection to a file. We match a single `>` with a non-empty
#    target, with a negative-lookbehind that rejects `>>` (append), `2>` /
#    `&>` (stderr / merged redirects), `1>` (explicit stdout fd), and we
#    special-case `/dev/null` as "discard, not file-write".
#
#    Implementation: scan the command string for a `>` that is preceded by
#    a non-`&`, non-digit, non-`>` character (or whitespace / start of
#    string) and is NOT followed by another `>`. Then check the target
#    isn't `/dev/null`.
_REDIRECT_RE = re.compile(r"(?<![&\d>])>(?!>)\s*(?P<target>\S+)")


# ---------------------------------------------------------------------------
# v1.4.1: read / list / sudo-prefix patterns.
#
# Path-aware suggestion: when the path is unambiguously extractable, we
# match it against ``redact_paths_globs`` and route to the ``_redacted``
# variant when it hits. When the command shape is too complex to extract
# a single path (awk, sed, grep, file -- any of which take flags,
# expressions, or multiple files), we fall back to a path-agnostic
# rejection with the plain tool name; the LLM still gets the redirect.
#
# Trade-off documented per-pattern. INC-064 follow-up: this is a partial
# mitigation. ``awk '{print}' .env`` still works because we refuse to
# extract paths from awk; the spec accepts that as the doomed
# arms-race we declined to pursue.
# ---------------------------------------------------------------------------

# Single-path read commands. Optional flags consumed; the LAST whitespace-
# separated token is treated as the path. We accept ``head -n 100 path``
# and ``tail -n 100 path`` shapes; ``cat /path``, ``less /path``, etc.
_READ_SINGLE_RE = re.compile(
    r"^\s*(?P<cmd>cat|head|tail|less|more|view|xxd|od|strings|wc)"
    r"(?:\s+-\S+(?:\s+\S+)?)*"
    r"\s+(?P<path>\S+)\s*$"
)

# Ambiguous-path read commands: awk, sed, grep, file. These take filters,
# expressions, multiple files, or BRE/ERE patterns -- extracting a single
# path reliably is not feasible. We refuse with a generic message.
_READ_AMBIGUOUS_RE = re.compile(r"^\s*(?P<cmd>awk|sed|grep|file)\s+\S")

# ``ls`` with optional flags then a single path. We treat ls as path-aware
# but listing tools don't trip the redact list (we list directories, not
# secret files), so no _redacted variant -- always ``ssh_sftp_list``.
_LIST_SINGLE_RE = re.compile(r"^\s*ls(?:\s+-\w+)*\s+(?P<path>\S+)\s*$")

# Sudo-prefix variants. We strip the leading ``sudo\s+`` (and optional sudo
# flags ``-u user`` / ``-n`` / ``-S`` / ``-H`` / ``-i`` / ``-E`` -- the
# minimum operators typically pass) so the same path-extraction regexes
# match the inner command. The match is on the FULL command so we can
# decide path-aware-ness without re-running the regex.
_SUDO_PREFIX_RE = re.compile(
    r"^\s*sudo(?:\s+-[A-Za-z]+(?:\s+\S+)?)*\s+(?P<rest>.+)$",
    re.DOTALL,
)

# ``sudo tee <path>``: a tee redirect is the canonical "write a file with
# sudo" pattern (``echo ... | sudo tee /etc/foo``). The PIPED-IN content
# is what the operator wants to write; ``ssh_sudo_write(content_text=...)``
# is the structured equivalent.
_SUDO_TEE_RE = re.compile(r"^\s*tee(?:\s+-\S+)*\s+(?P<path>\S+)\s*$")

# ``sudo sh -c 'cat > <path>'`` and friends: the operator embeds a
# write redirect in a sudo-elevated shell. We extract the path between
# ``cat >`` and the next whitespace / quote. Catches the common
# ``sudo sh -c 'cat > /etc/foo'`` pattern; complex heredocs / pipes
# fall through (not caught here -- documented limit).
_SUDO_SH_C_CAT_RE = re.compile(
    r"""^\s*sh\s+-c\s+['"]\s*cat\s+>\s*(?P<path>[^\s'"]+).*['"]\s*$""",
)

# ``sudo <editor> <path>``: the operator is editing a privileged file
# interactively. ``ssh_sudo_edit`` (structured replace) is the better
# tool surface.
_SUDO_EDITOR_RE = re.compile(r"^\s*(?:vi|vim|nano|emacs|ed)\s+(?P<path>\S+)\s*$")


# Read commands -> non-sudo wrapper choice (plain / redacted variant
# decided per-call by ``_suggest_read_tool`` against redact_paths_globs).
_READ_PLAIN_TOOL = "ssh_sftp_download"
_READ_REDACTED_TOOL = "ssh_read_redacted"
_SUDO_READ_PLAIN_TOOL = "ssh_sudo_read"
_SUDO_READ_REDACTED_TOOL = "ssh_sudo_read_redacted"


# ---------------------------------------------------------------------------
# Docker subcommand -> suggested wrapper mapping. Best-effort; falls back
# to the generic "ssh_docker_* family" hint when we can't cheaply parse.
# ---------------------------------------------------------------------------

_DOCKER_DIRECT_SUBCOMMAND_TO_TOOL: dict[str, str] = {
    # read tier
    "ps": "ssh_docker_ps",
    "images": "ssh_docker_images",
    "inspect": "ssh_docker_inspect",
    "logs": "ssh_docker_logs",
    "stats": "ssh_docker_stats",
    "top": "ssh_docker_top",
    "events": "ssh_docker_events",
    "volumes": "ssh_docker_volumes",
    "volume": "ssh_docker_volumes",
    # exec / lifecycle
    "exec": "ssh_docker_exec",
    "run": "ssh_docker_run",
    "stop": "ssh_docker_stop",
    "start": "ssh_docker_start",
    "restart": "ssh_docker_restart",
    "kill": "ssh_docker_stop",
    "rm": "ssh_docker_rm",
    "rmi": "ssh_docker_rmi",
    "pull": "ssh_docker_pull",
    "prune": "ssh_docker_prune",
    "cp": "ssh_docker_cp",
}

_DOCKER_COMPOSE_SUBCOMMAND_TO_TOOL: dict[str, str] = {
    "up": "ssh_docker_compose_up",
    "down": "ssh_docker_compose_down",
    "pull": "ssh_docker_compose_pull",
    "start": "ssh_docker_compose_start",
    "stop": "ssh_docker_compose_stop",
    "restart": "ssh_docker_compose_restart",
    "ps": "ssh_docker_compose_ps",
    "logs": "ssh_docker_compose_logs",
}

_DOCKER_FAMILY_FALLBACK = "ssh_docker_* family"


def _suggest_docker_tool(command: str) -> str:
    """Best-effort parse of `docker <subcommand>` -> wrapper tool name.

    Returns the family-level fallback when the subcommand isn't a clean
    one-to-one map (e.g. ``docker network ls``, ``docker buildx ...``).
    """
    parts = command.strip().split()
    # parts[0] is "docker" by the time we get here.
    if len(parts) < 2:
        return _DOCKER_FAMILY_FALLBACK
    sub = parts[1]
    if sub == "compose" and len(parts) >= 3:
        verb = parts[2]
        return _DOCKER_COMPOSE_SUBCOMMAND_TO_TOOL.get(verb, "ssh_docker_compose_* family")
    return _DOCKER_DIRECT_SUBCOMMAND_TO_TOOL.get(sub, _DOCKER_FAMILY_FALLBACK)


def _suggest_systemctl_tool(verb: str) -> str:
    """Map ``systemctl <verb>`` -> ``ssh_systemctl_<verb>`` (hyphen->underscore)."""
    return f"ssh_systemctl_{verb.replace('-', '_')}"


def _suggest_apt_tool(verb: str) -> str:
    """Map ``apt <verb>`` -> ``ssh_apt_<verb>``. ``purge`` shares ``ssh_apt_remove``."""
    if verb == "purge":
        return "ssh_apt_remove"
    return f"ssh_apt_{verb}"


def _suggest_fileop_tool(op: str, command: str) -> str:
    """Map ``mkdir`` / ``cp`` / ``mv`` / ``rm`` -> the structured tool.

    ``rm -rf`` redirects to ``ssh_delete_folder``; bare ``rm`` to
    ``ssh_delete``. ``mkdir``/``cp``/``mv`` map 1:1.
    """
    if op == "mkdir":
        return "ssh_mkdir"
    if op == "cp":
        return "ssh_cp"
    if op == "mv":
        return "ssh_mv"
    # rm: detect -rf / -fr / -r anywhere in argv to suggest delete_folder.
    if re.search(r"\s-[A-Za-z]*r[A-Za-z]*\b", command):
        return "ssh_delete_folder"
    return "ssh_delete"


def _is_composite(command: str) -> bool:
    """True if the command contains shell separators / command substitution.

    Used to suppress the single-fileop pattern when the operator is
    intentionally chaining multiple operations -- those are legitimate
    composite scripts that the cheatsheet must not break.
    """
    return any(tok in command for tok in _COMPOSITE_TOKENS)


def _suggest_read_tool(
    path: str | None,
    *,
    sudo: bool,
    policy: HostPolicy | None,
    settings: Settings | None,
) -> tuple[str, bool]:
    """Pick the right read-wrapper for a single-file read pattern.

    Returns ``(suggested_tool, hit_redact_globs)``. When ``path`` is
    unambiguously extractable AND the caller supplied a ``policy`` +
    ``settings``, we glob-match the path against
    ``redact_paths_globs``; a hit routes to the ``_redacted`` variant.

    Caveat: the path comes from the raw command string, not from
    ``realpath`` -- doing a remote canonicalization at cheatsheet-time
    would force an SSH call before the precheck even completes. Globs
    are typically operator-set against the SAME path shapes the LLM
    types (``/opt/app/.env``, ``**/.env``), so the raw match is the
    common case. Operators who set redact globs against canonical
    paths the LLM never references will see the plain tool suggested
    here -- still correct, just less specific.

    When ``path is None`` (extraction failed because the shape is
    ambiguous) or ``policy``/``settings`` were not threaded through,
    we fall back to the plain variant. The human_explanation surfaces
    both alternatives in that case.
    """
    # Choose the family up front -- sudo-tier vs plain.
    plain = _SUDO_READ_PLAIN_TOOL if sudo else _READ_PLAIN_TOOL
    redacted = _SUDO_READ_REDACTED_TOOL if sudo else _READ_REDACTED_TOOL
    if path is None or policy is None or settings is None:
        return plain, False
    # Local import: redact_policy depends on Settings/HostPolicy which we
    # already type-check under TYPE_CHECKING; runtime import stays
    # call-site-local to mirror the cheatsheet_precheck audit-coupling
    # pattern.
    from .redact_policy import path_matches_redact_globs, resolve_redact_paths_globs

    globs = resolve_redact_paths_globs(policy, settings)
    if path_matches_redact_globs(path, globs, platform=policy.platform):
        return redacted, True
    return plain, False


def _redirect_target_is_real_file(command: str) -> str | None:
    """Return a non-``/dev/null`` redirect target, or ``None``.

    Walks all `>` matches; returns the first target that isn't ``/dev/null``.
    If every match is to /dev/null (discard), returns ``None`` (no cheatsheet
    hit -- discard is a legitimate exec-tier pattern).
    """
    for m in _REDIRECT_RE.finditer(command):
        target = m.group("target")
        if target != "/dev/null":
            return target
    return None


# ---------------------------------------------------------------------------
# Public matcher.
# ---------------------------------------------------------------------------


def _match_sudo_inner(
    inner: str,
    policy: HostPolicy | None,
    settings: Settings | None,
) -> CheatsheetMatch | None:
    """Match the body of a ``sudo <flags> <inner>`` command.

    Returns a :class:`CheatsheetMatch` for sudo-tier read / write / edit /
    list shapes, or ``None`` when the inner shape doesn't match any
    sudo-specific pattern (caller falls through to the regular
    matcher; that's how ``sudo docker ps`` still hits the docker
    pattern). ``_is_composite`` is applied per-shape so ``sudo cat /etc/foo
    | grep ...`` still passes through as legitimate exec-tier shell.
    """
    # Read shapes -> ssh_sudo_read / ssh_sudo_read_redacted.
    m_read = _READ_SINGLE_RE.match(inner)
    if m_read is not None and not _is_composite(inner):
        path = m_read.group("path")
        suggested, hit_redact = _suggest_read_tool(path, sudo=True, policy=policy, settings=settings)
        explanation = (
            "sudo read of a path matching redact_paths_globs; "
            "ssh_sudo_read_redacted is the intended alternative."
            if hit_redact
            else "sudo single-file read; ssh_sudo_read is path-policy-checked and audited."
        )
        return CheatsheetMatch(
            pattern_id="sudo-read-single",
            suggested_tool=suggested,
            human_explanation=explanation,
        )
    # Ambiguous read shapes still get rejected -- but to the sudo-tier
    # generic tool so the LLM doesn't switch off sudo just to comply.
    m_ambig = _READ_AMBIGUOUS_RE.match(inner)
    if m_ambig is not None and not _is_composite(inner):
        return CheatsheetMatch(
            pattern_id="sudo-read-single",
            suggested_tool=_SUDO_READ_PLAIN_TOOL,
            human_explanation=(
                f"sudo `{m_ambig.group('cmd')}` -- path extraction refused. "
                "Use ssh_sudo_read for sudo-elevated single-file reads, or "
                "ssh_sudo_read_redacted for secret-bearing paths."
            ),
        )
    # ``sudo tee <path>`` -> ssh_sudo_write.
    m_tee = _SUDO_TEE_RE.match(inner)
    if m_tee is not None and not _is_composite(inner):
        return CheatsheetMatch(
            pattern_id="sudo-write-single",
            suggested_tool="ssh_sudo_write",
            human_explanation=(
                "sudo tee redirect is a privileged file write; ssh_sudo_write "
                "is atomic, path-policy-checked, and preserves ownership."
            ),
        )
    # ``sudo sh -c 'cat > /path'`` -> ssh_sudo_write.
    m_shc = _SUDO_SH_C_CAT_RE.match(inner)
    if m_shc is not None:
        return CheatsheetMatch(
            pattern_id="sudo-write-single",
            suggested_tool="ssh_sudo_write",
            human_explanation=(
                "sudo heredoc-style write; ssh_sudo_write delivers the same "
                "result atomically, with path-policy checks and audit."
            ),
        )
    # ``sudo vi|vim|nano|emacs|ed <path>`` -> ssh_sudo_edit.
    m_edit = _SUDO_EDITOR_RE.match(inner)
    if m_edit is not None and not _is_composite(inner):
        return CheatsheetMatch(
            pattern_id="sudo-edit-single",
            suggested_tool="ssh_sudo_edit",
            human_explanation=(
                "Interactive editor under sudo is not feasible over the MCP "
                "channel; ssh_sudo_edit does a structured atomic replace."
            ),
        )
    # ``sudo ls <path>`` -> ssh_sudo_sftp_list.
    m_ls = _LIST_SINGLE_RE.match(inner)
    if m_ls is not None and not _is_composite(inner):
        return CheatsheetMatch(
            pattern_id="sudo-list-single",
            suggested_tool="ssh_sudo_sftp_list",
            human_explanation=(
                "sudo directory listing; ssh_sudo_sftp_list is path-policy-checked "
                "and returns typed entries."
            ),
        )
    return None


def match_cheatsheet(
    command: str,
    *,
    policy: HostPolicy | None = None,
    settings: Settings | None = None,
) -> CheatsheetMatch | None:
    """Match ``command`` against the cheatsheet pattern classes.

    Returns the first matching :class:`CheatsheetMatch`, or ``None`` if the
    command looks like legitimate exec-tier shell. Empty / whitespace-only
    commands return ``None`` (``check_command`` will reject them later as
    "command is empty").

    ``policy`` + ``settings`` (v1.4.1) enable the path-aware suggestion
    for single-file read patterns: when a path is unambiguously extractable
    from the command and it matches ``redact_paths_globs``, the suggestion
    routes to the ``_redacted`` variant. Omit both to keep the match
    path-agnostic (the existing behavior for callers that have no policy
    handy).

    Order of patterns:
      1. Sudo-prefix variants (v1.4.1): sudo cat / head / tail / less /
         ... / tee / sh -c 'cat > ...' / vi / vim / nano / emacs / ed /
         ls. The inner shape decides the suggestion.
      2. Single-file read shapes: cat / head / tail / less / more /
         view / xxd / od / strings / wc.
      3. Ambiguous-path read shapes: awk / sed / grep / file -- path
         extraction refused, path-agnostic fallback.
      4. Single-path ``ls`` listing.
      5. ``docker`` -- catch any leading ``docker`` first; the wrappers cover
         ~22 tools.
      6. ``systemctl <verb>`` for the 16 wrapper-covered verbs.
      7. ``journalctl`` -- single wrapper, broad regex.
      8. ``apt`` / ``apt-get`` mutation verbs.
      9. Heredoc / tee / echo>/printf> file-writes.
      10. Single-statement ``mkdir`` / ``cp`` / ``mv`` / ``rm`` (composite-safe).
      11. Generic output redirection to a real file (``> /dev/null`` excluded).
    """
    if not command or not command.strip():
        return None

    # 0. Sudo-prefix: strip the leading sudo and route to the inner
    # matcher path-aware variants. If no sudo-specific shape matches,
    # recurse on the inner command so ``sudo docker ps`` still hits the
    # docker pattern (a legitimate use of sudo for docker on hardened
    # hosts where the ssh-user isn't in the docker group).
    m_sudo = _SUDO_PREFIX_RE.match(command)
    if m_sudo is not None:
        inner = m_sudo.group("rest")
        sudo_match = _match_sudo_inner(inner, policy, settings)
        if sudo_match is not None:
            return sudo_match
        # Recurse on inner: the regular docker / systemctl / journalctl /
        # apt / heredoc / single-fileop / output-redirect patterns expect
        # the command to start with the verb, not with "sudo". The
        # recursion is bounded -- _SUDO_PREFIX_RE requires "sudo <flags>
        # <something>", so once the prefix is gone the next call cannot
        # match _SUDO_PREFIX_RE again unless the operator wrote
        # ``sudo sudo cmd`` which is itself worth flagging at the
        # downstream layer.
        inner_match = match_cheatsheet(inner, policy=policy, settings=settings)
        if inner_match is not None:
            return inner_match

    # 1. Single-file read (non-sudo). Path-aware.
    m_read = _READ_SINGLE_RE.match(command)
    if m_read is not None and not _is_composite(command):
        path = m_read.group("path")
        suggested, hit_redact = _suggest_read_tool(path, sudo=False, policy=policy, settings=settings)
        explanation = (
            "path matches redact_paths_globs; the redacted variant is the " "intended alternative."
            if hit_redact
            else "single-file read; the SFTP-backed tool is path-policy-checked and audited."
        )
        return CheatsheetMatch(
            pattern_id="read-single",
            suggested_tool=suggested,
            human_explanation=explanation,
        )

    # 2. Ambiguous read shape -- refuse path extraction, generic fallback.
    m_ambig = _READ_AMBIGUOUS_RE.match(command)
    if m_ambig is not None and not _is_composite(command):
        return CheatsheetMatch(
            pattern_id="read-ambiguous",
            suggested_tool=_READ_PLAIN_TOOL,
            human_explanation=(
                f"`{m_ambig.group('cmd')}` takes flags / expressions / multiple files; "
                "the cheatsheet cannot extract a single path. Use ssh_sftp_download "
                "for reads, ssh_read_redacted for secret-bearing paths, and the "
                "structured tools (ssh_find, ssh_edit) for search / edit."
            ),
        )

    # 3. ``ls <path>`` listing (no redaction routing -- ls is directory-level).
    m_ls = _LIST_SINGLE_RE.match(command)
    if m_ls is not None and not _is_composite(command):
        return CheatsheetMatch(
            pattern_id="list-single",
            suggested_tool="ssh_sftp_list",
            human_explanation=(
                "Single-path `ls` listing; ssh_sftp_list is path-policy-checked, "
                "paginated, and returns typed entries."
            ),
        )

    # 1. Docker.
    if _DOCKER_RE.match(command):
        return CheatsheetMatch(
            pattern_id="docker",
            suggested_tool=_suggest_docker_tool(command),
            human_explanation=(
                "Raw `docker` invocation; use the native MCP wrapper for "
                "policy-gated, audited, structured output."
            ),
        )

    # 2. systemctl <verb>.
    m_systemctl = _SYSTEMCTL_RE.match(command)
    if m_systemctl is not None:
        verb = m_systemctl.group("verb")
        return CheatsheetMatch(
            pattern_id="systemctl",
            suggested_tool=_suggest_systemctl_tool(verb),
            human_explanation=(
                f"`systemctl {verb}` is covered by a dedicated MCP tool with "
                "narrower allowlist + structured result."
            ),
        )

    # 3. journalctl.
    if _JOURNALCTL_RE.match(command):
        return CheatsheetMatch(
            pattern_id="journalctl",
            suggested_tool="ssh_journalctl",
            human_explanation=(
                "Raw `journalctl` invocation; use ssh_journalctl for "
                "policy-gated tailing with typed records."
            ),
        )

    # 4. apt / apt-get mutation verbs.
    m_apt = _APT_MUTATION_RE.match(command)
    if m_apt is not None:
        verb = m_apt.group("verb")
        return CheatsheetMatch(
            pattern_id="apt-mutation",
            suggested_tool=_suggest_apt_tool(verb),
            human_explanation=(
                f"`apt {verb}` is a mutating package operation; the dedicated "
                "MCP wrapper enforces sudo + audit and returns a structured "
                "summary."
            ),
        )

    # 5. Heredoc / tee / echo+printf-to-file. All map to ssh_upload.
    if (
        _HEREDOC_RE.search(command)
        or _TEE_RE.search(command)
        or _ECHO_REDIRECT_RE.match(command)
        or _PRINTF_REDIRECT_RE.match(command)
    ):
        return CheatsheetMatch(
            pattern_id="heredoc",
            suggested_tool="ssh_upload",
            human_explanation=(
                "Heredoc / tee / echo > path / printf > path is a file write; "
                "use ssh_upload(content_text=...) for atomic, audited, "
                "path-policy-checked writes."
            ),
        )

    # 6. Single-statement fileop.
    m_fileop = _FILEOP_START_RE.match(command)
    if m_fileop is not None and not _is_composite(command):
        op = m_fileop.group("op")
        return CheatsheetMatch(
            pattern_id="single-fileop",
            suggested_tool=_suggest_fileop_tool(op, command),
            human_explanation=(
                f"Single `{op}` invocation has a dedicated SFTP-backed tool "
                "with path-policy gating and typed result."
            ),
        )

    # 7. Generic output redirect to a real file.
    if _redirect_target_is_real_file(command) is not None:
        return CheatsheetMatch(
            pattern_id="output-redirect",
            suggested_tool="ssh_upload",
            human_explanation=(
                "Output redirection to a file (`>`) writes a file via shell; "
                "use ssh_upload(content_text=...) or ssh_deploy instead."
            ),
        )

    return None


# ---------------------------------------------------------------------------
# B2: output-warnings hint footer for the opt-out path.
# ---------------------------------------------------------------------------


def cheatsheet_hint_warning(*, match: CheatsheetMatch, tool_name: str) -> str:
    """Build the output_warnings string for an exec that matched a cheatsheet
    pattern under the SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS opt-out.

    tool_name is the public name of the tool that ran (e.g. 'ssh_exec_run',
    'ssh_sudo_exec') -- surfaces in the hint so the LLM sees the right
    refactoring target.
    """
    return (
        f"{tool_name} command matched cheatsheet pattern "
        f"'{match.pattern_id}'; consider {match.suggested_tool} next time"
    )


# ---------------------------------------------------------------------------
# B1: rejection message + precheck (used by ssh_exec_run / _streaming /
# ssh_sudo_exec). Co-located here so the matcher, the message, and the
# precheck-or-raise decision live in one module -- tool layers only need
# to import ``cheatsheet_precheck``.
# ---------------------------------------------------------------------------


def build_cheatsheet_rejection_message(match: CheatsheetMatch, *, tool_name: str) -> str:
    """Standard rejection message format used by the exec-tier tools.

    ``tool_name`` is the public name of the tool that refused the command --
    surfaces in the message so the LLM does not mis-attribute the rejection
    (e.g. seeing "ssh_exec_run refused" after calling ssh_sudo_exec).
    """
    return (
        f"{tool_name} refused: command matched cheatsheet pattern "
        f"'{match.pattern_id}'. Use {match.suggested_tool} instead -- "
        f"it is safer (policy-checked, audited) and structured (typed "
        f"result instead of raw stdout). To bypass this check for legacy "
        f"automation, set SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true. The "
        f"opt-out is a temporary escape hatch, not a recommended workflow."
    )


def cheatsheet_precheck(
    command: str,
    allow_cheatsheet: bool,
    *,
    tool_name: str,
    policy: HostPolicy | None = None,
    settings: Settings | None = None,
) -> CheatsheetMatch | None:
    """Compute the cheatsheet match unconditionally; raise only if the
    operator hasn't opted out.

    The match is returned to the caller even when the opt-out is on so the
    B2 output-warnings wiring can surface "this command WOULD have been
    rejected; consider switching to <wrapper>" without re-running the
    matcher. ``None`` return means no pattern hit.

    ``tool_name`` flows into the rejection message so each calling tool
    (ssh_exec_run / _streaming / ssh_sudo_exec) gets its own name in the
    error rather than always "ssh_exec_run".

    On the opt-out path (allow_cheatsheet=True, match present), the
    matched ``pattern_id`` is stashed via
    :func:`ssh_mcp.services.audit.set_cheatsheet_bypass` so the audit line
    for this call gains a ``cheatsheet_pattern_id`` field. Operators
    grep ``jq 'select(.cheatsheet_pattern_id)'`` to count opt-out abuse
    by pattern without standing up a separate counter / dashboard.
    """
    match = match_cheatsheet(command, policy=policy, settings=settings) if command else None
    if match is not None:
        if not allow_cheatsheet:
            raise CommandIsCheatsheetMatch(
                pattern_id=match.pattern_id,
                command=command,
                suggested_tool=match.suggested_tool,
                message=build_cheatsheet_rejection_message(match, tool_name=tool_name),
            )
        # Local import: services.audit imports from ssh.errors, this module
        # imports from ssh.errors too -- no cycle, but we keep the import
        # call-site-local so test monkeypatching is straightforward and so
        # the rest of the module stays free of audit coupling.
        from .audit import set_cheatsheet_bypass

        set_cheatsheet_bypass(match.pattern_id)
    return match
