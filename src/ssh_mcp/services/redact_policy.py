"""Configuration resolution + glob matching for the secret-redaction layer.

Pure helpers that bridge ``Settings`` (env-level) and ``HostPolicy``
(per-host overrides) into the values the redactor and bypass-check
consume. No I/O, no SSH -- safe to call from anywhere on the request
path.

Resolution rule across every knob: per-host overrides env, never the
other way around. The mutex between ``redact_keys_add`` and
``redact_keys_replace`` is enforced at BOTH scopes (env via
``Settings._check_redact_config``, per-host via ``HostPolicy._check_redact_keys_mutex``);
this module therefore never sees both set on the same scope, but it
still computes the union the obvious way: per-host REPLACE wins outright,
otherwise per-host ADD and env-level ADD both append to the defaults.

See ADR-pending / SKILL.md / docstrings in :mod:`ssh_mcp.services.redactor`
for the actual redaction semantics; this module is purely the configuration
plumbing.
"""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ..config import Settings
    from ..models.policy import HostPolicy


# Built-in default redact-key list. Case-insensitive substring match on the
# KEY name in KEY=VALUE shape. Order is irrelevant -- the redactor uses a
# frozenset. Kept short and well-known on purpose: operators who need a
# specific token (project-internal "DB_TOKEN_V2", etc.) append it via
# ``SSH_REDACT_KEYS_ADD`` rather than the engine guessing.
_DEFAULT_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "PASSWORD",
        "PASSWD",
        # Anchored PASS variants: catch DB_PASS / USER_PASS / PASS_HEADER
        # without triggering on BYPASS_* / COMPASS_* (which the unanchored
        # substring `PASS` would otherwise over-match). See `_key_matches`
        # in redactor.py for the anchor semantics.
        "^PASS_",
        "_PASS$",
        "SECRET",
        "TOKEN",
        "KEY",
        "PRIVATE",
        "CREDENTIAL",
        "CREDENTIALS",
        "API_KEY",
        "APIKEY",
        "DSN",
        "AUTH",
        "BEARER",
        "COOKIE",
        "SESSION",
        "JWT",
        "OAUTH",
        "SSH_KEY",
    }
)


BypassMode = Literal["block", "warn", "audit_only"]


def default_redact_keys() -> frozenset[str]:
    """Return the immutable built-in default list. Test surface only."""
    return _DEFAULT_REDACT_KEYS


def resolve_redact_keys(policy: HostPolicy, settings: Settings) -> frozenset[str]:
    """Compute the active redact-key set for one host.

    Rules:

    - ``policy.redact_keys_replace`` set (non-empty): use that verbatim
      (per-host REPLACE wins outright; env additions ignored, defaults
      dropped).
    - Else ``settings.SSH_REDACT_KEYS_REPLACE`` set: use that verbatim.
    - Else: defaults + ``settings.SSH_REDACT_KEYS_ADD`` + ``policy.redact_keys_add``.

    Tokens are uppercased for the case-insensitive substring match the
    redactor does later. We don't dedupe here -- frozenset construction
    handles it for free.
    """
    if policy.redact_keys_replace:
        return frozenset(k.upper() for k in policy.redact_keys_replace)
    if settings.SSH_REDACT_KEYS_REPLACE:
        return frozenset(k.upper() for k in settings.SSH_REDACT_KEYS_REPLACE)
    return _DEFAULT_REDACT_KEYS | frozenset(
        k.upper() for k in (*settings.SSH_REDACT_KEYS_ADD, *policy.redact_keys_add)
    )


def resolve_redact_paths_globs(policy: HostPolicy, settings: Settings) -> list[str]:
    """Union of per-host + env-level redact-path globs. Order: host first,
    then env. Dedup preserves order so the first matcher is the host's.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for g in (*policy.redact_paths_globs, *settings.SSH_REDACT_PATHS_GLOBS):
        if g not in seen:
            seen.add(g)
            merged.append(g)
    return merged


def resolve_restricted_globs(policy: HostPolicy, settings: Settings) -> list[str]:
    """Union of per-host + env-level restricted-path globs.

    Parallel shape to :func:`resolve_redact_paths_globs` -- different list,
    different semantics. ``restricted_globs`` is hard-deny; ``redact_paths_globs``
    routes through the bypass policy.
    """
    merged: list[str] = []
    seen: set[str] = set()
    for g in (*policy.restricted_globs, *settings.SSH_RESTRICTED_GLOBS):
        if g not in seen:
            seen.add(g)
            merged.append(g)
    return merged


def resolve_bypass_policy(policy: HostPolicy, settings: Settings) -> BypassMode:
    """Per-host overrides env. None on the host means inherit."""
    if policy.redact_bypass_policy is not None:
        return policy.redact_bypass_policy
    return settings.SSH_REDACT_BYPASS_POLICY


def resolve_entropy_detection(policy: HostPolicy, settings: Settings) -> bool:
    """Per-host overrides env. None on the host means inherit."""
    if policy.redact_entropy_detection is not None:
        return policy.redact_entropy_detection
    return settings.SSH_REDACT_ENTROPY_DETECTION


def resolve_hint_chars(policy: HostPolicy, settings: Settings) -> int:
    """Per-host overrides env. Clamped to ``[0, 4]`` defensively even though
    both source paths already validate -- the cap is a security boundary,
    not a hint, so we double-belt it here.
    """
    raw = policy.redact_hint_chars if policy.redact_hint_chars is not None else settings.SSH_REDACT_HINT_CHARS
    return max(0, min(4, raw))


def resolve_salt(settings: Settings) -> str:
    """Return the HMAC salt. No per-host override -- the salt is an
    operator secret keyed to the deployment, not the target host.
    """
    return settings.SSH_REDACT_SALT


def path_matches_redact_globs(
    canonical_path: str,
    globs: list[str],
    *,
    platform: Literal["posix", "windows"] = "posix",
) -> bool:
    """True iff ``canonical_path`` matches any glob in ``globs``.

    Empty globs list returns ``False`` (the common case -- most hosts have
    no redact globs). POSIX hosts use :class:`pathlib.PurePosixPath.match`;
    Windows hosts route through :class:`PurePathWindowsPath.match`. Both
    map the same glob syntax (``*`` / ``?`` / ``**``) onto their respective
    separators.

    The match is path-prefix-sensitive in the standard pathlib sense: a glob
    of ``**/.env`` matches ``/opt/app/.env`` and ``/.env`` (the ``**`` allows
    zero or more leading components). A glob of ``/etc/*`` matches direct
    children of ``/etc``, not deeper -- use ``/etc/**`` for that.
    """
    if not globs:
        return False
    if platform == "windows":
        p_win = PureWindowsPath(canonical_path)
        return any(p_win.match(g) for g in globs)
    p_posix = PurePosixPath(canonical_path)
    return any(p_posix.match(g) for g in globs)


def should_block_redact_bypass(
    canonical_path: str,
    policy: HostPolicy,
    settings: Settings,
) -> bool:
    """True iff the path is on the redact list AND the policy says ``block``.

    Called from ``resolve_path`` (path_policy) so the standard low-access
    refuse-path raises before the tool body even runs. Tools that catch
    :class:`RedactBypassBlocked` surface it the same way they surface
    :class:`PathRestricted`.

    Note on audit: ``block`` mode deliberately does NOT stamp the audit-line
    ``redact_bypass`` flag (see :func:`check_redact_bypass`'s side-effect
    docstring). The raise itself produces an audit line with
    ``result=error`` + the exception class, which already records the
    intent — adding a redundant ``redact_bypass=true`` to a failure line
    would just noise up the schema.
    """
    if resolve_bypass_policy(policy, settings) != "block":
        return False
    return path_matches_redact_globs(
        canonical_path,
        resolve_redact_paths_globs(policy, settings),
        platform=policy.platform,
    )


def check_redact_bypass(
    canonical_path: str,
    policy: HostPolicy,
    settings: Settings,
) -> BypassMode | None:
    """Return the bypass mode that applies, or ``None`` when the path
    is not on the redact list.

    Used by path-bearing tools AFTER ``resolve_path`` succeeds. ``None``
    means "no special handling -- normal flow". ``block`` would already
    have raised via ``should_block_redact_bypass`` upstream; here it's
    just informational so the tool's own ``output_warnings`` code path
    can stay uniform. ``warn`` tells the tool to attach a warning to
    its result. ``audit_only`` is the audit-decorator's signal.

    Side-effect (v1.5.0 audit_only completion): when the resolved mode
    is ``warn`` or ``audit_only`` -- i.e. the call is about to deliver
    raw bytes from a redact-list path -- this flips a per-call ContextVar
    in ``services.audit`` so the ``@audited`` wrapper stamps
    ``redact_bypass: true`` onto the audit line. ``warn`` does BOTH (set
    the audit flag AND return the mode so the tool surfaces
    REDACT_BYPASS_WARNING to the LLM); ``audit_only`` only sets the audit
    flag -- the returned mode is the tool's signal to stay silent toward
    the LLM. ``block`` raised upstream and never reaches here.
    """
    if not path_matches_redact_globs(
        canonical_path,
        resolve_redact_paths_globs(policy, settings),
        platform=policy.platform,
    ):
        return None
    mode = resolve_bypass_policy(policy, settings)
    if mode in ("warn", "audit_only"):
        # Local import: ``services.audit`` doesn't import this module, but the
        # symmetric pattern (see ``exec_cheatsheet.cheatsheet_precheck``) keeps
        # the coupling call-site-local for easier test monkeypatching and
        # avoids a top-level import that would otherwise be a load-order
        # surprise for anyone touching either module.
        from .audit import set_redact_bypass_active

        set_redact_bypass_active(True)
    return mode


# Standard warning string attached to ``output_warnings`` in ``warn`` mode.
# Kept in one place so every tool surfaces identical wording -- makes both
# the SKILL docs and any operator parser deterministic.
REDACT_BYPASS_WARNING = "redact-list path: prefer ssh_read_redacted (this delivered raw secrets to the LLM)"
