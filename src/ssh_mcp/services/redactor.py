"""Secret-redaction engine. Pure functions, no I/O, no SSH.

The engine takes a string of file content + the resolved policy bits
(redact-key set, salt, hint chars, entropy toggle, format) and returns
the redacted string plus a list of :class:`RedactionRecord` describing
WHAT was redacted. The LLM consumes both: inline hashes let it reason
about the file's structure, the records list gives it a structured
view ("the DB_PASSWORD on line 4 hashed to abc123") without re-parsing.

Hash output format
------------------

For every redacted value we emit ``<sha:<12hex> len:<N>>``. The hex
prefix is HMAC-SHA256(salt, value)[:12] when salt is set, else plain
SHA256(value)[:12]. Both are deterministic across calls, so the same
secret on two hosts hashes identically -- which is the whole point:
the LLM can compare ``DB_PASSWORD`` across the fleet without seeing
the plaintext.

Optionally a ``hint:<first-N>...<last-N>`` segment leaks 2N characters
of the raw secret. Capped at 4 each side; the caller (``redact_policy.
resolve_hint_chars``) already enforces the cap, and we re-enforce
defensively here so a smuggled call with hint=99 still can't dump the
secret.

Per-format parsers
------------------

Format-specific patterns line-by-line:

- env / ini : ``KEY=VALUE`` line shape, KEY case-insensitive substring
  match against the redact set.
- yaml      : ``key: value`` line shape. Multi-line block scalars and
  flow-style mappings are NOT handled -- they pass through unchanged.
  Documented limit; a later sprint can add proper YAML support if a
  real-world config makes the regex insufficient.
- json      : ``"key": "value"`` regex. String values only. Nested
  arrays / objects are NOT redacted -- documented limit.
- generic   : applies env, then yaml, then json regexes sequentially,
  optionally followed by entropy detection.

Entropy detection
-----------------

When the per-host toggle is on, the redactor ALSO scans the
post-key-match text for:

- base64-shaped strings >= 20 chars (chars ``[A-Za-z0-9+/=]``)
- hex strings >= 32 chars
- PEM blocks (``-----BEGIN ... -----END ...``) -- always redacted
  regardless of toggle.

Comment-leading matches (line starts with ``#`` or ``//``) skip the
entropy redactor on the assumption they're log hashes, git SHAs, or
documentation, not live secrets. Already-redacted markers
(``<sha:...>``) also skip to avoid re-redacting our own output.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Literal

# Public format types. ``generic`` is the catch-all -- it tries env, then
# yaml, then json, then (optionally) entropy detection.
Format = Literal["env", "yaml", "json", "ini", "generic"]


@dataclass(frozen=True)
class RedactionRecord:
    """One redaction the engine performed.

    Fields
    ------
    key : str | None
        Name of the KEY=VALUE key when matched (e.g. ``"DB_PASSWORD"``).
        None for entropy-detected hits (no key on the line, just a
        suspicious-shaped string).
    hash : str
        The 12-char hex prefix that was emitted inline. Lets the caller
        correlate a record back to the marker without re-parsing.
    line : int | None
        1-indexed line number in the original text. None for cross-line
        matches (PEM blocks).
    kind : Literal["key_match", "entropy_base64", "entropy_hex", "pem_block"]
        Which branch produced the record. Useful for the LLM to reason
        about confidence ("entropy_hex on a config line is probably a
        legitimate hash; key_match on PASSWORD is definitely a secret").
    """

    key: str | None
    hash: str
    line: int | None
    kind: Literal["key_match", "entropy_base64", "entropy_hex", "pem_block"]


# --- regex patterns ------------------------------------------------------
#
# Kept as module-level compiled patterns so a hot path (reading many small
# config files) doesn't re-compile on every call.

# env / ini: ``KEY=VALUE`` with optional leading whitespace + flexible
# spacing around ``=``. Identifier shape ``[A-Z_][A-Z0-9_]*`` is the
# conventional env var name; we match it case-insensitively against the
# resolved redact-key set.
_ENV_LINE_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.+?)(\s*)$")

# yaml: ``key: value`` -- key is a yaml-style identifier (letters, digits,
# underscore, dash, dot), value is the rest of the line. We deliberately
# don't try to handle block scalars (``|`` / ``>``) or flow mappings.
_YAML_LINE_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_.\-]*)(\s*:\s*)(.+?)(\s*)$")

# json: ``"key": "value"`` -- string values only. ``(?:[^"\\]|\\.)`` allows
# backslash-escape sequences (``\"``, ``\\``, ``\n``, ``\uXXXX``) inside both
# spans, so a value like ``"p\"ass"`` is captured intact instead of silently
# leaking past a too-narrow ``[^"\\]+``. Nested structures (arrays, objects)
# NOT supported. The hash is computed over the JSON-encoded form -- two files
# with the same logical value but different escape styles will hash
# differently; in practice secrets are escape-free tokens.
_JSON_PAIR_RE = re.compile(r'"((?:[^"\\]|\\.)+)"\s*:\s*"((?:[^"\\]|\\.)*)"')

# entropy: base64-shape (letters/digits/+//=) of length >= 20, not bordered
# by a word char (avoids matching inside identifiers) or by ``<`` (avoids
# re-matching ``<sha:...>``).
_ENTROPY_BASE64_RE = re.compile(r"(?<![\w<])[A-Za-z0-9+/]{20,}={0,2}(?![\w])")

# entropy: hex-shape >= 32 chars, same border rules.
_ENTROPY_HEX_RE = re.compile(r"(?<![\w<])[a-fA-F0-9]{32,}(?![\w])")

# PEM blocks: greedy multi-line match for the BEGIN...END envelope. The
# (?s) inline flag means ``.`` matches newlines too. Always redacted.
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----", re.DOTALL)

# Border helpers for the "is this match inside a comment?" check.
_COMMENT_PREFIX_RE = re.compile(r"^\s*(?:#|//)")


def _hash_value(value: str, salt: str) -> str:
    """Compute the 12-char hex prefix for one secret value.

    HMAC-SHA256(salt, value)[:12] when salt is non-empty, else plain
    SHA256(value)[:12]. Both are deterministic so the same plaintext
    always maps to the same prefix -- which is the whole point of the
    layer.
    """
    if salt:
        digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    else:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


def _format_marker(value: str, salt: str, hint_chars: int) -> str:
    """Build the inline replacement string for one value.

    Shape: ``<sha:<12hex> len:<N>>`` plus optional ``hint:<first>...<last>``
    when ``hint_chars > 0``. We CLAMP hint_chars to ``[0, 4]`` defensively
    here even though the resolver already capped it -- a smuggled-in
    call should not be able to dump the secret.
    """
    h = _hash_value(value, salt)
    n = len(value)
    hint_chars = max(0, min(4, hint_chars))
    if hint_chars > 0 and n >= 2 * hint_chars:
        first = value[:hint_chars]
        last = value[-hint_chars:]
        return f"<sha:{h} len:{n} hint:{first}...{last}>"
    return f"<sha:{h} len:{n}>"


def _key_matches(key: str, redact_keys: frozenset[str]) -> bool:
    """Case-insensitive match: KEY matches if any redact token matches.

    Four token shapes (all uppercased):

    - ``"PASSWORD"`` (no anchor)  -> **substring** match.
      ``PASSWORD`` matches ``DB_PASSWORD``, ``OLD_PASSWORD``, plain
      ``PASSWORD``. The default mode; operators rarely list every prefix
      variation, the substring catches them all.
    - ``"^PASS_"`` (start anchor) -> KEY must START with ``PASS_``.
      Matches ``PASS_HEADER``, ``PASS_FILE``; does NOT match
      ``BYPASS_FOO`` (where the substring ``PASS_`` would otherwise hit).
    - ``"_PASS$"`` (end anchor)   -> KEY must END with ``_PASS``.
      Matches ``DB_PASS``, ``USER_PASS``; does NOT match ``BYPASS``
      (where ``PASS`` substring would otherwise hit).
    - ``"^FOO$"`` (both anchors)  -> **exact** match. ``FOO`` only.

    Anchors are an escape hatch for tokens whose unanchored substring
    would over-match (``PASS`` substring would catch ``BYPASS_*`` /
    ``COMPASS_*``). The four shapes are mutually exclusive: a token
    starts with ``^``, ends with ``$``, both, or neither. We don't
    validate the body -- any other regex metachar is treated literally.
    """
    upper = key.upper()
    for tok in redact_keys:
        has_start = tok.startswith("^")
        has_end = tok.endswith("$")
        if has_start and has_end:
            # ^FOO$ -> exact match on the stripped middle.
            if upper == tok[1:-1]:
                return True
        elif has_start:
            # ^PASS_ -> KEY starts with the suffix after `^`.
            if upper.startswith(tok[1:]):
                return True
        elif has_end:
            # _PASS$ -> KEY ends with the prefix before `$`.
            if upper.endswith(tok[:-1]):
                return True
        elif tok in upper:
            return True
    return False


def _strip_quotes(value: str) -> tuple[str, str, str]:
    """Split a yaml/json value into ``(prefix_quote, inner, suffix_quote)``.

    Handles double quotes, single quotes, and bare values. Lets the
    marker land inside the original quoting so the file's shape is
    preserved (``password: "<sha:...>"`` not ``password: <sha:...>``).
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[0], value[1:-1], value[-1]
    return "", value, ""


def _redact_env_line(
    line: str,
    redact_keys: frozenset[str],
    salt: str,
    hint_chars: int,
) -> tuple[str, RedactionRecord | None]:
    """Return ``(rewritten_line, record_or_None)`` for one env/ini line.

    Known over-redact: an inline trailing comment is folded into the value
    span. ``PASSWORD=hunter2 # the password`` reports ``len:22`` (the
    secret plus `` # the password``), not ``len:7``. The leak direction is
    safe (over-redact, not under-redact), but operators surprised by a
    long ``len:`` should know the `#`/`//` isn't being stripped. A proper
    fix would need to distinguish `URL=https://example.com#fragment`
    (where `#` is part of the value) from real comments -- deferred.
    """
    m = _ENV_LINE_RE.match(line)
    if not m:
        return line, None
    lead, key, eq, value, trail = m.groups()
    if not _key_matches(key, redact_keys):
        return line, None
    quote_l, inner, quote_r = _strip_quotes(value)
    marker = _format_marker(inner, salt, hint_chars)
    rewritten = f"{lead}{key}{eq}{quote_l}{marker}{quote_r}{trail}"
    h = _hash_value(inner, salt)
    return rewritten, RedactionRecord(key=key, hash=h, line=None, kind="key_match")


def _redact_yaml_line(
    line: str,
    redact_keys: frozenset[str],
    salt: str,
    hint_chars: int,
) -> tuple[str, RedactionRecord | None]:
    """Return ``(rewritten_line, record_or_None)`` for one yaml line."""
    m = _YAML_LINE_RE.match(line)
    if not m:
        return line, None
    lead, key, sep, value, trail = m.groups()
    if not _key_matches(key, redact_keys):
        return line, None
    quote_l, inner, quote_r = _strip_quotes(value)
    marker = _format_marker(inner, salt, hint_chars)
    rewritten = f"{lead}{key}{sep}{quote_l}{marker}{quote_r}{trail}"
    h = _hash_value(inner, salt)
    return rewritten, RedactionRecord(key=key, hash=h, line=None, kind="key_match")


def _redact_json_line(
    line: str,
    redact_keys: frozenset[str],
    salt: str,
    hint_chars: int,
) -> tuple[str, list[RedactionRecord]]:
    """Return ``(rewritten_line, records)`` for one json line.

    JSON often packs multiple ``"key": "value"`` pairs onto a single line
    so we sub-iterate instead of single-match. Each match produces a record
    when the key triggers redaction.
    """
    records: list[RedactionRecord] = []

    def _sub(match: re.Match[str]) -> str:
        key, value = match.group(1), match.group(2)
        if not _key_matches(key, redact_keys):
            return match.group(0)
        marker = _format_marker(value, salt, hint_chars)
        records.append(
            RedactionRecord(
                key=key,
                hash=_hash_value(value, salt),
                line=None,
                kind="key_match",
            )
        )
        return f'"{key}": "{marker}"'

    rewritten = _JSON_PAIR_RE.sub(_sub, line)
    return rewritten, records


def _redact_pem_blocks(text: str, salt: str) -> tuple[str, list[RedactionRecord]]:
    """Replace every PEM block with a single marker. Always runs regardless
    of the entropy-detection toggle -- PEM is unambiguously a private key
    or cert and should never reach the LLM in plaintext.
    """
    records: list[RedactionRecord] = []

    def _sub(match: re.Match[str]) -> str:
        block = match.group(0)
        marker = _format_marker(block, salt, hint_chars=0)
        records.append(
            RedactionRecord(
                key=None,
                hash=_hash_value(block, salt),
                line=None,
                kind="pem_block",
            )
        )
        # Preserve the BEGIN line so the LLM can see it was a PEM block.
        first_line = block.splitlines()[0] if block else ""
        return f"{first_line}\n{marker}\n-----END (redacted)-----"

    rewritten = _PEM_BLOCK_RE.sub(_sub, text)
    return rewritten, records


def _redact_entropy_line(
    line: str,
    salt: str,
    hint_chars: int,
) -> tuple[str, list[RedactionRecord]]:
    """Detect base64 and hex high-entropy substrings on one line.

    Skipped for comment-leading lines (``#``, ``//``). Inside ``<sha:...>``
    markers we already left alone via the negative lookbehind in the
    pattern, so this function is safe to call after the structured
    parsers ran.
    """
    if _COMMENT_PREFIX_RE.match(line):
        return line, []
    records: list[RedactionRecord] = []

    def _sub_b64(match: re.Match[str]) -> str:
        value = match.group(0)
        marker = _format_marker(value, salt, hint_chars)
        records.append(
            RedactionRecord(
                key=None,
                hash=_hash_value(value, salt),
                line=None,
                kind="entropy_base64",
            )
        )
        return marker

    def _sub_hex(match: re.Match[str]) -> str:
        value = match.group(0)
        marker = _format_marker(value, salt, hint_chars)
        records.append(
            RedactionRecord(
                key=None,
                hash=_hash_value(value, salt),
                line=None,
                kind="entropy_hex",
            )
        )
        return marker

    # Order matters: try base64 first (longer matches), then hex on what's
    # left. Hex strings of length 32+ are a strict subset of base64 chars,
    # so a pure-hex secret would otherwise be caught by base64 first --
    # which is fine, the hash is the same and the record just gets a
    # different ``kind``.
    rewritten = _ENTROPY_BASE64_RE.sub(_sub_b64, line)
    rewritten = _ENTROPY_HEX_RE.sub(_sub_hex, rewritten)
    return rewritten, records


def redact_text(
    content: str,
    *,
    keys: frozenset[str],
    salt: str,
    entropy_detection: bool,
    hint_chars: int,
    format: Format,
) -> tuple[str, list[RedactionRecord]]:
    """Redact ``content`` according to the given policy. Returns the
    redacted text plus a list of records describing every redaction.

    The records all carry ``line`` set to a 1-indexed line number when the
    redaction was produced by a line-based parser (env / yaml / json /
    entropy). PEM-block records leave ``line`` as ``None`` because the
    block spans multiple lines.

    ``format`` is the parser dispatch:

    - ``env`` / ``ini`` : line-based env parser
    - ``yaml``         : line-based yaml parser
    - ``json``         : line-based json regex (single line, multi-pair)
    - ``generic``      : env, then yaml, then json regexes sequentially,
                         then entropy (when enabled)

    PEM blocks are scanned ONCE over the whole text first -- they span
    multiple lines so we have to do them before the line loop. Entropy
    detection runs per-line (when enabled) after the structured parser
    matched (or didn't).
    """
    # PEM blocks first: cross-line, always-on. Replacing them first means
    # the rest of the engine never sees plaintext PEM and never has to
    # worry about a base64 line inside a PEM body matching the entropy
    # detector with a stale hash.
    text, pem_records = _redact_pem_blocks(content, salt)

    records: list[RedactionRecord] = list(pem_records)
    out_lines: list[str] = []
    for idx, raw_line in enumerate(text.splitlines(keepends=False), start=1):
        line = raw_line
        line_records: list[RedactionRecord] = []

        if format in ("env", "ini"):
            line, rec = _redact_env_line(line, keys, salt, hint_chars)
            if rec is not None:
                line_records.append(rec)
        elif format == "yaml":
            line, rec = _redact_yaml_line(line, keys, salt, hint_chars)
            if rec is not None:
                line_records.append(rec)
        elif format == "json":
            line, json_recs = _redact_json_line(line, keys, salt, hint_chars)
            line_records.extend(json_recs)
        else:  # generic
            line, env_rec = _redact_env_line(line, keys, salt, hint_chars)
            if env_rec is not None:
                line_records.append(env_rec)
            else:
                line, yaml_rec = _redact_yaml_line(line, keys, salt, hint_chars)
                if yaml_rec is not None:
                    line_records.append(yaml_rec)
            line, json_recs = _redact_json_line(line, keys, salt, hint_chars)
            line_records.extend(json_recs)

        # Entropy detection runs on every line in every format when enabled.
        # Even for env/yaml/json: a value that looked like a non-secret key
        # but contained a 50-char base64 token should still get caught.
        if entropy_detection:
            line, ent_recs = _redact_entropy_line(line, salt, hint_chars)
            line_records.extend(ent_recs)

        # Stamp the line number onto every record produced for this line.
        records.extend(
            RedactionRecord(
                key=rec.key,
                hash=rec.hash,
                line=idx,
                kind=rec.kind,
            )
            for rec in line_records
        )
        out_lines.append(line)

    # Preserve trailing newline state of the input. ``splitlines(keepends=False)``
    # drops it, so we re-add it iff the original ended with one. This keeps
    # the redacted shape byte-equivalent to the original for the common
    # case (file with trailing newline).
    trailing = "\n" if content.endswith("\n") else ""
    return ("\n".join(out_lines) + trailing, records)


def detect_format(path: str) -> Format:
    """Infer the redactor format from a path's extension.

    Used by ``ssh_read_redacted`` when the caller doesn't pin a format.
    Rules:

    - ``.env`` or no extension       -> ``env``
    - ``.yml`` / ``.yaml``           -> ``yaml``
    - ``.json``                      -> ``json``
    - ``.ini`` / ``.cfg`` / ``.conf`` -> ``ini``
    - anything else                  -> ``generic``
    """
    lower = path.lower()
    base = lower.rsplit("/", 1)[-1] if "/" in lower else lower
    # ``.env`` files including dotted variants (``.env.local``,
    # ``.env.production``, ``.env.test``...). ``cfg/.env`` ends in ``.env``;
    # ``cfg/.env.local`` matches via the basename-starts-with ``.env.`` check.
    if lower.endswith(".env") or lower.endswith("/.env") or base.startswith(".env."):
        return "env"
    if lower.endswith((".yml", ".yaml")):
        return "yaml"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith((".ini", ".cfg", ".conf")):
        return "ini"
    # No-extension files (no ``.`` in the basename) are treated as env --
    # they're typically ``.env`` style configs without the dot prefix.
    if "." not in base:
        return "env"
    return "generic"
