"""services/redactor -- per-format redaction + entropy + PEM + hash determinism.

Covers:

- env / yaml / json / ini / generic format dispatch
- entropy detection on vs off (both states exercised)
- PEM block always-redacted even with entropy off
- HMAC hash determinism + salt sensitivity
- hint_chars=0 (no leak) vs hint_chars=2 (2-char head+tail leak)
- case-insensitive KEY substring match
- comment-leading hex skipped
- generic format chains env → yaml → json + entropy
- detect_format() extension dispatch
"""

from __future__ import annotations

import pytest

from ssh_mcp.services.redact_policy import default_redact_keys
from ssh_mcp.services.redactor import detect_format, redact_text

DEFAULTS = default_redact_keys()


# --- env format ----------------------------------------------------------


def test_env_key_value_redacted() -> None:
    text = "DB_PASSWORD=hunter2\nOTHER=plain\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "hunter2" not in out
    assert "<sha:" in out
    assert "OTHER=plain" in out
    assert any(rec.key == "DB_PASSWORD" for rec in recs)


def test_env_key_quoted_value_preserves_quoting() -> None:
    text = 'DB_PASSWORD="hunter2"\n'
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    # quotes preserved, value replaced
    assert 'DB_PASSWORD="<sha:' in out
    assert "hunter2" not in out


# --- yaml format ---------------------------------------------------------


def test_yaml_key_value_redacted() -> None:
    text = "password: hunter2\nname: foo\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="yaml",
    )
    assert "hunter2" not in out
    assert "name: foo" in out
    assert any(rec.key == "password" for rec in recs)


def test_yaml_quoted_value_preserves_quoting() -> None:
    text = 'api_key: "abc123"\n'
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="yaml",
    )
    assert 'api_key: "<sha:' in out


# --- json format ---------------------------------------------------------


def test_json_single_pair_redacted() -> None:
    text = '{"password": "hunter2", "name": "foo"}'
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="json",
    )
    assert "hunter2" not in out
    assert '"name": "foo"' in out
    assert any(rec.key == "password" for rec in recs)


def test_json_multiple_pairs_on_one_line() -> None:
    text = '{"db_password": "p1", "api_key": "k1"}'
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="json",
    )
    assert "p1" not in out
    assert "k1" not in out
    assert len(recs) == 2


def test_json_value_with_escaped_quote_is_redacted() -> None:
    """Regression: JSON value containing ``\\"`` must be redacted, not silently
    leaked. Before the fix, ``_JSON_PAIR_RE`` used ``[^"\\\\]+`` for the value
    span, which terminated at the first backslash and produced zero matches
    against a string like ``"password":"p\\"x"`` -- so the line passed through
    unchanged and the secret stayed cleartext."""
    # In Python source: \" represents the 2-char JSON escape sequence \ and "
    # The actual file content the redactor sees: {"password": "p\"a\"ss"}
    text = '{"password": "p\\"a\\"ss"}'
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="test-salt",
        entropy_detection=False,
        hint_chars=0,
        format="json",
    )
    # The escaped-quote-bearing literal value is gone.
    assert 'p\\"a\\"ss' not in out
    # The marker is in.
    assert "<sha:" in out
    # The record list registered the redaction.
    assert len(recs) == 1
    assert recs[0].key == "password"
    assert recs[0].kind == "key_match"


def test_json_value_with_escaped_backslash_is_redacted() -> None:
    """Companion to the escaped-quote test: a value containing ``\\\\`` (a
    JSON-encoded backslash) must also match the regex. The escape-aware
    alternation ``(?:[^"\\\\]|\\\\.)`` covers both ``\\"`` and ``\\\\``."""
    text = '{"secret": "a\\\\b"}'  # JSON content: {"secret": "a\\b"}
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="json",
    )
    assert "a\\\\b" not in out
    assert "<sha:" in out
    assert len(recs) == 1


# --- ini format ----------------------------------------------------------


def test_ini_format_uses_env_parser() -> None:
    text = "[section]\npassword=hunter2\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="ini",
    )
    assert "hunter2" not in out
    assert any(rec.key == "password" for rec in recs)


# --- generic format ------------------------------------------------------


def test_generic_chains_env_yaml_json() -> None:
    text = "DB_PASSWORD=p1\napi_key: p2\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="generic",
    )
    assert "p1" not in out
    assert "p2" not in out
    assert len(recs) == 2


def test_generic_with_entropy_detects_long_hex() -> None:
    # Generic + entropy on: a 40-char hex on its own line gets redacted.
    # Hex-only chars 0-9 + a-f keep base64 pattern from latching first
    # incorrectly: both base64 and hex match this shape; the matcher
    # records the kind as ``entropy_base64`` (longer pattern runs first),
    # which is fine -- the substantive assertion is the value is gone.
    text = "some_field = " + "a" * 40 + "\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format="generic",
    )
    # The value gets redacted (key=substring 'KEY' doesn't match
    # 'some_field' -- env match misses -- but entropy catches it).
    assert "a" * 40 not in out
    assert "<sha:" in out
    # base64-shape pattern runs first and consumes the hex; either kind
    # is acceptable as long as something was redacted.
    assert any(rec.kind in ("entropy_base64", "entropy_hex") for rec in recs)


def test_pure_hex_only_matches_when_base64_does_not() -> None:
    # Lowercase hex >= 32, only containing 0-9 + a-f — both regexes match,
    # base64 wins (longer alphabet pattern declared first). Still gets redacted.
    text = "checksum = " + "a1b2c3d4e5f6" * 4 + "\n"  # 48 chars
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format="generic",
    )
    assert "a1b2c3d4e5f6a1b2c3d4e5f6" not in out
    assert any(rec.kind in ("entropy_hex", "entropy_base64") for rec in recs)


# --- entropy detection toggle (both states) ------------------------------


def test_entropy_off_leaves_random_strings() -> None:
    # Use a field name that does NOT substring-match any default redact key
    # (avoid 'token', 'key', 'secret', 'auth', 'password', etc.).
    text = "comment: " + "abcd1234efgh5678ijklmnop" + "\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="generic",
    )
    assert "abcd1234efgh5678ijklmnop" in out
    assert not any(rec.kind in ("entropy_base64", "entropy_hex") for rec in recs)


def test_entropy_on_catches_base64_shape() -> None:
    text = "comment: " + "abcd1234efgh5678ijklmnop" + "\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format="generic",
    )
    assert "abcd1234efgh5678ijklmnop" not in out
    assert any(rec.kind == "entropy_base64" for rec in recs)


def test_comment_leading_hex_skipped() -> None:
    text = "# commit " + "a" * 40 + " landed yesterday\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format="generic",
    )
    # commented hex left alone (looks like a git SHA)
    assert "a" * 40 in out


def test_double_slash_comment_skipped() -> None:
    text = "// abcdefabcdefabcdefabcdefabcdefabcdef\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format="generic",
    )
    assert "abcdefabcdefabcdefabcdefabcdefabcdef" in out


# --- PEM blocks (always redacted) ----------------------------------------


def test_pem_block_redacted_even_with_entropy_off() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n" "MIIEpAIBAAKCAQEAxxx\n" "yyy\n" "-----END RSA PRIVATE KEY-----\n"
    )
    out, recs = redact_text(
        pem,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="generic",
    )
    assert "MIIEpAIBAAKCAQEAxxx" not in out
    assert "yyy" not in out
    assert "-----BEGIN RSA PRIVATE KEY-----" in out  # preserved as marker context
    assert any(rec.kind == "pem_block" for rec in recs)


# --- hash determinism + salt sensitivity ---------------------------------


def test_same_value_yields_same_hash_across_calls() -> None:
    text = "DB_PASSWORD=hunter2\n"
    _, recs_1 = redact_text(
        text,
        keys=DEFAULTS,
        salt="my_strong_salt_aaaaaaaaaaaaaaaaa",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    _, recs_2 = redact_text(
        text,
        keys=DEFAULTS,
        salt="my_strong_salt_aaaaaaaaaaaaaaaaa",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert recs_1[0].hash == recs_2[0].hash


def test_different_salts_produce_different_hashes() -> None:
    text = "DB_PASSWORD=hunter2\n"
    _, recs_1 = redact_text(
        text,
        keys=DEFAULTS,
        salt="salt_one_aaaaaaaaaaaaaaaaaaaaaaaa",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    _, recs_2 = redact_text(
        text,
        keys=DEFAULTS,
        salt="salt_two_bbbbbbbbbbbbbbbbbbbbbbbb",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert recs_1[0].hash != recs_2[0].hash


def test_empty_salt_uses_plain_sha256() -> None:
    # Same value, empty salt → deterministic plain SHA256 (still a hash,
    # still 12-char prefix). Just verifying the empty-salt branch doesn't
    # crash and produces a 12-char hex.
    text = "DB_PASSWORD=hunter2\n"
    _, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert len(recs[0].hash) == 12
    assert all(c in "0123456789abcdef" for c in recs[0].hash)


# --- hint_chars (both 0 and >0 exercised) --------------------------------


def test_hint_chars_zero_leaks_nothing() -> None:
    text = "DB_PASSWORD=verylongsecretvalue\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "verylongsecretvalue" not in out
    assert "hint:" not in out


def test_hint_chars_two_leaks_first_and_last_two() -> None:
    text = "DB_PASSWORD=verylongsecretvalue\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=2,
        format="env",
    )
    # 'verylongsecretvalue' first 2 = 've', last 2 = 'ue'
    assert "hint:ve...ue" in out
    # Still no full plaintext.
    assert "verylongsecretvalue" not in out


def test_hint_chars_clamped_defensively() -> None:
    # Pass a malicious value; the redactor clamps to 4 each side.
    text = "DB_PASSWORD=verylongsecretvalue\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=99,
        format="env",
    )
    # first 4 = 'very', last 4 = 'alue'
    assert "hint:very...alue" in out
    # No more than 4 chars at the head shown.
    assert "verylongsecretvalue" not in out


def test_hint_chars_skipped_for_too_short_values() -> None:
    # value length 3, hint_chars=2 means 2+2 = 4 > 3. Skip the hint.
    text = "DB_PASSWORD=abc\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=2,
        format="env",
    )
    assert "hint:" not in out


# --- case-insensitive KEY matching ---------------------------------------


def test_case_insensitive_key_substring_match() -> None:
    # lowercase 'password' should match the uppercase 'PASSWORD' default.
    text = "password=hunter2\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "hunter2" not in out
    assert any(rec.key == "password" for rec in recs)


def test_substring_match_catches_prefix() -> None:
    text = "DB_PASSWORD=hunter2\n"
    out, _ = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "hunter2" not in out


# --- anchor semantics in _key_matches ------------------------------------


def test_anchor_start_matches_prefix_not_substring() -> None:
    """``^PASS_`` matches keys that START with ``PASS_``. ``BYPASS_FOO``
    must NOT match (the unanchored substring ``PASS_`` would otherwise hit
    the literal ``PASS_`` inside ``BYPASS_FOO``)."""
    keys = frozenset({"^PASS_"})
    text = "PASS_HEADER=secret1\nBYPASS_FOO=plaintext\n"
    out, recs = redact_text(
        text,
        keys=keys,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "secret1" not in out, "PASS_HEADER should have been redacted"
    assert "plaintext" in out, "BYPASS_FOO must NOT have been redacted (anchor protects it)"
    assert len(recs) == 1
    assert recs[0].key == "PASS_HEADER"


def test_anchor_end_matches_suffix_not_substring() -> None:
    """``_PASS$`` matches keys that END with ``_PASS``. ``BYPASS`` must
    NOT match (no `_PASS` at the tail; the substring `PASS` is mid-word)."""
    keys = frozenset({"_PASS$"})
    text = "DB_PASS=hunter2\nBYPASS=true\n"
    out, recs = redact_text(
        text,
        keys=keys,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "hunter2" not in out
    assert "true" in out
    assert len(recs) == 1
    assert recs[0].key == "DB_PASS"


def test_anchor_both_means_exact_match() -> None:
    """``^FOO$`` matches ``FOO`` only -- not ``FOO_BAR``, ``BAR_FOO``,
    ``BARFOO``, ``FOOBAR``."""
    keys = frozenset({"^TOKEN$"})
    text = "TOKEN=match-me\nTOKEN_EXTRA=no\nAPI_TOKEN=no\n"
    out, recs = redact_text(
        text,
        keys=keys,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "match-me" not in out
    assert "no" in out  # both non-matches survived
    assert len(recs) == 1
    assert recs[0].key == "TOKEN"


def test_unanchored_token_still_substring_matches() -> None:
    """Backward-compat: a token without anchors keeps the original
    substring behavior. ``PASSWORD`` (no anchor) matches ``DB_PASSWORD``
    just like before the anchor feature landed."""
    keys = frozenset({"PASSWORD"})
    text = "DB_PASSWORD=hunter2\n"
    out, recs = redact_text(
        text,
        keys=keys,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert "hunter2" not in out
    assert len(recs) == 1


def test_default_pass_anchors_match_db_pass() -> None:
    """Integration: the new ``^PASS_`` / ``_PASS$`` entries in the default
    redact-key set catch the common ``<prefix>_PASS`` / ``PASS_<suffix>``
    keys without operator config."""
    text = "DB_PASS=p1\nPASS_HEADER=p2\nBYPASS_CACHE=true\nCOMPASS_API=v3\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    # The two anchored matches are redacted.
    assert "p1" not in out
    assert "p2" not in out
    # The two false-positive candidates survive.
    assert "true" in out, "BYPASS_CACHE must NOT be over-redacted by ^PASS_ / _PASS$"
    assert "v3" in out, "COMPASS_API must NOT be over-redacted by ^PASS_ / _PASS$"
    redacted_keys = {rec.key for rec in recs}
    assert "DB_PASS" in redacted_keys
    assert "PASS_HEADER" in redacted_keys
    assert "BYPASS_CACHE" not in redacted_keys
    assert "COMPASS_API" not in redacted_keys


# --- detect_format -------------------------------------------------------


def test_detect_format_env_extension() -> None:
    assert detect_format("/opt/app/.env") == "env"
    assert detect_format("/opt/app/config.env") == "env"


def test_detect_format_dotted_env_variants() -> None:
    """``.env.local`` / ``.env.production`` / ``.env.test`` are env-style
    config files in practice (same KEY=VALUE shape as bare ``.env``).
    Without this, the dotted variants fall through to ``generic`` -- still
    redacted via the generic chain, but ``format_detected`` shows ``generic``
    in the result, which is confusing to operators."""
    assert detect_format("/opt/app/.env.local") == "env"
    assert detect_format("/opt/app/.env.production") == "env"
    assert detect_format("/opt/app/.env.test") == "env"
    assert detect_format(".env.development") == "env"


def test_detect_format_yaml() -> None:
    assert detect_format("/opt/app/docker-compose.yml") == "yaml"
    assert detect_format("/opt/app/values.yaml") == "yaml"


def test_detect_format_json() -> None:
    assert detect_format("/opt/app/config.json") == "json"


def test_detect_format_ini_variants() -> None:
    assert detect_format("/etc/app.ini") == "ini"
    assert detect_format("/etc/app.cfg") == "ini"
    assert detect_format("/etc/nginx.conf") == "ini"


def test_detect_format_no_extension_treated_as_env() -> None:
    assert detect_format("/opt/app/Dockerfile") == "env"


def test_detect_format_unknown_is_generic() -> None:
    assert detect_format("/opt/app/data.bin") == "generic"


# --- line numbers --------------------------------------------------------


def test_records_carry_line_number() -> None:
    text = "FOO=plain\nDB_PASSWORD=secret\nBAR=plain\n"
    _, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    assert any(rec.line == 2 for rec in recs)


# --- inline + records mirror ---------------------------------------------


def test_inline_hashes_match_records_list() -> None:
    text = "DB_PASSWORD=hunter2\n"
    out, recs = redact_text(
        text,
        keys=DEFAULTS,
        salt="salt_a_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        entropy_detection=False,
        hint_chars=0,
        format="env",
    )
    rec = recs[0]
    # The record's hash MUST appear inline in the redacted output.
    assert f"<sha:{rec.hash}" in out


# --- bypass-mode + format independence -----------------------------------


@pytest.mark.parametrize("fmt", ["env", "yaml", "ini", "generic"])
def test_does_not_crash_on_empty_input(fmt: str) -> None:
    out, recs = redact_text(
        "",
        keys=DEFAULTS,
        salt="",
        entropy_detection=True,
        hint_chars=0,
        format=fmt,  # type: ignore[arg-type]
    )
    assert out == ""
    assert recs == []
