"""edit_service.apply_edit + apply_unified_diff — pure Python, no SSH."""
from __future__ import annotations

from textwrap import dedent

import pytest

from ssh_mcp.services.edit_service import (
    EditError,
    PatchError,
    apply_edit,
    apply_unified_diff,
)

# --- apply_edit ---


def test_single_replacement_unique_match() -> None:
    out = apply_edit("alpha beta gamma", "beta", "BETA")
    assert out.new_text == "alpha BETA gamma"
    assert out.replacements == 1


def test_single_mode_multi_match_raises() -> None:
    with pytest.raises(EditError, match="appears 3 times"):
        apply_edit("a a a", "a", "b", occurrence="single")


def test_all_mode_replaces_every_occurrence() -> None:
    out = apply_edit("x.x.x", "x", "Y", occurrence="all")
    assert out.new_text == "Y.Y.Y"
    assert out.replacements == 3


def test_no_match_raises() -> None:
    with pytest.raises(EditError, match="not found"):
        apply_edit("hello", "world", "earth")


def test_empty_old_rejected() -> None:
    with pytest.raises(EditError, match="must not be empty"):
        apply_edit("anything", "", "x")


def test_noop_rejected() -> None:
    with pytest.raises(EditError, match="identical"):
        apply_edit("same", "same", "same")


def test_edit_preserves_surrounding_content() -> None:
    original = "LISTEN = 8080\nhost = 0.0.0.0\n"
    out = apply_edit(original, "LISTEN = 8080", "LISTEN = 9090")
    assert out.new_text == "LISTEN = 9090\nhost = 0.0.0.0\n"


# --- apply_unified_diff ---


def _diff(body: str) -> str:
    return dedent(body).lstrip("\n")


def test_simple_single_hunk_applied() -> None:
    original = "alpha\nbeta\ngamma\n"
    diff = _diff(
        """
        --- a/file
        +++ b/file
        @@ -1,3 +1,3 @@
         alpha
        -beta
        +BETA
         gamma
        """
    )
    out = apply_unified_diff(original, diff)
    assert out.new_text == "alpha\nBETA\ngamma\n"
    assert out.hunks_applied == 1
    assert out.hunks_rejected == 0


def test_patch_preserves_trailing_content_after_hunk() -> None:
    original = "one\ntwo\nthree\nfour\nfive\n"
    diff = _diff(
        """
        --- a/file
        +++ b/file
        @@ -2,1 +2,1 @@
        -two
        +TWO
        """
    )
    out = apply_unified_diff(original, diff)
    assert out.new_text == "one\nTWO\nthree\nfour\nfive\n"


def test_patch_context_mismatch_rejects() -> None:
    original = "alpha\nbeta\ngamma\n"
    diff = _diff(
        """
        --- a/file
        +++ b/file
        @@ -1,3 +1,3 @@
         WRONG_CONTEXT
        -beta
        +BETA
         gamma
        """
    )
    with pytest.raises(PatchError, match="context mismatch"):
        apply_unified_diff(original, diff)


def test_patch_removal_mismatch_rejects() -> None:
    original = "alpha\nbeta\ngamma\n"
    diff = _diff(
        """
        --- a/file
        +++ b/file
        @@ -2,1 +2,1 @@
        -BETA
        +beta
        """
    )
    with pytest.raises(PatchError, match="removal mismatch"):
        apply_unified_diff(original, diff)


def test_multi_file_diff_rejected() -> None:
    diff = _diff(
        """
        --- a/one
        +++ b/one
        @@ -1,1 +1,1 @@
        -old
        +new
        --- a/two
        +++ b/two
        @@ -1,1 +1,1 @@
        -other
        +thing
        """
    )
    with pytest.raises(PatchError, match="touches 2 files"):
        apply_unified_diff("old\n", diff)


def test_malformed_diff_rejected() -> None:
    with pytest.raises(PatchError, match="no files"):
        apply_unified_diff("anything", "totally garbage\n")


def test_two_hunks_applied_in_order() -> None:
    original = "one\ntwo\nthree\nfour\nfive\n"
    diff = _diff(
        """
        --- a/file
        +++ b/file
        @@ -1,1 +1,1 @@
        -one
        +ONE
        @@ -5,1 +5,1 @@
        -five
        +FIVE
        """
    )
    out = apply_unified_diff(original, diff)
    assert out.new_text == "ONE\ntwo\nthree\nfour\nFIVE\n"
    assert out.hunks_applied == 2
