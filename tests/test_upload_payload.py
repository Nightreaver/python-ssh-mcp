"""ssh_upload / ssh_deploy `content_text` vs `content_base64` validation.

Pinned contracts:
- Exactly one of content_text / content_base64 must be set; both = error,
  neither = error.
- content_text encodes as UTF-8 (zero-byte file allowed via empty string).
- content_base64 round-trips bytes verbatim (binary-safe).
- Existing ssh_upload callers passing content_base64 keep working.
"""
from __future__ import annotations

import base64
import binascii

import pytest

from ssh_mcp.tools.low_access_tools import WriteError, _resolve_upload_payload


def test_content_text_is_encoded_utf8() -> None:
    out = _resolve_upload_payload(content_text="hello world\n", content_base64=None)
    assert out == b"hello world\n"


def test_content_text_with_unicode() -> None:
    """Plain str is unicode in Python; encode round-trips losslessly."""
    out = _resolve_upload_payload(content_text="café", content_base64=None)
    assert out == "café".encode()


def test_content_text_empty_string_writes_zero_byte_file() -> None:
    """Empty string is a deliberate valid input (creating an empty file via
    `: > path` would otherwise have to use ssh_exec_run). It must NOT trip
    the 'neither was set' guard -- the validator uses `is not None`, not
    truthiness."""
    out = _resolve_upload_payload(content_text="", content_base64=None)
    assert out == b""


def test_content_base64_is_decoded() -> None:
    payload = b"\x00\x01\x02binary\xff\xfe"
    out = _resolve_upload_payload(
        content_text=None,
        content_base64=base64.b64encode(payload).decode("ascii"),
    )
    assert out == payload


def test_both_set_raises() -> None:
    with pytest.raises(WriteError, match="Both were set"):
        _resolve_upload_payload(content_text="x", content_base64="eA==")


def test_neither_set_raises() -> None:
    with pytest.raises(WriteError, match="Neither was set"):
        _resolve_upload_payload(content_text=None, content_base64=None)


def test_invalid_base64_raises() -> None:
    """validate=True on b64decode rejects non-base64 -- no silent truncation."""
    with pytest.raises(binascii.Error):
        _resolve_upload_payload(content_text=None, content_base64="not base64!@#")
