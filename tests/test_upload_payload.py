"""ssh_upload / ssh_deploy `content_text` vs `content_base64` validation.

Pinned contracts:
- Exactly one of content_text / content_base64 / local_path must be set;
  multiple = error, none = error.
- content_text encodes as UTF-8 (zero-byte file allowed via empty string).
- content_base64 round-trips bytes verbatim (binary-safe).
- Existing ssh_upload callers passing content_base64 keep working.
- local_path (v1.10.0) is covered separately by test_low_access_local_path.py
  (needs a tmp_path fixture + SSH_LOCAL_TRANSFER_ROOTS override).
"""

from __future__ import annotations

import base64
import binascii

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.tools.low_access_tools import (
    WriteError,
    _InlinePayload,
    _resolve_upload_payload,
)


def _bare_settings() -> Settings:
    """Settings with the local_path mode disabled (the test-conftest default)."""
    return Settings()


@pytest.mark.asyncio
async def test_content_text_is_encoded_utf8() -> None:
    out = await _resolve_upload_payload(
        content_text="hello world\n",
        content_base64=None,
        local_path=None,
        settings=_bare_settings(),
    )
    assert isinstance(out, _InlinePayload)
    assert out.data == b"hello world\n"


@pytest.mark.asyncio
async def test_content_text_with_unicode() -> None:
    """Plain str is unicode in Python; encode round-trips losslessly."""
    out = await _resolve_upload_payload(
        content_text="café",
        content_base64=None,
        local_path=None,
        settings=_bare_settings(),
    )
    assert isinstance(out, _InlinePayload)
    assert out.data == "café".encode()


@pytest.mark.asyncio
async def test_content_text_empty_string_writes_zero_byte_file() -> None:
    """Empty string is a deliberate valid input (creating an empty file via
    `: > path` would otherwise have to use ssh_exec_run). It must NOT trip
    the 'neither was set' guard -- the validator uses `is not None`, not
    truthiness."""
    out = await _resolve_upload_payload(
        content_text="",
        content_base64=None,
        local_path=None,
        settings=_bare_settings(),
    )
    assert isinstance(out, _InlinePayload)
    assert out.data == b""


@pytest.mark.asyncio
async def test_content_base64_is_decoded() -> None:
    payload = b"\x00\x01\x02binary\xff\xfe"
    out = await _resolve_upload_payload(
        content_text=None,
        content_base64=base64.b64encode(payload).decode("ascii"),
        local_path=None,
        settings=_bare_settings(),
    )
    assert isinstance(out, _InlinePayload)
    assert out.data == payload


@pytest.mark.asyncio
async def test_both_text_and_base64_set_raises() -> None:
    with pytest.raises(WriteError, match="Multiple were set"):
        await _resolve_upload_payload(
            content_text="x",
            content_base64="eA==",
            local_path=None,
            settings=_bare_settings(),
        )


@pytest.mark.asyncio
async def test_all_three_sources_set_raises() -> None:
    """3-way mutex (v1.10.0): passing text + base64 + local_path together
    must still trip the >1 guard, not silently dispatch on the first.

    Covers the counter-based check (`sum(... is not None) > 1`) directly
    -- the pairwise tests only confirm 2-of-3, leaving the all-three
    case implicit. Explicit pin here so a refactor that swaps the
    counter for a chain of `if`s gets caught.
    """
    with pytest.raises(WriteError, match="Multiple were set"):
        await _resolve_upload_payload(
            content_text="x",
            content_base64="eA==",
            local_path="/tmp/anything",
            settings=_bare_settings(),
        )


@pytest.mark.asyncio
async def test_no_source_raises() -> None:
    with pytest.raises(WriteError, match="None was set"):
        await _resolve_upload_payload(
            content_text=None,
            content_base64=None,
            local_path=None,
            settings=_bare_settings(),
        )


@pytest.mark.asyncio
async def test_invalid_base64_raises() -> None:
    """validate=True on b64decode rejects non-base64 -- no silent truncation."""
    with pytest.raises(binascii.Error):
        await _resolve_upload_payload(
            content_text=None,
            content_base64="not base64!@#",
            local_path=None,
            settings=_bare_settings(),
        )
