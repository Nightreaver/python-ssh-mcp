"""Canonical text-coercion helper for SSH/SFTP output.

asyncssh hands stdout/stderr back as ``bytes`` or ``str`` depending on the
remote and the channel mode. Several call sites used to re-implement the
"decode as UTF-8 with replace, treat None as empty" idiom inline; two
``_as_str`` private helpers also drifted in signature (one accepting
``bytes | bytearray | str | None``, the other ``object``). Centralising
the coercion here keeps the contract uniform: all SSH/SFTP byte-output
gets decoded the same way, errors-replace, and ``None`` collapses to the
empty string so downstream ``.splitlines()`` / ``.strip()`` / formatting
calls don't have to re-check.

The signature is deliberately tight -- ``object`` was rejected because the
inline sites all have ``bytes | bytearray | str | None`` data; widening
just hides bugs at construction. A site that legitimately needs ``object``
should keep its own coercion (and surface that as a flag for review).
"""

from __future__ import annotations


def as_str(value: bytes | bytearray | str | None) -> str:
    """Coerce SSH/SFTP output to ``str``. ``None`` -> ``""``. Bytes decoded as UTF-8 with replace."""
    if value is None:
        return ""
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    return value
