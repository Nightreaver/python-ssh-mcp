"""SSH_ENABLE_BM25 wiring: default off, on adds the search transform."""
from __future__ import annotations

from ssh_mcp.config import Settings


def test_bm25_defaults_off() -> None:
    s = Settings()
    assert s.SSH_ENABLE_BM25 is False
    assert s.SSH_BM25_MAX_RESULTS == 8
    assert "ssh_host_ping" in s.SSH_BM25_ALWAYS_VISIBLE


def test_bm25_accepts_csv_always_visible() -> None:
    s = Settings(SSH_BM25_ALWAYS_VISIBLE="ssh_host_ping, ssh_shell_list")
    assert s.SSH_BM25_ALWAYS_VISIBLE == ["ssh_host_ping", "ssh_shell_list"]


def test_bm25_accepts_empty_always_visible() -> None:
    s = Settings(SSH_BM25_ALWAYS_VISIBLE="")
    assert s.SSH_BM25_ALWAYS_VISIBLE == []


def test_bm25_transform_class_is_importable() -> None:
    """Guard against FastMCP renaming/removing the class we wire in."""
    from fastmcp.server.transforms.search.bm25 import BM25SearchTransform

    t = BM25SearchTransform(max_results=5, always_visible=[])
    assert t is not None
