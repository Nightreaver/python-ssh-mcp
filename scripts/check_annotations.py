"""Smoke test: spawn the server over stdio via the MCP Python SDK and verify
that the annotations we derive in lifespan survive the protocol round-trip.

This is what an MCP Inspector (or Claude Desktop) sees when it calls
`tools/list` against us. If `readOnlyHint` lands here, it lands in the client.

Run:
    uv run python scripts/check_annotations.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> int:
    env = dict(os.environ)
    env.setdefault("LOG_LEVEL", "WARNING")  # quiet for smoke test

    params = StdioServerParameters(command=sys.executable, args=["-m", "ssh_mcp"], env=env)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.list_tools()

        interesting = [
            "ssh_host_ping", "ssh_host_info", "ssh_docker_ps", "ssh_sftp_list",
            "ssh_mkdir", "ssh_cp", "ssh_upload",
            "ssh_delete", "ssh_delete_folder",
            "ssh_exec_run", "ssh_sudo_exec", "ssh_docker_run",
        ]
        index = {t.name: t for t in result.tools}

        print(f"{'tool':<28}  {'readOnly':>8}  {'destruct':>8}  {'tags'}")
        print(f"{'-'*28}  {'-'*8}  {'-'*8}  {'-'*30}")
        missing: list[str] = []
        bad_destructive_on_read: list[str] = []
        for name in interesting:
            tool = index.get(name)
            if tool is None:
                missing.append(name)
                continue
            ann = tool.annotations
            ro = ann.readOnlyHint if ann else None
            de = ann.destructiveHint if ann else None
            tags_field = getattr(getattr(tool, "meta", None), "_fastmcp", None) or {}
            tags = ",".join(sorted(tags_field.get("tags", []))) if isinstance(tags_field, dict) else "?"
            print(f"{name:<28}  {str(ro):>8}  {str(de):>8}  {tags}")
            if ("safe" in str(tags) or "read" in str(tags)) and de is True:
                bad_destructive_on_read.append(name)

        if missing:
            print(f"\n[FAIL] tools missing from tools/list (tier gate hiding them?): {missing}")
        if bad_destructive_on_read:
            print(f"\n[FAIL] read tools still marked destructive: {bad_destructive_on_read}")
            return 1
        print("\n[OK] annotations serialize across MCP protocol as expected.")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
