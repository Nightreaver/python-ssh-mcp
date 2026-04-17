"""Docker tool package.

Importing this package registers every `ssh_docker_*` tool with the MCP
server via the usual `@mcp_server.tool(...)` decorator side-effect. Layout:

- `_helpers.py`        -- shared helpers (_run_docker, _docker_prefix,
                          escalation-deny-list, regex constants, NDJSON
                          parsers). No tool registration.
- `read_tools.py`      -- read-tier tools (ps, logs, inspect, stats, top,
                          events, volumes, images, compose_ps, compose_logs).
- `lifecycle_tools.py` -- low-access tools (start/stop/restart, cp,
                          compose_start/stop/restart).
- `dangerous_tools.py` -- dangerous tools (exec, run, pull, rm, rmi, prune,
                          compose_up/down/pull).

Tests + external callers import from the `tools.docker_tools` facade (one
level up) for backward compat; new code may import here directly.
"""
from . import _helpers, dangerous_tools, lifecycle_tools, read_tools  # noqa: F401
