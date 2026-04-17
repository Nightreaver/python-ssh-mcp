"""Shared test fixtures + config overrides for pytest."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make src/ importable without requiring an editable install.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Keep tests from accidentally reaching out to real hosts or inheriting the
# operator's .env. `.env` values (SSH_DEFAULT_KEY etc.) otherwise flip auth
# defaults mid-test and break assertions that assume clean built-in defaults.
for _var in (
    "SSH_HOSTS_ALLOWLIST",
    "SSH_HOSTS_BLOCKLIST",
    "SSH_PATH_ALLOWLIST",
    "SSH_COMMAND_ALLOWLIST",
    "SSH_ENABLED_GROUPS",
    "SSH_DEFAULT_USER",
    "SSH_DEFAULT_KEY",
    "SSH_KNOWN_HOSTS",
    "SSH_CONFIG_FILE",
    "SSH_SUDO_PASSWORD",
    "SSH_SUDO_PASSWORD_CMD",
):
    os.environ.pop(_var, None)
os.environ["SSH_HOSTS_FILE"] = str(ROOT / "tests" / "fixtures" / "nonexistent.toml")

# Disable .env loading BEFORE ssh_mcp.config is imported. config.py checks
# this env var at module load to decide whether to read .env at all. Tests
# must not inherit the operator's personal .env (SSH_DEFAULT_KEY etc.) or
# they'll observe the wrong auth defaults and fail non-deterministically
# depending on whose machine the test suite runs on.
os.environ["SSH_MCP_DISABLE_DOTENV"] = "1"
os.environ.setdefault("ALLOW_LOW_ACCESS_TOOLS", "false")
os.environ.setdefault("ALLOW_DANGEROUS_TOOLS", "false")
os.environ.setdefault("ALLOW_SUDO", "false")
