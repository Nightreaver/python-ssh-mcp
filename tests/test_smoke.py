"""Phase 0 smoke test: the package imports and the FastMCP server constructs."""
from __future__ import annotations


def test_package_imports() -> None:
    import ssh_mcp

    assert ssh_mcp.__version__


def test_server_constructs() -> None:
    from ssh_mcp.server import mcp_server

    assert mcp_server.name == "ssh-mcp"


def test_config_defaults_are_safe() -> None:
    from ssh_mcp.config import settings

    assert settings.ALLOW_LOW_ACCESS_TOOLS is False
    assert settings.ALLOW_DANGEROUS_TOOLS is False
    assert settings.ALLOW_SUDO is False


def test_config_has_every_field_lifespan_reads() -> None:
    """INC-003 guard: every settings.* access in lifespan must resolve."""
    from ssh_mcp.config import settings

    # Fields that lifespan.ssh_lifespan reads at startup.
    for name in (
        "SSH_HOSTS_FILE",
        "SSH_HOSTS_ALLOWLIST",
        "SSH_HOSTS_BLOCKLIST",
        "SSH_KNOWN_HOSTS",
        "SSH_ENABLED_GROUPS",
        "SSH_SKILLS_DIR",
        "ALLOW_LOW_ACCESS_TOOLS",
        "ALLOW_DANGEROUS_TOOLS",
        "ALLOW_SUDO",
        "ALLOW_ANY_COMMAND",
        "ALLOW_PASSWORD_AUTH",
        "SSH_SUDO_MODE",
    ):
        assert hasattr(settings, name), f"Settings missing {name!r} (lifespan will crash)"
