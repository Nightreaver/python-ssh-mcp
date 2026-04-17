"""Verify every Phase 1c tool is registered and carries the right tags."""
from __future__ import annotations

import pytest

EXPECTED: dict[str, set[str]] = {
    "ssh_host_ping": {"safe", "read", "group:host"},
    "ssh_host_info": {"safe", "read", "group:host"},
    "ssh_host_disk_usage": {"safe", "read", "group:host"},
    "ssh_host_processes": {"safe", "read", "group:host"},
    "ssh_known_hosts_verify": {"safe", "read", "group:host"},
    "ssh_session_list": {"safe", "read", "group:session"},
    "ssh_session_stats": {"safe", "read", "group:session"},
    "ssh_sftp_list": {"safe", "read", "group:sftp-read"},
    "ssh_sftp_stat": {"safe", "read", "group:sftp-read"},
    "ssh_sftp_download": {"safe", "read", "group:sftp-read"},
    "ssh_find": {"safe", "read", "group:sftp-read"},
    "ssh_file_hash": {"safe", "read", "group:sftp-read"},
    "ssh_mkdir": {"low-access", "group:file-ops"},
    "ssh_delete": {"low-access", "group:file-ops"},
    "ssh_delete_folder": {"low-access", "group:file-ops"},
    "ssh_cp": {"low-access", "group:file-ops"},
    "ssh_mv": {"low-access", "group:file-ops"},
    "ssh_upload": {"low-access", "group:file-ops"},
    "ssh_edit": {"low-access", "group:file-ops"},
    "ssh_patch": {"low-access", "group:file-ops"},
    "ssh_exec_run": {"dangerous", "group:exec"},
    "ssh_exec_script": {"dangerous", "group:exec"},
    "ssh_exec_run_streaming": {"dangerous", "group:exec"},
    "ssh_sudo_exec": {"dangerous", "sudo", "group:sudo"},
    "ssh_sudo_run_script": {"dangerous", "sudo", "group:sudo"},
    # smart alerts
    "ssh_host_alerts": {"safe", "read", "group:host"},
    # persistent shell sessions
    # open/exec carry `persistent-session` so ALLOW_PERSISTENT_SESSIONS=false
    # hides them via a Visibility transform; list/close stay available for
    # audit/drain of pre-existing sessions.
    "ssh_shell_open": {"dangerous", "group:shell", "persistent-session"},
    "ssh_shell_exec": {"dangerous", "group:shell", "persistent-session"},
    "ssh_shell_close": {"low-access", "group:shell"},
    "ssh_shell_list": {"safe", "read", "group:shell"},
    # smart deployment
    "ssh_deploy": {"low-access", "group:file-ops"},
    # docker: read
    "ssh_docker_ps": {"safe", "read", "group:docker"},
    "ssh_docker_logs": {"safe", "read", "group:docker"},
    "ssh_docker_inspect": {"safe", "read", "group:docker"},
    "ssh_docker_stats": {"safe", "read", "group:docker"},
    "ssh_docker_top": {"safe", "read", "group:docker"},
    "ssh_docker_events": {"safe", "read", "group:docker"},
    "ssh_docker_volumes": {"safe", "read", "group:docker"},
    "ssh_docker_images": {"safe", "read", "group:docker"},
    "ssh_docker_compose_ps": {"safe", "read", "group:docker"},
    "ssh_docker_compose_logs": {"safe", "read", "group:docker"},
    # docker: low-access
    "ssh_docker_start": {"low-access", "group:docker"},
    "ssh_docker_stop": {"low-access", "group:docker"},
    "ssh_docker_restart": {"low-access", "group:docker"},
    "ssh_docker_cp": {"low-access", "group:docker"},
    "ssh_docker_compose_start": {"low-access", "group:docker"},
    "ssh_docker_compose_stop": {"low-access", "group:docker"},
    "ssh_docker_compose_restart": {"low-access", "group:docker"},
    # docker: dangerous
    "ssh_docker_exec": {"dangerous", "group:docker"},
    "ssh_docker_run": {"dangerous", "group:docker"},
    "ssh_docker_pull": {"dangerous", "group:docker"},
    "ssh_docker_rm": {"dangerous", "group:docker"},
    "ssh_docker_rmi": {"dangerous", "group:docker"},
    "ssh_docker_prune": {"dangerous", "group:docker"},
    "ssh_docker_compose_up": {"dangerous", "group:docker"},
    "ssh_docker_compose_down": {"dangerous", "group:docker"},
    "ssh_docker_compose_pull": {"dangerous", "group:docker"},
}


@pytest.mark.asyncio
async def test_phase_1c_tools_registered() -> None:
    from ssh_mcp.server import mcp_server

    tools = {t.name: t for t in await mcp_server.list_tools()}
    missing = sorted(set(EXPECTED) - set(tools))
    assert not missing, f"missing tools: {missing}"


@pytest.mark.asyncio
async def test_phase_1c_tool_tags_correct() -> None:
    from ssh_mcp.server import mcp_server

    tools = {t.name: t for t in await mcp_server.list_tools()}
    for name, expected_tags in EXPECTED.items():
        tool = tools[name]
        actual = set(getattr(tool, "tags", set()) or set())
        assert expected_tags.issubset(actual), f"{name}: want {expected_tags}, got {actual}"
