"""INC-022: ssh_docker_run must refuse host-escape flags by default.

The checks below are pure argv inspection via ``_reject_escalation_flags`` --
no SSH, no context. The integration path (``ssh_docker_run`` → settings lookup
→ helper) is covered by a minimal fake-ctx test at the bottom.
"""
from __future__ import annotations

from typing import Any, ClassVar

import pytest

from ssh_mcp.tools.docker_tools import _reject_escalation_flags


class TestRejectsEscalationFlags:
    @pytest.mark.parametrize(
        "args",
        [
            ["--privileged"],
            ["--cap-add", "SYS_ADMIN"],
            ["--cap-add=NET_ADMIN"],
            ["--pid=host"],
            ["--ipc=host"],
            ["--uts=host"],
            ["--userns=host"],
            ["--network=host"],
            ["--net=host"],
            ["--security-opt", "seccomp=unconfined"],
            ["--device", "/dev/kmsg"],
            ["--group-add", "docker"],
        ],
    )
    def test_rejects_direct_flags(self, args: list[str]) -> None:
        with pytest.raises(ValueError, match="ALLOW_DOCKER_PRIVILEGED"):
            _reject_escalation_flags(args)

    @pytest.mark.parametrize(
        "args",
        [
            ["--pid", "host"],
            ["--network", "host"],
            ["--net", "host"],
            ["--userns", "host"],
        ],
    )
    def test_rejects_two_token_namespace_host(self, args: list[str]) -> None:
        with pytest.raises(ValueError, match="namespace"):
            _reject_escalation_flags(args)

    @pytest.mark.parametrize(
        "args",
        [
            ["-v", "/:/host"],
            ["--volume", "/:/host"],
            ["--volume=/:/host"],
            ["--volume=/"],
        ],
    )
    def test_rejects_host_root_volume(self, args: list[str]) -> None:
        with pytest.raises(ValueError, match="host-root"):
            _reject_escalation_flags(args)

    # --- INC-024: --mount must not be a bypass ---

    @pytest.mark.parametrize(
        "args",
        [
            ["--mount", "type=bind,source=/,target=/host"],
            ["--mount", "type=bind,src=/,target=/host"],
            ["--mount=type=bind,source=/,target=/host"],
            ["--mount=type=bind,src=/,target=/host"],
            # normpath folds trailing slash
            ["--mount", "type=bind,source=//,target=/host"],
            ["--mount=type=bind,source=/./,target=/host"],
            # attribute order doesn't matter
            ["--mount", "target=/host,source=/,type=bind"],
        ],
    )
    def test_mount_host_root_blocked(self, args: list[str]) -> None:
        with pytest.raises(ValueError, match="host-root --mount"):
            _reject_escalation_flags(args)

    @pytest.mark.parametrize(
        "args",
        [
            ["--mount", "type=bind,source=/opt/app,target=/app"],
            ["--mount=type=volume,source=mydata,target=/data"],
            ["--mount", "type=tmpfs,target=/tmp"],
        ],
    )
    def test_mount_non_root_allowed(self, args: list[str]) -> None:
        _reject_escalation_flags(args)  # must not raise

    # --- INC-025: container:<id> namespace join ---

    @pytest.mark.parametrize(
        "args",
        [
            ["--pid=container:victim"],
            ["--ipc=container:abc123"],
            ["--uts=container:foo"],
            ["--userns=container:bar"],
            ["--network=container:baz"],
            ["--net=container:quux"],
            # Two-token form:
            ["--pid", "container:victim"],
            ["--network", "container:victim"],
        ],
    )
    def test_container_namespace_join_blocked(self, args: list[str]) -> None:
        with pytest.raises(ValueError, match="namespace|ALLOW_DOCKER_PRIVILEGED"):
            _reject_escalation_flags(args)

    @pytest.mark.parametrize(
        "args",
        [
            [],
            ["-e", "FOO=bar"],
            ["-p", "8080:80"],
            ["--name", "nginx"],
            ["--network", "bridge"],  # non-host network is fine
            ["-v", "/opt/app:/data"],  # non-root bind mount is fine
            ["--user", "1000:1000"],
            ["--rm", "-d"],
        ],
    )
    def test_accepts_benign_flags(self, args: list[str]) -> None:
        _reject_escalation_flags(args)  # must not raise


@pytest.mark.asyncio
async def test_ssh_docker_run_refuses_privileged_without_opt_in() -> None:
    """Integration-ish: ssh_docker_run must call the checker before touching
    the pool. We use a stub ctx that only surfaces settings; reaching SSH
    would throw a KeyError on ``hosts`` / ``pool`` instead of the ValueError
    we expect."""
    from ssh_mcp.config import Settings
    from ssh_mcp.tools.docker_tools import ssh_docker_run

    class _Ctx:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "settings": Settings(ALLOW_DOCKER_PRIVILEGED=False),
        }

    with pytest.raises(ValueError, match="ALLOW_DOCKER_PRIVILEGED"):
        await ssh_docker_run(
            host="web01",
            image="alpine",
            ctx=_Ctx(),  # type: ignore[arg-type]
            args=["--privileged"],
        )


@pytest.mark.asyncio
async def test_ssh_docker_run_opt_in_skips_the_check() -> None:
    """With ALLOW_DOCKER_PRIVILEGED=true the escalation check is not run.
    We stop the code before it actually runs docker by passing a ctx whose
    lifespan_context raises a distinctive sentinel when the tool reaches for
    ``hosts`` (the first key accessed after the escalation check)."""
    from ssh_mcp.config import Settings
    from ssh_mcp.tools.docker_tools import ssh_docker_run

    class _Sentinel(Exception):
        pass

    class _LifespanDict(dict):
        def __getitem__(self, key):  # type: ignore[override]
            if key in ("hosts", "pool"):
                raise _Sentinel(f"reached {key!r} -- escalation check was bypassed")
            return super().__getitem__(key)

    class _Ctx:
        lifespan_context = _LifespanDict(
            {"settings": Settings(ALLOW_DOCKER_PRIVILEGED=True)}
        )

    with pytest.raises(_Sentinel):
        await ssh_docker_run(
            host="web01",
            image="alpine",
            ctx=_Ctx(),  # type: ignore[arg-type]
            args=["--privileged"],
        )
