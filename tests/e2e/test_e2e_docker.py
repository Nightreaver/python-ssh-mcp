"""E2E tests for the `group:docker` tool family.

Each test starts by asking the host whether it has docker installed and
usable by the SSH user (``docker version``). If not, the test skips rather
than fails -- so this file is safe to run against a mixed fleet where only
some hosts have docker.

Everything is keyed off a disposable container named ``ssh-mcp-e2e-<rand>``
and the ``busybox:latest`` image (tiny, universally available). Finally
blocks best-effort-force-remove the container even when an assertion fails
so the host doesn't collect stuck containers between test runs.

Tests marked with `destructive=True` at the docstring level mutate shared
state (image pull, prune) and must only run against a dedicated test host
or a workstation the operator owns.
"""
from __future__ import annotations

import base64
import contextlib
import secrets

import pytest

from ssh_mcp.tools.docker_tools import (
    ssh_docker_compose_down,
    ssh_docker_compose_logs,
    ssh_docker_compose_ps,
    ssh_docker_compose_pull,
    ssh_docker_compose_restart,
    ssh_docker_compose_start,
    ssh_docker_compose_stop,
    ssh_docker_compose_up,
    ssh_docker_cp,
    ssh_docker_events,
    ssh_docker_exec,
    ssh_docker_images,
    ssh_docker_inspect,
    ssh_docker_logs,
    ssh_docker_prune,
    ssh_docker_ps,
    ssh_docker_pull,
    ssh_docker_restart,
    ssh_docker_rm,
    ssh_docker_rmi,
    ssh_docker_run,
    ssh_docker_start,
    ssh_docker_stats,
    ssh_docker_stop,
    ssh_docker_top,
    ssh_docker_volumes,
)
from ssh_mcp.tools.low_access_tools import (
    ssh_delete_folder,
    ssh_mkdir,
    ssh_upload,
)
from ssh_mcp.tools.sftp_read_tools import ssh_sftp_download

from .conftest import has_compose, has_docker, skip_if_unreachable

pytestmark = pytest.mark.e2e

IMAGE = "busybox:latest"


def pytest_generate_tests(metafunc):
    """Parametrize over every alias, same pattern as test_e2e_real_hosts.py."""
    if "alias" not in metafunc.fixturenames:
        return
    from ssh_mcp.config import Settings
    from ssh_mcp.hosts import load_hosts

    from .conftest import HOSTS_FILE

    if not HOSTS_FILE.exists():
        metafunc.parametrize("alias", [], ids=[])
        return
    settings = Settings(SSH_HOSTS_FILE=HOSTS_FILE)
    hosts = load_hosts(HOSTS_FILE, settings)
    names = sorted(hosts.keys())
    metafunc.parametrize("alias", names, ids=names)


async def _skip_unless_docker(alias, e2e_pool, e2e_hosts):
    """Common prologue: reach + docker probe. Skip cleanly if either fails."""
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        pytest.skip(f"{alias}: docker tests target POSIX hosts only")
    if not await has_docker(alias, e2e_pool, policy):
        pytest.skip(f"{alias}: docker not available (docker version failed)")


# --- Read-only docker tools ----------------------------------------------


async def test_docker_ps_images_volumes_events(
    alias, e2e_ctx, e2e_hosts, e2e_reachable, e2e_pool,
):
    """`ssh_docker_ps/images/volumes/events`: read-only, safe on any host.

    Bundled so one docker-availability probe covers four read-only tools.
    """
    skip_if_unreachable(e2e_reachable, alias)
    await _skip_unless_docker(alias, e2e_pool, e2e_hosts)

    ps = await ssh_docker_ps(host=alias, ctx=e2e_ctx, all_=True)
    assert "containers" in ps
    assert isinstance(ps["containers"], list)

    imgs = await ssh_docker_images(host=alias, ctx=e2e_ctx)
    assert "images" in imgs
    assert isinstance(imgs["images"], list)

    vols = await ssh_docker_volumes(host=alias, ctx=e2e_ctx)
    assert "volumes" in vols
    assert isinstance(vols["volumes"], list)

    # events defaults to `since="1h"` and returns a list of event dicts from
    # the daemon's audit log. On a freshly booted host with no activity the
    # list may be empty -- that's fine.
    evs = await ssh_docker_events(host=alias, ctx=e2e_ctx, since="1h")
    assert "events" in evs
    assert isinstance(evs["events"], list)


# --- Full container lifecycle (pull → run → inspect → logs → top → stats →
#                               exec → cp → stop → start → restart → rm) --


async def test_docker_container_lifecycle(
    alias, e2e_ctx, e2e_hosts, e2e_reachable, e2e_pool,
):
    """Drive a single busybox container through the whole dangerous-tier API.

    Chained on purpose so the pull runs once and each subsequent tool gets
    exercised against a container we know is in the expected state. Uses a
    unique container name so concurrent runs don't collide.
    """
    skip_if_unreachable(e2e_reachable, alias)
    await _skip_unless_docker(alias, e2e_pool, e2e_hosts)

    container = f"ssh-mcp-e2e-{secrets.token_hex(4)}"
    scratch = f"/tmp/ssh-mcp-e2e-docker-{secrets.token_hex(4)}"

    # 1. pull busybox. Idempotent -- already-pulled images are a no-op.
    pulled = await ssh_docker_pull(host=alias, image=IMAGE, ctx=e2e_ctx, timeout=60)
    assert pulled["exit_code"] == 0

    try:
        # 2. run detached with sleep infinity so subsequent tools have a target
        ran = await ssh_docker_run(
            host=alias, image=IMAGE, ctx=e2e_ctx,
            args=["sh", "-c", "sleep 3600"],
            name=container, detached=True, remove=False, timeout=30,
        )
        assert ran["exit_code"] == 0

        # 3. inspect the container
        insp = await ssh_docker_inspect(
            host=alias, ctx=e2e_ctx, target=container, kind="container",
        )
        assert insp["objects"], insp
        assert insp["objects"][0]["Name"].lstrip("/") == container

        # 4. logs (may be empty since busybox + sleep produces no output)
        logs = await ssh_docker_logs(
            host=alias, ctx=e2e_ctx, container=container, tail=10,
        )
        assert logs["exit_code"] == 0

        # 5. top (needs a running container -- ours is). `ssh_docker_top`
        # returns the raw ExecResult; `stdout` holds `ps`-style text with a
        # header line + one row per process.
        top = await ssh_docker_top(host=alias, ctx=e2e_ctx, container=container)
        assert top["exit_code"] == 0
        assert "PID" in top["stdout"] or "pid" in top["stdout"].lower()

        # 6. stats (daemon-wide, not scoped to our container). Parsed JSON
        # lines land under `containers`, not `stats` -- see
        # src/ssh_mcp/tools/docker_tools.py::ssh_docker_stats.
        stats = await ssh_docker_stats(host=alias, ctx=e2e_ctx)
        assert "containers" in stats
        names = [s.get("Name") for s in stats["containers"]]
        assert container in names, (
            f"our container {container!r} should show up in docker stats: {names!r}"
        )

        # 7. exec a command inside the container
        execed = await ssh_docker_exec(
            host=alias, ctx=e2e_ctx, container=container, command="echo hi-exec",
        )
        assert execed["exit_code"] == 0
        assert "hi-exec" in execed["stdout"]

        # 8. cp into the container + back out to verify contents
        await ssh_mkdir(host=alias, path=scratch, ctx=e2e_ctx, parents=False)
        host_in = f"{scratch}/upload.txt"
        host_out = f"{scratch}/download.txt"
        payload = b"cp-roundtrip-payload\n"
        await ssh_upload(
            host=alias, path=host_in, ctx=e2e_ctx,
            content_base64=base64.b64encode(payload).decode("ascii"),
        )
        to = await ssh_docker_cp(
            host=alias, ctx=e2e_ctx, container=container,
            container_path="/tmp/ssh-mcp-e2e.txt",
            host_path=host_in, direction="to_container",
        )
        assert to["exit_code"] == 0
        back = await ssh_docker_cp(
            host=alias, ctx=e2e_ctx, container=container,
            container_path="/tmp/ssh-mcp-e2e.txt",
            host_path=host_out, direction="from_container",
        )
        assert back["exit_code"] == 0
        dl = await ssh_sftp_download(host=alias, path=host_out, ctx=e2e_ctx)
        assert base64.b64decode(dl.content_base64) == payload

        # 9. stop → start → restart (low-access lifecycle, all idempotent)
        stop = await ssh_docker_stop(host=alias, ctx=e2e_ctx, container=container)
        assert stop["exit_code"] == 0
        start = await ssh_docker_start(host=alias, ctx=e2e_ctx, container=container)
        assert start["exit_code"] == 0
        restart = await ssh_docker_restart(
            host=alias, ctx=e2e_ctx, container=container,
        )
        assert restart["exit_code"] == 0

        # 10. rm -f (dangerous tier removal)
        rm = await ssh_docker_rm(
            host=alias, ctx=e2e_ctx, container=container, force=True,
        )
        assert rm["exit_code"] == 0

    finally:
        # Best-effort cleanup so a failed assertion still removes the container
        # + scratch dir; ignore errors since the happy path already removed them.
        with contextlib.suppress(Exception):
            await ssh_docker_rm(
                host=alias, ctx=e2e_ctx, container=container, force=True,
            )
        with contextlib.suppress(Exception):
            await ssh_delete_folder(
                host=alias, path=scratch, ctx=e2e_ctx, recursive=True,
            )


# --- Compose lifecycle ----------------------------------------------------


COMPOSE_YML = """\
services:
  svc:
    image: busybox:latest
    command: sh -c "sleep 3600"
    restart: unless-stopped
"""


async def test_docker_compose_lifecycle(
    alias, e2e_ctx, e2e_hosts, e2e_reachable, e2e_pool,
):
    """Full compose flow: pull -> up -> ps -> logs -> stop/start/restart -> down.

    Uses a tiny one-service compose file uploaded to a scratch dir so the
    whole project lives under /tmp and doesn't interfere with anything else.
    """
    skip_if_unreachable(e2e_reachable, alias)
    await _skip_unless_docker(alias, e2e_pool, e2e_hosts)
    policy = e2e_hosts[alias]
    if not await has_compose(alias, e2e_pool, policy):
        pytest.skip(f"{alias}: docker compose v2 plugin not installed")

    scratch = f"/tmp/ssh-mcp-e2e-compose-{secrets.token_hex(4)}"
    compose_path = f"{scratch}/compose.yml"

    await ssh_mkdir(host=alias, path=scratch, ctx=e2e_ctx, parents=False)
    try:
        await ssh_upload(
            host=alias, path=compose_path, ctx=e2e_ctx,
            content_base64=base64.b64encode(COMPOSE_YML.encode()).decode("ascii"),
        )

        pulled = await ssh_docker_compose_pull(
            host=alias, ctx=e2e_ctx, compose_file=compose_path, timeout=60,
        )
        assert pulled["exit_code"] == 0

        upped = await ssh_docker_compose_up(
            host=alias, ctx=e2e_ctx, compose_file=compose_path,
            detached=True, timeout=60,
        )
        assert upped["exit_code"] == 0

        try:
            ps = await ssh_docker_compose_ps(
                host=alias, ctx=e2e_ctx, compose_file=compose_path,
            )
            assert ps["exit_code"] == 0
            # stdout is line-delimited JSON per service
            assert "svc" in ps["stdout"]

            logs = await ssh_docker_compose_logs(
                host=alias, ctx=e2e_ctx, compose_file=compose_path, tail=20,
            )
            assert logs["exit_code"] == 0

            stopped = await ssh_docker_compose_stop(
                host=alias, ctx=e2e_ctx, compose_file=compose_path,
            )
            assert stopped["exit_code"] == 0

            started = await ssh_docker_compose_start(
                host=alias, ctx=e2e_ctx, compose_file=compose_path,
            )
            assert started["exit_code"] == 0

            restarted = await ssh_docker_compose_restart(
                host=alias, ctx=e2e_ctx, compose_file=compose_path,
            )
            assert restarted["exit_code"] == 0
        finally:
            # always tear down so the next run starts clean
            with contextlib.suppress(Exception):
                await ssh_docker_compose_down(
                    host=alias, ctx=e2e_ctx, compose_file=compose_path,
                    volumes=True, timeout=30,
                )

    finally:
        with contextlib.suppress(Exception):
            await ssh_delete_folder(
                host=alias, path=scratch, ctx=e2e_ctx, recursive=True,
            )


# --- Prune (destructive but scoped) --------------------------------------


async def test_docker_prune_containers(
    alias, e2e_ctx, e2e_hosts, e2e_reachable, e2e_pool,
):
    """`ssh_docker_prune(scope="container")` -- removes only stopped containers.

    Safer than image/volume prune because it can only delete containers that
    are already stopped. Scope=volume or scope=image with all_=True could
    wipe real data, so we deliberately stick to scope=container here.
    """
    skip_if_unreachable(e2e_reachable, alias)
    await _skip_unless_docker(alias, e2e_pool, e2e_hosts)

    result = await ssh_docker_prune(host=alias, ctx=e2e_ctx, scope="container")
    assert result["exit_code"] == 0


async def test_docker_rmi_busybox(
    alias, e2e_ctx, e2e_hosts, e2e_reachable, e2e_pool,
):
    """`ssh_docker_rmi`: remove busybox image pulled by earlier tests.

    Tolerates "image not present" (another test cleaned up first, or
    busybox isn't cached on this host) -- we just verify the tool's error
    surface is intact in that case.
    """
    skip_if_unreachable(e2e_reachable, alias)
    await _skip_unless_docker(alias, e2e_pool, e2e_hosts)

    result = await ssh_docker_rmi(
        host=alias, ctx=e2e_ctx, image=IMAGE, force=True,
    )
    # exit 0 on success, !=0 if image wasn't present -- both are fine.
    assert "exit_code" in result
