"""End-to-end tool tests against the operator's real hosts.toml.

Each test parametrizes over every alias declared in `hosts.toml`. Per-host
reachability is checked once per session; unreachable hosts skip rather than
fail. Platform-specific tools split via `skip_if_windows` / `skip_if_posix`.

Read paths (ping, host_info, sftp_*) cost almost nothing on the target.
Write paths confine themselves to a per-test scratch directory under `/tmp`
and clean up regardless of outcome.

Run with:
    pytest -m e2e -v

Or one host:
    pytest -m e2e -v -k test_ubuntu
"""
from __future__ import annotations

import base64
import contextlib
import secrets
import time

import pytest

from ssh_mcp.ssh.errors import PlatformNotSupported
from ssh_mcp.tools.host_tools import (
    ssh_host_alerts,
    ssh_host_disk_usage,
    ssh_host_info,
    ssh_host_ping,
    ssh_host_processes,
    ssh_known_hosts_verify,
)
from ssh_mcp.tools.low_access_tools import (
    ssh_cp,
    ssh_delete,
    ssh_delete_folder,
    ssh_deploy,
    ssh_edit,
    ssh_mkdir,
    ssh_mv,
    ssh_patch,
    ssh_upload,
)
from ssh_mcp.tools.session_tools import ssh_session_list, ssh_session_stats
from ssh_mcp.tools.sftp_read_tools import (
    ssh_file_hash,
    ssh_find,
    ssh_sftp_download,
    ssh_sftp_list,
    ssh_sftp_stat,
)

from .conftest import skip_if_unreachable, skip_if_windows

pytestmark = pytest.mark.e2e


def _aliases(hosts: dict) -> list[str]:
    return sorted(hosts.keys())


# Generic per-host parametrization. Pytest collects this once per session
# from the `e2e_hosts` fixture via indirect lookup. We can't `parametrize`
# over a fixture directly, so collect aliases lazily inside the body.


def pytest_generate_tests(metafunc):
    """Inject `alias` parametrization from the live hosts.toml."""
    if "alias" not in metafunc.fixturenames:
        return
    # Re-load hosts.toml at collection time -- the e2e_hosts fixture isn't
    # available yet (fixtures resolve at call-time, not collection-time).
    from ssh_mcp.config import Settings
    from ssh_mcp.hosts import load_hosts

    from .conftest import HOSTS_FILE

    if not HOSTS_FILE.exists():
        metafunc.parametrize("alias", [], ids=[])
        return
    settings = Settings(SSH_HOSTS_FILE=HOSTS_FILE)
    hosts = load_hosts(HOSTS_FILE, settings)
    metafunc.parametrize("alias", _aliases(hosts), ids=_aliases(hosts))


# --- Connectivity ---------------------------------------------------------


async def test_ping(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_host_ping: TCP + handshake + agent-auth round-trip."""
    skip_if_unreachable(e2e_reachable, alias)
    result = await ssh_host_ping(host=alias, ctx=e2e_ctx)
    assert result.host == e2e_hosts[alias].hostname
    assert result.reachable is True, f"ping says unreachable: {result}"
    assert result.auth_ok is True, (
        f"auth failed -- check ssh-agent has the pinned key loaded: {result}"
    )
    assert result.server_banner, "server banner should be populated after handshake"
    assert result.latency_ms >= 0


async def test_platform_matches_banner(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """Sanity check: the policy's `platform` should match what the banner claims.

    If hosts.toml declares a host without ``platform = "windows"`` but the
    server banner is OpenSSH_for_Windows, every POSIX-shell tool will fail on
    that host with a cryptic error -- catch it here as a config issue.
    """
    skip_if_unreachable(e2e_reachable, alias)
    result = await ssh_host_ping(host=alias, ctx=e2e_ctx)
    banner = (result.server_banner or "").lower()
    declared = e2e_hosts[alias].platform
    if "for_windows" in banner or "openssh_for_windows" in banner:
        assert declared == "windows", (
            f"{alias}: banner says Windows ({result.server_banner!r}) but "
            f"hosts.toml declares platform={declared!r}. Add "
            f"`platform = \"windows\"` to [hosts.{alias}] so POSIX-only tools "
            f"reject cleanly instead of failing on `realpath`/`uname`."
        )
    else:
        assert declared == "posix", (
            f"{alias}: banner looks POSIX ({result.server_banner!r}) but "
            f"hosts.toml declares platform={declared!r}. Fix the declaration."
        )


async def test_known_hosts_verify(alias, e2e_ctx, e2e_reachable):
    """ssh_known_hosts_verify: live host key matches the pinned entry."""
    skip_if_unreachable(e2e_reachable, alias)
    result = await ssh_known_hosts_verify(host=alias, ctx=e2e_ctx)
    assert result["matches_known_hosts"] is True, (
        f"known_hosts mismatch (or no entry pinned): {result}"
    )
    assert result["expected_fingerprint"], "no fingerprint in known_hosts -- pin first"
    assert result["live_fingerprint"] == result["expected_fingerprint"]
    assert result["error"] is None


# --- POSIX-shell-dependent tools -----------------------------------------


async def test_host_info_posix(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_host_info works on POSIX, raises PlatformNotSupported on Windows."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_host_info(host=alias, ctx=e2e_ctx)
        return
    result = await ssh_host_info(host=alias, ctx=e2e_ctx)
    assert result.host == policy.hostname
    assert result.uname, "uname empty -- target may not be POSIX after all"
    # /etc/os-release is universal on systemd Linux + most BSDs
    assert isinstance(result.os_release, dict)
    assert result.uptime, "uptime empty -- check `uptime` is on PATH"


async def test_exec_run_echo(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_exec_run: trivial `echo` round-trip on POSIX hosts."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    # ssh_exec_run is registered with @audited(tier="dangerous") -- when
    # ALLOW_DANGEROUS_TOOLS=False the tool function itself still works
    # (gating is at the Visibility-transform layer, not in the body). So we
    # call it directly here regardless of the env flag.
    from ssh_mcp.tools.exec_tools import ssh_exec_run

    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_exec_run(host=alias, command="echo hello", ctx=e2e_ctx)
        return
    sentinel = f"e2e-ping-{secrets.token_hex(4)}"
    result = await ssh_exec_run(
        host=alias, command=f"echo {sentinel}", ctx=e2e_ctx
    )
    assert result.exit_code == 0, result
    assert sentinel in result.stdout, result
    assert result.timed_out is False


# --- SFTP read ------------------------------------------------------------


async def test_sftp_list(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_sftp_list works on every platform (SFTP is universal)."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    target = "C:\\Users" if policy.platform == "windows" else "/tmp"
    result = await ssh_sftp_list(host=alias, path=target, ctx=e2e_ctx)
    assert isinstance(result.entries, list)
    # /tmp on Linux nearly always has at least systemd-private-* dirs etc.;
    # C:\Users always has the user's profile + Default + Public. Don't be
    # rigid -- just confirm the SFTP listdir round-tripped. Slash direction
    # isn't load-bearing: OpenSSH-for-Windows returns forward slashes even
    # for Windows paths, so normalize before comparison.
    got = result.path.lower().replace("\\", "/")
    want = target.lower().replace("\\", "/")
    assert got.startswith(want[:3])  # "/tm" or "c:/"


async def test_sftp_stat_known_file(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_sftp_stat on a file that exists on every box of its platform.

    `StatResult` (see src/ssh_mcp/models/results.py) has no `exists` field --
    a missing file raises ``SFTPError``. Presence is asserted by the absence
    of an exception; `kind` then tells us it's a regular file.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    target = (
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
        if policy.platform == "windows"
        else "/etc/hostname"  # universal on every Linux distro
    )
    result = await ssh_sftp_stat(host=alias, path=target, ctx=e2e_ctx)
    assert result.kind == "file", result
    assert result.size >= 0
    assert result.path.lower().endswith(("hostname", "hosts"))


# --- File-hash (POSIX + Windows after INC-028) ---------------------------


async def test_file_hash(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """`ssh_file_hash` on a known file, both platforms.

    INC-028: Windows dispatches to the PowerShell `-EncodedCommand` path
    (base64-UTF16LE of a `Get-FileHash` script). Prior to the fix this
    test raised `PlatformNotSupported` on Windows; now it returns a real
    digest. Shape of the assertion is identical across platforms because
    the tool lowercases the hex before returning.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    target = (
        "C:\\Windows\\System32\\drivers\\etc\\hosts"
        if policy.platform == "windows"
        else "/etc/hostname"
    )
    result = await ssh_file_hash(host=alias, path=target, ctx=e2e_ctx)
    assert result.algorithm == "sha256"
    # HashResult.digest is lowercase hex, 64 chars for sha256.
    assert len(result.digest) == 64
    assert all(c in "0123456789abcdef" for c in result.digest)
    assert result.size > 0


# --- Write + cleanup roundtrip (POSIX low-access) ------------------------


async def test_upload_download_hash_delete_roundtrip(
    alias, e2e_ctx, e2e_hosts, e2e_reachable
):
    """Full mutate-and-clean cycle in /tmp: mkdir -> upload -> stat -> hash
    -> sftp_download -> delete file -> rmdir folder. Skips Windows; we don't
    have a guaranteed-writable allowlisted path there yet (would need per-user
    AppData\\Local\\Temp in path_allowlist + canonicalization tested first)."""
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    rand = secrets.token_hex(6)
    scratch = f"/tmp/ssh-mcp-e2e-{rand}"
    target = f"{scratch}/payload.txt"
    payload = f"hello from e2e at {time.time()}\n".encode()

    # 1. mkdir scratch (parents=False -- /tmp exists everywhere)
    mk = await ssh_mkdir(host=alias, path=scratch, ctx=e2e_ctx, parents=False)
    assert mk.success is True

    try:
        # 2. upload
        up = await ssh_upload(
            host=alias,
            path=target,
            content_base64=base64.b64encode(payload).decode("ascii"),
            ctx=e2e_ctx,
        )
        assert up.success is True
        assert up.bytes_written == len(payload)

        # 3. stat
        st = await ssh_sftp_stat(host=alias, path=target, ctx=e2e_ctx)
        assert st.kind == "file"
        assert st.size == len(payload)

        # 4. hash + verify locally
        import hashlib

        expected = hashlib.sha256(payload).hexdigest()
        h = await ssh_file_hash(
            host=alias, path=target, ctx=e2e_ctx, algorithm="sha256"
        )
        assert h.digest == expected, (
            f"remote digest {h.digest} != local sha256 {expected} -- transfer corrupted"
        )

        # 5. download + byte-compare
        dl = await ssh_sftp_download(host=alias, path=target, ctx=e2e_ctx)
        assert dl.content_base64, dl
        roundtripped = base64.b64decode(dl.content_base64)
        assert roundtripped == payload

        # 6. delete the file
        rm = await ssh_delete(host=alias, path=target, ctx=e2e_ctx)
        assert rm.success is True

    finally:
        # rmdir scratch (best-effort; ignore failure so the assertion above
        # is what surfaces if something went wrong)
        with contextlib.suppress(Exception):
            await ssh_delete_folder(
                host=alias, path=scratch, ctx=e2e_ctx, recursive=True
            )


# --- Extra host read tools ------------------------------------------------


async def test_host_disk_usage(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_host_disk_usage on POSIX hosts; Windows raises PlatformNotSupported."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_host_disk_usage(host=alias, ctx=e2e_ctx)
        return
    result = await ssh_host_disk_usage(host=alias, ctx=e2e_ctx)
    assert result.host == policy.hostname
    # Every Linux box mounts at least `/` -- if entries is empty, something's
    # wrong with df parsing or the call itself.
    assert result.entries, f"no df entries returned: {result}"
    mounts = [e.mount for e in result.entries]
    assert "/" in mounts, f"no root mount in df output: {mounts}"


async def test_host_processes(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_host_processes returns top-N by CPU; Windows raises."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_host_processes(host=alias, ctx=e2e_ctx, top=5)
        return
    result = await ssh_host_processes(host=alias, ctx=e2e_ctx, top=5)
    assert result.host == policy.hostname
    assert 1 <= len(result.entries) <= 5
    # PID 1 is always running on Linux -- confirms ps parsed at all.
    pids = [e.pid for e in result.entries]
    assert all(p > 0 for p in pids)


async def test_host_alerts(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_host_alerts executes end-to-end; breaches depend on host state.

    With no thresholds configured in hosts.toml the breach list is empty but
    metrics are populated. That's the shape we verify here.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_host_alerts(host=alias, ctx=e2e_ctx)
        return
    result = await ssh_host_alerts(host=alias, ctx=e2e_ctx)
    assert result["host"] == policy.hostname
    assert isinstance(result["breaches"], list)
    assert "metrics" in result


# --- Extra SFTP read: find ------------------------------------------------


async def test_sftp_find(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_find: locate a known file in a known tree.

    POSIX uses the remote `find` binary; Windows uses the SFTP walk fallback
    (ssh_find is platform-agnostic at the tool level). We test both by
    searching for a name we know exists on each platform.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        root = "C:\\Windows\\System32\\drivers\\etc"
        name = "hosts"
    else:
        root = "/etc"
        name = "hostname"
    result = await ssh_find(
        host=alias, path=root, ctx=e2e_ctx,
        name_pattern=name, kind="f", max_depth=1,
    )
    assert result.host == policy.hostname
    assert isinstance(result.matches, list)
    assert any(m.lower().endswith(name.lower()) for m in result.matches), (
        f"expected to find {name!r} under {root!r}, got {result.matches!r}"
    )


# --- Session / pool inspection -------------------------------------------


async def test_session_list_and_stats(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_session_list / stats after acquiring a connection via ping.

    Both tools are ctx-only (no host arg), but we parametrize per alias so
    that each alias's ping warms the pool, then we inspect it. The shape
    check is enough -- actual pool contents depend on test ordering.
    """
    skip_if_unreachable(e2e_reachable, alias)
    # Warm the pool by pinging so there's at least one session to list.
    await ssh_host_ping(host=alias, ctx=e2e_ctx)

    listing = await ssh_session_list(ctx=e2e_ctx)
    assert "sessions" in listing
    assert "count" in listing
    assert listing["count"] >= 1

    stats = await ssh_session_stats(ctx=e2e_ctx)
    assert "open" in stats
    assert "entries" in stats
    assert stats["open"] >= 1


# --- Extra exec tools -----------------------------------------------------


class _StubProgress:
    """No-op stand-in for ``fastmcp.Progress`` outside a server context.

    ``Progress()`` itself errors with "Progress must be used as a dependency"
    because FastMCP expects the framework to inject it. For tool-level e2e
    we just need the three awaitables the tool body actually calls.
    """

    async def set_total(self, total):
        return None

    async def increment(self, amount: int = 1) -> None:
        return None

    async def set_message(self, message):
        return None


async def test_exec_run_streaming(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_exec_run_streaming: short command that still exits cleanly.

    The streaming variant takes a FastMCP ``Progress`` dependency. Outside
    the server `Progress()` errors ("must be used as a dependency"), so we
    inject a duck-typed no-op stub for test purposes.
    """
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    from ssh_mcp.tools.exec_tools import ssh_exec_run_streaming
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_exec_run_streaming(
                host=alias, command="echo hi", ctx=e2e_ctx,
                progress=_StubProgress(),  # type: ignore[arg-type]
            )
        return
    sentinel = f"stream-{secrets.token_hex(3)}"
    result = await ssh_exec_run_streaming(
        host=alias, command=f"echo {sentinel}", ctx=e2e_ctx,
        progress=_StubProgress(),  # type: ignore[arg-type]
    )
    assert result.exit_code == 0
    assert sentinel in result.stdout


async def test_exec_script(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_exec_script: multi-line script piped to `sh -s --`."""
    skip_if_unreachable(e2e_reachable, alias)
    policy = e2e_hosts[alias]
    from ssh_mcp.tools.exec_tools import ssh_exec_script
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_exec_script(host=alias, script="echo hi", ctx=e2e_ctx)
        return
    sentinel = f"script-{secrets.token_hex(3)}"
    script = f"""#!/bin/sh
set -e
x={sentinel}
echo "tag=$x"
"""
    result = await ssh_exec_script(host=alias, script=script, ctx=e2e_ctx)
    assert result.exit_code == 0
    assert f"tag={sentinel}" in result.stdout


# --- Low-access file ops: cp / mv / edit / patch / deploy ----------------


async def test_cp_mv_edit_patch_deploy(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """Full file-ops sweep in one scratch dir: cp, mv, edit, patch, deploy.

    Stays POSIX because `ssh_cp` uses `cp -a` (POSIX only) and `ssh_mv`
    needs cross-fs fallback that isn't wired on Windows. All operations
    confined to ``/tmp/ssh-mcp-e2e-<rand>/``.
    """
    skip_if_unreachable(e2e_reachable, alias)
    skip_if_windows(e2e_hosts[alias])

    rand = secrets.token_hex(6)
    scratch = f"/tmp/ssh-mcp-e2e-ops-{rand}"
    src = f"{scratch}/src.txt"
    dst = f"{scratch}/dst.txt"
    moved = f"{scratch}/moved.txt"

    await ssh_mkdir(host=alias, path=scratch, ctx=e2e_ctx, parents=False)
    try:
        initial = b"greeting = hello\nfoo = bar\n"
        await ssh_upload(
            host=alias, path=src, ctx=e2e_ctx,
            content_base64=base64.b64encode(initial).decode("ascii"),
        )

        # ssh_cp: src -> dst
        cp = await ssh_cp(host=alias, src=src, dst=dst, ctx=e2e_ctx)
        assert cp.success is True
        dst_stat = await ssh_sftp_stat(host=alias, path=dst, ctx=e2e_ctx)
        assert dst_stat.size == len(initial)

        # ssh_edit: single-occurrence replace on dst
        edit = await ssh_edit(
            host=alias, path=dst, ctx=e2e_ctx,
            old_string="hello", new_string="world",
        )
        assert edit.success is True
        dl = await ssh_sftp_download(host=alias, path=dst, ctx=e2e_ctx)
        body = base64.b64decode(dl.content_base64).decode()
        assert "greeting = world" in body
        assert "hello" not in body

        # ssh_patch: apply a unified diff that flips foo=bar -> foo=baz
        diff = (
            "--- a/dst.txt\n"
            "+++ b/dst.txt\n"
            "@@ -1,2 +1,2 @@\n"
            " greeting = world\n"
            "-foo = bar\n"
            "+foo = baz\n"
        )
        patched = await ssh_patch(
            host=alias, path=dst, ctx=e2e_ctx, unified_diff=diff,
        )
        assert patched.success is True
        dl = await ssh_sftp_download(host=alias, path=dst, ctx=e2e_ctx)
        body = base64.b64decode(dl.content_base64).decode()
        assert "foo = baz" in body

        # ssh_mv: dst -> moved
        mv = await ssh_mv(host=alias, src=dst, dst=moved, ctx=e2e_ctx)
        assert mv.success is True
        # Original dst should now be gone -- `canonicalize_and_check` runs
        # `realpath` and surfaces "no such file" as `PathNotAllowed` (the path
        # can't be canonicalized so it can't be checked against the allowlist).
        from ssh_mcp.ssh.errors import PathNotAllowed
        with pytest.raises(PathNotAllowed):
            await ssh_sftp_stat(host=alias, path=dst, ctx=e2e_ctx)

        # ssh_deploy: atomic replace with backup of `moved`
        new_payload = b"greeting = deployed\n"
        dep1 = await ssh_deploy(
            host=alias, path=moved, ctx=e2e_ctx,
            content_base64=base64.b64encode(b"initial = v1\n").decode("ascii"),
            backup=False,
        )
        assert dep1["success"] is True

        # Second deploy with backup=True -- the prior file should be kept as
        # `<path>.bak-<ts>`; we confirm by listing the scratch dir.
        dep2 = await ssh_deploy(
            host=alias, path=moved, ctx=e2e_ctx,
            content_base64=base64.b64encode(new_payload).decode("ascii"),
            backup=True,
        )
        assert dep2["success"] is True
        listing = await ssh_sftp_list(host=alias, path=scratch, ctx=e2e_ctx)
        names = [e.name for e in listing.entries]
        assert any(n.startswith("moved.txt.bak-") for n in names), (
            f"expected a backup sibling of moved.txt in {names!r}"
        )

    finally:
        with contextlib.suppress(Exception):
            await ssh_delete_folder(
                host=alias, path=scratch, ctx=e2e_ctx, recursive=True,
            )


# --- Persistent shell sessions (POSIX-only) ------------------------------


async def test_shell_session_lifecycle(alias, e2e_ctx, e2e_hosts, e2e_reachable):
    """ssh_shell_open / exec / list / close as one flow.

    Opens a session, runs two commands that mutate cwd, verifies the cwd
    sentinel stuck, then closes. POSIX-only (shell tools rely on the sh
    cwd sentinel).
    """
    skip_if_unreachable(e2e_reachable, alias)
    from ssh_mcp.tools.shell_tools import (
        ssh_shell_close,
        ssh_shell_exec,
        ssh_shell_list,
        ssh_shell_open,
    )

    policy = e2e_hosts[alias]
    if policy.platform == "windows":
        with pytest.raises(PlatformNotSupported):
            await ssh_shell_open(host=alias, ctx=e2e_ctx)
        return

    opened = await ssh_shell_open(host=alias, ctx=e2e_ctx)
    sid = opened["session_id"]
    try:
        # First exec: cd to /tmp -- sentinel updates session.cwd
        r1 = await ssh_shell_exec(
            session_id=sid, command="cd /tmp && pwd", ctx=e2e_ctx,
        )
        assert r1["exit_code"] == 0
        assert "/tmp" in r1["stdout"]
        assert r1["cwd"] == "/tmp"

        # Second exec: pwd alone -- confirms cwd was persisted across calls.
        r2 = await ssh_shell_exec(session_id=sid, command="pwd", ctx=e2e_ctx)
        assert r2["exit_code"] == 0
        assert "/tmp" in r2["stdout"]

        # List -- at least our session should appear.
        listed = await ssh_shell_list(ctx=e2e_ctx)
        assert listed["count"] >= 1
        ids = [s["id"] for s in listed["sessions"]]
        assert sid in ids
    finally:
        closed = await ssh_shell_close(session_id=sid, ctx=e2e_ctx)
        assert closed["session_id"] == sid
        assert closed["closed"] is True
