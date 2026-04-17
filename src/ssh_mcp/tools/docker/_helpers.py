"""Shared helpers for the docker tool family.

Split out of the original 1016-line `tools/docker_tools.py` (INC-043). Everything
here is stateless and reused by the three tier-specific tool modules:
`read_tools`, `lifecycle_tools`, `dangerous_tools`. Nothing in here registers a
tool -- that's the job of the sibling modules.

Private surface: every name starts with `_` except the regex constants that
tests reference directly. The facade in `../docker_tools.py` re-exports
everything tests + external callers have historically imported.
"""
from __future__ import annotations

import json
import posixpath
import re
import shlex
from typing import TYPE_CHECKING, Any

from ...services.path_policy import (
    canonicalize_and_check,
    effective_allowlist,
)
from ...ssh.exec import run as exec_run
from .._context import pool_from, require_posix, resolve_host, settings_from

if TYPE_CHECKING:
    from fastmcp import Context

    from ...config import Settings
    from ...models.policy import HostPolicy


# ---------------------------------------------------------------------------
# Name validation
# ---------------------------------------------------------------------------

# Docker container/image names: start with alnum, continue with alnum / _ . -.
# Matches Docker's own rule (see reference/rules for naming).
_DOCKER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")


def _validate_name(kind: str, name: str) -> str:
    if not _DOCKER_NAME_RE.match(name):
        raise ValueError(
            f"invalid docker {kind} name {name!r}: must match [A-Za-z0-9][A-Za-z0-9_.-]*"
        )
    return name


# ---------------------------------------------------------------------------
# Host-escape deny-list for `docker run` (INC-022 / INC-024 / INC-025)
# ---------------------------------------------------------------------------

# Flags that let a container escape to the host. `docker run` under the
# `dangerous` tier would accept these by default -- operators who flipped
# ALLOW_DANGEROUS_TOOLS for "docker ps / logs / one-shot run" typically don't
# realize `--privileged` is effectively root on the target. We deny-list them
# unless the operator explicitly opts in via ALLOW_DOCKER_PRIVILEGED=true.
_DOCKER_ESCALATION_PREFIXES = (
    "--privileged",
    "--cap-add",         # any capability add -- Linux cap escalation
    "--pid=host",
    "--ipc=host",
    "--uts=host",
    "--userns=host",
    "--network=host",
    "--net=host",
    "--security-opt",    # apparmor=unconfined, seccomp=unconfined, etc.
    "--device",          # arbitrary host device access
    "--group-add",       # e.g. adding docker/root group inside container
)
# Two-token form: "--network host" equivalent to "--network=host".
_DOCKER_NAMESPACE_FLAGS = frozenset({
    "--pid", "--ipc", "--uts", "--userns", "--network", "--net",
})
_DOCKER_VOLUME_FLAGS = frozenset({"-v", "--volume", "--mount"})


def _mount_source_is_host_root(mount_spec: str) -> bool:
    """Parse a ``--mount type=bind,source=/,target=/host`` value and return
    True if source / src resolves to ``/``. INC-024.
    """
    kv: dict[str, str] = {}
    for part in mount_spec.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            kv[k.strip()] = v.strip()
    src = kv.get("source") or kv.get("src")
    if not src:
        return False
    # posixpath.normpath folds trailing slashes + `/./` to `/`, but preserves
    # leading `//` (POSIX reserves `//` as implementation-defined). Treat any
    # normalised form that collapses to `/` or `//` as host-root.
    normalised = posixpath.normpath(src)
    return normalised in ("/", "//")


def _reject_escalation_flags(args: list[str]) -> None:
    """Raise ValueError on any flag known to break the container boundary.

    Best-effort: covers the common patterns (``--privileged``, ``--cap-add``,
    ``--network=host``, ``--volume=/:``, ``-v / /host``, namespace-sharing
    flags including ``container:<id>`` joins, ``--mount source=/`` bind
    mounts). Operators who need these flags set ``ALLOW_DOCKER_PRIVILEGED=true``;
    bypass is explicit and grep-able in env / audit logs.
    """
    prev = None
    for arg in args:
        # Direct flag match or `=value` form. Namespace flags additionally
        # reject `=container:<id>` (INC-025).
        for pat in _DOCKER_ESCALATION_PREFIXES:
            if arg == pat or arg.startswith(pat + "="):
                raise ValueError(
                    f"ssh_docker_run refuses flag {arg!r}: grants container "
                    f"capabilities equivalent to root on the host. Set "
                    f"ALLOW_DOCKER_PRIVILEGED=true to permit."
                )
        # `--pid=container:victim`, `--ipc=container:victim`, ... (N2b).
        for ns in _DOCKER_NAMESPACE_FLAGS:
            if arg.startswith(ns + "=container:"):
                raise ValueError(
                    f"ssh_docker_run refuses {arg!r}: joins another "
                    f"container's namespace. Set ALLOW_DOCKER_PRIVILEGED=true "
                    f"to permit."
                )
        # Two-token form for namespace-sharing flags: `--pid host`,
        # `--pid container:<id>` (N2b).
        if prev in _DOCKER_NAMESPACE_FLAGS and (
            arg == "host" or arg.startswith("container:")
        ):
            raise ValueError(
                f"ssh_docker_run refuses {prev!r} {arg!r}: shares the host "
                f"or another container's namespace. Set "
                f"ALLOW_DOCKER_PRIVILEGED=true to permit."
            )
        # Host-root bind mount via `-v / /host` or `-v /:...`.
        if prev in ("-v", "--volume") and (arg == "/" or arg.startswith("/:")):
            raise ValueError(
                f"ssh_docker_run refuses host-root volume mount {arg!r}: "
                f"grants the container the entire host filesystem. Set "
                f"ALLOW_DOCKER_PRIVILEGED=true to permit."
            )
        # `--volume=/:...` in one-token form.
        if arg.startswith("--volume=/:") or arg.startswith("--volume=/ ") or arg == "--volume=/":
            raise ValueError(
                f"ssh_docker_run refuses host-root volume mount {arg!r}: "
                f"grants the container the entire host filesystem. Set "
                f"ALLOW_DOCKER_PRIVILEGED=true to permit."
            )
        # `--mount type=bind,source=/,target=/host` -- N2a: the post-flag
        # checker above doesn't fire because --mount values never start with
        # "/" or "/:". Parse the KV blob and reject when source resolves to /.
        if prev == "--mount":
            if _mount_source_is_host_root(arg):
                raise ValueError(
                    f"ssh_docker_run refuses host-root --mount source in "
                    f"{arg!r}: grants the container the entire host filesystem. "
                    f"Set ALLOW_DOCKER_PRIVILEGED=true to permit."
                )
        elif arg.startswith("--mount="):
            spec = arg.split("=", 1)[1]
            if _mount_source_is_host_root(spec):
                raise ValueError(
                    f"ssh_docker_run refuses host-root --mount source in "
                    f"{arg!r}: grants the container the entire host filesystem. "
                    f"Set ALLOW_DOCKER_PRIVILEGED=true to permit."
                )
        prev = arg


# ---------------------------------------------------------------------------
# CLI prefix resolution (docker vs podman, compose subcommand vs legacy binary)
# ---------------------------------------------------------------------------


def _docker_prefix(policy: HostPolicy, settings: Settings) -> list[str]:
    """Return the argv tokens for the Docker CLI on this host.

    Resolution: per-host ``docker_cmd`` (from hosts.toml) wins; otherwise the
    global ``SSH_DOCKER_CMD``. Shell-split so operators can prepend wrappers
    like ``sudo docker`` or ``env FOO=bar docker``.
    """
    raw = policy.docker_cmd or settings.SSH_DOCKER_CMD or "docker"
    return shlex.split(raw)


def _compose_prefix(
    policy: HostPolicy, settings: Settings, *, v1: bool = False,
) -> list[str]:
    """Return the argv tokens for the compose invocation on this host.

    Default (``v1=False``): use ``SSH_DOCKER_COMPOSE_CMD`` shell-split if set
    (operator override), otherwise derive ``{docker_prefix} compose`` (v2 plugin
    subcommand form -- ``docker compose``, ``podman compose``, etc.). That way
    ``SSH_DOCKER_CMD=podman`` / per-host ``docker_cmd = "podman"`` automatically
    yields ``podman compose`` without a second knob.

    ``v1=True``: force the legacy standalone-binary form (``docker-compose``,
    ``podman-compose``). Derived from the docker prefix so ``sudo``, ``env``,
    and other wrappers still apply -- e.g. ``["sudo", "docker"]`` becomes
    ``["sudo", "docker-compose"]``. Overrides ``SSH_DOCKER_COMPOSE_CMD`` on
    purpose: when the caller asks for v1, they're overriding whatever was
    configured globally.
    """
    if v1:
        docker = _docker_prefix(policy, settings)
        # Replace the last token (binary name) with its dashed-compose variant.
        # `docker[:-1]` preserves wrappers like `sudo` / `env FOO=bar`.
        return [*docker[:-1], f"{docker[-1]}-compose"]
    explicit = (settings.SSH_DOCKER_COMPOSE_CMD or "").strip()
    if explicit:
        return shlex.split(explicit)
    return [*_docker_prefix(policy, settings), "compose"]


# ---------------------------------------------------------------------------
# The shared runner that every docker tool routes through
# ---------------------------------------------------------------------------


async def _run_docker(
    ctx: Context,
    host: str,
    subargs: list[str],
    *,
    compose: bool = False,
    compose_v1: bool = False,
    timeout: int | None = None,
    stdin: str | None = None,
    stdout_cap: int | None = None,
) -> dict[str, Any]:
    """Execute a docker subcommand on the remote and return ``ExecResult.model_dump()``.

    ``subargs`` is everything that comes AFTER the docker binary -- e.g.
    ``["ps", "--format", "{{json .}}"]`` for a non-compose call, or
    ``["-f", compose_file, "ps", "--format", "json"]`` for a compose call.
    The binary (and `compose` subcommand, when ``compose=True``) is prepended
    here based on `SSH_DOCKER_CMD` / per-host `docker_cmd` / `SSH_DOCKER_COMPOSE_CMD`.

    ``stdout_cap`` lets log tools tighten the byte budget below the global
    ``SSH_STDOUT_CAP_BYTES`` (default 1 MiB) -- a full megabyte of docker logs
    is ~250k LLM tokens and would blow out most context windows on a single call.
    """
    pool = pool_from(ctx)
    settings = settings_from(ctx)
    policy = resolve_host(ctx, host)
    # All docker tools assume POSIX shell quoting via shlex.join + pkill-backed
    # timeout cleanup. Docker Desktop on Windows targets is out of scope for
    # now (see DECISIONS.md ADR-0023).
    require_posix(
        policy,
        tool="ssh_docker_*",
        reason="docker tools use POSIX shell quoting (`shlex.join`) + pkill",
    )
    conn = await pool.acquire(policy)
    prefix = (
        _compose_prefix(policy, settings, v1=compose_v1)
        if compose
        else _docker_prefix(policy, settings)
    )
    argv = [*prefix, *subargs]
    result = await exec_run(
        conn,
        shlex.join(argv),
        host=policy.hostname,
        timeout=float(timeout if timeout is not None else settings.SSH_COMMAND_TIMEOUT),
        stdout_cap=stdout_cap if stdout_cap is not None else settings.SSH_STDOUT_CAP_BYTES,
        stderr_cap=settings.SSH_STDERR_CAP_BYTES,
        stdin=stdin,
    )
    return result.model_dump()


# Log tools ship far more bytes per line than a typical command. Default to a
# smaller cap (~16k tokens equivalent) and let callers raise it via `max_bytes`.
_DEFAULT_LOG_MAX_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Compose subcommand runner (shared between lifecycle_tools + dangerous_tools)
# ---------------------------------------------------------------------------


async def _compose_project_op(
    ctx: Context,
    host: str,
    compose_file: str,
    subcommand: str,
    *,
    compose_v1: bool = False,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Shared runner for compose subcommands that just take -f <file> <cmd>."""
    settings = settings_from(ctx)
    pool = pool_from(ctx)
    policy = resolve_host(ctx, host)
    conn = await pool.acquire(policy)
    canonical = await canonicalize_and_check(
        conn, compose_file, effective_allowlist(policy, settings),
        must_exist=True, platform=policy.platform,
    )
    argv = ["-f", canonical, subcommand]
    return await _run_docker(
        ctx, host, argv, compose=True, compose_v1=compose_v1, timeout=timeout,
    )


# ---------------------------------------------------------------------------
# docker events time-anchor + filter regexes (used by read_tools.ssh_docker_events)
# ---------------------------------------------------------------------------

# Time-anchor formats accepted by `docker events --since|--until`:
#   - relative: `10m`, `2h`, `24h30m`  (units: s/m/h only -- no `d`!)
#   - Unix epoch: `1710000000` or `1710000000.123456`
#   - RFC3339: `2026-04-16T12:00:00Z` / with offset / with fractional seconds
# Relative durations route through Go's `time.ParseDuration` on the daemon
# side, which recognizes ns/us/ms/s/m/h but NOT `d`. We reject `d` here
# rather than let it reach the daemon and fail with `time: unknown unit "d"`.
# For longer windows, use epoch timestamps or multiply hours (`168h` = 7d).
_DOCKER_TIME_RE = re.compile(
    r"^(?:"
    r"\d+(?:\.\d+)?"                            # epoch (int or float)
    r"|(?:\d+[smh])+"                           # relative (e.g. 10m, 2h, 24h30m)
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"    # ISO datetime
      r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"    # optional fractional + tz
    r"|now"
    r")$",
)

# Filter expressions for `docker events --filter KEY=VALUE`. Conservative:
# key is a bare identifier, value is alphanumeric + a few path-safe chars. If
# an operator needs something fancier, `ssh_exec_run` + a command-allowlist
# entry covers the escape hatch.
_DOCKER_FILTER_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9._\-:/ ]{1,256}$",
)


# ---------------------------------------------------------------------------
# stdout post-processing for list tools (ps / images / compose ps)
# ---------------------------------------------------------------------------


def _parse_json_lines(stdout: str) -> list[Any]:
    """Parse newline-delimited JSON (``--format '{{json .}}'`` output)."""
    out: list[Any] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _strip_noisy_fields(objects: list[Any], fields: tuple[str, ...]) -> None:
    """Drop ``fields`` from each dict in-place. Non-dict entries are skipped.

    Called from the list tools to cut OCI label bloat before the result hits
    the MCP output cap. Mutates ``objects``.
    """
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        for field_name in fields:
            obj.pop(field_name, None)


def _rewrite_stdout(result: dict[str, Any], objects: list[Any]) -> None:
    """Re-serialize ``objects`` as NDJSON back into ``result['stdout']`` and
    recompute byte counts. Keeps the returned ExecResult consistent with the
    parsed list after we've dropped fields from it.
    """
    new_stdout = "\n".join(
        json.dumps(o, separators=(",", ":")) for o in objects
    )
    if new_stdout:
        new_stdout += "\n"
    result["stdout"] = new_stdout
    result["stdout_bytes"] = len(new_stdout.encode("utf-8"))
    # Preserve the original stdout_truncated: if docker's output hit the cap
    # before we got to parse it, we're still missing entries the caller can't
    # see. The fact that our rewritten stdout is smaller doesn't change that.
