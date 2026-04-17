"""Server lifespan: pool lifecycle + tier gating via Visibility transforms."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastmcp.server.lifespan import lifespan
from fastmcp.server.transforms import Visibility

from .config import settings
from .hosts import load_hosts, merged_host_allowlist
from .services.hooks import HookContext, HookEvent, HookRegistry, load_external_hooks
from .services.shell_sessions import SessionRegistry
from .ssh.known_hosts import KnownHosts
from .ssh.pool import ConnectionPool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

ALL_GROUPS: frozenset[str] = frozenset(
    {
        "host",
        "session",
        "sftp-read",
        "file-ops",
        "exec",
        "sudo",
        "keys",
        "docker",
        "shell",
        "systemctl",
    }
)


def _warn_task_backend(dangerous_enabled: bool) -> None:
    """ADR-0011: warn if running exec tools on an in-memory task backend."""
    if not dangerous_enabled:
        return
    import os

    url = os.environ.get("FASTMCP_DOCKET_URL", "memory://")
    if url.startswith("memory://"):
        logger.warning(
            "ALLOW_DANGEROUS_TOOLS=true with FASTMCP_DOCKET_URL=%s — long-running "
            "exec tasks will be lost on restart. Set FASTMCP_DOCKET_URL=redis://... "
            "for production.",
            url,
        )


_TIER_TAGS = ("safe", "low-access", "dangerous", "sudo")


def _classify_tier(tags: set[str]) -> str:
    """Pick the highest tier tag for display. Falls back to 'untagged'."""
    # sudo > dangerous > low-access > safe
    for tier in reversed(_TIER_TAGS):
        if tier in tags:
            return tier
    return "untagged"


def _group_of(tags: set[str]) -> str:
    for t in tags:
        if t.startswith("group:"):
            return t.split(":", 1)[1]
    return "-"


async def _apply_mcp_annotations(server: Any) -> None:
    """Map our FastMCP-level tier tags onto MCP-protocol ToolAnnotations.

    The MCP spec defaults `destructiveHint` to **true** and `readOnlyHint` to
    **false** for every tool that doesn't set them explicitly. Clients use
    these hints to decide whether to show an approval prompt. Without this
    step every `safe` / `read` tool (ping, sftp_list, docker_ps, ...) shows
    up as "destructive" in the client because we only expose the tier info
    via FastMCP tags, which the MCP layer doesn't see.

    We iterate every registered tool post-transform and derive annotations
    from the existing tier tags:
      - `safe` / `read`  -> readOnlyHint=True, destructiveHint=False, idempotentHint=True
      - `low-access`     -> destructiveHint=False (modifies state, but additive -- no deletes)
                             Exception: `ssh_delete*` tools keep destructive=True (tag: `destructive`)
      - `dangerous` / `sudo` -> destructiveHint=True (default; explicit for clarity)
    All tools get openWorldHint=True -- remote SSH is by definition an open world.
    """
    try:
        from mcp.types import ToolAnnotations
    except ImportError:
        logger.debug("mcp.types not importable; skipping MCP annotation derivation")
        return
    try:
        tools = list(await server._list_tools())
    except Exception as exc:
        logger.warning("could not enumerate tools for MCP annotation derivation: %s", exc)
        return

    for tool in tools:
        # Skip if the operator or FastMCP already set annotations -- respect
        # explicit intent.
        if getattr(tool, "annotations", None) is not None:
            continue
        tags = set(getattr(tool, "tags", set()) or set())
        if "safe" in tags or "read" in tags:
            ann = ToolAnnotations(
                readOnlyHint=True,
                destructiveHint=False,
                idempotentHint=True,
                openWorldHint=True,
            )
        elif "low-access" in tags:
            # File ops / container lifecycle: mutate state but additive.
            # `ssh_delete*` explicitly tag `destructive` to bump this back up.
            is_destructive = "destructive" in tags or tool.name.startswith(
                ("ssh_delete", "ssh_docker_rm", "ssh_docker_prune")
            )
            ann = ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=is_destructive,
                idempotentHint=False,
                openWorldHint=True,
            )
        else:
            # `dangerous`, `sudo`, or untagged -- conservative: honor the spec
            # defaults but be explicit so the client shows the right prompt.
            ann = ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=True,
            )
        tool.annotations = ann


async def _log_tool_catalog(server: Any) -> None:
    """Emit a per-tier / per-group overview of registered + visible tools.

    Visible counts reflect Visibility transforms applied earlier in the lifespan,
    so this is what the LLM actually sees in tools/list.
    """
    try:
        all_tools = list(await server._list_tools())
        visible = list(await server.list_tools())
    except Exception as exc:
        logger.warning("could not enumerate tools for startup overview: %s", exc)
        return

    visible_names = {t.name for t in visible}
    tier_counts: dict[str, list[int]] = {t: [0, 0] for t in _TIER_TAGS}
    tier_counts["untagged"] = [0, 0]
    group_counts: dict[str, list[int]] = {}

    for tool in all_tools:
        tags = set(getattr(tool, "tags", set()) or set())
        tier = _classify_tier(tags)
        group = _group_of(tags)
        tier_counts.setdefault(tier, [0, 0])[0] += 1
        bucket = group_counts.setdefault(group, [0, 0])
        bucket[0] += 1
        if tool.name in visible_names:
            tier_counts[tier][1] += 1
            bucket[1] += 1

    logger.info(
        "tools registered: %d total, %d visible (after tier+group filters)",
        len(all_tools),
        len(visible),
    )
    logger.info(
        "  by tier:  %s",
        " | ".join(f"{tier}={c[1]}/{c[0]}" for tier, c in tier_counts.items() if c[0] > 0),
    )
    logger.info(
        "  by group: %s",
        " | ".join(f"{grp}={c[1]}/{c[0]}" for grp, c in sorted(group_counts.items())),
    )


def _mount_skills(server: Any, skills_dir: Any, *, label: str = "skills") -> None:
    """Mount a FastMCP Skills provider rooted at `skills_dir`. See ADR-0009.

    Called separately for per-tool skills (`SSH_SKILLS_DIR`) and workflow
    runbooks (`SSH_RUNBOOKS_DIR`). The ``label`` is purely cosmetic -- it
    disambiguates the startup log line so operators can tell which directory
    actually mounted.
    """
    if skills_dir is None:
        return
    path = skills_dir.expanduser()
    if not path.exists() or not path.is_dir():
        logger.info("%s dir %s not found; skipping provider", label, path)
        return
    try:
        from fastmcp.server.providers import SkillsDirectoryProvider

        server.add_provider(SkillsDirectoryProvider(roots=path))
        logger.info("mounted %s provider at %s", label, path)
    except Exception as exc:
        logger.warning("could not mount %s provider: %s", label, exc)


@lifespan
async def ssh_lifespan(server: Any) -> AsyncIterator[dict[str, Any]]:
    """Start pool, apply tier gates, tear everything down on shutdown."""
    # `fastmcp run` skips run_server.main() (our normal entry), so nothing
    # configures Python logging. Without a handler our INFO/DEBUG lines fall
    # through to logging.lastResort, which is hardcoded to WARNING -- that's
    # why operators only see WARNING+ from us. Attach a stderr handler to
    # our package logger (idempotent) and set the configured level.
    pkg_logger = logging.getLogger("ssh_mcp")
    pkg_logger.setLevel(settings.LOG_LEVEL)
    if not any(getattr(h, "_ssh_mcp_lifespan", False) for h in pkg_logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        handler._ssh_mcp_lifespan = True  # type: ignore[attr-defined]
        pkg_logger.addHandler(handler)
        # Don't propagate -- root has its own handlers (FastMCP Rich) and
        # we'd get duplicate lines.
        pkg_logger.propagate = False

    hosts = load_hosts(settings.SSH_HOSTS_FILE, settings)
    allowlist = merged_host_allowlist(hosts, settings)

    logger.info(
        "ssh-mcp starting: hosts_file=%s named_hosts=%d allowlisted=%d " "low=%s dangerous=%s sudo=%s",
        settings.SSH_HOSTS_FILE,
        len(hosts),
        len(allowlist),
        settings.ALLOW_LOW_ACCESS_TOOLS,
        settings.ALLOW_DANGEROUS_TOOLS,
        settings.ALLOW_SUDO,
    )

    # Visibility for the SSH_CONFIG_FILE setting. asyncssh tolerates a missing
    # file silently, which makes "I set the env var but my ProxyJump still
    # doesn't apply" debug sessions awful -- log explicitly at startup so the
    # operator sees the resolved absolute path (or the warning) up front.
    if settings.SSH_CONFIG_FILE is not None:
        ssh_config = settings.SSH_CONFIG_FILE.expanduser()
        if ssh_config.is_file():
            logger.info("ssh_config: honoring %s", ssh_config)
        else:
            logger.warning(
                "SSH_CONFIG_FILE=%s not found; asyncssh will skip it silently",
                ssh_config,
            )

    _warn_task_backend(settings.ALLOW_DANGEROUS_TOOLS)

    if settings.ALLOW_SUDO:
        from .ssh.sudo import reject_env_password, warn_if_persistent_mode

        warn_if_persistent_mode(settings)
        reject_env_password()

    known_hosts = KnownHosts(settings.SSH_KNOWN_HOSTS)
    pool = ConnectionPool(settings)
    pool.bind(hosts, known_hosts)
    pool.start_reaper()
    shell_sessions = SessionRegistry()

    hooks = HookRegistry()
    load_external_hooks(hooks, settings.SSH_HOOKS_MODULE)

    _mount_skills(server, settings.SSH_SKILLS_DIR, label="skills")
    if settings.SSH_ENABLE_RUNBOOKS:
        _mount_skills(server, settings.SSH_RUNBOOKS_DIR, label="runbooks")
    else:
        logger.info("runbooks disabled via SSH_ENABLE_RUNBOOKS=false")

    if not settings.ALLOW_LOW_ACCESS_TOOLS:
        server.add_transform(Visibility(False, tags={"low-access"}))
    if not settings.ALLOW_DANGEROUS_TOOLS:
        server.add_transform(Visibility(False, tags={"dangerous"}))
    if not settings.ALLOW_SUDO:
        server.add_transform(Visibility(False, tags={"sudo"}))
    if not settings.ALLOW_PERSISTENT_SESSIONS:
        # Hides only ssh_shell_open / ssh_shell_exec. ssh_shell_list and
        # ssh_shell_close remain visible so operators can still audit and
        # drain any sessions that were opened before the flag was flipped.
        server.add_transform(Visibility(False, tags={"persistent-session"}))

    # Tool groups — orthogonal to tiers. Empty list = all tier-allowed groups.
    # See ADR-0016.
    enabled_groups: set[str] = (
        set(settings.SSH_ENABLED_GROUPS) if settings.SSH_ENABLED_GROUPS else set(ALL_GROUPS)
    )
    unknown = enabled_groups - ALL_GROUPS
    if unknown:
        logger.warning("SSH_ENABLED_GROUPS contains unknown groups (ignored): %s", sorted(unknown))
        enabled_groups -= unknown
    for group in ALL_GROUPS - enabled_groups:
        server.add_transform(Visibility(False, tags={f"group:{group}"}))
    logger.info("enabled tool groups: %s", sorted(enabled_groups))

    # BM25 search transform: replaces tools/list with search_tools + call_tool
    # once the catalog outgrows what an LLM can chew per turn. Applied AFTER
    # the Visibility filters so hidden tools are also hidden from search.
    if settings.SSH_ENABLE_BM25:
        from fastmcp.server.transforms.search.bm25 import BM25SearchTransform

        server.add_transform(
            BM25SearchTransform(
                max_results=settings.SSH_BM25_MAX_RESULTS,
                always_visible=list(settings.SSH_BM25_ALWAYS_VISIBLE),
            )
        )
        logger.info(
            "BM25 search transform enabled: max_results=%d always_visible=%s",
            settings.SSH_BM25_MAX_RESULTS,
            list(settings.SSH_BM25_ALWAYS_VISIBLE),
        )

    await _apply_mcp_annotations(server)
    await _log_tool_catalog(server)

    try:
        await hooks.emit(HookContext(event=HookEvent.STARTUP), blocking=True)
        yield {
            "pool": pool,
            "settings": settings,
            "hosts": hosts,
            "host_allowlist": allowlist,
            "known_hosts": known_hosts,
            "shell_sessions": shell_sessions,
            "hooks": hooks,
        }
    finally:
        logger.info("ssh-mcp shutting down; closing %d connection(s)", pool.size())
        await hooks.emit(HookContext(event=HookEvent.SHUTDOWN), blocking=True)
        await pool.close_all()
