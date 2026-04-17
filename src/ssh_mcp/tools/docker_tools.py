"""Docker tools facade. Real code lives in the `docker/` subpackage.

INC-043: the original monolithic module grew to ~1000 lines covering three
tiers (read / low-access / dangerous) plus helpers, compose subcommands, and
the host-escape deny-list. Split out for readability; this file is now a
backward-compat re-export shim so existing imports and test monkeypatches
keep working unchanged.

New code should import from the specific submodule:

    from ssh_mcp.tools.docker.read_tools import ssh_docker_ps
    from ssh_mcp.tools.docker._helpers import _run_docker

Tests that monkeypatch module-level bindings (e.g. `_run_docker`) MUST
target the submodule where the tool being exercised lives -- monkeypatching
this facade only rebinds the re-exported alias, not the binding the tool
body resolves at call time.
"""
from __future__ import annotations

# canonicalize_and_check + check_not_restricted are re-exported for tests
# that monkeypatch them against this module (legacy test pattern).
from ..services.path_policy import (  # noqa: F401
    canonicalize_and_check,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
)

# Importing the subpackage triggers tool registration via decorator side-effects.
from .docker import dangerous_tools, lifecycle_tools, read_tools  # noqa: F401

# --- Helper re-exports (tests reference these directly) -------------------
# Marked `noqa: F401` because nothing inside this facade uses them; they exist
# purely for backward compat with `from ssh_mcp.tools.docker_tools import _foo`.
from .docker._helpers import (  # noqa: F401
    _DEFAULT_LOG_MAX_BYTES,
    _DOCKER_ESCALATION_PREFIXES,
    _DOCKER_FILTER_RE,
    _DOCKER_NAME_RE,
    _DOCKER_NAMESPACE_FLAGS,
    _DOCKER_TIME_RE,
    _DOCKER_VOLUME_FLAGS,
    _compose_prefix,
    _compose_project_op,
    _docker_prefix,
    _mount_source_is_host_root,
    _parse_json_lines,
    _reject_escalation_flags,
    _rewrite_stdout,
    _run_docker,
    _strip_noisy_fields,
    _validate_name,
)

# --- Dangerous-tier re-exports --------------------------------------------
from .docker.dangerous_tools import (
    ssh_docker_compose_down,
    ssh_docker_compose_pull,
    ssh_docker_compose_up,
    ssh_docker_exec,
    ssh_docker_prune,
    ssh_docker_pull,
    ssh_docker_rm,
    ssh_docker_rmi,
    ssh_docker_run,
)

# Lifecycle-private re-export for tests that monkeypatch the factory builder.
# --- Low-access lifecycle re-exports --------------------------------------
from .docker.lifecycle_tools import (
    _simple_container_op,  # noqa: F401
    ssh_docker_compose_restart,
    ssh_docker_compose_start,
    ssh_docker_compose_stop,
    ssh_docker_cp,
    ssh_docker_restart,
    ssh_docker_start,
    ssh_docker_stop,
)

# --- Read-tier tool re-exports --------------------------------------------
from .docker.read_tools import (
    ssh_docker_compose_logs,
    ssh_docker_compose_ps,
    ssh_docker_events,
    ssh_docker_images,
    ssh_docker_inspect,
    ssh_docker_logs,
    ssh_docker_ps,
    ssh_docker_stats,
    ssh_docker_top,
    ssh_docker_volumes,
)

__all__ = [
    "ssh_docker_compose_down",
    "ssh_docker_compose_logs",
    "ssh_docker_compose_ps",
    "ssh_docker_compose_pull",
    "ssh_docker_compose_restart",
    "ssh_docker_compose_start",
    "ssh_docker_compose_stop",
    "ssh_docker_compose_up",
    "ssh_docker_cp",
    "ssh_docker_events",
    "ssh_docker_exec",
    "ssh_docker_images",
    "ssh_docker_inspect",
    "ssh_docker_logs",
    "ssh_docker_prune",
    # Tools
    "ssh_docker_ps",
    "ssh_docker_pull",
    "ssh_docker_restart",
    "ssh_docker_rm",
    "ssh_docker_rmi",
    "ssh_docker_run",
    "ssh_docker_start",
    "ssh_docker_stats",
    "ssh_docker_stop",
    "ssh_docker_top",
    "ssh_docker_volumes",
]
