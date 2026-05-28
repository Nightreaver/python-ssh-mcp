"""Low-access tools facade. Real code lives in the `low_access/` subpackage.

Mirrors the `docker_tools.py` re-export shim (INC-043). The original monolithic
module covered five distinct ops (mkdir/delete/cp/mv, link, upload/deploy,
edit/patch) plus shared SFTP plumbing -- ~1050 lines. Split out for
readability; this file is now a backward-compat re-export shim so existing
imports and test monkeypatches keep working unchanged.

New code should import from the specific submodule:

    from ssh_mcp.tools.low_access.upload_tools import ssh_upload
    from ssh_mcp.tools.low_access._helpers import _atomic_write

Tests that monkeypatch module-level bindings (e.g. ``resolve_path``,
``canonicalize_and_check``) MUST target the submodule where the tool being
exercised lives -- monkeypatching this facade only rebinds the re-exported
alias, not the binding the tool body resolves at call time.
"""

from __future__ import annotations

# --- Legacy path-policy re-exports ----------------------------------------
# Tests historically monkeypatch these against `low_access_tools`. Re-export
# is harmless for forward-compat code; monkeypatching the facade will NOT
# affect the bindings inside the submodules (see warning in the module
# docstring above).
from ..services.path_policy import (  # noqa: F401
    canonicalize_and_check,
    check_in_allowlist,
    check_not_restricted,
    effective_allowlist,
    effective_restricted_paths,
    reject_bad_characters,
    resolve_path,
)

# Importing the subpackage modules triggers tool registration via decorator
# side-effects. Order is irrelevant; FastMCP collects tools as decorators fire.
from .low_access import edit_tools, fs_tools, link_tools, upload_tools  # noqa: F401

# --- Shared helper re-exports (tests reference these directly) ------------
# Marked `noqa: F401` because nothing inside this facade uses them; they
# exist purely for backward compat with
# `from ssh_mcp.tools.low_access_tools import _foo`.
from .low_access._helpers import (  # noqa: F401
    WriteError,
    _atomic_write,
    _atomic_write_stream,
    _is_missing,
    _prepare_creatable,
    _prepare_existing,
    _tmp_sibling,
)

# --- edit_tools re-exports ------------------------------------------------
from .low_access.edit_tools import ssh_edit, ssh_patch

# --- fs_tools re-exports --------------------------------------------------
from .low_access.fs_tools import (
    _is_cross_device,  # noqa: F401  (re-exported for tests that touch the helper)
    _mkdir_p,  # noqa: F401
    _walk_tree,  # noqa: F401
    ssh_cp,
    ssh_delete,
    ssh_delete_folder,
    ssh_mkdir,
    ssh_mv,
)

# --- link_tools re-exports ------------------------------------------------
from .low_access.link_tools import (
    _create_hard_link_followed,  # noqa: F401
    _create_hard_link_unfollowed,  # noqa: F401
    _create_symbolic_link,  # noqa: F401
    ssh_link,
)

# --- upload_tools re-exports ----------------------------------------------
from .low_access.upload_tools import (
    _PAYLOAD_MUTEX_HINT,  # noqa: F401
    _InlinePayload,
    _LocalFilePayload,
    _resolve_upload_payload,
    ssh_deploy,
    ssh_upload,
)

__all__ = [
    "WriteError",
    "_InlinePayload",
    "_LocalFilePayload",
    "_resolve_upload_payload",
    "ssh_cp",
    "ssh_delete",
    "ssh_delete_folder",
    "ssh_deploy",
    "ssh_edit",
    "ssh_link",
    "ssh_mkdir",
    "ssh_mv",
    "ssh_patch",
    "ssh_upload",
]
