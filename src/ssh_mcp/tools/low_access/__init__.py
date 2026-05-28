"""Low-access tier (file mutation via SFTP). Real tool modules live in this
subpackage; ``ssh_mcp.tools.low_access_tools`` is a thin re-export facade
preserved for backward compatibility with imports + test monkeypatches.

See [low_access_tools.py](../low_access_tools.py) for the facade and the
sibling docker subpackage for the same split pattern (INC-043).
"""

from __future__ import annotations
