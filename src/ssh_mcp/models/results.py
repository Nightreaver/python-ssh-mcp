"""Canonical result shapes returned by tools.

INC-046: every model here carries ``model_config = ConfigDict(extra="forbid")``
so a typo at the construction site (`HashResult(digets="...")` → AttributeError
at runtime) becomes a pydantic ValidationError at the construction call instead
of propagating a silently-empty field into the audit log / MCP output.

Mirrors the policy on `models/policy.py`; catches the class of bug that
discovered INC-030 (`ssh_file_hash` building a `HashResult` with an unknown
field while the tool still returned `{"success": True}`).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# Every result model uses this config. Pulled into a module constant so a
# future switch to `extra="ignore"` (or similar) lands in one place rather
# than a sweep of 13 classes.
_RESULT_MODEL_CONFIG = ConfigDict(extra="forbid")


class ExecResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    exit_code: int
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int
    timed_out: bool = False
    killed_by_signal: str | None = None
    # Optional remediation hint for known recognizable failure modes
    # (e.g. "input device is not a tty" -> suggest batch flags). Null when
    # nothing recognizable. The field is for the LLM, not for control flow.
    hint: str | None = None


class StatResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    path: str
    kind: str  # "file" | "dir" | "symlink" | "other"
    size: int
    mode: str
    mtime: str
    owner: str | None = None
    group: str | None = None
    symlink_target: str | None = None


class WriteResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    success: bool
    bytes_written: int = 0
    message: str | None = None


class PingResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    reachable: bool
    auth_ok: bool
    latency_ms: int
    server_banner: str | None = None
    known_host_fingerprint: str | None = None


class HostInfoResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    uname: str | None = None
    os_release: dict[str, str] = {}
    uptime: str | None = None


class DiskUsageEntry(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    filesystem: str
    type: str
    size: str
    used: str
    available: str
    use_percent: str
    mount: str


class DiskUsageResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    entries: list[DiskUsageEntry]


class ProcessEntry(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    pid: int
    user: str
    pcpu: float
    pmem: float
    command: str


class ProcessListResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    entries: list[ProcessEntry]


class SftpEntry(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    name: str
    kind: str
    size: int
    mode: str
    mtime: str
    symlink_target: str | None = None


class SftpListResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    entries: list[SftpEntry]
    offset: int
    limit: int
    has_more: bool


class FindResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    root: str
    matches: list[str]
    truncated: bool


class DownloadResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    size: int
    content_base64: str
    truncated: bool


class HashResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    algorithm: str  # "md5" | "sha1" | "sha256" | "sha512"
    digest: str  # lowercase hex, no prefix
    size: int  # file size in bytes (-1 if unavailable)


class HostListEntry(BaseModel):
    """Sanitized view of a single host in the loaded fleet.

    Never includes credentials (key_path, password, passphrase). Only
    metadata an operator already knows from their own hosts.toml.
    """

    model_config = _RESULT_MODEL_CONFIG

    alias: str
    hostname: str
    port: int
    platform: str  # "posix" | "windows"
    user: str
    auth_method: str  # "agent" | "key" | "password" — method only, not secret


class HostListResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    hosts: list[HostListEntry]
    count: int


class HostReloadResult(BaseModel):
    """Result of an in-place reload of hosts.toml into the running server."""

    model_config = _RESULT_MODEL_CONFIG

    loaded: int  # total hosts now in memory after reload
    source: str  # absolute path that was read (or "<none>" if path is None)
    added: list[str]  # aliases present after reload but not before
    removed: list[str]  # aliases present before reload but not after
    changed: list[str]  # aliases whose HostPolicy content changed
