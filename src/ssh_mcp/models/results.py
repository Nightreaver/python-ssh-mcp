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
    # INC-057: warnings about the output itself (after sanitization). Empty
    # when stdout/stderr look normal. Each entry is a short human-readable
    # string flagging a category: ANSI stripped, NUL bytes stripped,
    # bidi-override characters present, zero-width characters present,
    # C1 controls present, LLM protocol markers present, conversation-
    # mimicking lines present. The LLM should treat output with non-empty
    # warnings as untrusted remote data, not as operator instructions.
    output_warnings: list[str] = []


class BroadcastResult(BaseModel):
    """Per-host outcome of `ssh_broadcast`.

    `results` carries one ExecResult per host that *completed* (the command
    ran, regardless of exit code). `errors` carries the exception class name
    for hosts where the call raised before producing an ExecResult — typically
    `CommandNotAllowed` (allowlist denial), `PlatformNotSupported` (Windows
    target), `ConnectError`, `AuthenticationFailed`, `UnknownHost`,
    `HostKeyMismatch`. A host appears in `succeeded` only when its ExecResult
    has `exit_code == 0` AND `timed_out == False`; everything else lands in
    `failed` (with details either in `results[alias]` or `errors[alias]`).

    `command` is echoed back so the broadcast call is self-describing in the
    result body — the audit log records `host="?"` for fan-out tools, so the
    result is the durable record of what was run.
    """

    model_config = _RESULT_MODEL_CONFIG

    command: str
    results: dict[str, ExecResult]
    succeeded: list[str]
    failed: list[str]
    errors: dict[str, str]
    elapsed_ms: int


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
    # v1.4.0: populated when the redact-bypass layer flags the path in
    # ``warn`` mode. Empty in the common case.
    output_warnings: list[str] = []


class WriteResult(BaseModel):
    """Outcome of a file-mutating low-access tool (ssh_upload / ssh_deploy /
    ssh_mkdir / ssh_cp / ssh_mv / ssh_link / ssh_edit / ssh_patch / ...).

    ``local_path_written`` is populated only when ``ssh_upload`` / ``ssh_deploy``
    sourced its bytes from ``local_path=`` (v1.3.0). It carries the
    canonical MCP-host path the bytes were read from, for the audit trail
    -- the LLM never saw the payload but the operator should be able to
    correlate the destination back to its local source.

    v1.4.0: ``output_warnings`` added so the secret-redaction bypass layer
    can attach a per-call warning when ``redact_bypass_policy="warn"`` lets
    a redact-list path through. Same shape as ``ExecResult.output_warnings``
    and ``DownloadResult.output_warnings``.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    success: bool
    bytes_written: int = 0
    message: str | None = None
    local_path_written: str | None = None
    output_warnings: list[str] = []


class PingResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    reachable: bool
    auth_ok: bool
    latency_ms: int
    server_banner: str | None = None
    known_host_fingerprint: str | None = None
    # INC-059: operator-set hard-rule notes from hosts.toml's `notes`
    # field. Auto-injected here when `SSH_PING_INCLUDES_NOTES=True`
    # (default) and the host has notes -- ping is the canonical
    # "starting work on this host" probe, so surfacing the operator's
    # constraints here gets them into LLM context without the LLM
    # having to remember a separate `ssh_host_notes` call.
    operator_notes: str | None = None
    # INC-060: agent-side notes (the LLM's own session-spanning sidecar
    # at <SSH_HOST_NOTES_DIR>/<alias>.md). Auto-injected when
    # `SSH_PING_INCLUDES_AGENT_NOTES=True` (default) and the sidecar
    # exists with content. Toggleable independently of `operator_notes`
    # because the agent layer can grow to 256 KiB and operators may
    # want to skip auto-inclusion in ping for context budget reasons.
    agent_notes: str | None = None


class HostInfoResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    uname: str | None = None
    os_release: dict[str, str] = {}
    uptime: str | None = None
    # INC-052: extension of `ssh_host_info`. All three optional so a missing
    # probe (no `nproc` on busybox, no `/proc/cpuinfo` in a restricted ctr,
    # `hostname -f` falling back to short name) leaves the field None rather
    # than fabricating data. Parsers treat empty / missing as "unavailable".
    cpu_model: str | None = None
    cpu_count: int | None = None
    hostname_fqdn: str | None = None
    # Sprint 5: free-form fields above (uname / uptime / os_release values)
    # are remote-controlled text -- the LLM reads them as strings. Run
    # them through `services.output_sanitizer.scan()` before constructing
    # the model and surface any flagged categories here. Empty when every
    # captured field looks textually clean. Mirrors the
    # `ExecResult.output_warnings` / `DownloadResult.output_warnings`
    # pattern from INC-057 / INC-058.
    output_warnings: list[str] = []


class NetworkInterfaceAddress(BaseModel):
    """Single inet / inet6 address bound to an interface."""

    model_config = _RESULT_MODEL_CONFIG

    family: str  # "inet" | "inet6"
    address: str
    prefix_length: int


class NetworkInterfaceEntry(BaseModel):
    """One interface from `ip -j addr show`. Only the fields LLMs actually
    use are surfaced -- raw `ip` output carries dozens of kernel-internal
    fields (broadcast, valid_life_time, scope, link_index, etc.) that bloat
    schema with no operational value."""

    model_config = _RESULT_MODEL_CONFIG

    name: str
    state: str  # "UP" | "DOWN" | "UNKNOWN" | "LOWERLAYERDOWN" ...
    mac: str | None = None
    addresses: list[NetworkInterfaceAddress] = []


class HostNetworkResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    interfaces: list[NetworkInterfaceEntry]


class UserInfoResult(BaseModel):
    """Result of `ssh_user_info` -- structured /etc/passwd row + group list.

    Sourced from `getent passwd` + `id -Gn` + `id -gn`. None of these need
    sudo. `chage -l` (password aging info) was deliberately omitted because
    it requires root on most distros and broadcast it would force the tool
    into the dangerous tier.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    username: str
    uid: int
    gid: int
    gecos: str  # GECOS / display-name field; often empty on system accounts
    home: str
    shell: str
    primary_group: str
    groups: list[str]
    # Sprint 5: GECOS is a free-form, attacker-controllable field on
    # shared boxes (any user with shell access can `chfn` their own).
    # Scan it with `services.output_sanitizer.scan()` and surface the
    # flagged categories here so the LLM treats suspicious values as
    # untrusted data rather than display strings. Empty when GECOS
    # looks clean (the common case for service accounts / locked-down
    # machines).
    output_warnings: list[str] = []


class TransferResult(BaseModel):
    """Result of `ssh_transfer` -- host-to-host file copy via the MCP server.

    `throughput_mb_s` is a derived convenience field (size / duration). It is
    bottlenecked by the slower of (src→MCP) and (MCP→dst) hops -- on a
    residential MCP machine bridging two cloud hosts, this caps near the
    operator's upload bandwidth. For inter-host gigabit, an `scp` invoked
    via `ssh_exec_run` between hosts that already trust each other will be
    faster (no transit through the MCP host).
    """

    model_config = _RESULT_MODEL_CONFIG

    src_host: str
    src_path: str
    dst_host: str
    dst_path: str
    size: int
    duration_ms: int
    throughput_mb_s: float


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
    # v1.4.0: populated when the redact-bypass layer flags the path in
    # ``warn`` mode. Empty in the common case.
    output_warnings: list[str] = []


class FindResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    root: str
    matches: list[str]
    truncated: bool
    # v1.4.0: populated when the redact-bypass layer flags the search root
    # in ``warn`` mode. Empty in the common case.
    output_warnings: list[str] = []


class DownloadResult(BaseModel):
    """Outcome of ``ssh_sftp_download``.

    Two delivery modes:

    - default (no ``local_path``): bytes round-trip through the MCP JSON
      channel as base64 in ``content_base64``. Subject to
      ``SSH_UPLOAD_MAX_FILE_BYTES`` (default 256 MiB); larger files come
      back with ``truncated=True`` and an empty payload.
    - ``local_path=`` mode (v1.3.0): the MCP server streams the file
      directly to disk at the caller-supplied local path.
      ``content_base64`` is empty, ``truncated`` is False, and
      ``local_path_written`` carries the canonical MCP-host path the
      bytes landed at. Subject to ``SSH_LOCAL_TRANSFER_MAX_BYTES``
      (default 2 GiB) instead of the upload cap.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    size: int
    content_base64: str
    truncated: bool
    # INC-058: warnings about what a UTF-8 decode of `content_base64`
    # would surface. ANSI escapes / NUL bytes / bidi overrides / etc.
    # The bytes themselves are NOT modified -- callers who need a clean
    # text view should `sanitize()` after decoding. Empty for files
    # that look textually clean or aren't text at all.
    output_warnings: list[str] = []
    # v1.3.0: populated only in `local_path` mode. Canonical MCP-host
    # absolute path the file was written to. None when the download went
    # back via the base64 channel.
    local_path_written: str | None = None


class HashResult(BaseModel):
    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    algorithm: str  # "md5" | "sha1" | "sha256" | "sha512"
    digest: str  # lowercase hex, no prefix
    size: int  # file size in bytes (-1 if unavailable)
    # v1.4.0: populated when the redact-bypass layer flags the hashed path
    # in ``warn`` mode -- a SHA over a secret file is the same as the SHA
    # of the secret, so the warning helps the LLM know it just leaked an
    # identifying fingerprint of the cleartext.
    output_warnings: list[str] = []


class RedactedReadResult(BaseModel):
    """Outcome of ``ssh_read_redacted`` -- read a remote file and pass it
    through the secret-redactor before delivering to the LLM.

    Why a separate model: the LLM needs to know WHAT was redacted to
    reason about the file's structure ("the DB_PASSWORD on line 4 maps
    to hash abc123 -- the same hash I saw on the prod-app host, so the
    secret is shared"). Embedding that as inline ``<sha:abc123>`` markers
    in the content covers the comparison case; the ``redactions`` list
    covers the structured case (don't make the LLM regex-parse its own
    input back out).

    Fields
    ------
    host : str
        Canonical hostname (= policy.hostname after resolve).
    path : str
        Canonical remote path that was read.
    size_original : int
        File size in bytes BEFORE redaction. The redacted ``content`` can
        be larger (markers tend to be longer than the secrets they
        replace) so size of ``content`` is not a useful comparison point.
    content : str
        Redacted text. Always UTF-8 decoded (errors=replace) -- the tool
        is intended for config files, not binary blobs.
    format_detected : str
        Which parser the redactor ran -- ``env`` / ``yaml`` / ``json`` /
        ``ini`` / ``generic``. Mirrors the input ``format`` parameter
        when set, else the auto-detected format from the extension.
    redactions : list[dict]
        One dict per redaction: ``{"key": "DB_PASSWORD" | None,
        "hash": "abc123def456", "line": 4 | None, "kind":
        "key_match" | "entropy_base64" | "entropy_hex" | "pem_block"}``.
        Kept as ``dict`` rather than a nested model so the LLM gets a
        flat JSON-shaped surface and we don't pay for an extra schema.
    truncated : bool
        True when the file's size exceeded ``SSH_UPLOAD_MAX_FILE_BYTES``
        and the read was skipped. ``content`` is empty when this is True,
        same pattern as ``DownloadResult.truncated``.
    output_warnings : list[str]
        Free-form warnings the tool wants the LLM to see. The redactor
        attaches "no salt configured" when ``SSH_REDACT_SALT`` is empty
        (the operator opted into plain-SHA256 mode, secrets are still
        hashed but the hash is rainbow-tableable). Empty in the common
        case.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    path: str
    size_original: int
    content: str
    format_detected: str
    redactions: list[dict[str, str | int | None]] = []
    truncated: bool = False
    output_warnings: list[str] = []


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
    # INC-055: True when the host has operator notes in `hosts.toml`. The
    # actual notes body lives behind `ssh_host_notes(host=alias)` -- keeping
    # the list response compact lets the LLM browse the fleet cheaply and
    # then drill in. has_notes=False means the lookup is unnecessary.
    has_notes: bool = False


class HostNotesResult(BaseModel):
    """Result of `ssh_host_notes` -- two-layer per-host memory for one host.

    Layer 1 (`operator_notes`): hard-rule baseline from `hosts.toml`'s
    `notes` field. Operator-controlled, READ-ONLY to the agent. Use for
    constraints not expressible as allowlists -- "never install apache2",
    "logs ship to /var/log/myapp -- do NOT change rotation", "owner:
    platform-team@".

    Layer 2 (`agent_notes`): the LLM's own working memory across sessions,
    stored as a markdown sidecar at `<SSH_HOST_NOTES_DIR>/<alias>.md`.
    Read here, written via `ssh_host_notes_append` (preferred -- adds a
    timestamped entry) or `ssh_host_notes_set` (replaces the whole file
    for consolidation). `agent_notes_path` is the absolute path the
    sidecar would live at, even when `agent_notes is None` -- useful for
    operator visibility.

    `has_notes` is True when EITHER layer has content.
    """

    model_config = _RESULT_MODEL_CONFIG

    alias: str
    hostname: str
    operator_notes: str | None
    agent_notes: str | None
    agent_notes_path: str | None  # absolute path of the sidecar, or None when SSH_HOST_NOTES_DIR is unset
    has_notes: bool


class HostNotesWriteResult(BaseModel):
    """Result of `ssh_host_notes_append` / `ssh_host_notes_set`.

    `bytes_written` is the size of the new sidecar file on disk after the
    write. `was_created` is True when the file did not previously exist
    (vs. an in-place update). `message` is a short human-readable summary
    suitable for the audit line.
    """

    model_config = _RESULT_MODEL_CONFIG

    alias: str
    hostname: str
    agent_notes_path: str
    bytes_written: int
    was_created: bool
    message: str


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


class AlertBreach(BaseModel):
    """One threshold breach surfaced by `ssh_host_alerts`.

    Mirrors the fields of `services.alerts.Breach` (which is a frozen
    dataclass internal to the evaluator). Promoting to a pydantic model
    here -- per ADR-0025 / INC-046 -- gives the LLM a typed, schema'd
    view of the breach instead of the previous untyped dict.
    """

    model_config = _RESULT_MODEL_CONFIG

    metric: str  # "disk_use_percent" / "load_avg_1min" / "mem_free_percent"
    threshold: float  # configured limit
    current: float  # observed value
    severity: str  # "warning" (breach of configured threshold)
    detail: str  # human-readable context (mount path, etc.)


class HostAlertsResult(BaseModel):
    """Result of `ssh_host_alerts` -- threshold-evaluation snapshot for one host.

    Promoted from `dict[str, Any]` to a typed model (Sprint 5 / ADR-0025).
    `breaches` carries one `AlertBreach` per crossed threshold (possibly
    empty). `metrics` carries the raw observations the evaluator looked at:
    a permissive shape because different metrics produce different value
    types -- `disk_entries` is a list of per-mount mappings, while
    `load_avg_1min` / `mem_free_percent` are scalars.
    """

    model_config = _RESULT_MODEL_CONFIG

    host: str
    breaches: list[AlertBreach]
    # `metrics` is intentionally permissive: scalars (load avg, free %)
    # live alongside list-shaped disk_entries. Pydantic validates the
    # outer dict; the inner shape is whatever the evaluator emits.
    metrics: dict[str, float | list[dict[str, float | str]]] = {}


class ServerInfoResult(BaseModel):
    """Identity + capability surface of the running MCP server (v1.5.0+).

    Returned by ``ssh_server_info`` (tool) AND by the
    ``mcp://ssh-mcp/server-info`` resource -- same payload shape so the
    LLM can consume whichever surface the client exposes. The resource is
    the primary discovery path; the tool is the fallback for clients that
    do not surface MCP resources to the model.

    Operators use this for "which server am I talking to?". LLMs use it
    for capability discovery -- "am I on v1.12+ so ``ssh_read_redacted``
    is available?" -- though checking ``tools/list`` for the tool name is
    equivalent and cheaper in catalog terms.
    """

    model_config = _RESULT_MODEL_CONFIG

    name: str
    version: str
    # Post-Visibility count: the tools/list the LLM actually sees. Equal
    # to the registered catalog when no tier or group filters apply.
    total_tools: int
    # Tiers the operator has unlocked. ``read`` is always included.
    # ``low-access`` / ``dangerous`` / ``sudo`` appear when their
    # respective ALLOW_* flag is True.
    enabled_tiers: list[str]
    # The configured ``SSH_ENABLED_GROUPS`` filter, or ``[]`` when empty
    # (all groups visible -- the default). Operator-visible knob; not a
    # post-filter derivation.
    enabled_groups: list[str]
