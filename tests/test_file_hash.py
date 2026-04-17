"""ssh_file_hash: input validation + POSIX/Windows command shape + output parsing.

Covers:
- invalid algorithm rejected
- POSIX path hits `<algo>sum -- <canonical>` with correct binary per algo
- Windows path hits `powershell ... Get-FileHash -Algorithm <ALGO> -LiteralPath '<p>'`
- digest lowercase, path-with-spaces in POSIX output parsed correctly
- non-zero exit -> HashError with stderr
- unparseable digest -> HashError
- path canonicalize + restricted-paths checks invoked (catches missing import)

No live SSH. `monkeypatch.setattr` swaps `canonicalize_and_check` / the conn's
`conn.run` / SFTP stat with shim objects; we assert on the captured argv.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar
from unittest.mock import MagicMock

import pytest

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools import sftp_read_tools
from ssh_mcp.tools.sftp_read_tools import HashError, ssh_file_hash


@dataclass
class _FakeRun:
    stdout: str = ""
    stderr: str = ""
    exit_status: int = 0


class _FakeAttrs:
    def __init__(self, size: int) -> None:
        self.size = size
        self.permissions = 0o100644
        self.mtime = 0
        self.uid = 1000
        self.gid = 1000


class _FakeSFTP:
    def __init__(self, size: int, *, stat_raises: bool = False) -> None:
        self._size = size
        self._stat_raises = stat_raises

    async def __aenter__(self) -> _FakeSFTP:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def stat(self, _path: str) -> _FakeAttrs:
        if self._stat_raises:
            import asyncssh

            raise asyncssh.SFTPError(
                asyncssh.sftp.FX_NO_SUCH_FILE,
                "no such file",
            )
        return _FakeAttrs(self._size)


class _FakeConn:
    def __init__(
        self,
        *,
        run_result: _FakeRun,
        size: int = 1234,
        stat_raises: bool = False,
    ) -> None:
        self._run_result = run_result
        self._size = size
        self._stat_raises = stat_raises
        self.run_calls: list[str] = []
        self.run_kwargs: list[dict[str, Any]] = []

    async def run(self, args: str, *, check: bool = False, timeout: float | None = None) -> _FakeRun:
        self.run_calls.append(args)
        self.run_kwargs.append({"check": check, "timeout": timeout})
        return self._run_result

    def start_sftp_client(self) -> _FakeSFTP:
        return _FakeSFTP(self._size, stat_raises=self._stat_raises)


def _ctx(policy: HostPolicy) -> Any:
    """Stub ctx with just enough lifespan_context for the tool body."""
    pool = MagicMock()
    conn_holder: dict[str, _FakeConn] = {}

    async def _acquire(_policy):
        return conn_holder["conn"]

    pool.acquire = _acquire

    class _C:
        lifespan_context: ClassVar[dict[str, Any]] = {
            "pool": pool,
            "settings": Settings(SSH_PATH_ALLOWLIST=["/opt/app", "C:\\opt\\app"]),
            "hosts": {"x": policy},
        }

    return _C(), conn_holder


def _posix_policy() -> HostPolicy:
    return HostPolicy(
        hostname="web01",
        user="deploy",
        auth=AuthPolicy(method="agent"),
        path_allowlist=["/opt/app"],
    )


def _windows_policy() -> HostPolicy:
    return HostPolicy(
        hostname="winbox",
        user="Administrator",
        auth=AuthPolicy(method="agent"),
        platform="windows",
        path_allowlist=["C:\\opt\\app"],
    )


# --- input validation ---


class TestInputValidation:
    @pytest.mark.asyncio
    async def test_rejects_unknown_algorithm(self) -> None:
        policy = _posix_policy()
        ctx, _holder = _ctx(policy)
        with pytest.raises(ValueError, match="algorithm must be one of"):
            await ssh_file_hash(
                host="x",
                path="/opt/app/f",
                ctx=ctx,
                algorithm="sha3_256",  # type: ignore[arg-type]
            )


# --- POSIX happy path ---


class TestPosixHashing:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("algorithm", "expected_binary"),
        [
            ("md5", "md5sum"),
            ("sha1", "sha1sum"),
            ("sha256", "sha256sum"),
            ("sha512", "sha512sum"),
        ],
    )
    async def test_invokes_correct_binary(
        self,
        monkeypatch,
        algorithm: str,
        expected_binary: str,
    ) -> None:
        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _posix_policy()
        ctx, holder = _ctx(policy)
        conn = _FakeConn(
            run_result=_FakeRun(stdout="deadbeef1234  /opt/app/f\n"),
            size=42,
        )
        holder["conn"] = conn

        result = await ssh_file_hash(
            host="x",
            path="/opt/app/f",
            ctx=ctx,
            algorithm=algorithm,  # type: ignore[arg-type]
        )
        # One run call, and it starts with the right binary.
        assert len(conn.run_calls) == 1
        assert conn.run_calls[0].startswith(f"{expected_binary} -- ")
        assert result.algorithm == algorithm
        assert result.digest == "deadbeef1234"
        assert result.size == 42

    @pytest.mark.asyncio
    async def test_parses_path_with_spaces(self, monkeypatch) -> None:
        """`<hex>  <path>` -- split once on whitespace, take the digest."""

        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _posix_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            run_result=_FakeRun(
                stdout="cafebabe1234  /opt/app/with spaces in name\n",
            ),
        )
        result = await ssh_file_hash(
            host="x",
            path="/opt/app/with spaces in name",
            ctx=ctx,
        )
        assert result.digest == "cafebabe1234"

    @pytest.mark.asyncio
    async def test_non_zero_exit_raises_HashError(self, monkeypatch) -> None:
        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _posix_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            run_result=_FakeRun(
                stderr="sha256sum: /opt/app/f: Permission denied\n",
                exit_status=1,
            ),
        )
        with pytest.raises(HashError, match="Permission denied"):
            await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)

    @pytest.mark.asyncio
    async def test_unparseable_digest_raises_HashError(self, monkeypatch) -> None:
        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _posix_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            run_result=_FakeRun(stdout="NOT-A-HEX-STRING  /opt/app/f\n"),
        )
        with pytest.raises(HashError, match="unparseable"):
            await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)

    @pytest.mark.asyncio
    async def test_digest_lowercased_even_if_upstream_uppercase(self, monkeypatch) -> None:
        """sha256sum is already lowercase but BusyBox variants can differ."""

        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _posix_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            run_result=_FakeRun(stdout="DEADBEEF  /opt/app/f\n"),
        )
        result = await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)
        assert result.digest == "deadbeef"


# --- Windows (PowerShell -EncodedCommand path, INC-028) ---


class TestWindowsHashing:
    """ssh_file_hash on Windows targets dispatches to `_hash_windows`, which
    base64-UTF16LE-encodes a `Get-FileHash` PowerShell script and ships it as a
    single `-EncodedCommand` argv token. Avoids every shell-quoting corner the
    previous `shlex.join`-based attempt (INC-031) hit on cmd.exe / PowerShell.
    """

    @staticmethod
    def _decode_encoded_cmd(run_call: str) -> str:
        """Pull the b64 payload out of the `powershell.exe ... -EncodedCommand <b64>`
        command and decode back to the original UTF-16-LE script."""
        import base64 as _b64

        token = run_call.rsplit(" ", 1)[-1]
        return _b64.b64decode(token).decode("utf-16-le")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("algorithm", "expected_ps_algo"),
        [
            ("md5", "MD5"),
            ("sha1", "SHA1"),
            ("sha256", "SHA256"),
            ("sha512", "SHA512"),
        ],
    )
    async def test_invokes_powershell_encoded_command(
        self,
        monkeypatch,
        algorithm: str,
        expected_ps_algo: str,
    ) -> None:
        """Argv must be `powershell.exe -NoProfile -NonInteractive
        -EncodedCommand <b64>`, and the b64 must decode to a Get-FileHash
        call naming the right algorithm + LiteralPath."""

        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        # Digest length per algorithm (matches the shape check in _hash_windows).
        digest_len = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}[algorithm]
        fake_digest = ("DEADBEEF" * 16)[:digest_len]  # uppercase hex, correct length

        policy = _windows_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            # Get-FileHash returns uppercase hex; parser lowercases.
            run_result=_FakeRun(stdout=f"{fake_digest}\r\n"),
            size=99,
        )
        result = await ssh_file_hash(
            host="x",
            path="C:\\opt\\app\\f",
            ctx=ctx,
            algorithm=algorithm,  # type: ignore[arg-type]
        )
        assert len(holder["conn"].run_calls) == 1
        call = holder["conn"].run_calls[0]
        assert call.startswith("powershell.exe -NoProfile -NonInteractive -EncodedCommand ")

        script = self._decode_encoded_cmd(call)
        assert f"-Algorithm {expected_ps_algo}" in script
        assert "Get-FileHash" in script
        assert "-LiteralPath" in script
        assert "C:\\opt\\app\\f" in script
        # Fix: suppresses PowerShell progress-record CLIXML on stderr and
        # forces an exit-status request over SSH (Windows OpenSSH quirk).
        assert "$ProgressPreference='SilentlyContinue'" in script
        assert script.rstrip(";").endswith("exit 0")
        assert result.digest == fake_digest.lower()
        assert result.algorithm == algorithm
        assert result.size == 99

    @pytest.mark.asyncio
    async def test_windows_path_with_single_quote_is_ps_escaped(
        self,
        monkeypatch,
    ) -> None:
        """PowerShell literal single-quoted strings escape `'` as `''`.

        Catches the "operator has a file named `O'Brien.txt`" class of bug that
        would otherwise inject unquoted script into the -EncodedCommand payload
        and either crash PowerShell or (worse) execute attacker-supplied code
        if the path came through an attacker-reachable channel.
        """

        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _windows_policy()
        ctx, holder = _ctx(policy)
        # Default algorithm is sha256 (64 hex chars).
        fake_sha256 = ("CAFEBABE" * 16)[:64]
        holder["conn"] = _FakeConn(run_result=_FakeRun(stdout=f"{fake_sha256}\r\n"))
        path = "C:\\opt\\app\\O'Brien.txt"
        # `canonicalize_and_check` is monkeypatched to echo the path, so the
        # real allowlist check is bypassed; we're verifying the script shape.
        await ssh_file_hash(host="x", path=path, ctx=ctx)

        script = self._decode_encoded_cmd(holder["conn"].run_calls[0])
        # The `'` in `O'Brien` must appear as `''` between the enclosing
        # single quotes of the LiteralPath argument.
        assert "-LiteralPath 'C:\\opt\\app\\O''Brien.txt'" in script

    @pytest.mark.asyncio
    async def test_windows_non_zero_exit_raises_HashError(self, monkeypatch) -> None:
        async def fake_canonicalize(_conn, path, _allowlist, **_kw):
            return path

        monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

        policy = _windows_policy()
        ctx, holder = _ctx(policy)
        holder["conn"] = _FakeConn(
            run_result=_FakeRun(
                stderr="Get-FileHash : Access is denied.",
                exit_status=1,
            ),
        )
        with pytest.raises(HashError, match="powershell"):
            await ssh_file_hash(host="x", path="C:\\opt\\app\\f", ctx=ctx)


# --- Path policy reachability (would catch missing imports) ---


@pytest.mark.asyncio
async def test_file_hash_invokes_check_not_restricted(monkeypatch) -> None:
    """Drive past validation with stubbed I/O and assert check_not_restricted
    is actually called. Catches the NameError class of bugs where a helper
    is referenced but not imported."""
    calls: list[Any] = []

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    def fake_check_not_restricted(canonical, restricted, platform):
        calls.append((canonical, list(restricted), platform))

    monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)
    monkeypatch.setattr(sftp_read_tools, "check_not_restricted", fake_check_not_restricted)

    policy = _posix_policy()
    ctx, holder = _ctx(policy)
    holder["conn"] = _FakeConn(run_result=_FakeRun(stdout="cafebabe  /opt/app/f\n"))

    await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)

    assert len(calls) == 1
    canonical, _restricted, platform = calls[0]
    assert canonical == "/opt/app/f"
    assert platform == "posix"


# --- Gap coverage: canonical != raw, stat failure, timeout propagation ---


@pytest.mark.asyncio
async def test_hash_uses_canonical_path_not_raw_input(monkeypatch) -> None:
    """`realpath -m` resolves `/opt/app/../app/f` to `/opt/app/f`; the hash
    command must see the canonical form, not the raw input. Catches a bug
    where a future refactor passes `path` through instead of `canonical`."""

    async def fake_canonicalize(_conn, _path, _allowlist, **_kw):
        return "/opt/app/canonical/f"  # deliberately different from input

    monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

    policy = _posix_policy()
    ctx, holder = _ctx(policy)
    conn = _FakeConn(run_result=_FakeRun(stdout="abc123  /opt/app/canonical/f\n"))
    holder["conn"] = conn

    result = await ssh_file_hash(host="x", path="/opt/app/../app/raw/f", ctx=ctx)

    # argv must reference the canonical path, NOT the raw input.
    assert "/opt/app/canonical/f" in conn.run_calls[0]
    assert "raw" not in conn.run_calls[0]
    # Returned `path` field also reflects the canonical form.
    assert result.path == "/opt/app/canonical/f"


@pytest.mark.asyncio
async def test_stat_failure_yields_negative_size(monkeypatch) -> None:
    """`_stat_size` returns -1 when SFTP stat fails (e.g. after the hash
    succeeds but the file vanished, or the SFTP subsystem barfs). The tool
    must not raise -- the digest is still useful without a size."""

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

    policy = _posix_policy()
    ctx, holder = _ctx(policy)
    holder["conn"] = _FakeConn(
        run_result=_FakeRun(stdout="deadbeef  /opt/app/f\n"),
        stat_raises=True,
    )

    result = await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)
    assert result.digest == "deadbeef"
    assert result.size == -1


@pytest.mark.asyncio
async def test_timeout_propagates_to_conn_run(monkeypatch) -> None:
    """Caller-supplied timeout reaches the conn.run call. Without this, the
    docstring promise of `timeout` control would be a lie."""

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

    policy = _posix_policy()
    ctx, holder = _ctx(policy)
    conn = _FakeConn(run_result=_FakeRun(stdout="deadbeef  /opt/app/f\n"))
    holder["conn"] = conn

    await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx, timeout=300)

    assert len(conn.run_kwargs) == 1
    assert conn.run_kwargs[0]["timeout"] == 300.0


@pytest.mark.asyncio
async def test_timeout_defaults_to_settings_value(monkeypatch) -> None:
    """No explicit timeout -> Settings.SSH_COMMAND_TIMEOUT is used."""

    async def fake_canonicalize(_conn, path, _allowlist, **_kw):
        return path

    monkeypatch.setattr(sftp_read_tools, "canonicalize_and_check", fake_canonicalize)

    policy = _posix_policy()
    ctx, holder = _ctx(policy)
    # Customize the settings in the ctx so the assertion has a distinctive value.
    from ssh_mcp.config import Settings

    ctx.__class__.lifespan_context["settings"] = Settings(
        SSH_PATH_ALLOWLIST=["/opt/app"],
        SSH_COMMAND_TIMEOUT=777,
    )
    conn = _FakeConn(run_result=_FakeRun(stdout="deadbeef  /opt/app/f\n"))
    holder["conn"] = conn

    await ssh_file_hash(host="x", path="/opt/app/f", ctx=ctx)
    assert conn.run_kwargs[0]["timeout"] == 777.0
