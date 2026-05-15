"""Unit tests for apt_tools, apt models, and apt_parser.

Pure Python -- no SSH connections, no real apt. The shared SSH runner
``ssh_mcp.tools.apt_tools._run_apt`` plus the cheaper ``_probe_apt`` are
monkeypatched at the module boundary so the tools think every host is a
fully-stocked Debian box.

Coverage:
- Pattern validator: globs accepted, metacharacters rejected.
- Package-name validator: lowercase debian shape accepted, injection
  payloads rejected.
- ``parse_apt_list``: typical rows, multi-state brackets, header lines
  skipped, empty input.
- ``parse_apt_search``: ``" - "`` split, descriptions with embedded
  dashes, lines without separator skipped.
- ``parse_apt_show``: scalar / CSV-list / Description (incl. the apt
  paragraph dot) fields.
- ``parse_apt_policy``: installed/candidate/(none), repo dedup, dpkg
  status line ignored.
- ``ssh_apt_list``: happy path for each mode, pattern validation,
  ``PlatformNotSupported`` when ``apt`` missing, output_warnings
  propagation, truncation flag when stdout fills the cap.
- ``ssh_apt_search``: happy path, empty result, no metachars, warnings
  propagation.
- ``ssh_apt_show``: combined show+policy, package not found, package
  name validation rejects injection payloads, warnings dedup across
  the two probes.
"""

from __future__ import annotations

from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from ssh_mcp.models.apt import (
    AptListResult,
    AptPackage,
    AptSearchHit,
    AptSearchResult,
    AptShowResult,
)
from ssh_mcp.services.apt_parser import (
    parse_apt_list,
    parse_apt_policy,
    parse_apt_search,
    parse_apt_show,
)
from ssh_mcp.ssh.errors import PlatformNotSupported
from ssh_mcp.tools import apt_tools
from ssh_mcp.tools.apt_tools import (
    _validate_package_name,
    _validate_pattern,
    ssh_apt_list,
    ssh_apt_search,
    ssh_apt_show,
)

# ---------------------------------------------------------------------------
# Shared test context / patching helpers
# ---------------------------------------------------------------------------


def _make_ctx(hostname: str = "testhost", *, platform: str = "linux") -> Any:
    """Return a minimal fake FastMCP Context usable by the apt tools.

    ``platform`` defaults to "linux" so ``require_posix`` allows the call.
    Pass ``platform="windows"`` to drive the rejection path.
    """
    from ssh_mcp.config import Settings
    from ssh_mcp.models.policy import AuthPolicy, HostPolicy

    pool = MagicMock()
    pool.acquire = AsyncMock(return_value=MagicMock(name="conn"))
    settings = Settings()
    policy = HostPolicy(
        hostname=hostname,
        user="deploy",
        auth=AuthPolicy(method="agent"),
        platform=platform,
    )

    class _Ctx:
        lifespan_context: ClassVar[dict] = {
            "pool": pool,
            "settings": settings,
            "hosts": {hostname: policy},
        }

    return _Ctx()


def _patch_apt(
    monkeypatch: Any,
    *,
    probe_ok: bool = True,
    runs: list[tuple[str, str, int, list[str]]] | None = None,
) -> dict[str, list[Any]]:
    """Patch ``_probe_apt`` and ``_run_apt`` to simulate a Debian host.

    ``runs`` is a queue: each call to ``_run_apt`` consumes the head and
    returns it as ``(stdout, stderr, exit_code, output_warnings)``. The
    fixture extends each entry to the helper's full
    ``(..., stdout_truncated)`` shape (``False`` by default); tests that
    need to drive the truncation flag synthesise an oversize stdout
    instead -- exercises both the helper and the cap in one go.
    """
    runs_q = list(runs or [])
    captured: dict[str, list[Any]] = {"argv": [], "host": []}

    # Match _run_apt's behavior: synthesise stdout_truncated from a byte
    # comparison against the configured cap. Lets the existing 4-tuple
    # fixture inputs keep working unchanged while the test asserting
    # truncation (oversize stdout) still flips the flag.
    from ssh_mcp.config import Settings as _Settings

    cap = _Settings().SSH_STDOUT_CAP_BYTES

    async def fake_probe(_ctx: Any, host: str) -> None:
        if not probe_ok:
            raise PlatformNotSupported(f"apt not available on host {host!r}")

    async def fake_run(_ctx: Any, host: str, argv: list[str]) -> tuple[str, str, int, list[str], bool]:
        captured["argv"].append(list(argv))
        captured["host"].append(host)
        if not runs_q:
            return ("", "", 0, [], False)
        stdout, stderr, exit_code, warnings = runs_q.pop(0)
        truncated = len(stdout.encode("utf-8", errors="replace")) >= cap
        return (stdout, stderr, exit_code, warnings, truncated)

    monkeypatch.setattr(apt_tools, "_probe_apt", fake_probe)
    monkeypatch.setattr(apt_tools, "_run_apt", fake_run)
    return captured


# ---------------------------------------------------------------------------
# _validate_pattern
# ---------------------------------------------------------------------------


class TestValidatePattern:
    @pytest.mark.parametrize(
        "pat",
        [
            "nginx",
            "nginx*",
            "*-server",
            "lib?",
            "lib*-dev",
            "python3.11",
            "ca-certificates",
            "g++",  # plus signs allowed
            "lib_foo",  # underscore tolerated
            "a",  # one char
            "x" * 128,  # exactly at limit
        ],
    )
    def test_valid(self, pat: str) -> None:
        assert _validate_pattern(pat) == pat

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "x" * 129,
            "nginx;ls",
            "nginx|ls",
            "nginx&ls",
            "`whoami`",
            "$(whoami)",
            "nginx ls",  # space
            "nginx\nls",
            "nginx/etc",  # slash
            "<inject>",
            "nginx\\foo",
        ],
    )
    def test_invalid(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _validate_pattern(bad)


# ---------------------------------------------------------------------------
# _validate_package_name
# ---------------------------------------------------------------------------


class TestValidatePackageName:
    @pytest.mark.parametrize(
        "name",
        [
            "nginx",
            "openssl",
            "python3.11",
            "libssl3",
            "ca-certificates",
            "g++",
            "lib0",
            "0install",  # starts with digit, rest alnum -- legitimate Debian pkg shape
        ],
    )
    def test_valid(self, name: str) -> None:
        assert _validate_package_name(name) == name

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "Nginx",  # uppercase rejected
            "NGINX",
            "nginx;rm -rf /",
            "nginx|cat",
            "nginx`whoami`",
            "$(whoami)",
            "nginx ls",
            "nginx\nls",
            "/etc/nginx",  # slash
            "-leading-dash",  # must start alnum
            ".dotfile",  # must start alnum
            "x" * 129,  # too long
        ],
    )
    def test_invalid(self, bad: str) -> None:
        with pytest.raises(ValueError):
            _validate_package_name(bad)


# ---------------------------------------------------------------------------
# parse_apt_list
# ---------------------------------------------------------------------------


class TestParseAptList:
    def test_typical_installed_row(self) -> None:
        stdout = "Listing...\n" "nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.4 amd64 [installed]\n"
        rows = parse_apt_list(stdout)
        assert len(rows) == 1
        assert rows[0].name == "nginx"
        assert rows[0].version == "1.18.0-6ubuntu14.4"
        assert rows[0].architecture == "amd64"
        assert rows[0].state == "installed"

    def test_multi_state_bracket(self) -> None:
        stdout = "curl/now 7.81.0-1ubuntu1.16 amd64 [installed,local]\n"
        rows = parse_apt_list(stdout)
        assert rows[0].state == "installed,local"

    def test_no_state_bracket(self) -> None:
        # apt elides the bracket for non-installed entries on some versions.
        stdout = "libfoo/jammy 1.2.3 amd64\n"
        rows = parse_apt_list(stdout)
        assert len(rows) == 1
        assert rows[0].state == ""

    def test_header_line_skipped(self) -> None:
        stdout = (
            "Listing...\n"
            "WARNING: apt does not have a stable CLI interface. Use with caution in scripts.\n"
            "nginx/jammy 1.18.0 amd64 [installed]\n"
        )
        rows = parse_apt_list(stdout)
        assert len(rows) == 1

    def test_multiple_rows(self) -> None:
        stdout = (
            "Listing...\n"
            "nginx/jammy 1.18.0 amd64 [installed]\n"
            "openssl/jammy 3.0.2 amd64 [installed,automatic]\n"
            "curl/jammy 7.81.0 amd64 [installed]\n"
        )
        rows = parse_apt_list(stdout)
        assert len(rows) == 3
        assert {r.name for r in rows} == {"nginx", "openssl", "curl"}

    def test_empty_input(self) -> None:
        assert parse_apt_list("") == []

    def test_blank_and_garbage_lines_skipped(self) -> None:
        stdout = "\n  \nnot a real row\n  more garbage\nnginx/j 1.0 amd64\n"
        rows = parse_apt_list(stdout)
        assert len(rows) == 1
        assert rows[0].name == "nginx"


# ---------------------------------------------------------------------------
# parse_apt_search
# ---------------------------------------------------------------------------


class TestParseAptSearch:
    def test_typical(self) -> None:
        stdout = (
            "nginx - small, powerful, scalable web/proxy server\n"
            "openssl - Secure Sockets Layer toolkit - cryptographic utility\n"
        )
        hits = parse_apt_search(stdout)
        assert len(hits) == 2
        assert hits[0].name == "nginx"
        assert "small" in hits[0].short_description
        # Internal " - " in the description must NOT cause re-splitting.
        assert hits[1].name == "openssl"
        assert hits[1].short_description == "Secure Sockets Layer toolkit - cryptographic utility"

    def test_lines_without_separator_skipped(self) -> None:
        stdout = "nginx - web server\nrandomline-without-separator\nopenssl - toolkit\n"
        hits = parse_apt_search(stdout)
        assert {h.name for h in hits} == {"nginx", "openssl"}

    def test_empty_input(self) -> None:
        assert parse_apt_search("") == []


# ---------------------------------------------------------------------------
# parse_apt_show
# ---------------------------------------------------------------------------


class TestParseAptShow:
    def test_basic_fields(self) -> None:
        stdout = (
            "Package: nginx\n"
            "Version: 1.18.0-6ubuntu14.4\n"
            "Depends: libc6 (>= 2.34), libssl3 (>= 3.0.0)\n"
            "Recommends: nginx-core\n"
            "Suggests: ufw\n"
            "Description: small, powerful, scalable web/proxy server\n"
            ' Nginx ("engine X") is a high-performance web and reverse proxy\n'
            " server.\n"
            "\n"
            "Package: nginx\n"  # second stanza ignored
            "Version: 1.18.0-other\n"
        )
        out = parse_apt_show(stdout)
        assert out["depends"] == ["libc6 (>= 2.34)", "libssl3 (>= 3.0.0)"]
        assert out["recommends"] == ["nginx-core"]
        assert out["suggests"] == ["ufw"]
        desc = out["description"]
        assert isinstance(desc, str)
        assert desc.startswith("small")
        assert "engine X" in desc

    def test_paragraph_dot_renders_blank_line(self) -> None:
        stdout = (
            "Package: foo\n"
            "Description: short summary\n"
            " First paragraph.\n"
            " .\n"
            " Second paragraph.\n"
        )
        out = parse_apt_show(stdout)
        desc = out["description"]
        assert isinstance(desc, str)
        assert "\n\n" in desc  # the dot turned into a blank line
        assert "First paragraph." in desc
        assert "Second paragraph." in desc

    def test_missing_optional_fields_default_empty(self) -> None:
        stdout = "Package: foo\nVersion: 1.0\n"
        out = parse_apt_show(stdout)
        assert out["depends"] == []
        assert out["recommends"] == []
        assert out["description"] is None

    def test_empty_input(self) -> None:
        out = parse_apt_show("")
        assert out["description"] is None
        assert out["depends"] == []


# ---------------------------------------------------------------------------
# parse_apt_policy
# ---------------------------------------------------------------------------


class TestParseAptPolicy:
    def test_installed_with_repos(self) -> None:
        stdout = (
            "nginx:\n"
            "  Installed: 1.18.0-6ubuntu14.4\n"
            "  Candidate: 1.18.0-6ubuntu14.4\n"
            "  Version table:\n"
            " *** 1.18.0-6ubuntu14.4 500\n"
            "        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages\n"
            "        500 http://security.ubuntu.com/ubuntu jammy-security/main amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
        )
        out = parse_apt_policy(stdout)
        assert out["installed_version"] == "1.18.0-6ubuntu14.4"
        assert out["candidate_version"] == "1.18.0-6ubuntu14.4"
        repos = out["repos"]
        assert isinstance(repos, list)
        assert any("archive.ubuntu.com" in r for r in repos)
        assert any("security.ubuntu.com" in r for r in repos)
        # The dpkg status line is local state -- must not appear as a repo.
        assert not any("/var/lib/dpkg/status" in r for r in repos)

    def test_not_installed(self) -> None:
        stdout = "nginx:\n" "  Installed: (none)\n" "  Candidate: 1.18.0\n"
        out = parse_apt_policy(stdout)
        assert out["installed_version"] is None
        assert out["candidate_version"] == "1.18.0"

    def test_unknown_package(self) -> None:
        out = parse_apt_policy("")
        assert out["installed_version"] is None
        assert out["candidate_version"] is None
        assert out["repos"] == []

    def test_repos_dedup(self) -> None:
        stdout = (
            "  Installed: 1.0\n"
            "  Candidate: 1.0\n"
            "        500 http://r.example/ubuntu jammy/main amd64 Packages\n"
            "        500 http://r.example/ubuntu jammy/main amd64 Packages\n"
        )
        out = parse_apt_policy(stdout)
        repos = out["repos"]
        assert isinstance(repos, list)
        assert len(repos) == 1


# ---------------------------------------------------------------------------
# ssh_apt_list
# ---------------------------------------------------------------------------


class TestSshAptList:
    @pytest.mark.asyncio
    async def test_installed_happy_path(self, monkeypatch: Any) -> None:
        stdout = (
            "Listing...\n" "nginx/jammy 1.18.0 amd64 [installed]\n" "openssl/jammy 3.0.2 amd64 [installed]\n"
        )
        captured = _patch_apt(monkeypatch, runs=[(stdout, "", 0, [])])
        result = await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx())
        assert result["host"] == "testhost"
        assert result["mode"] == "installed"
        assert result["total"] == 2
        assert result["truncated"] is False
        assert result["packages"][0]["name"] == "nginx"
        # argv must include --installed and use fixed positional pattern slot.
        assert captured["argv"][0] == ["apt", "list", "--installed"]

    @pytest.mark.asyncio
    async def test_upgradable_with_pattern(self, monkeypatch: Any) -> None:
        stdout = "Listing...\nnginx/jammy 1.18.1 amd64 [upgradable from: 1.18.0]\n"
        captured = _patch_apt(monkeypatch, runs=[(stdout, "", 0, [])])
        result = await ssh_apt_list(host="testhost", mode="upgradable", ctx=_make_ctx(), pattern="nginx*")
        assert result["mode"] == "upgradable"
        assert result["total"] == 1
        # `--` separator before the pattern guards against pattern-as-flag.
        assert captured["argv"][0] == ["apt", "list", "--upgradable", "--", "nginx*"]

    @pytest.mark.asyncio
    async def test_all_mode_omits_flag(self, monkeypatch: Any) -> None:
        captured = _patch_apt(monkeypatch, runs=[("Listing...\n", "", 0, [])])
        await ssh_apt_list(host="testhost", mode="all", ctx=_make_ctx())
        # No --installed / --upgradable flag in argv for "all".
        assert captured["argv"][0] == ["apt", "list"]

    @pytest.mark.asyncio
    async def test_invalid_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            await ssh_apt_list(host="testhost", mode="bogus", ctx=_make_ctx())  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_pattern_metachar_rejected(self) -> None:
        with pytest.raises(ValueError):
            await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx(), pattern="nginx;rm -rf /")

    @pytest.mark.asyncio
    async def test_no_apt_raises_platform_not_supported(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, probe_ok=False)
        with pytest.raises(PlatformNotSupported):
            await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx())

    @pytest.mark.asyncio
    async def test_output_warnings_propagated(self, monkeypatch: Any) -> None:
        warnings = ["ANSI escape sequences stripped"]
        _patch_apt(monkeypatch, runs=[("Listing...\n", "", 0, warnings)])
        result = await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx())
        assert result["output_warnings"] == warnings

    @pytest.mark.asyncio
    async def test_empty_result(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, runs=[("Listing...\n", "", 0, [])])
        result = await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx())
        assert result["packages"] == []
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_truncated_when_at_cap(self, monkeypatch: Any) -> None:
        # Synthesize stdout >= the configured stdout cap to flip the flag.
        from ssh_mcp.config import Settings

        cap = Settings().SSH_STDOUT_CAP_BYTES
        big = "x" * (cap + 10)
        _patch_apt(monkeypatch, runs=[(big, "", 0, [])])
        result = await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx())
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_windows_platform_rejected(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, runs=[("Listing...\n", "", 0, [])])
        with pytest.raises(PlatformNotSupported):
            await ssh_apt_list(host="testhost", mode="installed", ctx=_make_ctx(platform="windows"))


# ---------------------------------------------------------------------------
# ssh_apt_search
# ---------------------------------------------------------------------------


class TestSshAptSearch:
    @pytest.mark.asyncio
    async def test_happy_path(self, monkeypatch: Any) -> None:
        stdout = (
            "nginx - small, powerful, scalable web/proxy server\n"
            "nginx-core - nginx web/proxy server (core version)\n"
        )
        captured = _patch_apt(monkeypatch, runs=[(stdout, "", 0, [])])
        result = await ssh_apt_search(host="testhost", pattern="nginx", ctx=_make_ctx())
        assert result["host"] == "testhost"
        assert result["pattern"] == "nginx"
        assert len(result["results"]) == 2
        # apt-cache must be invoked with -- separator before the pattern.
        assert captured["argv"][0] == ["apt-cache", "search", "--", "nginx"]

    @pytest.mark.asyncio
    async def test_empty_result(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, runs=[("", "", 0, [])])
        result = await ssh_apt_search(host="testhost", pattern="totallybogus", ctx=_make_ctx())
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_pattern_metachar_rejected(self) -> None:
        with pytest.raises(ValueError):
            await ssh_apt_search(host="testhost", pattern="`whoami`", ctx=_make_ctx())

    @pytest.mark.asyncio
    async def test_output_warnings_propagated(self, monkeypatch: Any) -> None:
        warnings = ["ANSI escape sequences stripped"]
        _patch_apt(monkeypatch, runs=[("", "", 0, warnings)])
        result = await ssh_apt_search(host="testhost", pattern="nginx", ctx=_make_ctx())
        assert result["output_warnings"] == warnings

    @pytest.mark.asyncio
    async def test_no_apt_raises_platform_not_supported(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, probe_ok=False)
        with pytest.raises(PlatformNotSupported):
            await ssh_apt_search(host="testhost", pattern="nginx", ctx=_make_ctx())


# ---------------------------------------------------------------------------
# ssh_apt_show
# ---------------------------------------------------------------------------


class TestSshAptShow:
    @pytest.mark.asyncio
    async def test_combined_show_and_policy(self, monkeypatch: Any) -> None:
        show_out = (
            "Package: nginx\n"
            "Version: 1.18.0-6ubuntu14.4\n"
            "Depends: libc6 (>= 2.34), libssl3\n"
            "Description: web server\n"
            " Long body line.\n"
        )
        policy_out = (
            "nginx:\n"
            "  Installed: 1.18.0-6ubuntu14.4\n"
            "  Candidate: 1.18.0-6ubuntu14.4\n"
            "        500 http://archive.ubuntu.com/ubuntu jammy/main amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
        )
        captured = _patch_apt(
            monkeypatch,
            runs=[(show_out, "", 0, []), (policy_out, "", 0, [])],
        )
        result = await ssh_apt_show(host="testhost", package="nginx", ctx=_make_ctx())
        assert result["package"] == "nginx"
        assert result["installed_version"] == "1.18.0-6ubuntu14.4"
        assert result["candidate_version"] == "1.18.0-6ubuntu14.4"
        assert result["depends"] == ["libc6 (>= 2.34)", "libssl3"]
        assert result["description"] is not None
        assert "web server" in result["description"]
        # Two probes: show then policy, both with -- before package.
        assert captured["argv"][0] == ["apt-cache", "show", "--", "nginx"]
        assert captured["argv"][1] == ["apt-cache", "policy", "--", "nginx"]

    @pytest.mark.asyncio
    async def test_package_not_found(self, monkeypatch: Any) -> None:
        # apt-cache exits non-zero with empty output for unknown packages.
        _patch_apt(
            monkeypatch,
            runs=[("", "N: Unable to locate package bogus\n", 100, []), ("", "", 100, [])],
        )
        result = await ssh_apt_show(host="testhost", package="bogus", ctx=_make_ctx())
        # Partial parse must construct cleanly with optional fields = None / [].
        assert result["installed_version"] is None
        assert result["candidate_version"] is None
        assert result["repos"] == []
        assert result["description"] is None
        assert result["depends"] == []

    @pytest.mark.asyncio
    async def test_package_name_validation_blocks_injection(self) -> None:
        with pytest.raises(ValueError):
            await ssh_apt_show(host="testhost", package="nginx;rm -rf /", ctx=_make_ctx())
        with pytest.raises(ValueError):
            await ssh_apt_show(host="testhost", package="`whoami`", ctx=_make_ctx())
        with pytest.raises(ValueError):
            await ssh_apt_show(host="testhost", package="$(id)", ctx=_make_ctx())

    @pytest.mark.asyncio
    async def test_output_warnings_dedup(self, monkeypatch: Any) -> None:
        # Both probes raise the same warning -- result should carry it once.
        warnings = ["ANSI escape sequences stripped"]
        _patch_apt(
            monkeypatch,
            runs=[("", "", 0, warnings), ("", "", 0, warnings)],
        )
        result = await ssh_apt_show(host="testhost", package="nginx", ctx=_make_ctx())
        assert result["output_warnings"] == warnings

    @pytest.mark.asyncio
    async def test_no_apt_raises_platform_not_supported(self, monkeypatch: Any) -> None:
        _patch_apt(monkeypatch, probe_ok=False)
        with pytest.raises(PlatformNotSupported):
            await ssh_apt_show(host="testhost", package="nginx", ctx=_make_ctx())


# ---------------------------------------------------------------------------
# Model round-trip sanity
# ---------------------------------------------------------------------------


class TestModelRoundTrip:
    def test_apt_list_result(self) -> None:
        m = AptListResult(
            host="h",
            mode="installed",
            packages=[AptPackage(name="nginx", version="1.0", architecture="amd64", state="installed")],
            total=1,
            truncated=False,
        )
        d = m.model_dump()
        assert d["mode"] == "installed"
        assert d["total"] == 1
        assert d["packages"][0]["name"] == "nginx"

    def test_apt_search_result(self) -> None:
        m = AptSearchResult(
            host="h",
            pattern="nginx",
            results=[AptSearchHit(name="nginx", short_description="web server")],
        )
        d = m.model_dump()
        assert d["results"][0]["short_description"] == "web server"

    def test_apt_show_result_minimal(self) -> None:
        # All optional fields default to None / [] -- partial parses construct.
        m = AptShowResult(host="h", package="nginx")
        d = m.model_dump()
        assert d["installed_version"] is None
        assert d["repos"] == []
        assert d["depends"] == []

    def test_apt_show_result_full(self) -> None:
        m = AptShowResult(
            host="h",
            package="nginx",
            installed_version="1.0",
            candidate_version="1.1",
            repos=["http://r jammy/main amd64 Packages"],
            description="web server",
            depends=["libc6"],
            recommends=["nginx-core"],
        )
        d = m.model_dump()
        assert d["installed_version"] == "1.0"
        assert d["candidate_version"] == "1.1"
        assert d["depends"] == ["libc6"]
