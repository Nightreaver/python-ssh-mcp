"""SSH_DOCKER_CMD / per-host docker_cmd: podman vs docker routing.

Exercises the `_docker_prefix` + `_compose_prefix` helpers without hitting
a live remote. The prefix logic is the only thing that differs between
docker and podman targets -- once the argv is built correctly, everything
downstream is the same code path.
"""
from __future__ import annotations

from typing import Any

from ssh_mcp.config import Settings
from ssh_mcp.models.policy import AuthPolicy, HostPolicy
from ssh_mcp.tools.docker_tools import _compose_prefix, _docker_prefix


def _policy(**kw: Any) -> HostPolicy:
    defaults = {
        "hostname": "web01",
        "user": "deploy",
        "auth": AuthPolicy(method="agent"),
    }
    defaults.update(kw)
    return HostPolicy(**defaults)


class TestDockerPrefix:
    def test_default_is_docker(self) -> None:
        assert _docker_prefix(_policy(), Settings()) == ["docker"]

    def test_global_override(self) -> None:
        s = Settings(SSH_DOCKER_CMD="podman")
        assert _docker_prefix(_policy(), s) == ["podman"]

    def test_per_host_wins_over_global(self) -> None:
        s = Settings(SSH_DOCKER_CMD="podman")
        p = _policy(docker_cmd="docker")
        assert _docker_prefix(p, s) == ["docker"]

    def test_shell_split_for_wrappers(self) -> None:
        """Operator prepends sudo / env via shell syntax."""
        p = _policy(docker_cmd="sudo docker")
        assert _docker_prefix(p, Settings()) == ["sudo", "docker"]

    def test_empty_global_falls_back_to_docker(self) -> None:
        s = Settings(SSH_DOCKER_CMD="")
        assert _docker_prefix(_policy(), s) == ["docker"]


class TestComposePrefix:
    def test_derives_from_docker_cmd_by_default(self) -> None:
        """Default case: SSH_DOCKER_COMPOSE_CMD empty -> `{docker} compose`."""
        assert _compose_prefix(_policy(), Settings()) == ["docker", "compose"]

    def test_derives_from_podman_when_docker_cmd_is_podman(self) -> None:
        """The whole point of the refactor: operator sets docker_cmd=podman,
        compose follows automatically to `podman compose`."""
        s = Settings(SSH_DOCKER_CMD="podman")
        assert _compose_prefix(_policy(), s) == ["podman", "compose"]

    def test_per_host_podman_derives_compose(self) -> None:
        p = _policy(docker_cmd="podman")
        assert _compose_prefix(p, Settings()) == ["podman", "compose"]

    def test_explicit_override_wins(self) -> None:
        """Legacy standalone binary: operator pins SSH_DOCKER_COMPOSE_CMD."""
        s = Settings(
            SSH_DOCKER_CMD="podman",
            SSH_DOCKER_COMPOSE_CMD="podman-compose",
        )
        assert _compose_prefix(_policy(), s) == ["podman-compose"]

    def test_explicit_override_shell_split(self) -> None:
        s = Settings(SSH_DOCKER_COMPOSE_CMD="docker-compose --project-name myapp")
        assert _compose_prefix(_policy(), s) == [
            "docker-compose",
            "--project-name",
            "myapp",
        ]

    def test_whitespace_only_override_is_treated_as_unset(self) -> None:
        s = Settings(SSH_DOCKER_CMD="podman", SSH_DOCKER_COMPOSE_CMD="   ")
        assert _compose_prefix(_policy(), s) == ["podman", "compose"]


class TestComposePrefixV1:
    """`v1=True` selects the legacy standalone-binary form (`docker-compose`).

    Per-tool-call opt-in so a host that mostly runs v2 can still reach the
    occasional service still shipped on the v1 wrapper.
    """

    def test_v1_from_default_docker(self) -> None:
        assert _compose_prefix(_policy(), Settings(), v1=True) == ["docker-compose"]

    def test_v1_from_podman(self) -> None:
        """Podman ships v1 as `podman-compose` -- derivation must follow."""
        s = Settings(SSH_DOCKER_CMD="podman")
        assert _compose_prefix(_policy(), s, v1=True) == ["podman-compose"]

    def test_v1_preserves_sudo_wrapper(self) -> None:
        """Operator wrappers (`sudo`, `env FOO=bar`) stay in front of the
        dashed binary so permissions/env pass through to the v1 invocation."""
        p = _policy(docker_cmd="sudo docker")
        assert _compose_prefix(p, Settings(), v1=True) == ["sudo", "docker-compose"]

    def test_v1_overrides_explicit_compose_cmd(self) -> None:
        """If the operator pinned `SSH_DOCKER_COMPOSE_CMD=docker compose ...`
        globally but the caller asks for v1, v1 wins -- the whole point of the
        per-call switch is to override the configured path."""
        s = Settings(SSH_DOCKER_COMPOSE_CMD="docker compose --profile prod")
        assert _compose_prefix(_policy(), s, v1=True) == ["docker-compose"]

    def test_v2_default_unchanged(self) -> None:
        """Regression guard: v1=False (default) keeps the existing behavior."""
        assert _compose_prefix(_policy(), Settings(), v1=False) == ["docker", "compose"]


class TestPolicyField:
    def test_docker_cmd_default_none(self) -> None:
        assert _policy().docker_cmd is None

    def test_docker_cmd_accepts_string(self) -> None:
        p = _policy(docker_cmd="podman")
        assert p.docker_cmd == "podman"
