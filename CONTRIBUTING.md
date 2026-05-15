# Contributing to python-ssh-mcp

Thanks for considering a contribution. This project is small, opinionated, and security-sensitive — please read this file end-to-end before opening a PR.

## Dev setup

```bash
uv sync --extra dev
```

`tasks` is a hard dependency and pulled in automatically. See [pyproject.toml](./pyproject.toml) for the full list of optional extras.

## Runner rule (hard)

All tests, lint, and type-check go through `uv run`:

- `uv run pytest`
- `uv run ruff check .`
- `uv run ruff format --check .`
- `uv run mypy src tests`

Bare `pytest` / `ruff` / `mypy` invocations hit permission prompts in some sandboxed harnesses and stall workers. Mirror the rule documented in [CLAUDE.md](./CLAUDE.md).

## Branch / PR flow

- Fork or branch off `main`.
- Open a PR back into `main`.
- Expect review before merge. Squash-merge is the default.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/). Common prefixes:

- `feat:` — new tool, new flag, new capability
- `fix:` — bug fix
- `chore:` — tooling, deps, repo hygiene
- `docs:` — documentation only
- `refactor:` — internal restructure, no behaviour change
- `test:` — test-only changes

## Testing expectations

- Unit tests live in [tests/](./tests/). New tools must ship with unit tests.
- Integration tests live in `tests/integration/` and require the `@pytest.mark.integration` marker plus the docker-sshd fixture. Recommended whenever you touch transport surface.
- End-to-end tests live in `tests/e2e/`, marked `@pytest.mark.e2e`, and run against the operator's real `hosts.toml`. Optional, but useful for changes that span multiple tools.

## Architectural context

For the tool tier model, policy gate layout, audit log decorator chain, connection pool semantics, and overall layering, see [AGENTS.md](./AGENTS.md) — this is the architectural single source of truth.

For per-tool operator playbooks (`SKILL.md` per runbook), see [runbooks/](./runbooks/).

## Security-sensitive changes

Anything touching the following needs an explicit note in the PR body:

- `host_policy`, `path_policy`, or `exec_policy` (in `src/ssh_mcp/services/`)
- The `@audit_log` decorator chain
- Host key verification or `known_hosts` handling
- The dangerous-tool or sudo tier gates (`ALLOW_DANGEROUS_TOOLS`, `ALLOW_SUDO`, etc.)
- Any tier-flag logic or FastMCP `Visibility` transforms

See [SECURITY.md](./SECURITY.md) for what counts as in-scope for security review.
