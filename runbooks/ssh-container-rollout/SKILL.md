---
description: Roll a single standalone Docker container to a new image tag with pre-pull, health verification, and rollback
---

# SSH Container Rollout

For hosts running **standalone `docker run`** containers (not
compose-managed). Pulls the new image first, stops + removes the old
container, starts the new one with the same config, then verifies
healthy. If verification fails, rolls back to the previous image.

## Default-on cheatsheet rejection (since v1.9.0)

`ssh_exec_run` refuses commands that have a native MCP tool -- see
`skills/ssh-exec-run/SKILL.md`. The native-tool flow below avoids
that. Composite scripts (where the script IS the artefact) opt out
via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` at the operator level.

Sections 4 and 6 below intentionally use `ssh_exec_run` for
`docker run` with persistent-service flags (`-p`, `-v`, `-e`,
`--restart`, `--network`). These match the `docker` cheatsheet
pattern; the operator must enable the opt-out for this runbook
because `ssh_docker_run` is intentionally limited to ephemeral
one-shot containers and cannot express those flags.

For compose-managed stacks, use
[ssh-deploy-verify](../ssh-deploy-verify/SKILL.md) + `ssh_docker_compose_up`
instead -- compose handles the stop/start/dependency ordering, re-deriving
it here is error-prone.

## Sequence

1. Capture current config (so you can recreate it)
2. Pull the new image (no service impact yet)
3. Stop + remove the old container
4. Start the new container with identical config
5. Verify health
6. Roll back on failure

## 1. Capture current config

```python
ssh_docker_inspect(host="web01", target="my-service", kind="container")
ssh_docker_ps(host="web01")  # confirm it's actually running
```

From the inspect payload, record everything you'll need to recreate the
container on the new tag:

- Image ID **and** image tag (`Image` vs `Config.Image`). The tag is
  what you'll bump; the image ID is your rollback anchor.
- `HostConfig.PortBindings`, `HostConfig.Mounts`, `HostConfig.Binds`
  (bind mounts + volumes).
- `Config.Env` (environment variables). Note: some env vars may be
  secrets -- handle accordingly, don't dump them into logs.
- `HostConfig.RestartPolicy`.
- `HostConfig.NetworkMode` + `NetworkSettings.Networks` (which user-
  defined networks to attach to).
- `Config.Cmd` / `Config.Entrypoint` if overridden from the image default.
- `Config.Labels` (some orchestrators key off these).

If any of the above is surprising or undocumented, **stop** and get
operator confirmation that a rollout is safe. Recreating a container
from a partially-captured config is how you end up with a service
missing its database connection string in prod.

## 2. Pull the new image

```python
ssh_docker_pull(host="web01", image="ghcr.io/myorg/my-service:v2.3.0")
```

Pull before stopping anything -- pulls take seconds to minutes and can
fail (registry auth, network, rate limit). Failing a pull while the
current container is still serving traffic is a non-event; failing a
pull after you've stopped the old container is an outage.

Optional but recommended: hash/signature-verify the pulled image before
activation. See
[ssh-verify-signature](../ssh-verify-signature/SKILL.md) for the
runbook. Image digest pinning (`...@sha256:<digest>`) is a stronger
pattern than tag pinning; tags are mutable.

## 3. Stop + remove the old container

Requires `ALLOW_LOW_ACCESS_TOOLS` (stop) + `ALLOW_DANGEROUS_TOOLS` (rm):

```python
ssh_docker_stop(host="web01", container="my-service")
ssh_docker_rm(host="web01", container="my-service")
```

The default SIGTERM grace period is whatever the daemon / image defines
(usually 10s). `ssh_docker_stop` does not expose `--time` -- if the
service needs a longer drain window (databases, queue workers), call
`docker stop -t <seconds>` via `ssh_exec_run` instead. Too-short
shutdown + `rm` = data loss for stateful workloads; if the container is
stateful, confirm volumes hold the state (Section 1's `Mounts`) before
removing it.

## 4. Start the new container

`ssh_docker_run` is intentionally a thin wrapper for ephemeral one-shot
containers -- its argv is hardcoded to `docker run --rm -d --name <n>
-- <image> [container-cmd...]` and the `args` list is passed **after**
the image (so it becomes the container's command, not docker options).
That means flags like `--restart`, `-p`, `-v`, `-e`, `--network`
cannot be set through it. For a persistent service rollout, drive
`docker run` through `ssh_exec_run` instead. This call matches the
`docker` cheatsheet pattern and requires
`SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` on the server because the
persistent-service flag surface is intentionally outside
`ssh_docker_run`:

```python
import shlex

flags = [
    "--name", "my-service",
    "-d",
    "--restart", "unless-stopped",
    "-p", "8080:8080",
    "-v", "/opt/my-service/data:/data",
    "-e", "DATABASE_URL=postgres://...",
    "--network", "frontend",
]
cmd = "docker run " + " ".join(shlex.quote(f) for f in flags) \
      + " -- ghcr.io/myorg/my-service:v2.3.0"

ssh_exec_run(host="web01", command=cmd, timeout=60)
```

Every flag here comes from Section 1. A common bug: forgetting to
reattach a user-defined network, so the new container comes up on
bridge and can't reach its peers. Verify `NetworkSettings.Networks` in
Section 5's inspect.

Note: this step needs `ALLOW_DANGEROUS_TOOLS` (for `ssh_exec_run`) and
`docker` in the host's `command_allowlist`. The capability-escalation
checks that `ssh_docker_run` enforces by default (rejecting
`--privileged`, `--cap-add`, host bind mounts, etc.) do **not** apply
when you go through `ssh_exec_run` -- it's your responsibility to keep
escalation flags out of the command string.

## 5. Verify health

Give the service a moment to start, then inspect + tail logs:

```python
ssh_docker_inspect(host="web01", target="my-service", kind="container")
ssh_docker_logs(host="web01", container="my-service", tail=200)
```

Read `State` from inspect:

- `State.Status == "running"` + `State.Health.Status == "healthy"` ->
  rollout succeeded. Done.
- `State.Health.Status == "starting"` -> healthcheck is still in its
  start period. Re-poll after 10-30s.
- `State.Status == "exited"` + non-zero `State.ExitCode` -> roll back
  (Section 6). Log `State.ExitCode` and the log tail so the operator
  can diagnose the failed release without re-running.
- `State.Status == "restarting"` with high `RestartCount` -> crash
  loop. Roll back.
- Container has no healthcheck (`State.Health` absent) -> inspect tells
  you the process is up but nothing about whether it works. Either
  trust logs (risky), or pair this with an application-level probe from
  outside the container before declaring success.

For containers without a Dockerfile `HEALTHCHECK`, consider `docker_top`
to at least confirm PID 1 is the expected process:

```python
ssh_docker_top(host="web01", container="my-service")
```

A shell or init wrapper as PID 1 when the image's entrypoint should be
the application binary means the process died and the wrapper is idling.

## 6. Roll back on failure

The previous image is still on the host (you just stopped and removed
the container, not the image). Recreate the old container on the
previous tag / digest from Section 1:

```python
import shlex

ssh_docker_stop(host="web01", container="my-service")
ssh_docker_rm(host="web01", container="my-service")

# Same flag list as Section 4, only the image tag changes. Same
# cheatsheet opt-out applies: requires SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true.
cmd = "docker run " + " ".join(shlex.quote(f) for f in flags) \
      + " -- ghcr.io/myorg/my-service:v2.2.9"  # previous tag from Section 1
ssh_exec_run(host="web01", command=cmd, timeout=60)
```

Then re-run Section 5 against the rolled-back container. A bad rollback
(old image no longer runnable because deps moved, volume schema
migrated forward, etc.) is worse than the failed rollout -- don't
assume the rollback worked until verified.

Note on image retention: don't `ssh_docker_rmi` the old image as part
of the rollout, even on success. Keep at least the previous release
image on the host for fast rollback; prune it in a later scheduled
cleanup after you're confident the new one is stable.

## When NOT to use this runbook

- Service is compose-managed -> use
  [ssh-deploy-verify](../ssh-deploy-verify/SKILL.md).
- Multi-host fleet rollout -> wrap this runbook in a per-host loop
  with health-gating between hosts. Never parallel.
- Stateful single-instance services (a Postgres running in `docker run`
  on one box) -> this runbook causes downtime between Section 3 and
  Section 5's healthy signal. Plan for the downtime window explicitly
  or use an orchestrator with rolling capability.
- Zero-downtime requirement -> put a load balancer in front of two
  containers; this runbook assumes brief downtime is acceptable.

## Boundaries

- Section 1 + 2 + 5 are read-only.
- Section 3 needs `ALLOW_LOW_ACCESS_TOOLS` (stop) and
  `ALLOW_DANGEROUS_TOOLS` (`docker_rm`).
- Section 4 needs `ALLOW_DANGEROUS_TOOLS` (`ssh_exec_run`) and `docker`
  in the host's `command_allowlist`.
- Section 6 has the same tier requirements as 3+4.
- This runbook does **not** manage secrets. If Section 1 surfaces env
  vars that are secrets, re-pass them via the `-e KEY=VALUE` flags in
  Section 4 without logging them. The audit log of `ssh_exec_run`
  records the full command string -- if a secret would land there in
  plaintext, escalate to an operator who can configure secrets via
  `--env-file <path>` or a docker secret out-of-band instead.
- Image pull source is assumed already configured (registry auth in
  `docker login` state on the host). Re-authing mid-rollout is its own
  runbook.

## Related runbooks

- [ssh-deploy-verify](../ssh-deploy-verify/SKILL.md) -- compose-managed
  equivalent.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  -- when Section 5 shows unhealthy and rollback also fails.
- [ssh-verify-signature](../ssh-verify-signature/SKILL.md) -- optional
  hardening between Section 2 and Section 3.
