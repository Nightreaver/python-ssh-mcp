---
description: Roll a single standalone Docker container to a new image tag with pre-pull, health verification, and rollback
---

# SSH Container Rollout

For hosts running **standalone `docker run`** containers (not
compose-managed). Pulls the new image first, stops + removes the old
container, starts the new one with the same config, then verifies
healthy. If verification fails, rolls back to the previous image.

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
ssh_docker_stop(host="web01", container="my-service", timeout=30)
ssh_docker_rm(host="web01", container="my-service")
```

`timeout=30` gives the process 30s to handle SIGTERM before Docker
escalates to SIGKILL. Tune upward for services that need time to drain
(databases, queue workers). Too-short timeout + `rm` = data loss for
stateful workloads; if the container is stateful, confirm volumes hold
the state (Section 1's `Mounts`) before removing it.

## 4. Start the new container

```python
ssh_docker_run(
    host="web01",
    image="ghcr.io/myorg/my-service:v2.3.0",
    name="my-service",
    detach=True,
    restart_policy="unless-stopped",
    ports={"8080/tcp": 8080},
    volumes={"/opt/my-service/data": "/data"},
    env={"DATABASE_URL": "...", ...},
    networks=["frontend"],
)
```

Every argument here comes from Section 1. A common bug: forgetting to
reattach a user-defined network, so the new container comes up on
bridge and can't reach its peers. Verify `NetworkSettings.Networks` in
Section 5's inspect.

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
ssh_docker_stop(host="web01", container="my-service", timeout=30)
ssh_docker_rm(host="web01", container="my-service")
ssh_docker_run(
    host="web01",
    image="ghcr.io/myorg/my-service:v2.2.9",  # previous tag from Section 1
    name="my-service",
    # ...same args as Section 4...
)
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
  `ALLOW_DANGEROUS_TOOLS` (`docker_rm`, `docker_run`).
- Section 6 has the same tier requirements as 3+4.
- This runbook does **not** manage secrets. If Section 1 surfaces env
  vars that are secrets, re-pass them via `env=` in Section 4 without
  logging them. If the LLM can't re-supply a secret it was shown in
  inspect output, escalate -- don't guess.
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
