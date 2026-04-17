---
description: Upload an artifact, verify the remote hash, bring the stack up, and tail logs to confirm health
---

# SSH Deploy + Verify

Workflow runbook for "push this file/config to a host and confirm the
service actually came up healthy". Closes the gap between `ssh_upload`
landing bytes and a user seeing a working service. Uses `read` +
`low-access` + `dangerous` tiers; explicit markers on each step.

## Sequence

1. Precheck host capacity (read)
2. Compute local hash, then upload with backup (dangerous: file write)
3. Verify remote hash matches local (read)
4. Bring compose stack up or restart service (dangerous)
5. Tail logs + inspect state (read)
6. Roll back on failure (low-access + dangerous)

## 1. Precheck

Before writing anything, confirm the target is actually in a state to
accept a deploy. In parallel:

- `ssh_known_hosts_verify(host=...)` -- identity check. A failure here is
  a security event, not a deploy failure. Stop.
- `ssh_host_alerts(host=...)` -- if the host is already in breach (disk
  full, load spiking), deploying on top of it will likely make it worse.
  Resolve the alert first, or explicitly acknowledge.
- `ssh_host_disk_usage(host=...)` -- confirm the partition holding the
  deploy target has enough headroom for the new file **and** its `.bak-<ts>`
  sibling.

## 2. Upload with backup

Compute the local hash **before** the upload, so the comparison in step 3
is against a value the remote can't tamper with:

```python
import base64, hashlib
blob = open("config.json", "rb").read()
local_digest = hashlib.sha256(blob).hexdigest()

ssh_deploy(
    host="web01",
    path="/opt/app/config.json",
    content_base64=base64.b64encode(blob).decode("ascii"),
    mode=0o644,
    backup=True,  # leaves <path>.bak-<UTC-iso8601> for rollback
)
```

Prefer `ssh_deploy` over `ssh_upload` for anything that has a currently-in-use
version on the target. The `.bak-<ts>` sibling is your rollback lever in
Section 6; losing it means a forward-only deploy with no undo.

## 3. Verify remote hash

```python
result = ssh_file_hash(host="web01", path="/opt/app/config.json",
                       algorithm="sha256")
assert result["digest"] == local_digest, (
    f"mismatch: local {local_digest}, remote {result['digest']}"
)
```

Mismatch means silent TCP corruption, a truncated transfer, or concurrent
writes from another operator. **Do not proceed to step 4** -- roll back
(Section 6) and investigate. For binaries / release artifacts with a
pinned manifest hash, compare against the manifest, not a hash you just
computed locally -- otherwise you're verifying your own copy against
itself.

If the deploy is a release artifact (not a config file), chain into
[`ssh-verify-signature`](../ssh-verify-signature/SKILL.md) between steps
3 and 4. Hash-match confirms integrity; signature verify confirms
provenance. Both matter for anything an attacker could have swapped
upstream.

## 4. Activate

For compose-managed services:

```python
ssh_docker_compose_up(
    host="web01",
    compose_file="/opt/app/docker-compose.yml",
    detached=True,
    build=False,  # repin the image tag instead of rebuilding in prod
)
```

For a systemd-style service (requires exec tier + allowlisted
`systemctl`):

```python
ssh_exec_run(host="web01", command="systemctl reload nginx", timeout=15)
```

Prefer **reload** over **restart** when the service supports it -- reload
re-reads config without dropping in-flight connections. Restart breaks
long-lived clients.

## 5. Tail logs + confirm healthy

Give the service a few seconds to start, then pull logs + state in
parallel:

```python
ssh_docker_compose_ps(host="web01",
                      compose_file="/opt/app/docker-compose.yml")
ssh_docker_compose_logs(host="web01",
                        compose_file="/opt/app/docker-compose.yml",
                        tail=200)
```

What you're reading for:

- `compose_ps` -- every expected service is `running` (not `exit 1`, not
  `restarting`). A service flipping between `running` and `restarting` is
  in a crash loop; log tail will tell you why.
- `compose_logs` -- no fresh tracebacks or `error` / `panic` lines dated
  after your upload timestamp. Pre-existing warnings are noise unless
  they changed.
- For a single-container rollout, `ssh_docker_inspect(kind="container")`
  `State.Health.Status` is the canonical health signal; prefer it to
  grepping logs when the image has a healthcheck.

If the service uses `depends_on: condition: service_healthy`, the
first `compose_ps` after `compose_up` may still show dependents in
`starting`. Re-poll after 10-20s before declaring failure.

## 6. Roll back on failure

`ssh_deploy` left a `.bak-<UTC-iso8601>` sibling (result key
`backup_path`). Swap it back into place and re-activate:

```python
ssh_mv(host="web01",
       source="/opt/app/config.json.bak-20260415T031500Z",
       destination="/opt/app/config.json",
       overwrite=True)
ssh_docker_compose_restart(host="web01",
                           compose_file="/opt/app/docker-compose.yml")
```

Then re-run Section 5 to confirm the rollback actually restored a healthy
state -- a bad backup is worse than no backup.

## Boundaries

- Section 1 + 3 + 5 are read-only.
- Section 2 requires `ALLOW_DANGEROUS_TOOLS=true` (`ssh_deploy` is
  dangerous tier because it writes files).
- Section 4 + 6 require `ALLOW_LOW_ACCESS_TOOLS` (restart) or
  `ALLOW_DANGEROUS_TOOLS` (`compose_up`, `ssh_mv`, `ssh_exec_run`).
- Multi-host rollouts are out of scope. Deploy to one host, verify, then
  loop. Parallel deploys across a fleet without between-host
  health-gating is an outage pattern.

## Related runbooks

- [ssh-verify-signature](../ssh-verify-signature/SKILL.md) -- step
  between 3 and 4 for release artifacts.
- [ssh-docker-incident-response](../ssh-docker-incident-response/SKILL.md)
  -- if Section 5 shows the stack unhealthy and Section 6 rollback
  doesn't recover.
- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- expand
  Section 1 when deploying to a host you don't routinely monitor.
