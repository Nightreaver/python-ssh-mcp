---
description: Confirm a host's identity, file integrity, artifact signatures, and surface SUID / world-writable oddities
---

# SSH Integrity Audit

A read-only audit pass you can run against a host to confirm:

- The host is the one you think it is (key pinning intact).
- Pinned binaries / configs haven't drifted from expected hashes.
- Release artifacts on disk match their signatures.
- No surprising SUID / world-writable files appeared since last audit.

Not a full security hardening review -- that belongs with a dedicated
security tool (lynis, oscap, etc.). This is the "did something change
since I last looked?" pass that the LLM can run on a schedule without
escalated privileges.

## Sequence

1. Identity pinning
2. File-level hash drift
3. Signature verification of deployed artifacts
4. SUID / world-writable surface scan

## 1. Identity pinning

```python
ssh_known_hosts_verify(host="web01")
```

`matches_known_hosts=true` is the only acceptable outcome. Anything
else -- mismatched fingerprint, unknown host, or tool error -- is a
security event. **Stop the audit** and escalate; every subsequent step
in this runbook depends on the channel being trusted, and a key
mismatch means it isn't.

Do not call `ssh_host_ping` as a substitute -- it confirms TCP reach
and auth works, not that the key matches a pin.

## 2. File-level hash drift

You need a **local, out-of-band** list of `(path, expected_sha256)`
pairs for this step -- the release manifest, an infra-as-code bundle,
a ops-side inventory. If the expected hash comes from the same box
you're auditing, you're verifying the box against itself; an attacker
with write access wins that comparison every time.

For each pinned path:

```python
ssh_file_hash(host="web01", path="/usr/local/bin/my-agent",
              algorithm="sha256")
```

Compare `.digest` to your out-of-band expected value. Use `sha256` or
`sha512`; `md5` and `sha1` have practical collision attacks and are
wrong for this use case (the attacker model is "could substitute
content with a matching digest").

Paths worth pinning:

- Self-managed binaries under `/usr/local/bin`, `/opt/<app>/bin`.
- Service configs where drift is a security signal: `/etc/ssh/sshd_config`,
  `/etc/sudoers` (if readable), `/etc/nginx/nginx.conf`, cron files.
- Key material the app uses (public keys only; private keys shouldn't
  be readable by the audit user).

Do NOT hash `/etc/passwd`, `/etc/shadow`, or any file whose content is
legitimately user-mutable -- drift is expected, so the signal is
meaningless.

## 3. Signature verification of deployed artifacts

For release artifacts on the host (tarballs, blobs, images pulled from
a registry), hash-match is integrity; signature-match is provenance.
You want both.

Hand off to
[ssh-verify-signature](../ssh-verify-signature/SKILL.md) for the
actual verify call per artifact. That runbook covers GPG / cosign /
minisign and the pubkey distribution rules; don't re-derive them here.

Boundary reminder: signature verification requires the pubkey to have
arrived on the host through a channel **the LLM did not control**. If
this audit turn is also the first turn that pushed the pubkey, the
verify step is theatre.

## 4. Surface scan: SUID and world-writable files

Novel SUID binaries outside the OS package set are a classic privilege
escalation primitive. World-writable files in system directories are
frequently a deploy script's mistake but occasionally persistence.

```python
# SUID files across the system
ssh_find(host="web01", path="/", name_pattern="*", kind="f",
         max_depth=6)
```

`ssh_find` can't filter by permission bits natively -- the `-name`
argument is fixed-argv for safety. If exec tier is available, the
right call is:

```python
ssh_exec_run(host="web01",
             command="find / -xdev -perm -4000 -type f",
             timeout=60)
```

Requires `find` in the host's `command_allowlist`. Without exec tier,
the LLM-only approximation is to `ssh_find` specific high-risk
directories (`/usr/bin`, `/usr/local/bin`, `/tmp`) and `ssh_sftp_stat`
each result to read `.mode`, then filter client-side. Noisier and
slower but stays read-only.

Compare the result to a **previous snapshot** stored operator-side.
New entries are the signal; a system with 40 SUID binaries is normal,
a system with 41 is the question. Without a previous snapshot, capture
this run as the baseline and flag that future runs should compare.

Same pattern for world-writable:

```python
ssh_exec_run(host="web01",
             command="find / -xdev -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*'",
             timeout=60)
```

## 5. Report

Output should read as: **identity ok | drift: N files | signature: ok | SUID delta: +M / -K**.

Escalate to a human if **any** of:

- Section 1 mismatch (always).
- Section 2 drift on a pinned path, especially `sshd_config`, `sudoers`,
  or anything under `/etc/cron*`.
- Section 3 signature failure on a release artifact.
- Section 4 SUID delta against the baseline is non-zero and unexplained.

Do NOT attempt to "fix" drift from this runbook -- the drift might be a
legitimate operator change the LLM doesn't know about, and overwriting
it is its own security event.

## Boundaries

- Everything here is `read`-tier except the optional `ssh_exec_run`
  calls in Section 4; those need `ALLOW_DANGEROUS_TOOLS` + allowlisted
  `find`.
- `ssh_file_hash` is POSIX-only today (Windows targets raise
  `PlatformNotSupported`). Windows hosts need a separate PowerShell-
  aware path.
- Expected hashes and the previous SUID snapshot must live **outside**
  the audited host. Storing them on the same host makes this audit
  self-verifying and therefore useless.
- This runbook does not rotate keys, patch packages, or change permissions.
  Those are separate operator-driven workflows with their own escalations.

## Related runbooks

- [ssh-verify-signature](../ssh-verify-signature/SKILL.md) -- Section 3
  driver.
- [ssh-deploy-verify](../ssh-deploy-verify/SKILL.md) -- catches integrity
  failures at deploy time; this runbook catches drift between deploys.
- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- pair on a
  schedule: healthcheck catches operational breakage, this runbook
  catches security drift.
