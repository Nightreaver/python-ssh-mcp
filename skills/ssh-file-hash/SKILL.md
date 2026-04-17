---
description: Compute MD5 / SHA1 / SHA256 / SHA512 of a remote file for integrity verification
---

# `ssh_file_hash`

**Tier:** read-only | **Group:** `sftp-read` | **Tags:** `{safe, read, group:sftp-read}`

Computes a cryptographic hash of a remote file and returns the digest as
lowercase hex plus the file's byte size. Primary use case: verify a file
landed intact after a transfer (`ssh_upload`, `ssh_deploy`, `ssh_docker_cp`)
by comparing the returned digest to one you computed locally. Secondary use:
confirm a pinned binary or config hasn't drifted between deploys.

**POSIX targets only** right now. Runs `<algo>sum -- <path>`. Path is
canonicalized + allowlist-checked like every other sftp-read tool.
Windows targets raise `PlatformNotSupported` -- our `shlex.join` argv
assembly is POSIX-shell-only, and Windows OpenSSH's default shell
(cmd.exe) / PowerShell host parses single-quote escapes differently. A
future Windows implementation would need PowerShell's
`-EncodedCommand <base64-UTF16LE>` plus a Windows-aware argv serializer;
see [INCIDENTS.md](../../INCIDENTS.md) INC-028 for the open item.

## Inputs

| name | type | required | default | notes |
|---|---|---|---|---|
| `host` | str | yes | -- | Alias |
| `path` | str | yes | -- | Remote file path; canonicalized + allowlisted |
| `algorithm` | `"md5"` \| `"sha1"` \| `"sha256"` \| `"sha512"` | no | `"sha256"` | See Security notes below |
| `timeout` | int | no | `SSH_COMMAND_TIMEOUT` (60s) | Per-call timeout in seconds. Bump for files > a few GB. |

## Returns

```json
{
  "host": "web01.example.com",
  "path": "/opt/app/config.json",
  "algorithm": "sha256",
  "digest": "a1b2c3d4e5f6...",
  "size": 1234
}
```

`digest` is lowercase hex, no `algo:` prefix. `size` is the file size in
bytes (from SFTP stat), or `-1` if the stat failed.

## When to call it

- After `ssh_upload` / `ssh_deploy`: compute the local hash in your workflow,
  call `ssh_file_hash` on the remote, assert the two match. Catches silent
  TCP-level corruption, truncated transfers, and upload races.
- After `ssh_docker_cp from_container`: verify the file you pulled out has
  the expected hash before trusting it.
- Drift detection: store expected hashes of pinned binaries / configs and
  periodically compare.

## When NOT to call it

- Massive trees -- this is a per-file tool. For a whole tree, tar-then-hash
  via `ssh_exec_run` (with an allowlisted `tar | sha256sum` pipeline) or use
  a purpose-built deploy tool.
- Security-sensitive identity checks with `md5` or `sha1` -- both are broken
  for collision resistance. Use `sha256` or `sha512`.
- Files > a few GiB without bumping `timeout` -- `SSH_COMMAND_TIMEOUT`
  default is 60s. Hashing streams the file in fixed-size blocks so memory
  is constant, but wall time scales linearly with file size. Pass an
  explicit `timeout=600` (seconds) for big artifacts rather than waiting
  for a protocol-level timeout.

## Example

```python
# Manual verify-after-upload two-step flow.
import hashlib
local_digest = hashlib.sha256(open("config.json", "rb").read()).hexdigest()

ssh_upload(host="web01", path="/opt/app/config.json",
           content_base64=base64.b64encode(local_bytes).decode())

result = ssh_file_hash(host="web01", path="/opt/app/config.json")
assert result["digest"] == local_digest, (
    f"mismatch: local {local_digest}, remote {result['digest']}"
)
```

```python
# Drift detection example.
ssh_file_hash(host="web01", path="/usr/local/bin/my-agent", algorithm="sha256")
# -> compare against your pinned hash from the release pipeline
```

## Common failures

- `PathNotAllowed` -- target is outside `path_allowlist` on this host.
- `PathRestricted` -- inside a `restricted_paths` zone.
- `HashError: sha256sum exited 1 ...` -- file missing or permission-denied
  on the remote. Check with `ssh_sftp_stat` first.
- `HashError: remote hash command returned unparseable digest` -- the
  remote output didn't match `[0-9a-f]+`. Unexpected locale, binary tools
  renamed, BusyBox variant without the expected output format, etc.
- `ValueError: algorithm must be one of ...` -- unsupported algorithm name.

## Security notes

- For the common case (verify a transfer landed intact, detect config
  drift) ANY of the four algorithms is fine -- you're comparing a digest
  to one you computed yourself moments earlier, no adversary involved.
- `md5` and `sha1` have **practical collision attacks**. Use `sha256` or
  `sha512` when the expected hash comes from an attacker-reachable source
  (someone else's release manifest, a checksum file downloaded from the
  web, a third-party registry). A same-prefix collision lets an attacker
  substitute content with matching digest.
- A digest alone verifies **integrity**, not **authenticity** -- it
  confirms the remote file matches an expected value, nothing more. If
  the expected value and the artifact both came through the same channel
  an attacker controls, verification is theatre. The correct boundary is:
  - **Supply-chain integrity** belongs in your CI/CD pipeline BEFORE the
    artifact reaches the SSH target. ssh-mcp does not verify signatures.
  - **Second-line checks on the deployed artifact** (signature verify
    against a separately-distributed pubkey) are operator-composed via
    `ssh_exec_run` + a command-allowlist entry for `gpg` / `cosign` /
    `minisign`. See [`runbooks/ssh-verify-signature/SKILL.md`](../../runbooks/ssh-verify-signature/SKILL.md)
    for the runbook.

## Related

- [`ssh_upload`](../ssh-upload/SKILL.md) -- what you typically hash after
- [`ssh_deploy`](../ssh-deploy/SKILL.md) -- upload with backup
- [`ssh_docker_cp`](../ssh-docker-cp/SKILL.md) -- container bidirectional copy
- [`ssh_sftp_stat`](../ssh-sftp-stat/SKILL.md) -- just the size + metadata, no hash
