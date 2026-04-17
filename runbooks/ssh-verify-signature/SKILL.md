---
description: Verify the signature of a remote artifact (GPG, cosign, minisign) via ssh_exec_run
---

# SSH Signature Verification

This is a **workflow runbook**, not a tool. ssh-mcp intentionally does not
ship an `ssh_file_verify_signature` tool; signature verification has too
much config-and-trust surface (keyrings, registries, transparency logs,
trust models) to hide behind a one-size-fits-all wrapper. Instead, you
compose `ssh_exec_run` with the right command-allowlist entry and the
right pubkey distribution. This runbook describes the shape.

## Responsibility boundary

If you care about supply-chain integrity, the **right place to verify is
in your CI/CD pipeline BEFORE the artifact reaches the SSH target**. Once
content lands on the box, the attacker has already won if they compromised
upload. This runbook covers the second-line check: confirm a deployed file
matches a signature you already trust.

Anti-pattern: storing the pubkey, the artifact, and the signature in the
same bucket / same git repo / same release tarball. An attacker who flipped
all three wins every verification. The pubkey must come from a separate,
out-of-band trusted channel (OS package manager, your own HSM-signed
config-management bundle, operator-side `ssh_upload` under a tightly
scoped path_allowlist).

## Prerequisites

- `ALLOW_DANGEROUS_TOOLS=true` on the server (signature verify uses
  `ssh_exec_run`).
- The right binary on the target:
  - **GPG**: `gpg` (or `gpg2`), typically pre-installed on Linux.
  - **cosign**: separate install, usually via the sigstore release.
  - **minisign**: `apt install minisign` / `brew install minisign`.
- The binary on the host's `command_allowlist` in `hosts.toml`:

  ```toml
  [hosts.deploy-target]
  command_allowlist = ["gpg", "cosign", "minisign", "systemctl"]
  ```

- The trusted pubkey material already in place on the target, distributed
  out-of-band. See the "Pubkey distribution" section below.

## 1. Pubkey distribution (do this first)

Your options, best to worst for integrity:

1. **OS package manager** -- `apt-key` (deprecated but widely deployed)
   or `/etc/apt/keyrings/<name>.gpg` for keyrings, `dnf config-manager`
   for RPM repos. The package manager signs its own repo metadata so the
   key travels through an existing trust chain.
2. **Config management** (Ansible, Chef, your own shell runbook) pushes
   the pubkey from a signed source bundle. `ssh_upload` is fine for this
   AS LONG AS the pubkey sits in a `path_allowlist`-protected location
   that only operators write to. The LLM MUST NOT be the one distributing
   the pubkey for a key it then uses to verify.
3. **Operator hand-delivers via an out-of-band channel** (KMS, 1Password
   vault, etc.). Most auditable, most annoying.

If you find yourself about to call `ssh_upload` for both `artifact.tar.gz`
AND `pubkey.asc` in the same LLM turn -- stop. You've just created a
circular trust.

## 2. Hash first, then verify

Before the signature check, confirm the file is intact:

```python
ssh_file_hash(host="deploy-target", path="/opt/app/releases/v1.2.3.tar.gz",
              algorithm="sha256")
```

Compare the returned digest to the one in your release manifest (NOT the
one on the same target). If the hash differs, stop -- a mismatched hash
means either transfer corruption or substitution, and signature verify on
a corrupted artifact is wasted cycles.

## 3. GPG verify

```python
ssh_exec_run(
    host="deploy-target",
    command="gpg --verify /opt/app/releases/v1.2.3.tar.gz.sig "
            "/opt/app/releases/v1.2.3.tar.gz",
    timeout=30,
)
```

Read the result:

- `exit_code == 0` AND stderr contains `Good signature from "<expected
  uid>"` -> pass.
- `exit_code == 0` but uid is unexpected -> **fail**. The signature is
  valid but not from the identity you expected (different release signer,
  an attacker with a key that happens to be in the keyring).
- `exit_code != 0` -> **fail**. Log the stderr verbatim and stop.

Gotchas:

- GPG's default "trust model" will warn `WARNING: This key is not
  certified with a trusted signature!` if the pubkey is not in the
  operator's keyring's trust DB. This is fine for one-off verify, but if
  you want `exit_code != 0` on untrusted keys, use `gpg
  --trust-model=always` deliberately AND confirm the pubkey identity
  before the call.
- `gpg --verify` can print "Good signature" to stderr; don't grep stdout.

## 4. cosign verify-blob

```python
ssh_exec_run(
    host="deploy-target",
    command="cosign verify-blob "
            "--key /etc/cosign/release.pub "
            "--signature /opt/app/releases/v1.2.3.tar.gz.sig "
            "/opt/app/releases/v1.2.3.tar.gz",
    timeout=30,
)
```

- `exit_code == 0` + stderr/stdout `Verified OK` -> pass.
- Non-zero -> fail; common causes: wrong pubkey, tampered artifact, clock
  skew (cosign checks Rekor log timestamps in keyless mode).

For keyless (Fulcio/Rekor) verification the command changes -- see
`cosign verify-blob --help`. Keyless verify requires network from the
target to the sigstore infrastructure; confirm that before wiring into a
deploy path.

## 5. minisign verify

```python
ssh_exec_run(
    host="deploy-target",
    command="minisign -Vm /opt/app/releases/v1.2.3.tar.gz "
            "-p /etc/minisign/release.pub",
    timeout=10,
)
```

Expects the signature file at `<artifact>.minisig` next to the artifact.
`exit_code == 0` and stdout `Signature and comment signature verified` ->
pass.

## 6. After verification

Only after the signature verifies cleanly should the assistant proceed to
activate the new artifact -- restart service, swap symlink, `ssh_deploy`
the config, etc. Sign once, verify once, deploy once.

## Common failures

- `CommandNotAllowed` -- `gpg` / `cosign` / `minisign` is not in the
  host's `command_allowlist`. Add it (and only it) -- do not flip to
  `ALLOW_ANY_COMMAND=true` for this.
- `Good signature from "<unexpected uid>"` -- signature is mathematically
  valid but from an unexpected signer. Treat as a fail.
- GPG hangs waiting for `pinentry` -- some keys require a passphrase that
  the non-interactive `gpg` cannot prompt for. Use a subkey that doesn't
  require passphrase for verify, or export the pubkey without the private
  material.

## Boundaries

- This runbook is for **verifying an artifact already on the target**.
  Upstream supply-chain controls (CI signing, registry trust, reproducible
  builds) live outside ssh-mcp entirely.
- ssh-mcp never manages trust roots. Pubkey material, trust DBs, and CA
  bundles are operator-owned. If a verify command needs interactive input
  (passphrase prompts, trust-on-first-use dialogs), it will hang; use the
  non-interactive variants above.
- See also: [`ssh_file_hash`](../../skills/ssh-file-hash/SKILL.md) for the first
  integrity check, [`ssh_exec_run`](../../skills/ssh-exec-run/SKILL.md) for the
  allowlist + execution rules.
