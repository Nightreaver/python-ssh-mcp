---
description: Capture a structured point-in-time inventory of a host (packages, systemd, network, storage, docker) for later diff or rollback reference
---

# SSH Host Snapshot

A reproducible "this is what the host looked like at time T" capture.
The artifact is a directory of plain-text/JSON files plus a bundled
tar.gz + sha256, written either on the target host or pulled off-box.

The point is not the snapshot itself -- it is the **diff against the
next one**. A snapshot you never compare to anything is wasted I/O.
Take one whenever a future-you might ask "what changed since then?":

- Before an OS upgrade (`do-release-upgrade`, distro hop).
- Before a major Docker / compose stack rewrite.
- After an incident, to freeze the surviving state for forensics.
- On a quarterly cadence as a baseline for drift detection.
- Before handing a box off to another operator.

Not in scope: file-content backup (that's bareos / restic), security
drift on pinned binaries (that's
[ssh-integrity-audit](../ssh-integrity-audit/SKILL.md)), live metrics
(that's [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md)).

## Default-on cheatsheet rejection (since v1.9.0)

`ssh_exec_run` refuses commands that have a native MCP tool -- see
`skills/ssh-exec-run/SKILL.md`. The native-tool flow below avoids
that. Composite scripts (where the script IS the artefact) opt out
via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` at the operator level.

Section 2a's exec-tier capture script IS such a composite artefact:
the umask+mkdir+dpkg+systemctl+tar+sha256 sequence MUST run
atomically under a single audit correlation id to be a meaningful
point-in-time snapshot. Running it as N separate native-tool calls
would produce a snapshot smeared across N audit records and would
race against host state. The composite is intentional; the opt-out
env var is the gate.

## Sequence

1. Decide label + destination
2. Capture the inventory
3. Bundle + checksum
4. Pull off-box + verify hash
5. Diff (later, when a question arises)

Steps 1-4 are one workflow -- a snapshot that stays only on the host
it was taken from is half-done. The on-host copy can be lost to the
same event the snapshot was meant to survive (disk failure, the
upgrade that breaks the box, the incident under investigation).
Always finish through step 4.

## 1. Decide label + destination

A snapshot needs a stable name so two captures of the same host are
comparable. Convention:

```text
/root/snapshots/<host>-<label>-<UTC-timestamp>/
                                ^ YYYYMMDD-HHMMSS
```

`<label>` is free-form but short and meaningful: `baseline`,
`pre-jammy-to-noble`, `pre-compose-rewrite`, `post-incident-2026-05-22`.
Don't bake the trigger reason into the label too tightly -- "snapshot
before the thing" is the same artifact regardless of which "thing"
came next.

Default storage path on the target is `/root/snapshots/`. That copy is
the *working set* -- it survives reboots and is what you compare
against on the same host. The **canonical copy lives off-box**: every
snapshot run ends with Section 4 pulling the bundle + sha256 to the
operator side. The on-host copy stays around for convenience until
retention rotates it.

## 2. Capture the inventory

There is no single MCP tool that "produces a snapshot". Two paths:

### 2a. Exec-tier path (preferred, comprehensive)

One scripted `ssh_exec_run` writes every artifact into the snapshot
directory. Requires the target to allow `ssh_exec_run` in its policy
tier AND `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` on the server --
the script triggers multiple cheatsheet patterns (heredoc for
`SECRETS_WARNING.txt`, `mkdir`, `dpkg`/`systemctl`/`tar`
redirections) but is the versioned snapshot artefact and must run
atomically under one audit record. Skeleton -- adapt the package /
service manager calls to the target distro:

```python
ssh_exec_run(host="iruelg4", timeout=300, command="""
umask 077  # artifacts contain secrets; mode 0600 from creation
SNAP=/root/snapshots/$(hostname -s)-baseline-$(date -u +%Y%m%d-%H%M%S)-SECRETS
mkdir -p "$SNAP" && cd "$SNAP" || exit 1

# Marker the operator cannot miss
cat > SECRETS_WARNING.txt <<'EOF'
This snapshot contains sensitive credentials including but not limited to:
  - /etc/shadow (password hashes -- offline-crackable)
  - /etc/ssh/ssh_host_*_key (plaintext SSH host private keys)
  - /etc/ssl/private/*, /etc/letsencrypt/{archive,keys,live}/ (plaintext TLS keys)
  - app-specific keys under /etc (bareos, fail2ban, wireguard, ...)

Treat this archive like a credential file:
  - keep mode 0600 / dir 0700 throughout its lifecycle
  - do NOT commit to git, paste into chat, upload to pastebins, share via Slack
  - off-box copies belong in a vault (1Password, age/gpg-encrypted, hardware token)
  - delete from operator workstations once the diff / restore is done
EOF

# 00. Identity
{ echo "Host: $(hostname -f)"; date -u --iso-8601=seconds; } > 00-README.txt
uname -a > 01-uname.txt
cp /etc/os-release 02-os-release
uptime > 03-uptime.txt

# 10. Packages (Debian/Ubuntu)
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\t${Status}\n' | sort > 10-packages-all.tsv
apt-mark showmanual | sort > 11-packages-manual.txt
apt-mark showhold   | sort > 12-packages-hold.txt
apt-mark showauto   | sort > 13-packages-auto.txt
dpkg-query -W -f='${binary:Package}\t${Status}\n' | grep -v 'install ok installed' > 15-packages-issues.txt
dpkg --verify 2>/dev/null > 16-dpkg-verify.txt

# 20. Systemd
systemctl list-unit-files --state=enabled --no-pager > 20-systemd-enabled.txt
systemctl list-unit-files --state=masked  --no-pager > 21-systemd-masked.txt
systemctl list-units --type=service --state=running --no-pager > 22-systemd-running.txt
systemctl --failed --no-pager > 23-systemd-failed.txt

# 30. Network (also in 80-etc.tar.gz; kept top-level for quick diffing)
ip -j addr show > 30-ip-addr.json
ip route show    > 31-ip-route.txt

# 40. Storage
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL,UUID > 40-lsblk.txt
df -hT > 41-df.txt
cat /proc/mounts > 43-proc-mounts.txt

# 50. Users / cron (passwd only -- shadow comes in via 80-etc.tar.gz)
getent passwd > 50-passwd.txt
getent group  > 51-group.txt
crontab -l > 52-root-crontab.txt 2>/dev/null

# 70. Docker (skip block if not installed)
if command -v docker >/dev/null; then
  docker --version > 70-docker-version.txt 2>&1
  docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > 71-docker-ps.txt
  docker images --format 'table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}' > 72-docker-images.txt
  docker volume ls  > 73-docker-volumes.txt
  docker network ls > 74-docker-networks.txt
fi

# 80. Full /etc -- tar preserves owner/mode by default so the archive
#    reflects original sensitivity (e.g. shadow stays root:shadow 0640).
tar -czf 80-etc.tar.gz /etc 2>/dev/null

ls -lR "$SNAP" > 99-manifest.txt
echo "SNAP_DIR=$SNAP"
""")
```

Cherry-picked top-level copies of `/etc/fstab`, `/etc/hosts`, etc. were
removed -- they're now redundant with `80-etc.tar.gz`. If you want them
back for ergonomic diffing without un-taring, add them after the
`tar /etc` line as `cp /etc/fstab 42-fstab` etc.; they're just
convenience duplicates.

### 2b. Read-tier path (fallback)

Without `ssh_exec_run`, you can still capture a thinner snapshot using
the native MCP tools. The artifact lives operator-side (the local
session) rather than on the host:

```python
ssh_host_info(host="iruelg4")          # identity, kernel, uptime, CPU
ssh_host_disk_usage(host="iruelg4")    # df entries
ssh_host_network(host="iruelg4")       # ip addr
ssh_host_processes(host="iruelg4")     # top processes (volatile)
ssh_apt_list(host="iruelg4")           # installed packages
ssh_systemctl_list_units(host="iruelg4", pattern="*")
```

Save each result as JSON next to a `MANIFEST.json` documenting which
tools were used. This path misses: APT sources, dpkg --verify, fstab,
cron files, Docker inventory, **and all of `/etc`** -- so no private
keys, no shadow file, no app secrets.

That cuts both ways:

- The artifact is shareable (no secrets) -- safe to attach to a ticket
  or commit to an audit repo.
- The artifact is incomplete for restore -- a host you "snapshotted"
  this way still needs its real keys from another source if you have
  to rebuild it.

Acceptable for "I want a record of state I can share", inadequate for
"I'm preparing for an OS upgrade or might need to rebuild this host".

### What the snapshot contains (and how to handle it)

The snapshot is **complete on purpose** -- it includes `/etc` wholesale
via `80-etc.tar.gz`, which means it carries:

- `/etc/shadow`, `/etc/gshadow` (password hashes)
- `/etc/ssh/ssh_host_*_key` (SSH host private keys)
- `/etc/ssl/private/`, Letsencrypt private keys
- App-specific keys (bareos PKI, fail2ban API keys, wireguard configs,
  ...)

An /etc snapshot without these is useless for restore: you'd diff
sshd_config but lose the host identity, capture bareos-fd.d/ but lose
the key needed to decrypt the volumes. Operationally that's worse than
not snapshotting at all -- it gives false confidence in recoverability.

**The trade-off is moved from "exclude secrets" to "handle the bundle
as a secret"**:

- Bundle name carries the `-SECRETS` suffix so the operator can't
  confuse it with a sanitized artifact.
- `SECRETS_WARNING.txt` lives inside the snapshot directory with the
  same handling rules.
- File mode is 0600 on creation (script `umask 077`).
- Off-box copies belong in a vault (1Password, age/GPG-encrypted, or
  hardware-backed). **Not** in git, **not** in a shared Drive, **not**
  pasted into chat.
- After the diff / restore is done, delete operator-side copies. The
  on-host copy can stay under `/root/snapshots/` (it's already
  root-only) until retention rotates it.

What the snapshot still does NOT contain:

- File contents of databases, app data, logs. Not a backup tool --
  that's bareos / restic.
- Anything from `/proc/<pid>/` or `/proc/kcore`. Volatile and/or huge.
- **`/boot/grub/grub.cfg`** and `/boot/grub/i386-pc/*` (grub modules).
  The snapshot captures `/etc/default/grub` and `/etc/grub.d/*` (the
  *inputs* to `update-grub`), but not the generated config or the
  grub binaries. Trade-off: those are regeneratable from the inputs
  via `update-grub`, and pinning them across a kernel upgrade would
  produce stale entries on every snapshot cycle. If you need them as
  a rollback reference for a specific change, see "Optional add-ons"
  below.
- **The MBR boot code** (stage 1 + stage 1.5 in the MBR gap). Not
  filesystem-resident -- lives in the first ~1 MiB of each boot
  disk. Capture via `dd` when relevant; see "Optional add-ons".

### Optional add-ons

The default capture is enough for "what changed in the OS" diffs.
Specific scenarios benefit from extra captures bolted on to the
script in Section 2a:

**Bootloader state** -- before any `grub-install` /
`dpkg-reconfigure grub-pc` / kernel package upgrade where you might
need to recover from a botched MBR write. The relevant runbook is
[ssh-os-upgrade](../ssh-os-upgrade/SKILL.md) Section 6 ("Continue
without installing GRUB?" trap).

```bash
# Add into the Section 2a script before the bundling step
tar -czf 81-boot-grub.tar.gz /boot/grub 2>/dev/null
dd if=/dev/sda bs=512 count=2048 of=81-sda-mbr-gap.bin status=none
dd if=/dev/sdb bs=512 count=2048 of=81-sdb-mbr-gap.bin status=none
# 1 MiB per disk covers MBR + MBR gap + start of partition table;
# rollback via `dd if=81-<disk>-mbr-gap.bin of=/dev/<disk> bs=512
# count=2048 conv=notrunc` from Hetzner rescue.
```

Adjust the device list for non-standard layouts (single-disk hosts,
software-RAID with more than two members, NVMe with different
device names). On EFI systems the MBR `dd` is pointless -- snapshot
`/boot/efi/EFI/` instead, it's a normal FAT filesystem.

**Live process / open-file inventory** -- before a planned daemon
restart you want to compare against:

```bash
ps auxfww > 95-ps.txt
ss -tlnp > 96-listen-tcp.txt   # ports + owning processes
ss -ulnp > 97-listen-udp.txt
```

These are volatile by definition; only useful if you're snapshotting
*right before* the change and *right after*.

## 3. Bundle + checksum

Compress for transport and pin a hash so the operator can detect
tampering or transfer corruption. Lock down the artifacts on creation:

```bash
cd /root/snapshots
tar czf "<dir>-SECRETS.tar.gz" "<dir>-SECRETS"
sha256sum "<dir>-SECRETS.tar.gz" > "<dir>-SECRETS.tar.gz.sha256"
chmod 0600 "<dir>-SECRETS.tar.gz" "<dir>-SECRETS.tar.gz.sha256"

# Loud banner so the operator can't miss what they're holding
cat <<EOF

================================================================
  SNAPSHOT CONTAINS SECRETS
  Bundle: /root/snapshots/<dir>-SECRETS.tar.gz
  Treat as a credential file: mode 0600, no git, no pastebins, no chat.
  See SECRETS_WARNING.txt inside the bundle for handling rules.
================================================================
EOF
```

Size will typically be a few MB to low tens of MB -- mostly the
`80-etc.tar.gz` content plus the package list. If it's hundreds of
MB, the host has unusually large `/etc` directories (often: certbot
archives, fail2ban databases dropped under `/etc` by mistake) -- worth
investigating regardless.

## 4. Pull off-box + verify hash

**This step is part of the snapshot run, not optional.** Always pull
both the `.tar.gz` and the `.tar.gz.sha256` to the operator side, then
verify locally before considering the snapshot "done".

`ssh_sftp_download` supports two delivery modes. For large snapshot
bundles, the `local_path` mode is strongly preferred -- it streams
directly to disk without encoding the bytes as base64 in the tool
response.

### Small files (.sha256, anything under ~500 KB)

```python
result = ssh_sftp_download(host="iruelg4",
    path="/root/snapshots/<dir>-SECRETS.tar.gz.sha256")
# result["content_base64"] -> base64-decode -> write to local file
```

### Large bundles (tar.gz) -- preferred path with `local_path`

If the operator has configured `SSH_LOCAL_TRANSFER_ROOTS` to include
a local staging directory (e.g. `SSH_LOCAL_TRANSFER_ROOTS=/srv/snapshots`),
stream directly to disk -- no base64, no token overhead, works up to 2 GiB:

```python
result = ssh_sftp_download(
    host="iruelg4",
    path="/root/snapshots/<dir>-SECRETS.tar.gz",
    local_path="/srv/snapshots/<dir>-SECRETS.tar.gz",
)
# result["local_path_written"] confirms the canonical destination path
```

### Large bundles without `local_path` configured

Without `SSH_LOCAL_TRANSFER_ROOTS`, the full base64 response may exceed
the LLM tool-result token cap. The harness auto-saves the raw JSON
response to a tool-results file on the operator machine:

```bash
# Find the saved response (path appears in the size-cap error message)
RESP="<path-from-error-message>.txt"

# Extract content_base64, decode, write to snapshots/
python -c "import json,base64; d=json.load(open(r'$RESP')); \
  open('snapshots/<dir>-SECRETS.tar.gz','wb').write(base64.b64decode(d['content_base64']))"
```

`jq -r .content_base64 "$RESP" | base64 -d > <out>` also works where
`jq` is available; on Windows/PowerShell-only environments fall back
to the python one-liner.

### Verify

Verify the hash locally -- if this fails, the transfer was corrupted
or the bundle was modified between bundle creation and download. The
snapshot is not trustworthy; re-pull or re-create:

```bash
cd snapshots && sha256sum -c <dir>-SECRETS.tar.gz.sha256
# expected output: <dir>-SECRETS.tar.gz: OK
```

Confirm the local file landed under a path covered by `.gitignore`
(or outside the repo entirely) before doing anything else.

Why this is mandatory:

- The on-host copy can be lost to the very event the snapshot was
  meant to survive (disk failure, the upgrade itself, the incident
  under investigation).
- For incidents and audit cases the off-box copy **is** the
  immutable record -- the on-host copy can be modified by whatever
  caused the incident.
- A snapshot that exists only on one disk is one disk failure away
  from being no snapshot at all.

Since the bundle contains sensitive credentials (private keys,
password hashes):

- Land the file under a path your shell / editor / git knows to leave
  alone (a `.gitignored` directory, or outside the repo entirely).
- For longer-term retention, re-encrypt with `age` or `gpg` and only
  keep the encrypted copy; delete the plaintext bundle.
  Example: `age -r <recipient> -o <dir>.tar.gz.age <dir>-SECRETS.tar.gz`
  then `shred -u <dir>-SECRETS.tar.gz`.
- Never attach the raw bundle to a ticket / chat / email. If a
  colleague needs to look at it, share the encrypted form and the
  recipient key out-of-band.

## 5. Diff against a future snapshot

The whole point. When the next change is done, take another snapshot
with the same label scheme and diff the directories.

For diffs against `/etc/...` files you first need to extract the
per-snapshot `80-etc.tar.gz` -- once for `pre`, once for `post`:

```bash
mkdir -p pre/etc post/etc
tar -xzf pre/80-etc.tar.gz  -C pre/etc  --strip-components=1
tar -xzf post/80-etc.tar.gz -C post/etc --strip-components=1
```

Useful diffs:

```bash
# Package set change (what got installed/removed/upgraded)
diff <(cut -f1,2 pre/10-packages-all.tsv) \
     <(cut -f1,2 post/10-packages-all.tsv)

# Systemd unit state changes
diff pre/20-systemd-enabled.txt post/20-systemd-enabled.txt

# Modified conffiles since baseline (dpkg's own audit)
diff pre/16-dpkg-verify.txt post/16-dpkg-verify.txt

# Repo source changes (after extracting /etc above)
diff -ru pre/etc/apt/sources.list.d/ post/etc/apt/sources.list.d/

# Any /etc change (broad strokes)
diff -ruN pre/etc/ post/etc/ | less
```

If a question can't be answered from these diffs, the snapshot was
missing something -- add the missing capture to Section 2 and re-take
the baseline.

## Boundaries

- The exec-tier path requires `ssh_exec_run` to be permitted by the
  host's policy. The script is one composite invocation; if the policy
  blocks any of the inner commands (`dpkg-query`, `systemctl`, ...)
  the corresponding file will be empty rather than the run failing.
- POSIX / Debian-flavored by default. Adapt the `dpkg`/`apt-mark`
  block to `rpm -qa` / `dnf repolist` on RHEL-family, or `pkg info` on
  FreeBSD. Windows targets are out of scope -- need a PowerShell
  equivalent runbook.
- Snapshot files are owned by whichever user `ssh_exec_run` runs as
  (typically root) and created under `umask 077` so they start at mode
  0600. Keep it that way -- the bundle contains sensitive credentials (see
  Section 2 "What the snapshot contains"). The `-SECRETS` filename
  suffix and `SECRETS_WARNING.txt` inside the bundle are reminders,
  not enforcement; the operator is the enforcement.
- Retention is the operator's call. Keep at least the last two
  snapshots per host so a diff is always possible; age out the rest to
  off-box archival or delete.

## Related runbooks

- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- snapshot
  captures structure; healthcheck captures live state. Take both
  before a risky change.
- [ssh-integrity-audit](../ssh-integrity-audit/SKILL.md) -- security
  drift on pinned binaries / configs. Complementary, not a replacement.
- [ssh-incident-response](../ssh-incident-response/SKILL.md) -- if
  you're taking a snapshot **because** something is wrong, that
  runbook is the parent flow; this one is the artifact step inside it.
