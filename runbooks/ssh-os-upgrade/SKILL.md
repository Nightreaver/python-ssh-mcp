---
description: Staged procedure for a major OS version upgrade (Ubuntu LTS-to-LTS, Debian point release) on a Docker-heavy host, with mandatory tmux-wrapping of long-running package ops
---

# SSH OS Upgrade

Choreography for taking a host across a major OS boundary (e.g. Ubuntu
jammy -> noble) without ad-hoc improvisation. Read-only verification
calls are LLM-driven; package mutations and `do-release-upgrade` itself
are operator-driven inside `tmux` so they survive the inevitable
mid-upgrade SSH session loss.

Not for: minor security updates (unattended-upgrades handles those, no
choreography needed); kernel-only updates within the same release
(`apt upgrade && reboot`); container / app upgrades that don't touch
the OS.

## Default-on cheatsheet rejection (since v1.9.0)

`ssh_exec_run` refuses commands that have a native MCP tool -- see
`skills/ssh-exec-run/SKILL.md`. The native-tool flow below avoids
that. Composite scripts (where the script IS the artefact) opt out
via `SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` at the operator level.

This runbook is operator-driven: Section 6 (`do-release-upgrade`),
Sections 4 and 8 (`tmux new -d -s ... 'apt update && apt upgrade ...
| tee'`), and the Section 5 docker-stack-stop loop are all
multi-step bash scripts that the operator runs from their own SSH
session (not via `ssh_exec_run`). Where the runbook does call
native MCP tools (Section 1's snapshot via `ssh-host-snapshot`,
Section 7's `ssh_host_ping` / `ssh_host_info` / `ssh_host_alerts`,
package mutations via `ssh_apt_*`, service mutations via
`ssh_systemctl_*`), use those wrappers directly.

If you DO drive any step from the LLM via `ssh_exec_run`
(e.g. catching up the current release with `apt update && apt upgrade`
inside tmux), the wrapped command is a composite artefact -- the
tmux+apt+dpkg-options+tee bundle MUST run atomically under one
audit correlation id to behave correctly. Set
`SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true` for that opt-out, then
prefer `ssh_apt_upgrade` for non-tmux-wrapped catch-ups instead.

## Sequence

1. Pre-flight + snapshot
2. Cleanup orphans
3. Hold app packages
4. Catch up current release (apt upgrade, **tmux-wrapped**)
5. Stop service stacks (internal -> mid -> edge, edge-proxy LAST)
6. `do-release-upgrade` interactively (operator-driven, tmux)
7. Post-reboot verification
8. Remap third-party APT sources + final `apt upgrade`
9. Bring services back up (edge-proxy LAST, again)
10. Post-snapshot + diff vs pre-upgrade snapshot

## 1. Pre-flight + snapshot

- Capture via [ssh-host-snapshot](../ssh-host-snapshot/SKILL.md) with
  label `pre-<target-codename>` (e.g. `pre-noble`). Pull off-box per
  that runbook's Section 4 -- a snapshot only on the host being
  upgraded is the wrong place for it.
- Verify the host's backup system (bareos / restic / borg) is actually
  running and the most recent job completed cleanly.
- Confirm rescue-mode access at the hosting provider (Hetzner Robot,
  Hetzner Cloud console, etc.). That is the Plan B if `do-release-
  upgrade` breaks boot.
- Read `ssh_host_notes` for the host. Per-host quirks (forbidden
  packages, custom port bindings, edge-proxy dependency order) live
  there, not in this generic runbook.

**What the standard snapshot does NOT cover** -- worth knowing because
the OS upgrade can land you in territory the snapshot can't restore by
itself:

- `/boot/grub/grub.cfg` and `/boot/grub/i386-pc/*` -- the snapshot
  captures `/etc/default/grub` and `/etc/grub.d/*` (so `update-grub`
  can regenerate `grub.cfg`), but the generated config itself and the
  grub modules aren't in the tarball.
- The MBR boot code (stage 1 + stage 1.5 in the MBR gap). Not
  filesystem-resident. If grub-install corrupts it, only Hetzner
  rescue + `dd` from a backup recovers.

If you anticipate touching the bootloader (Section 6 GRUB prompts
might force this), capture these extras as a mini-snapshot **before**
the change -- see Section 6's "If you hit GRUB prompts" subsection.

## 2. Cleanup orphans

Stuff that makes the upgrade noisier than it needs to be:

- Exited compose containers from removed services: `docker ps -a
  --filter status=exited` -> `docker rm <name>` once confirmed not
  referenced in any compose file.
- dpkg `rc`-state packages (removed-but-conffiles-remain):
  `dpkg -l | awk '/^rc/ {print $2}'` -> `dpkg --purge <pkg>`. They can
  reactivate dependencies during the upgrade if anything pulls them
  back transitively.
- Failed systemd units: `systemctl --failed` -> resolve or mask before
  proceeding.

Per-host traps (e.g. "do not let apt re-pull apache2") belong in
`ssh_host_notes` -- check before purging.

## 3. Hold app packages

`do-release-upgrade` will move every package available in its target
dist's repos. If you don't want application stacks to move at the same
time, hold them now. From the LLM use the dedicated wrapper:

```python
ssh_apt_mark(host="...", action="hold",
             packages=["postgresql-14", "mariadb-server"])
```

Operator-side equivalent (run from the operator's own root shell):

```bash
apt-mark hold <package> [<package>...]
```

Worth holding:

- Database engines (postgres, mariadb, mongodb) where major-version
  bumps need separate migration work.
- Pre-release / nightly / `current`-channel packages where the
  third-party repo churns aggressively.

**Do NOT hold:** `linux-image-*`, `linux-headers-*`, `grub-*`,
`systemd*`, `udev*`, `openssh-*`, `glibc`, `libcap*`, `netplan.io`,
`networkmanager`, anything in `essential` / `required` priority. The
OS upgrade depends on these moving.

**Trap: held packages can block `do-release-upgrade` from starting.**

`update-manager-core` counts held packages from third-party repos as
"available updates" and refuses with the misleading error message
"Please install all available updates for your release before
upgrading." Holds (`hi` state) don't actually prevent that count.

The clean workaround is to temporarily disable the third-party
`*.list` file whose packages you held -- this makes the packages
disappear from `apt list --upgradable` entirely:

```bash
# Example: held bareos packages from bareos.org
mv /etc/apt/sources.list.d/bareos.list \
   /etc/apt/sources.list.d/bareos.list.disabled-pre-<codename>
apt update
apt list --upgradable | grep -v '^Listing'   # should be empty now
do-release-upgrade -c   # check passes
```

`do-release-upgrade` would rename the `.list` file to
`.list.distUpgrade` during the upgrade anyway, so pre-disabling is
just doing that step yourself. Restore it in Section 8 with the new
codename.

## 4. Catch up current release -- TMUX-WRAPPED

`do-release-upgrade` refuses to start if the current release has
pending updates. Apply them first.

**Wrap every long-running apt / dpkg call in tmux.** This rule applies
to the operator's interactive session AND to anything the LLM runs
via `ssh_exec_run`. `apt upgrade` can pull `systemd`, `udev`,
`netplan.io`, `openssh-server`, `dbus`; any of those getting restarted
mid-run will kill the SSH session that owns the apt process. With tmux
the apt continues detached; without tmux you get half-installed
packages and the next operator has to clean up after you.

```bash
tmux new -d -s aptcatchup '
  apt update && \
  DEBIAN_FRONTEND=noninteractive apt upgrade -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" 2>&1 | tee /root/aptcatchup.log
'
```

Poll with short idempotent calls instead of one giant blocking one:

```bash
tmux has-session -t aptcatchup 2>/dev/null && echo running || echo done
tail -50 /root/aptcatchup.log    # progress
```

If `tmux` isn't installed (rare on a server): `nohup setsid bash -c
'...' > /root/aptcatchup.log 2>&1 &` is the equivalent.

After it finishes, all of these should be empty:

```bash
dpkg --audit
dpkg -l | awk '$1 ~ /^(iU|iF|iH|iW)/'   # half-installed / configured
apt list --upgradable 2>/dev/null | grep -v Listing | grep -v '\[held\]'
```

**Trap: pending reboot blocks `do-release-upgrade` too.**

If the catch-up apt run installs a new kernel (very likely on a host
that's been up for months under `unattended-upgrades`), it sets
`/var/run/reboot-required`. `do-release-upgrade` refuses with the
SAME misleading error message ("Please install all available updates
for your release before upgrading") -- it does not say "reboot first",
but that's what it means.

Check and resolve before invoking `do-release-upgrade`:

```bash
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required.pkgs
uname -r                                                  # running
dpkg -l 'linux-image-[0-9]*' | awk '/^ii/ {print $2}'     # installed

# If running != latest installed: reboot into the latest installed
# kernel first. do-release-upgrade then proceeds.
reboot
```

This is the Right Time to do that reboot anyway -- it confirms the
new kernel actually boots cleanly before you commit to the much
bigger upgrade.

## 5. Stop service stacks

Order: internal-only -> mid-tier (databases, registries, CI) -> edge-
facing. **The edge proxy stops LAST and starts LAST** -- see Section 9.

For Docker compose hosts:

```bash
# Enumerate compose projects with their config files
docker ps --format '{{.Names}}' | while read c; do
  docker inspect "$c" --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}'
done | sort -u

# Stop per project (parallel within a batch is fine)
docker compose -f <config> -p <project> stop --timeout 30
```

For database / persistence-heavy stacks (mailcow's mariadb, postgres
with large WAL queues), bump `--timeout 60` so the engine has time to
flush before SIGKILL.

After Section 5: `docker ps -q | wc -l` should be 0.

**Trap: docker daemon restart re-launches `restart: always` containers.**

If Section 4's apt catch-up upgraded `docker-ce` (or anything that
restarts the daemon), the daemon-restart hook re-launches every
container with `restart: always` -- regardless of whether `docker
compose stop` had stopped them moments earlier. `restart:
unless-stopped` containers respect the stop intent and stay down;
`restart: always` always wins.

Spot the situation:

```bash
docker ps -q | wc -l     # expected 0, actual 30-something -> trap fired
```

Three ways to handle this, pick one before any further reboot or apt
work:

- **Mask docker for the boot** -- simplest. Daemon doesn't start, no
  containers auto-launch. Required if you're about to reboot before
  `do-release-upgrade` (kernel-pending-reboot case in Section 4).
  From the LLM use the dedicated wrappers (one unit per call -- the
  shell example below is the operator-side equivalent):

  ```python
  ssh_systemctl_mask(host="...", unit="docker.service")
  ssh_systemctl_mask(host="...", unit="docker.socket")
  # operator reboots, finishes do-release-upgrade
  # ... after upgrade, in Section 8:
  ssh_systemctl_unmask(host="...", unit="docker.service")
  ssh_systemctl_unmask(host="...", unit="docker.socket")
  ssh_systemctl_start(host="...", unit="docker.service")
  ```

  Operator-side equivalent (run from the operator's own root shell):

  ```bash
  systemctl mask docker.service docker.socket
  reboot
  # ... after upgrade:
  systemctl unmask docker.service docker.socket
  systemctl start docker.service
  ```

- **Set restart=no per container** -- granular alternative, preserves
  the running daemon. Useful if you can't afford a host-wide docker
  outage right now:

  ```bash
  docker ps -q | xargs -I {} docker update --restart=no {}
  docker stop --timeout 60 $(docker ps -q)
  ```

  Compose-up in Section 9 restores the file's restart policy when
  containers get recreated.

- **Pragmatic: let docker handle it.** Acceptable if the operator is
  fine with `restart: always` services auto-recovering in some
  uncontrolled order post-reboot, and only intervening on outliers.
  Trade-off: edge-proxy ordering (Section 9) gets violated, some
  upstream-dependent containers may flap before they catch their
  backends.

## 6. `do-release-upgrade` -- operator-driven, tmux

The LLM **cannot** drive `do-release-upgrade` via `ssh_exec_run`. It's
interactive: conffile prompts (`Y`/`N`/`D`/`Z`), SSH-port confirmation,
"start fallback sshd on port 1022", final reboot confirmation. The
operator answers these; the LLM has no useful signal to offer when
asked "merge /etc/ssh/sshd_config?".

```bash
# Operator does this from their own session
ssh -p <port> root@<host>
tmux new -s upgrade
do-release-upgrade
```

Tmux is mandatory here too: the upgrade WILL restart sshd at least
once. Without tmux the operator's session dies and the upgrade
becomes a guessing game.

Sane prompt defaults:
- Third-party sources disabled? **OK** -- restore them in Section 8.
- Continue under SSH? **Y**.
- Fallback sshd on port 1022? **Y** (failsafe if primary sshd kills).
- Conffile prompts: **N (keep local)** as default, **D** to view diff
  before deciding. Never blind-Y any conffile you've customized.
- Remove obsolete packages? **Y**.
- Restart services without asking? **Y** (all your stacks are stopped
  in Section 5 anyway).
- Reboot now? **Y** -- *unless* you hit a GRUB prompt earlier and
  haven't fixed it yet (see next subsection); in that case **N** so
  you can repair the bootloader before booting into it.

While `do-release-upgrade` runs, the LLM stays out: `ssh_exec_run`
against the host would compete for dpkg locks.

When the host is back up, operator confirms to the LLM. LLM picks up
at Section 7.

### If you hit GRUB prompts

GRUB prompts during `do-release-upgrade` are the highest-stakes
prompts in the run -- the wrong answer leaves the host unbootable
after the final reboot. There are three variants:

**A) "GRUB install devices" checkbox list.** On BIOS hosts with
software RAID (typical Hetzner setup with `md0`/`md1`/`md2` on
`/dev/sda` + `/dev/sdb`), select **BOTH** physical disks (by-id
preferred). Selecting only one disk works until that disk fails.
Selecting the `md*` devices is wrong (grub-install can't write to
mdraid). Selecting the data-only disks (`/dev/sdc`, `/dev/sdd`) is
wrong and harmless but pointless. The current selection is preserved
in `debconf-show grub-pc | grep install_devices` -- check before
guessing.

**B) Conffile diff for `/etc/default/grub`.** Default `N (keep
local)`. Hetzner setups customize the kernel cmdline
(`consoleblank=0 systemd.show_status=true` etc.) -- `Y (replace)`
would lose those.

**C) "Continue without installing GRUB?" Yes/No.** This is the trap.
It comes up when grub-install actually failed during package
configuration -- most often because the upgrade replaced the BIOS
`grub-pc` metapackage with `grub-efi-amd64` (whose grub-install
target is the wrong one for a BIOS host) and ran the EFI variant.

If you answered **Y (continue without)**: the new GRUB stage 1 is
NOT on the MBR. The old GRUB binaries are still there from before
the upgrade, and they probably can read the new `/boot/grub/grub.cfg`
(GRUB 2 is forward-compatible), but you don't want to bet a reboot
on it. **Do not say Y to "Reboot now?" yet.** Instead:

```bash
# This grub-fix-prep block IS a composite artefact: the
# mkdir+tar+dd+sha256sum sequence must run as a single unit so the
# captured MBR images are pinned to a single grub state. Run it from
# the operator's tmux session inside Section 6, not from
# ssh_exec_run -- if you must drive it from the LLM, that requires
# SSH_EXEC_ALLOW_CHEATSHEET_PATTERNS=true because the block triggers
# the mkdir / output-redirect cheatsheet patterns.

# 1. Mini-snapshot of bootloader state, in case grub-install goes wrong
SNAP=/root/snapshots/$(hostname -s)-grub-pre-fix-$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$SNAP" && cd "$SNAP"
tar -czf boot-grub.tar.gz /boot/grub
dd if=/dev/sda bs=512 count=2048 of=sda-mbr-gap.bin status=none   # 1 MiB
dd if=/dev/sdb bs=512 count=2048 of=sdb-mbr-gap.bin status=none
sha256sum * > SHA256SUMS

# 2. Verify which grub packages got pulled in
dpkg -l 'grub-*' 2>/dev/null | awk '/^ii/ {print $2}'
# Smoking gun for the trap: grub-efi-amd64 present, grub-pc absent.
# debconf knows the right disks: debconf-show grub-pc | grep install_devices

# 3. Force a BIOS grub-install to BOTH physical disks
grub-install --target=i386-pc /dev/sda
grub-install --target=i386-pc /dev/sdb
update-grub                                # safe to re-run, idempotent

# 4. Clean up the package mess: install grub-pc (Conflicts with
#    grub-efi-amd64, so apt auto-removes it):
DEBIAN_FRONTEND=noninteractive apt install -y grub-pc

# 5. Verify a Noble menuentry is the default
grep -m1 menuentry /boot/grub/grub.cfg
```

Rollback if grub-install fails: Hetzner rescue mode, mount the
filesystem, `dd if=<saved-mbr-gap>.bin of=/dev/<disk> bs=512
count=2048 conv=notrunc` to restore the pre-fix MBR + MBR gap.
Partition table at the very end of sector 0 is preserved (the saved
`.bin` contains it verbatim).

## 7. Post-reboot verification

```python
ssh_host_ping(host="...")            # reachable, key still pinned
ssh_known_hosts_verify(host="...")   # paranoia
ssh_host_info(host="...")            # new kernel, new VERSION_ID
ssh_host_alerts(host="...")          # thresholds OK
```

Cross-check:

- `uname -r` matches the new distro's GA kernel line.
- `/etc/os-release VERSION_ID` is the target.
- `systemctl --failed` empty (or only units you knew would fail).
- `dpkg --audit` empty.
- `apt list --upgradable` only your holds and the still-pinned
  third-party packages (about to be remapped in Section 8).
- `dpkg -l 'grub-*' | awk '/^ii/'` matches firmware type:
  `grub-pc` + `grub-pc-bin` on BIOS, `grub-efi-amd64` + `-bin` on
  EFI. Mixed state (`grub-efi-amd64` on a BIOS box) is the
  pre-condition for the Section 6 "Continue without GRUB" trap and
  must be cleaned up before the next kernel update.

If any of these is off, **stop**. Hand back to the operator with the
specific finding. Do not proceed to Section 8 with the host in an
unexpected state.

## 8. Remap third-party APT sources

`do-release-upgrade` renamed `*.list` -> `*.list.distUpgrade` in
`/etc/apt/sources.list.d/`. Restore them with corrected codenames:

```bash
cd /etc/apt/sources.list.d
for f in *.distUpgrade; do
  base="${f%.distUpgrade}"
  cp "$f" "$base"
  # then edit each: bump the codename / xUbuntu_NN.NN suffix
done
```

Verify the new URLs exist **before** running apt update -- some
third-party repos lag distro releases by weeks/months. The pre-flight
in Section 1 should have caught this, but re-verify:

```bash
curl -sIL -o /dev/null -w '%{http_code} %{url_effective}\n' \
  https://download.docker.com/linux/ubuntu/dists/<codename>/InRelease
```

Common per-repo changes (Ubuntu LTS-to-LTS, jammy -> noble example):
- `docker.com/linux/ubuntu jammy stable` -> `noble stable`
- `bareos.org/current/xUbuntu_22.04` -> `xUbuntu_24.04`
- PPAs: `dists/jammy/` -> `dists/noble/` -- verify the PPA publishes
  for the new codename, some don't.

Then catch up (tmux-wrapped, same as Section 4):

```bash
tmux new -d -s aptremap '
  apt update && \
  DEBIAN_FRONTEND=noninteractive apt upgrade -y \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" 2>&1 | tee /root/aptremap.log
'
```

Release the holds you set in Section 3 IF the held packages should
now move (they'll usually pull a noble-built version of the same
upstream release). From the LLM:

```python
ssh_apt_mark(host="...", action="unhold",
             packages=["postgresql-14", "mariadb-server"])
ssh_apt_upgrade(host="...")
```

Operator-side equivalent:

```bash
apt-mark unhold <package> [<package>...]
apt upgrade -y
```

If a held package has a major version waiting in the new dist (e.g.
postgres 14 -> 16) and you want to **stay** on the old major, leave it
held and plan the major-version migration as a separate change.

## 9. Bring services back up -- edge-proxy LAST

Reverse of Section 5, with one specific rule the generic template
can't infer:

**The edge proxy starts LAST.** Examples: jc21/nginx-proxy-manager,
Traefik with file/docker provider, any nginx config that does upstream
health checks at startup. These often fail or restart-loop when
their declared upstreams are unreachable on boot.

Straightforward order:

```
1. Internal-only stacks (databases, internal services, gaming servers, dev tools)
2. Mid-tier (registries, CI, chat backends, anything other stacks depend on)
3. Mail / VPN / other independent edge stacks (mailcow, wireguard, etc.)
4. Edge proxy -- LAST
```

This is operator-knowledge -- the precise dependency graph lives in
each host's `ssh_host_notes`. Obey the notes over the generic template
when they conflict.

**Pragmatic alternative** (operator's call): if you took the "let
docker handle it" path in Section 5, you don't get to enforce this
order -- the daemon-restart at boot brings up `restart: always`
containers in some internal order. Acceptable trade-off if the
operator is willing to tolerate edge-proxy flapping until its
upstreams catch up, and to manually troubleshoot only the outliers
that fail to come back. Document the choice in the post-upgrade
`ssh_host_notes` entry so the next operator knows which discipline
applies on this host.

```bash
docker compose -f <config> -p <project> start
# `up -d` if compose state was disrupted by the OS upgrade
```

Verify with [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md)
and `docker ps`.

## 10. Post-snapshot + diff

Second snapshot via [ssh-host-snapshot](../ssh-host-snapshot/SKILL.md)
with label `post-<target-codename>`. Pull off-box.

The diff against the pre-snapshot is the deliverable of the whole
operation -- it documents which conffile changes you accepted, which
packages came along for the ride, which units the new distro enabled
by default:

```bash
# Extract /etc tars first (per snapshot runbook section 5)
tar -xzf pre/80-etc.tar.gz  -C pre-etc/  --strip-components=1
tar -xzf post/80-etc.tar.gz -C post-etc/ --strip-components=1

# Package set diff
diff <(cut -f1,2 pre/10-packages-all.tsv) \
     <(cut -f1,2 post/10-packages-all.tsv)

# /etc-wide drift
diff -ruN pre-etc/ post-etc/ | less

# Systemd state
diff pre/20-systemd-enabled.txt post/20-systemd-enabled.txt
```

Update `ssh_host_notes` for the host:
- Bump the recorded OS version.
- Note any conffile decisions you made (which `N (keep local)` you
  chose, which `Y (replace)` you accepted).
- Record any packages you held / unheld and why.
- Stale notes that the upgrade obsoleted -- remove them at the next
  consolidation.

## Boundaries

- Requires exec-tier policy (`ssh_exec_run`). Read-tier alone can
  monitor an upgrade in progress but can't drive package installs.
- Debian-family only. RHEL/SLES/Arch have their own upgrade tools
  (`leapp`, `zypper dup`, `pacman -Syu`) -- the principles transfer
  but the commands don't.
- `do-release-upgrade` (Section 6) is operator-driven, not LLM-driven.
  Don't try to script around its interactivity with
  `DistUpgradeViewNonInteractive` -- you lose control over conffile
  prompts on a production host with custom configs.
- Major DB engine upgrades (postgres 14 -> 16, mariadb 10 -> 11) are
  explicitly out of scope. Hold those, do the OS upgrade, plan the DB
  migration separately.
- The tmux-wrap rule (Sections 4, 8) is non-negotiable for any apt /
  dpkg call that might touch systemd/udev/openssh/netplan. Skipping it
  is how you end up with orphaned dpkg state and a 2am cleanup.

## Related runbooks

- [ssh-host-snapshot](../ssh-host-snapshot/SKILL.md) -- Sections 1, 7
  (verification), 10.
- [ssh-host-healthcheck](../ssh-host-healthcheck/SKILL.md) -- Section
  7 verification and post-Section 9 sanity check.
- [ssh-disk-cleanup](../ssh-disk-cleanup/SKILL.md) -- if `/` or
  `/boot` is tight before the upgrade. Noble's kernels are larger than
  Jammy's; `/boot` headroom is the first thing to bite.
- [ssh-incident-response](../ssh-incident-response/SKILL.md) -- if the
  upgrade goes sideways and the host needs rescue-mode recovery.
