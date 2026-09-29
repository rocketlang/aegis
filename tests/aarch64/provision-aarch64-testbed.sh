#!/usr/bin/env bash
# Build the aarch64 test bed from nothing. Idempotent; safe to re-run.
#
# The bed is a full QEMU VM with a real arm64 kernel, NOT qemu-user and NOT a docker
# arm64 image. Both of those run on the HOST x86 kernel, and seccomp filters and cgroup
# BPF are kernel objects — testing them there measures x86 enforcement behind an ARM
# userspace and reports it as an ARM result. That is the failure mode this bed exists
# to catch, so it must not be built out of it.
#
# The guest needs no login, no ssh and no network: a systemd oneshot mounts a 9p share
# from the host, runs /hostshare/run.sh, writes the exit code, and powers the VM off.
set -euo pipefail

BED=/var/lib/ankr-testbed/aarch64          # images live OUTSIDE any git tree, on purpose
IMG_URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-arm64.qcow2

need() { command -v "$1" >/dev/null || { echo "missing: $1 — apt-get install $2"; exit 2; }; }
need qemu-system-aarch64 qemu-system-arm
need qemu-img qemu-utils
need qemu-nbd qemu-utils
[ -f /usr/share/qemu-efi-aarch64/QEMU_EFI.fd ] || { echo "missing UEFI firmware — apt-get install qemu-efi-aarch64"; exit 2; }

mkdir -p "$BED/share/out"

if [ ! -f "$BED/base.qcow2" ]; then
  echo "[provision] fetching $IMG_URL"
  curl -fsSL -o "$BED/base.qcow2.part" "$IMG_URL"
  mv "$BED/base.qcow2.part" "$BED/base.qcow2"
  echo "$IMG_URL" > "$BED/IMAGE_URL"
fi

# Overlay, so base.qcow2 stays pristine and a corrupted run is thrown away, never repaired.
rm -f "$BED/test.qcow2"
qemu-img create -f qcow2 -F qcow2 -b "$BED/base.qcow2" "$BED/test.qcow2" 8G >/dev/null

modprobe nbd max_part=8
qemu-nbd --disconnect /dev/nbd0 >/dev/null 2>&1 || true
qemu-nbd --connect=/dev/nbd0 "$BED/test.qcow2"
sleep 2
MNT=$(mktemp -d)
mount /dev/nbd0p1 "$MNT"
cleanup() { sync; umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true; qemu-nbd --disconnect /dev/nbd0 >/dev/null 2>&1 || true; }
trap cleanup EXIT

cat > "$MNT/etc/systemd/system/ankr-testbed.service" <<'UNIT'
[Unit]
Description=ANKR aarch64 test bed — run host-supplied harness, then power off
After=local-fs.target
DefaultDependencies=no
Conflicts=shutdown.target
Before=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=no
ExecStartPre=/bin/mkdir -p /hostshare
ExecStartPre=/bin/mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 hostshare /hostshare
ExecStart=/bin/sh -c '/bin/sh /hostshare/run.sh > /hostshare/out/console.log 2>&1; echo $? > /hostshare/out/exitcode'
ExecStopPost=/bin/sh -c '/bin/sync; /bin/umount /hostshare || true'
ExecStopPost=/usr/bin/systemctl --no-block poweroff
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
UNIT

mkdir -p "$MNT/etc/systemd/system/multi-user.target.wants"
ln -sf ../ankr-testbed.service "$MNT/etc/systemd/system/multi-user.target.wants/ankr-testbed.service"
printf '9pnet_virtio\n9p\n9pnet\n' > "$MNT/etc/modules-load.d/9p.conf"

# Assert the injection landed rather than trusting ln, and say which guest this is.
[ -L "$MNT/etc/systemd/system/multi-user.target.wants/ankr-testbed.service" ] || { echo "[provision] FAIL: unit not enabled"; exit 1; }
echo "[provision] guest: $(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' "$MNT/etc/os-release")"
echo "[provision] guest kernel: $(basename "$(ls "$MNT"/boot/vmlinuz-* | head -1)" | sed 's/vmlinuz-//')"
echo "[provision] ready — run tests with run-aarch64-testbed.sh <harness.sh> [payload ...]"
