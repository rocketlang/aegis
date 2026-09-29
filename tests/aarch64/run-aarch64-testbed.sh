#!/usr/bin/env bash
# aarch64 test bed — boot a real arm64 kernel under QEMU TCG and run a harness in it.
#
# WHY A FULL VM AND NOT qemu-user OR A DOCKER arm64 IMAGE: both of those keep the HOST
# x86 kernel. seccomp filters and cgroup BPF are kernel objects, so on either of them we
# would be testing x86 enforcement with an ARM userspace and calling it an ARM result.
# That is the exact "measured the wrong thing and reported success" failure this test bed
# exists to catch. A full VM is slower and is the only honest option.
#
# No KVM here (arm64 guest on an x86 host), so this is pure TCG emulation.
set -uo pipefail

BED=/var/lib/ankr-testbed/aarch64
SHARE="$BED/share"
HARNESS="${1:?usage: run-aarch64-testbed.sh <harness.sh> [payload ...]}"
shift || true

[ -f "$BED/test.qcow2" ] || { echo "no $BED/test.qcow2 — run provision-aarch64-testbed.sh first"; exit 2; }

rm -rf "$SHARE"; mkdir -p "$SHARE/out"
cp "$HARNESS" "$SHARE/run.sh"
for p in "$@"; do cp -r "$p" "$SHARE/"; done

echo "[testbed] booting aarch64 (TCG, no KVM) …"
timeout 2700 qemu-system-aarch64 \
  -machine virt -cpu cortex-a72 -smp 4 -m 2048 \
  -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
  -drive if=virtio,file="$BED/test.qcow2",format=qcow2 \
  -virtfs local,path="$SHARE",mount_tag=hostshare,security_model=none,id=hostshare \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  -nographic -no-reboot \
  > "$SHARE/out/boot.log" 2>&1
qrc=$?

echo "[testbed] qemu exit=$qrc"
if [ -f "$SHARE/out/console.log" ]; then
  echo "───────── harness output ─────────"
  cat "$SHARE/out/console.log"
  echo "──────────────────────────────────"
  rc=$(cat "$SHARE/out/exitcode" 2>/dev/null || echo "NO-EXITCODE")
  echo "[testbed] harness exit=$rc"
  # A harness that never ran is a FAILED run, never a passed one (absent != ok).
  [ "$rc" = "0" ] || exit 1
else
  echo "[testbed] FAIL: the harness produced no output — it did not run."
  echo "[testbed] last 40 lines of boot log:"; tail -40 "$SHARE/out/boot.log"
  exit 1
fi
