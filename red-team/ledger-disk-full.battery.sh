#!/usr/bin/env bash
# aegis red-team — the signed ledger on a FULL DISK (2026-10-10, aegis 2.16.1).
# Before 2.16.1 a full disk left half a row in the ledger; the next row was written onto the same line, so a
# refusal that had been acknowledged could not be read and the ledger never verified again (3 runs of 3).
# This mounts a 160 KB memory-backed folder in a PRIVATE mount namespace (it disappears with the process, the
# host's mounts are not touched), runs a real authority on it, fills it, asks, frees it, asks again, verifies.
# It needs the right to make a mount namespace (root, or user namespaces). Without it: exit 3, not a pass.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · signed ledger on a full disk ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
M="$(mktemp -d /tmp/aegis-disk-full-XXXXXX)"; trap 'rmdir "$M" 2>/dev/null' EXIT
unshare -m sh -c "mount -t tmpfs -o size=160k,mode=700 tmpfs '$M' 2>/dev/null || exit 97; exec timeout 120 '$BUN' '$HERE/ledger-disk-full.probe.ts' '$M'"; rc=$?
[ "$rc" = 97 ] && { echo "BROKE — this box will not let the battery mount a private folder; nothing was tested"; rc=3; }
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = only the unwritten row is lost · 1 = a fragment, an unreadable row or a ledger that no longer verifies, RED · 3 = broke / could not run)"
exit $rc
