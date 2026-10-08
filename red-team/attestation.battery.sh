#!/usr/bin/env bash
# aegis red-team — attestation: identify a malformed/impostor agent (2026-10-08). Proves the boundary
# refuses tampered code/config (measurement != baseline), a wrong identity (not signed by the
# registered key), and an unpinned agent (no baseline = refused). Hermetic (crypto + temp files).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · attestation (who + what) ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/attestation.probe.ts"; rc=$?
echo "EXIT=$rc   (0 = tampered/impostor/unpinned all refused · 1 = one slipped, RED · 3 = broke)"
exit $rc
