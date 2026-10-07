#!/usr/bin/env bash
# aegis red-team — NALLASETU shared-HMAC → forgery + repudiation (review finding, 2026-10-08).
# Proves the hard cutover to per-agent Ed25519 seals: no forgery from the public key, non-repudiation,
# and a captured attestation can't be escalated or extended. GAP = still forgeable. Runs vs repo source.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · nallasetu asymmetric (no forgery / no repudiation) ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/nallasetu-asymmetric.probe.ts"; rc=$?
echo "EXIT=$rc   (0 = forgery + repudiation closed · 1 = reproduced, RED until fixed · 3 = broke)"
exit $rc
