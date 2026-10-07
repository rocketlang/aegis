#!/usr/bin/env bash
# aegis red-team — VARUNA no-auth (review finding, 2026-10-08). Proves the listener defaults are closed:
# loopback bind, CORS off, off-box+no-token refuses to start, and ingest requires a bearer token.
# GAP = the open/cross-origin/unauth-write exploit still works. Runs against repo source.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · varuna no-auth ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/varuna-no-auth.probe.ts"; rc=$?
echo "EXIT=$rc   (0 = defaults closed · 1 = exploit reproduced, RED until fixed · 3 = broke)"
exit $rc
