#!/usr/bin/env bash
# aegis red-team — refusal-ledger concealment (JieGou finding, 2026-10-08). Proves the sequenced+signed
# ledger catches an edited/deleted/forged row (and reads an unsigned ledger as UNVERIFIABLE), so hiding
# a refusal becomes a caught break, not a clean log. Hermetic (crypto + arrays). Runs vs repo source.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · refusal-ledger concealment ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/ledger-concealment.probe.ts"; rc=$?
echo "EXIT=$rc   (0 = tamper caught · 1 = concealment slipped, RED · 3 = broke)"
exit $rc
