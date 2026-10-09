#!/usr/bin/env bash
# aegis red-team — the signed ledger, ANCHORED in a public transparency log (2026-10-10, aegis 2.15.0).
# Real processes: the authority signs a statement of where its ledger stands, `aegis ledger-anchor` submits
# it, `aegis ledger-verify --anchor-log` reads the log back; and the failures are forced: a file cut back
# below an anchor, a rewritten ledger, a wrong log key, a log that swaps a leaf it shows, no anchor at all,
# a log that refuses for want of a token. The log is a stand-in written from the protocol; the dated
# rehearsal against the public test log is in the changelog. It does NOT check the log's cosigning
# witnesses, and it does NOT prove the uid boundary (one user here).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · signed ledger, anchored in a public log ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
cd "$HERE/.." || { echo "BROKE — repo root not found"; exit 3; }
"$BUN" test tests/ledger-anchor.test.ts --timeout 60000; rc=$?
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = anchored, read back, every failure loud · 1 = one slipped, RED · 3 = broke)"
exit $rc
