#!/usr/bin/env bash
# aegis red-team — a quiet ledger or a dead authority? (2026-10-11, aegis 2.17.0)
# Pointed out by Andrey Lazarev against 2.16.2: an anchor carried no time, so from the public log a week with no
# refusals and an authority switched off a week ago looked the same. With dated anchors, one leaf a day, the probe
# runs a real authority and the real commands against a stand-in log with cosigning witnesses, sets their clocks,
# and checks that silence, a missed day, a day filled in late and a day that has not come are each named.
# See the probe for each case and for what a stand-in log does not prove.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · a quiet ledger or a dead authority ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
timeout 300 "$BUN" "$HERE/ledger-quiet-or-dead.probe.ts"; rc=$?
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = silence, a late day and a future day are each named · 1 = one read as clean, RED · 3 = broke / could not run)"
exit $rc
