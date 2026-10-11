#!/usr/bin/env bash
# aegis red-team — what a person approves is not what they were shown (2026-10-11, aegis 2.17.1).
# A refused command shown only in part, and two refused commands under one approval code. See the probe.
# To see it red: AEGIS_PROBE_REPO=<an installed 2.17.0> ./red-team/approval-unseen.battery.sh
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 7 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · an approval for more than the person was shown ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
timeout 120 "$BUN" "$HERE/approval-unseen.probe.ts"; rc=$?
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = an approval covers only what was shown, or what the person says they read · 1 = a gap, RED · 3 = broke / could not run)"
exit $rc
