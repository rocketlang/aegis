#!/usr/bin/env bash
# aegis red-team — POINT 1: approval authority at the agent's own uid (independent review, Oct 2026).
#
# Reproduces the self-approval gap in the destructive gate: a thread at the agent's OWN uid writes the
# one-time-approval file, and the gate honours it — no person, no signature. A "GAP" line means the
# exploit succeeded. RED until the approver moves off the agent's uid (separate-uid supervisor) or the
# approval key is hardware-bound. Runs against the repo source (public):
#   src/kavach/destructive-approval.ts  +  src/kavach/destructive-verdict.ts
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · point 1 — self-approval at the agent's own uid ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/point1-self-approval.probe.ts"
rc=$?
echo "EXIT=$rc   (0 = authority is off the agent's uid · 1 = self-approval reproduced, RED until fixed · 3 = broke)"
exit $rc
