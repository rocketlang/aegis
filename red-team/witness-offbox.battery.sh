#!/usr/bin/env bash
# aegis red-team — off-box witness (concealment rung 3, 2026-10-08). Proves an independent collector
# alarms on a suppressed row (gap), a silent source (stall), a forged row (signature), and tail
# truncation (reconcile vs its high-water-mark) — the gaps rung 2 and the agent itself can't surface.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · off-box witness (concealment rung 3) ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
"$BUN" "$HERE/witness-offbox.probe.ts"; rc=$?
echo "EXIT=$rc   (0 = gap/silence/forgery/truncation all alarm · 1 = one slipped, RED · 3 = broke)"
exit $rc
