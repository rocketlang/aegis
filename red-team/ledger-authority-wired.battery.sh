#!/usr/bin/env bash
# aegis red-team — the signed ledger and the witness, WIRED (2026-10-08). Before 2.14.0 the signing
# functions and the witness existed but no gate called them. This proves the path end to end with real
# processes: a gate refuses → the authority numbers and signs the row → a witness process keeps its
# own copy; and that an unreachable authority, a cut-off ledger, a silent authority and an undelivered
# row are each loud. It does NOT prove the uid boundary (one user here; see
# point1-uid-boundary.disposable.sh) and it does NOT catch a gate that refuses without asking.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · signed ledger + witness, wired ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
cd "$HERE/.." || { echo "BROKE — repo root not found"; exit 3; }
"$BUN" test tests/ledger-authority.test.ts; rc=$?
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = signed, witnessed, every failure loud · 1 = one slipped, RED · 3 = broke)"
exit $rc
