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
OUT="$(mktemp)"; trap 'rm -f "$OUT"' EXIT
if [ -e /etc/aegis/ledger-signing.pub ]; then
  # This box pins a ledger key, and the tests that start a throwaway authority skip themselves under it. Run in a
  # PRIVATE mount namespace with an empty folder over /etc/aegis (gone with the process; the host's mounts are not
  # touched). Until 11 October 2026 this battery ran on the pinned box as it was: 8 of its 13 tests were skipped
  # and it still said green. Not allowed: exit 3.
  unshare -m sh -c "mount -t tmpfs -o mode=755 tmpfs /etc/aegis 2>/dev/null || exit 97; exec '$BUN' test tests/ledger-authority.test.ts" 2>&1 | tee "$OUT"; rc=${PIPESTATUS[0]}
  [ "$rc" = 97 ] && { echo "BROKE — this box pins a ledger key and will not let the battery hide it in a private namespace; nothing was tested"; rc=3; }
else
  "$BUN" test tests/ledger-authority.test.ts 2>&1 | tee "$OUT"; rc=${PIPESTATUS[0]}
fi
[ "$rc" -gt 1 ] && rc=3
# A skipped test proved nothing, and a run with no passing test proved nothing: neither is green.
skipped="$(sed -n 's/^ *\([0-9][0-9]*\) skip$/\1/p' "$OUT" | tail -1)"; passed="$(sed -n 's/^ *\([0-9][0-9]*\) pass$/\1/p' "$OUT" | tail -1)"
if [ "$rc" = 0 ] && { [ "${skipped:-0}" != 0 ] || [ "${passed:-0}" = 0 ]; }; then
  echo "BROKE — ${passed:-0} test(s) passed and ${skipped:-0} were skipped; a skipped test proves nothing"; rc=3
fi
echo "EXIT=$rc   (0 = signed, witnessed, every failure loud · 1 = one slipped, RED · 3 = broke)"
exit $rc
