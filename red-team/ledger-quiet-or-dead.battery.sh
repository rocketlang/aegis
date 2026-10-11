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
if [ -e /etc/aegis/ledger-signing.pub ]; then
  # This box pins a ledger key, which every aegis command here obeys. Run in a PRIVATE mount namespace with an
  # empty folder over /etc/aegis (gone with the process; the host's mounts are not touched). Not allowed: exit 3.
  unshare -m sh -c "mount -t tmpfs -o mode=755 tmpfs /etc/aegis 2>/dev/null || exit 97; exec timeout 300 '$BUN' '$HERE/ledger-quiet-or-dead.probe.ts'"; rc=$?
  [ "$rc" = 97 ] && { echo "BROKE — this box pins a ledger key and will not let the battery hide it in a private namespace; nothing was tested"; rc=3; }
else
  timeout 300 "$BUN" "$HERE/ledger-quiet-or-dead.probe.ts"; rc=$?
fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = silence, a late day and a future day are each named · 1 = one read as clean, RED · 3 = broke / could not run)"
exit $rc
