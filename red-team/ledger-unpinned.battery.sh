#!/usr/bin/env bash
# aegis red-team — an authority is set up and nobody pinned its key (2026-10-11, aegis 2.17.1).
# Pointed out by Andrey Lazarev against 2.17.0. See the probe for each case.
# To see it red: AEGIS_PROBE_REPO=<an installed 2.17.0> ./red-team/ledger-unpinned.battery.sh
#
# On a box that pins a key the probe runs in a PRIVATE mount namespace with an empty folder over /etc/aegis
# (it disappears with the process; the host's mounts are not touched). Where that is not allowed: exit 3.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 12 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · an authority with no pinned key ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
if [ -e /etc/aegis/ledger-signing.pub ]; then
  unshare -m sh -c "mount -t tmpfs -o mode=755 tmpfs /etc/aegis 2>/dev/null || exit 97; exec timeout 120 '$BUN' '$HERE/ledger-unpinned.probe.ts'"; rc=$?
  [ "$rc" = 97 ] && { echo "BROKE — this box pins a ledger key and will not let the battery hide it in a private namespace; nothing was tested"; rc=3; }
else
  timeout 120 "$BUN" "$HERE/ledger-unpinned.probe.ts"; rc=$?
fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = unchecked is said, and the pin step cannot be turned · 1 = a gap, RED · 3 = broke / could not run)"
exit $rc
