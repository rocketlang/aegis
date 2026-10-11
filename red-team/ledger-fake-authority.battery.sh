#!/usr/bin/env bash
# aegis red-team — something that is not the authority answers the gate (2026-10-11, aegis 2.16.3).
# Reported by Andrey Lazarev against 2.16.2: a socket of the agent's own, named in the pointer file, answered
# "ok, 42" and the local row read as signed; the real ledger never saw the refusal, and nothing compared the two.
# The probe runs a real authority and several false ones in a temporary folder. See the probe for each case.
#
# A box that pins the ledger key at /etc/aegis/ledger-signing.pub pins it for every gate, the probe's too. There
# the probe runs in a PRIVATE mount namespace with an empty folder over /etc/aegis (it disappears with the
# process; the host's mounts are not touched). Where that is not allowed: exit 3, not a pass.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · a false authority answers the gate ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
if [ -e /etc/aegis/ledger-signing.pub ]; then
  unshare -m sh -c "mount -t tmpfs -o mode=755 tmpfs /etc/aegis 2>/dev/null || exit 97; exec timeout 120 '$BUN' '$HERE/ledger-fake-authority.probe.ts'"; rc=$?
  [ "$rc" = 97 ] && { echo "BROKE — this box pins a ledger key and will not let the battery hide it in a private namespace; nothing was tested"; rc=3; }
else
  timeout 120 "$BUN" "$HERE/ledger-fake-authority.probe.ts"; rc=$?
fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc   (0 = a false authority is refused or found · 1 = a refusal read as signed, or went unsaid, RED · 3 = broke / could not run)"
exit $rc
