#!/usr/bin/env bash
# aegis red-team — POINT 1, the UID BOUNDARY (DISPOSABLE HOST ONLY).
#
# The same-process probe (point1-self-approval.probe.ts) proves the gate no longer trusts the
# agent-writable file. This proves the other half: with the approver running as a SEPARATE uid,
# the agent's uid genuinely cannot (a) write the approver's store, (b) open the person-only
# approve socket — while it CAN still ask over the consume socket. That needs a real second uid,
# so it mutates system users and MUST run on a throwaway host, never the live box.
#
#   sudo AEGIS_DISPOSABLE_HOST=1 ./red-team/point1-uid-boundary.disposable.sh
#
# GAP = the agent crossed the boundary (exploit succeeded). Exit 0 all held · 1 a gap · 3 broke.
set -u
[ "${AEGIS_DISPOSABLE_HOST:-}" = "1" ] || { echo "REFUSING — set AEGIS_DISPOSABLE_HOST=1 and run on a THROWAWAY host (this creates/deletes system users)."; exit 3; }
[ "$(id -u)" = "0" ] || { echo "REFUSING — needs root to create the separate uid."; exit 3; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }

APPROVER=aegis-approver-test
AGENT=aegis-agent-test
STORE=/var/lib/${APPROVER}
SOCKDIR=/run/${APPROVER}
CONSUME="$SOCKDIR/consume.sock"
APPROVE="$SOCKDIR/approve.sock"
DAEMON_PID=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  rm -rf "$STORE" "$SOCKDIR"
  userdel "$APPROVER" 2>/dev/null; groupdel "$APPROVER" 2>/dev/null
  userdel "$AGENT" 2>/dev/null
}
trap cleanup EXIT

echo "=== aegis red-team · point 1 — uid boundary (disposable host) ==="
# Accounts: approver owns the store; agent is NOT in the approver group.
groupadd -f "$APPROVER"
id -u "$APPROVER" >/dev/null 2>&1 || useradd -r -g "$APPROVER" -s /usr/sbin/nologin "$APPROVER"
id -u "$AGENT"    >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$AGENT"

mkdir -p "$STORE" "$SOCKDIR"
chown "$APPROVER:$APPROVER" "$STORE";   chmod 700 "$STORE"      # agent uid: no read, no write
chown "$APPROVER:$APPROVER" "$SOCKDIR"; chmod 750 "$SOCKDIR"

# Start the daemon AS the approver.
sudo -u "$APPROVER" env AEGIS_APPROVER_SUPPRESS_UID_WARN=1 \
  "$BUN" run "$ROOT/src/cli/index.ts" approver-daemon --store "$STORE" --consume "$CONSUME" --approve "$APPROVE" &
DAEMON_PID=$!
sleep 1
[ -S "$CONSUME" ] && [ -S "$APPROVE" ] || { echo "BROKE — daemon did not create sockets"; exit 3; }
# consume socket: reachable by the agent. approve socket: approver group only.
chmod 666 "$CONSUME"
chown "$APPROVER:$APPROVER" "$APPROVE"; chmod 660 "$APPROVE"

gaps=0
R() { echo "  [$([ "$1" = 1 ] && echo 'GAP ' || echo 'safe')] $2 — $3"; [ "$1" = 1 ] && gaps=$((gaps+1)); }

# (a) agent tries to WRITE the approver's store → must be denied by the OS.
if sudo -u "$AGENT" bash -c "echo forged > '$STORE/destructive-approvals.json'" 2>/dev/null; then
  R 1 "agent writes the approver store" "the agent's uid wrote $STORE — the boundary FAILED"
else
  R 0 "agent cannot write the approver store" "EACCES — the store is owned by $APPROVER, mode 700"
fi

# (b) agent tries to OPEN the approve socket → must be denied.
if sudo -u "$AGENT" "$BUN" -e "require('net').createConnection('$APPROVE').on('connect',()=>process.exit(0)).on('error',()=>process.exit(7))" 2>/dev/null; then
  R 1 "agent opens the approve socket" "the agent connected to the person-only approve socket — the boundary FAILED"
else
  R 0 "agent cannot open the approve socket" "EACCES — approve socket is $APPROVER-group only"
fi

# (c) agent CAN ask over the consume socket (this is allowed) and gets 'false' (no approval).
ASK="require('net');const s=require('net').createConnection('$CONSUME');s.on('connect',()=>s.write(JSON.stringify({op:'consume',command:'rm -rf /x'})+'\n'));s.setEncoding('utf8');s.on('data',d=>{const r=JSON.parse(d);process.exit(r.ok&&r.value===false?0:8)});s.on('error',()=>process.exit(9))"
if sudo -u "$AGENT" "$BUN" -e "$ASK" 2>/dev/null; then
  R 0 "agent may ASK over the consume socket" "consume returned false (no approval) — asking is allowed, approving is not"
else
  R 1 "agent ask over consume socket" "the consume path did not behave as expected"
fi

echo
echo "  point1-uid-boundary: $gaps gap(s) — $([ $gaps -eq 0 ] && echo 'the agent cannot forge or self-approve across the uid boundary ✓' || echo 'the boundary leaked (RED)')"
exit $(( gaps > 0 ? 1 : 0 ))
