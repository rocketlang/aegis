#!/usr/bin/env bash
# Smoke test — Anumati permissive layer + Pramana assurance loop + fail-closed repair.
#
# @rule:ANU-YK-001 · feedback_guards_decay_silently_assert_both_outcomes:
# every gate is exercised in BOTH directions. A test that only proves a gate says yes
# proves nothing about whether it can still say no.
#
# Self-contained: touches only a temp dir. Never writes to the shared edit-heat ledger.

set -uo pipefail
AEGIS="${AEGIS_ROOT:-/root/aegis}"
CLI="bun run $AEGIS/src/cli/index.ts"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n     %s\n' "$1" "${2:-}"; }

# expect <name> <needle> <<< output
expect() { # name needle output
  if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1" "expected to find: $2"; fi
}
expect_exit() { # name wanted actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "wanted exit $2, got $3"; fi
}

echo "── ANU-I-001 database class ──────────────────────────────────────────"
PROD_DB=$(python3 -c "
import json;d=json.load(open('/root/.ankr/config/databases.json'))['databases']
print(next((k for k,v in d.items() if isinstance(v,dict) and v.get('class')=='prod'),''))")
DEV_DB=$(python3 -c "
import json;d=json.load(open('/root/.ankr/config/databases.json'))['databases']
print(next((k for k,v in d.items() if isinstance(v,dict) and v.get('class')=='dev'),''))")

expect "refuses a schema op on a prod-class database" "INVARIANT VIOLATED" \
  "$($CLI anumati try Bash "psql -d $PROD_DB -c 'DROP TABLE x'" 2>&1)"
expect "permits the same op on a dev-class database" "PERMIT" \
  "$($CLI anumati try Bash "psql -d $DEV_DB -c 'DROP TABLE x'" 2>&1)"
expect "refuses when the target database cannot be resolved" "UNKNOWN STATE" \
  "$($CLI anumati try Bash "prisma db push" 2>&1)"

echo "── ANU-I-002 file heat ───────────────────────────────────────────────"
touch "$TMP/hot.txt"
touch -d '2 hours ago' "$TMP/cold.txt"
expect "refuses a Write to a file an unledgered writer just touched" "INVARIANT VIOLATED" \
  "$($CLI anumati try Write "$TMP/hot.txt" 2>&1)"
expect "permits a Write to a cold file" "PERMIT" \
  "$($CLI anumati try Write "$TMP/cold.txt" 2>&1)"
expect "sees a Bash redirect as a write target" "INVARIANT VIOLATED" \
  "$($CLI anumati try Bash "echo x > $TMP/hot.txt" 2>&1)"
expect "sees sed -i as a write target" "INVARIANT VIOLATED" \
  "$($CLI anumati try Bash "sed -i 's/a/b/' $TMP/hot.txt" 2>&1)"

echo "── ANU-I-003 shared git index ────────────────────────────────────────"
REPO="$TMP/repo"; mkdir -p "$REPO"
git -C "$REPO" init -q
git -C "$REPO" config user.email t@t; git -C "$REPO" config user.name t
echo a > "$REPO/a.txt"; git -C "$REPO" add a.txt; git -C "$REPO" commit -qm init
echo b > "$REPO/b.txt"; git -C "$REPO" add b.txt
expect "refuses a bare commit while the shared index is dirty" "INVARIANT VIOLATED" \
  "$(cd "$REPO" && $CLI anumati try Bash "git commit -m msg" 2>&1)"
expect "permits a pathspec commit" "PERMIT" \
  "$(cd "$REPO" && $CLI anumati try Bash "git commit -m msg -- b.txt" 2>&1)"

echo "── ANU-I-004 port authority ──────────────────────────────────────────"
FREE_PORT_SVC=$(python3 - <<'PY'
import json,re,subprocess
d=json.load(open('/root/.ankr/config/ports.json'))
bound={int(m) for m in re.findall(r':(\d+)\s', subprocess.run(['ss','-lntH'],capture_output=True,text=True).stdout)}
for g,v in d.items():
    if g.startswith('_') or not isinstance(v,dict): continue
    if g == 'reserved': continue
    for k,p in v.items():
        if k.startswith('_') or not isinstance(p,int) or p<4000 or p in bound: continue
        # only unambiguous keys
        hits=sum(1 for gg,vv in d.items() if isinstance(vv,dict) for kk,pp in vv.items() if kk==k and isinstance(pp,int))
        if hits==1: print(f"{g}-{k} {p}"); raise SystemExit
PY
)
SVC=${FREE_PORT_SVC%% *}; PORT=${FREE_PORT_SVC##* }
if [ -n "${PORT:-}" ]; then
  expect "permits a start when the declared port is free" "PERMIT" \
    "$($CLI anumati try Bash "ankr-ctl start $SVC" 2>&1)"
  python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$PORT)); s.listen(1); time.sleep(10)" &
  SQUATTER=$!
  sleep 2
  expect "refuses a start when a foreign process squats the declared port" "INVARIANT VIOLATED" \
    "$($CLI anumati try Bash "ankr-ctl start $SVC" 2>&1)"
  kill $SQUATTER 2>/dev/null; wait $SQUATTER 2>/dev/null
else
  bad "port test setup" "no free unambiguous declared port found"
fi
expect "refuses when a service key resolves to two ports" "UNKNOWN STATE" \
  "$($CLI anumati try Bash "ankr-ctl start ankrtms" 2>&1)"

echo "── hook face: shadow reports, enforce bites ──────────────────────────"
PAYLOAD=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'smoke','cwd':'/root',
'tool_input':{'command':\"psql -d $PROD_DB -c 'DROP TABLE x'\"}}))")

OUT=$(printf '%s' "$PAYLOAD" | ANUMATI_MODE=shadow $CLI check-anumati 2>&1); RC=$?
expect_exit "shadow mode does not block" 0 "$RC"
expect "shadow mode still reports" "WOULD REFUSE" "$OUT"

OUT=$(printf '%s' "$PAYLOAD" | ANUMATI_MODE=enforce $CLI check-anumati 2>&1); RC=$?
expect_exit "enforce mode blocks" 2 "$RC"
expect "enforce mode says authority is untouched" "Authority is unchanged" "$OUT"

echo "── fail-closed repair: check-destructive ─────────────────────────────"
DESTRUCTIVE=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'smoke',
'tool_input':{'command':'psql -c \"TRUNCATE TABLE users\"'}}))")
BENIGN=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'smoke','tool_input':{'command':'echo hello'}}))")

printf '%s' "$BENIGN" | $CLI check-destructive >/dev/null 2>&1
expect_exit "benign command passes with rules present" 0 $?

# The repair must not have cost the gate its original job.
printf '%s' "$DESTRUCTIVE" | $CLI check-destructive >/dev/null 2>&1
expect_exit "destructive command is still blocked with rules present" 2 $?

EMPTY_HOME="$TMP/nohome"; mkdir -p "$EMPTY_HOME"
OUT=$(printf '%s' "$BENIGN" | HOME="$EMPTY_HOME" $CLI check-destructive 2>&1); RC=$?
expect_exit "unreadable rules now REFUSE instead of allowing everything" 2 "$RC"
expect "refusal explains itself" "cannot judge the command" "$OUT"

OVERRIDE=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'smoke',
'tool_input':{'command':'echo hello # HUMAN-DESTRUCTIVE-CONFIRMED-ANKR'}}))")
printf '%s' "$OVERRIDE" | HOME="$EMPTY_HOME" $CLI check-destructive >/dev/null 2>&1
expect_exit "override token still works when the rules file is gone" 0 $?

echo "── PRA assurance loop ────────────────────────────────────────────────"
echo "payload" > "$TMP/written.txt"
expect "confirms a write by re-reading the bytes" "confirmed by an independent path" \
  "$($CLI pramana file "$TMP/written.txt" "payload
" 2>&1)"
expect "refutes a write whose content does not match" "REFUTED" \
  "$($CLI pramana file "$TMP/written.txt" "something else" 2>&1)"
expect "refutes a missing file" "REFUTED" \
  "$($CLI pramana file "$TMP/never-written.txt" 2>&1)"

expect "refutes a port nothing listens on" "REFUTED" \
  "$($CLI pramana port 65001 2>&1)"
LIVE_PORT=$(ss -lntH | grep -oP ':\K(4\d{3})' | head -1)
[ -n "$LIVE_PORT" ] && expect "confirms a port that answers a fresh socket" "confirmed by an independent path" \
  "$($CLI pramana port "$LIVE_PORT" 2>&1)"

git -C "$REPO" commit -qm second -- b.txt
expect "confirms a commit that contains exactly the intended files" "confirmed by an independent path" \
  "$($CLI pramana commit "$REPO" b.txt 2>&1)"
expect "refutes a commit that swept an unintended file" "REFUTED" \
  "$($CLI pramana commit "$REPO" a.txt 2>&1)"

echo
echo "─────────────────────────────────────────────────────────────────────"
printf 'passed %d · failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
