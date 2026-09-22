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
trap 'rm -rf "$TMP"; rm -f "/root/.aegis/agents/$SID.valve.json"' EXIT
# A FIXED session id poisons the suite: every run increments this agent's
# violation/loop counters until the gate valve narrows to CRACKED, clears EXEC_BASH,
# and the benign-command case starts failing for reasons that have nothing to do with
# what it tests. Unique per run, and the valve record is removed on exit.
SID="smoke-$$-$(date +%s)"

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
import json;print(json.dumps({'tool_name':'Bash','session_id':'$SID','cwd':'/root',
'tool_input':{'command':\"psql -d $PROD_DB -c 'DROP TABLE x'\"}}))")

OUT=$(printf '%s' "$PAYLOAD" | ANUMATI_MODE=shadow $CLI check-anumati 2>&1); RC=$?
expect_exit "shadow mode does not block" 0 "$RC"
expect "shadow mode still reports" "WOULD REFUSE" "$OUT"

OUT=$(printf '%s' "$PAYLOAD" | ANUMATI_MODE=enforce $CLI check-anumati 2>&1); RC=$?
expect_exit "enforce mode blocks" 2 "$RC"
expect "enforce mode says authority is untouched" "Authority is unchanged" "$OUT"

echo "── fail-closed repair: check-destructive ─────────────────────────────"
DESTRUCTIVE=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'$SID',
'tool_input':{'command':'psql -c \"TRUNCATE TABLE users\"'}}))")
BENIGN=$(python3 -c "
import json;print(json.dumps({'tool_name':'Bash','session_id':'$SID','tool_input':{'command':'echo hello'}}))")

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
import json;print(json.dumps({'tool_name':'Bash','session_id':'$SID',
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

echo "── ANU-007 source integrity ──────────────────────────────────────────"
DB=/root/.ankr/config/databases.json

# Detector, against synthetic ledger lines — never the shared ledger.
DET=$(bun -e '
import { detectTaintInLedger } from "/root/aegis/src/kavach/plant-state";
const hit = detectTaintInLedger([JSON.stringify({ts:Date.now(),sid:"abcd1234",fp:"/root/.ankr/config/databases.json"})]);
const miss = detectTaintInLedger([JSON.stringify({ts:Date.now(),sid:"abcd1234",fp:"/root/some/ordinary/file.ts"})]);
const rel  = detectTaintInLedger([JSON.stringify({ts:Date.now(),sid:"RELEASED",fp:"/root/.ankr/config/databases.json"})]);
console.log(JSON.stringify({hit:hit.length,miss:miss.length,rel:rel.length}));
' 2>&1 | tail -1)
expect "detects an agent write to a protected source" '"hit":1' "$DET"
expect "ignores an agent write to an ordinary file" '"miss":0' "$DET"
expect "ignores a founder RELEASE marker" '"rel":0' "$DET"

# Downgrade + human clear, driven through the real persisted-taint path.
PROD_SCHEMA="psql -d $PROD_DB -c 'DROP TABLE x'"
expect "clean source still gives a plain invariant refusal" "INVARIANT VIOLATED" \
  "$($CLI anumati try Bash "$PROD_SCHEMA" 2>&1)"

bun -e 'import { recordTaint } from "/root/aegis/src/kavach/plant-state"; recordTaint("/root/.ankr/config/databases.json","smoke test");' >/dev/null 2>&1
expect "a tainted source downgrades the verdict to UNKNOWN" "UNKNOWN STATE" \
  "$($CLI anumati try Bash "$PROD_SCHEMA" 2>&1)"
expect "taint report names the tainted source" "TAINTED" "$($CLI anumati taint 2>&1)"

$CLI anumati clear "$DB" >/dev/null 2>&1
expect_exit "clear without a reason is refused" 1 $?

$CLI anumati clear "$DB" --reason "smoke test cleanup" >/dev/null 2>&1
expect_exit "clear with a reason succeeds" 0 $?
expect "verdict returns to a plain refusal once cleared" "INVARIANT VIOLATED" \
  "$($CLI anumati try Bash "$PROD_SCHEMA" 2>&1)"

# The instrument may not be hand-written.
expect "refuses a Write to a protected source" "ANU-I-005" \
  "$($CLI anumati try Write "$DB" 2>&1)"
expect "refuses a shell redirect into a protected source" "ANU-I-005" \
  "$($CLI anumati try Bash "echo x >> /root/.ankr/config/ports.json" 2>&1)"
expect "leaves the sanctioned machine route alone" "PERMIT" \
  "$($CLI anumati try Bash "ankr-ctl restart ai-proxy" 2>&1)"

echo "── ANU-007 mode seal ─────────────────────────────────────────────────"
MODE=/root/.aegis/anumati-mode; SEAL=/root/.aegis/anumati-mode.seal.json
[ -f "$MODE" ] && cp "$MODE" "$TMP/mode.bak"
[ -f "$SEAL" ] && cp "$SEAL" "$TMP/seal.bak"

$CLI anumati mode enforce >/dev/null 2>&1
expect "a mode set through the CLI is sealed" "sealed" "$($CLI anumati mode 2>&1)"

printf 'shadow\n' > "$MODE"          # a raw downgrade, as an agent would do it
OUT=$($CLI anumati mode 2>&1)
expect "an unsealed downgrade is detected" "SEAL MISMATCH" "$OUT"
expect "and resolves to the stricter mode" "anumati mode: enforce" "$OUT"

rm -f "$MODE" "$SEAL"
[ -f "$TMP/mode.bak" ] && cp "$TMP/mode.bak" "$MODE"
[ -f "$TMP/seal.bak" ] && cp "$TMP/seal.bak" "$SEAL"

echo "── ANU-008/009/010 the compiler ──────────────────────────────────────"
CAGENT="cc-$$"
COUT="/root/.aegis/kernel/$CAGENT.coarse.json"
OUT=$($CLI anumati compile --agent "$CAGENT" --domain general --trust-mask 255 2>&1)

expect "denies an address carrying no dev-class database" "DENY" "$OUT"
expect "refuses to claim coverage it does not have" "have NO coarse form" "$OUT"
expect "names the addresses where dev and non-dev share an endpoint" "[ambiguity]" "$OUT"
expect "says an unnarrowed loopback wildcard makes local denies advisory" "[conflict]" "$OUT"

# A compiled artefact's only valid assertion is that re-deriving reproduces it.
$CLI anumati compile --agent "$CAGENT" --check >/dev/null 2>&1
expect_exit "re-deriving reproduces the compiled policy" 0 $?

python3 - "$COUT" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
d["egress_deny"] = d["egress_deny"][1:]   # a hand edit, exactly as a person would make it
json.dump(d, open(sys.argv[1], "w"), indent=2)
PYEOF
OUT=$($CLI anumati compile --agent "$CAGENT" --check 2>&1); RC=$?
expect_exit "a hand-edited coarse policy is caught as drift" 2 "$RC"
expect "and is named as a compiler bug, not patched" "Recompile, do not patch" "$OUT"

# --needs lets the compiler narrow the wildcard instead of leaving denies decorative
OUT=$($CLI anumati compile --agent "$CAGENT-n" --needs ai-proxy 2>&1)
expect "narrows the loopback wildcard when given the ports an agent needs" "[substitution]" "$OUT"

rm -f "$COUT" "/root/.aegis/kernel/$CAGENT-n.coarse.json"

echo "── ANU-I-005 enforced in the path face ───────────────────────────────"
PROFILE=/root/aegis/src/kernel/apparmor/kavachos-agent.profile

expect "the generated block is present in the profile" ">>> anumati" "$(cat $PROFILE)"
expect "it denies write on a protected source" "deny /root/.ankr/config/databases.json wkl," "$(cat $PROFILE)"
expect "it does NOT deny read (the layer must still read them)" "wkl," "$(grep 'deny /root/.aegis/anumati-mode ' $PROFILE)"

$CLI anumati enforce-paths --check >/dev/null 2>&1
expect_exit "the profile reproduces what ANU-I-005 compiles to" 0 $?

cp "$PROFILE" "$TMP/profile.bak"
sed -i 's|deny /root/.ankr/config/ports.json wkl,||' "$PROFILE"
$CLI anumati enforce-paths --check >/dev/null 2>&1
expect_exit "a hand-edited path face is caught as drift" 2 $?
cp "$TMP/profile.bak" "$PROFILE"

$CLI anumati enforce-paths --check >/dev/null 2>&1
expect_exit "and restoring it clears the drift" 0 $?

echo "── ANU-008 egress face enforces ──────────────────────────────────────"

# Regression: the base policy carries BOTH localhost:0 and 127.0.0.1:0. Removing
# only the first leaves the whole of loopback permitted and every local deny
# decorative — the exact failure this compiler exists to catch.
LOOPBACK=$(bun -e '
import { compilePolicy } from "/root/aegis/src/kavach/compile-policy";
const p = compilePolicy({agentId:"t",domain:"general",trustMask:255,loopbackPorts:[4444]});
const w = p.egress_allow.filter(e=>["127.0.0.1","::1","localhost"].includes(e.host));
console.log(JSON.stringify({wild: w.filter(e=>e.port===0).length, explicit: w.filter(e=>e.port===4444).length}));
' 2>/dev/null | tail -1)
expect "narrowing removes EVERY loopback wildcard, not just the first" '"wild":0' "$LOOPBACK"
expect "and replaces them with the explicit port on each host" '"explicit":2' "$LOOPBACK"

# End-to-end: an agent inside the jail, one allowed port and one denied address.
ALLOWED=4444
DENIED=5437
if ss -lntH "sport = :$ALLOWED" 2>/dev/null | grep -q . && ss -lntH "sport = :$DENIED" 2>/dev/null | grep -q .; then
  cat > "$TMP/both.py" <<'PYEOF'
import socket, sys
for port in (int(sys.argv[1]), int(sys.argv[2])):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3); s.close()
        print(f"REACHED {port}")
    except OSError as e:
        print(f"BLOCKED {port} {e}")
PYEOF
  OUT=$(timeout 150 bun /root/aegis/src/kavachos-cli.ts run --trust-mask=255 --domain=general \
        --session-id="anu-egress-$$" --needs=$ALLOWED -- python3 "$TMP/both.py" $ALLOWED $DENIED 2>&1)
  expect "an allowed endpoint is still reachable from inside the jail" "REACHED $ALLOWED" "$OUT"
  expect "a denied endpoint is refused at the cgroup boundary" "BLOCKED $DENIED" "$OUT"
else
  skip_note="ports $ALLOWED/$DENIED not both listening"
  bad "egress end-to-end" "$skip_note — cannot exercise enforcement"
fi

echo
echo "─────────────────────────────────────────────────────────────────────"
printf 'passed %d · failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
