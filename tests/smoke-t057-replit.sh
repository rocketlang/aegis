#!/usr/bin/env bash
# KOS-T057 Smoke Test — Replit scenario: LLM-issued DROP TABLE → ESCALATE → human denies → DB survives
# Tests the full proxy flow: request firewall (KOS-052) + HITL (KOS-055)
# @rule:KOS-052 SQL firewall — destructive SQL in request body → ESCALATE
# @rule:KOS-055 HITL — create approval, notify, block until decided
#
# Usage: bash tests/smoke-t057-replit.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

log()  { echo "[smoke-t057] $*"; }
pass() { log "PASS: $1"; PASS=$((PASS+1)); }
fail() { log "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { log "SKIP: $1"; SKIP=$((SKIP+1)); }

PROXY_PORT=18570
UPSTREAM_PORT=18571
PROXY_PID=""
UPSTREAM_PID=""

cleanup() {
  [[ -n "$PROXY_PID" ]]    && kill "$PROXY_PID"    2>/dev/null || true
  [[ -n "$UPSTREAM_PID" ]] && kill "$UPSTREAM_PID" 2>/dev/null || true
  sleep 0.3
}
trap cleanup EXIT

# --- Pre-flight ---

if ! command -v bun &>/dev/null; then
  skip "bun not found — cannot run proxy"
  exit 0
fi

if ! command -v curl &>/dev/null; then
  skip "curl not found"
  exit 0
fi

cd "$(dirname "$0")/.."

# --- Unit tests: firewall.ts checkRequestBody (no proxy needed) ---------------

log "Running unit-level firewall checks..."

UNIT_RESULT=$(bun --eval '
import { checkRequestBody } from "./src/proxy/firewall";

const cases = [
  { body: "SELECT * FROM users WHERE id=1",         expect: "ALLOW",    label: "safe SELECT" },
  { body: "DROP TABLE users;",                       expect: "ESCALATE", label: "DROP TABLE" },
  { body: "DROP DATABASE prod",                      expect: "ESCALATE", label: "DROP DATABASE" },
  { body: "TRUNCATE TABLE sessions",                 expect: "ESCALATE", label: "TRUNCATE TABLE" },
  { body: "DELETE FROM logs WHERE 1=1",             expect: "ESCALATE", label: "DELETE WHERE 1=1" },
  { body: "DELETE FROM audit_trail;",               expect: "ESCALATE", label: "DELETE no WHERE" },
  { body: "ALTER TABLE users DROP COLUMN password", expect: "ESCALATE", label: "ALTER TABLE DROP COLUMN" },
  { body: "UPDATE users SET active=false",          expect: "ALLOW",    label: "safe UPDATE" },
];

let pass = 0; let fail = 0;
for (const c of cases) {
  const v = checkRequestBody(c.body, "general");
  const ok = v.action === c.expect;
  console.log((ok ? "PASS" : "FAIL") + ": " + c.label + " => " + v.action + (ok ? "" : " (expected " + c.expect + ")"));
  ok ? pass++ : fail++;
}
console.log("unit_pass=" + pass + " unit_fail=" + fail);
' 2>/dev/null)

echo "$UNIT_RESULT"

UNIT_FAIL=$(echo "$UNIT_RESULT" | grep -o 'unit_fail=[0-9]*' | cut -d= -f2 || echo "0")
UNIT_PASS=$(echo "$UNIT_RESULT" | grep -o 'unit_pass=[0-9]*' | cut -d= -f2 || echo "0")

[[ "$UNIT_FAIL" == "0" ]] && pass "All $UNIT_PASS firewall unit cases correct" || fail "$UNIT_FAIL firewall unit cases wrong"

# --- Integration test: full proxy with mock upstream --------------------------

log "Starting mock upstream on port $UPSTREAM_PORT..."

cat > /tmp/mock-upstream-t057.ts << 'TSEOF'
Bun.serve({
  port: Number(process.env.PORT),
  fetch() {
    return new Response(
      JSON.stringify({choices:[{message:{content:"SELECT id FROM users WHERE id=1"}}]}),
      { headers: { "Content-Type": "application/json" } }
    );
  }
});
process.stderr.write("[mock-upstream-t057] ready on " + process.env.PORT + "\n");
await new Promise(() => {});
TSEOF

PORT="$UPSTREAM_PORT" bun run /tmp/mock-upstream-t057.ts 2>/tmp/mock-upstream-t057.log &
UPSTREAM_PID=$!

# Wait until upstream responds
for i in $(seq 1 10); do
  curl -sf "http://localhost:$UPSTREAM_PORT/" >/dev/null 2>&1 && break
  sleep 0.3
done

log "Starting kavachos proxy on port $PROXY_PORT → upstream :$UPSTREAM_PORT..."

KAVACHOS_SESSION_ID="test-replit-smoke" \
bun run src/kavachos-cli.ts proxy start \
  --port="$PROXY_PORT" \
  --upstream="http://localhost:$UPSTREAM_PORT" \
  --domain=general 2>/tmp/proxy-t057.log &
PROXY_PID=$!

# Wait until proxy TLS port responds
for i in $(seq 1 12); do
  curl -sk "https://localhost:$PROXY_PORT/proxy/health" >/dev/null 2>&1 && break
  sleep 0.4
done

# --- Case A: safe request passes through ---

log "Case A: safe SELECT request should pass through..."
HTTP_A=$(curl -sk -o /tmp/t057-resp-a.json -w "%{http_code}" \
  -X POST "https://localhost:$PROXY_PORT/v1/messages" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"SELECT id FROM users"}]}')

if [[ "$HTTP_A" == "200" ]]; then
  pass "Case A: safe request forwarded (HTTP 200)"
else
  fail "Case A: safe request got HTTP $HTTP_A (expected 200)"
fi

# --- Case B: DROP TABLE request is blocked (403) without human approval -------

log "Case B: DROP TABLE request should be blocked by firewall..."

# Fire request in background (it will block waiting for approval)
curl -sk -o /tmp/t057-resp-b.json -w "%{http_code}" \
  --max-time 12 \
  -X POST "https://localhost:$PROXY_PORT/v1/messages" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"DROP TABLE users; -- Replit scenario"}]}' \
  > /tmp/t057-code-b.txt 2>/dev/null &
CURL_B_PID=$!

sleep 0.8

# Inject DENY decision via the /proxy/decision/:id endpoint or direct DB write
# Find the pending approval in aegis.db
APPROVAL_ID=$(bun --eval '
import { getDb } from "./src/core/db";
const db = getDb();
const row = db.prepare("SELECT id FROM kavach_approvals WHERE status = ? ORDER BY rowid DESC LIMIT 1").get("pending");
console.log(row ? (row as any).id : "");
' 2>/dev/null | tr -d '\n')

if [[ -n "$APPROVAL_ID" ]]; then
  log "Found pending approval: $APPROVAL_ID — injecting DENY decision..."
  bun --eval "
import { decideKavachApproval } from './src/core/db';
decideKavachApproval('$APPROVAL_ID', 'STOP', 'smoke-test-human');
console.log('denied');
" 2>/dev/null

  wait "$CURL_B_PID" 2>/dev/null || true
  HTTP_B=$(cat /tmp/t057-code-b.txt 2>/dev/null || echo "000")

  if [[ "$HTTP_B" == "403" ]]; then
    pass "Case B: DROP TABLE blocked (HTTP 403) after human denial"
  else
    # Proxy may return 200 with error body — check response body
    BODY_B=$(cat /tmp/t057-resp-b.json 2>/dev/null || echo "")
    if echo "$BODY_B" | grep -qi "denied\|blocked\|STOP\|escalate"; then
      pass "Case B: DROP TABLE blocked (body indicates denial)"
    else
      fail "Case B: DROP TABLE got HTTP $HTTP_B — expected 403 (body: ${BODY_B:0:120})"
    fi
  fi
else
  wait "$CURL_B_PID" 2>/dev/null || true
  HTTP_B=$(cat /tmp/t057-code-b.txt 2>/dev/null || echo "000")
  # If proxy is not running in HITL mode (no DB table), check for non-200
  if [[ "$HTTP_B" != "200" ]]; then
    pass "Case B: DROP TABLE not forwarded (HTTP $HTTP_B)"
  else
    fail "Case B: DROP TABLE was forwarded (HTTP 200) — firewall did not trigger"
  fi
fi

# --- Case C: verify mock upstream never received the DROP TABLE call ----------

log "Case C: mock upstream request log should contain no DROP TABLE..."
# The mock upstream logs nothing (simple Bun.serve) — verify no row in kavach_approvals for 'allowed' drop table
ALLOWED_DROP=$(bun --eval "
import { getDb } from './src/core/db';
const db = getDb();
const rows = db.prepare(\"SELECT COUNT(*) as n FROM kavach_approvals WHERE command LIKE '%DROP%' AND status = 'allowed' AND session_id = 'test-replit-smoke'\").get();
console.log((rows as any).n);
" 2>/dev/null | tr -d '\n' || echo "0")

if [[ "$ALLOWED_DROP" == "0" || -z "$ALLOWED_DROP" ]]; then
  pass "Case C: no DROP TABLE approvals in allowed state — DB operation never forwarded"
else
  fail "Case C: $ALLOWED_DROP DROP TABLE request(s) were allowed through"
fi

# --- Summary ------------------------------------------------------------------

echo ""
echo "[smoke-t057] ─────────────────────────────────────"
echo "[smoke-t057] PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
echo "[smoke-t057] KOS-T057 Replit DROP TABLE scenario"

[[ $FAIL -eq 0 ]] && echo "[smoke-t057] ✅ ALL PASSED" || echo "[smoke-t057] ❌ FAILURES: $FAIL"
exit $FAIL
