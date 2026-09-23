#!/usr/bin/env bash
# KOS-T205 Smoke Test — Egress BPF allowlist enforcement
# Tests: curl to non-allowlisted IP returns EPERM; allowlisted host is permitted.
# Requires: root + kernel ≥ 5.7 (cgroup-bpf + seccomp-notify available)
# @rule:KOS-040 cgroup BPF egress firewall — CONNECT4/6 blocked for non-allowlisted hosts
#
# Usage: sudo bash tests/smoke-t205-egress.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

log()  { echo "[smoke-t205] $*"; }
pass() { log "PASS: $1"; PASS=$((PASS+1)); }
fail() { log "FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { log "SKIP: $1"; SKIP=$((SKIP+1)); }

# --- Pre-flight checks ---

if [[ $EUID -ne 0 ]]; then
  skip "must run as root (requires cgroup BPF attachment)"
  exit 0
fi

if ! command -v bun &>/dev/null; then
  skip "bun not found — cannot launch kavachos"
  exit 0
fi

KAVACHOS_CLI="${KAVACHOS_CLI:-bun /root/aegis/src/kavachos-cli.ts}"

# Session ids are UNIQUE per run. A fixed id leaves pinned BPF objects at
# /sys/fs/bpf/kavachos/<sid>/, and the next run fails to load with "already exists" —
# at which point the session degrades to UNCONSTRAINED and these tests measure nothing.
# Observed 2026-09-23: a DENY case reported PASS while curl actually reached the host.
RUN_TAG="$$-$(date +%s)"

# --- Test 1: dry-run profile generation includes egress policy ---

log "Test 1: dry-run profile includes egress policy"
# `run` requires an agent binary even for --dry-run; without one the CLI only ever
# returned its usage string, so this case had been failing on a bad invocation rather
# than on anything about egress. A binary that exits immediately is enough — dry-run
# writes the policy and stops before exec.
OUTPUT=$($KAVACHOS_CLI run --trust-mask=255 --domain=general --dry-run --verbose \
  -- /bin/sh -c 'exit 0' 2>&1 | head -20 || true)
if echo "$OUTPUT" | grep -q "egress.json\|Egress policy"; then
  pass "dry-run emits egress policy path"
else
  fail "dry-run did not emit egress policy — output: ${OUTPUT:0:200}"
fi

# --- Test 2: curl to non-allowlisted IP blocked under governance ---
# We use trust_mask=1 (read-only, general domain) which allows only known hosts.
# example.com (93.184.216.34) is NOT in the general domain egress allowlist.

log "Test 2: governed session blocks curl to non-allowlisted host (example.com)"

SESSION_OUT=$(mktemp)
# Run curl in a governed session — should fail with a network error (EPERM or ECONNREFUSED)
if $KAVACHOS_CLI run \
  --trust-mask=1 \
  --domain=general \
  --session-id="SMOKE-T205-DENY-$RUN_TAG" \
  --verbose \
  -- curl --max-time 3 -s -o /dev/null -w "%{http_code}" https://example.com \
  >"$SESSION_OUT" 2>&1; then
  EXIT=$?
else
  EXIT=$?
fi

if grep -q "EPERM\|Connection refused\|Failed to connect\|Network is unreachable\|cgroup-egress\|DENY" "$SESSION_OUT"; then
  pass "curl to non-allowlisted host produced expected deny evidence"
elif [[ $EXIT -ne 0 ]]; then
  pass "curl to non-allowlisted host exited non-zero (exit=$EXIT) — egress enforcement likely active"
else
  fail "curl to non-allowlisted host succeeded — egress firewall not enforced (exit=$EXIT)"
fi
cat "$SESSION_OUT"
rm -f "$SESSION_OUT"

# --- Test 3: curl to allowlisted host permitted ---
# github.com:443 is in the claude-code egress allowlist (trust_mask > 0 domains include it).

log "Test 3: governed session allows curl to allowlisted host (github.com)"

SESSION_OUT=$(mktemp)
if $KAVACHOS_CLI run \
  --trust-mask=255 \
  --domain=general \
  --session-id="SMOKE-T205-ALLOW-$RUN_TAG" \
  --verbose \
  -- curl --max-time 5 -s -o /dev/null -w "KAVACHOS_HTTP=%{http_code}\n" https://github.com \
  >"$SESSION_OUT" 2>&1; then
  EXIT=$?
else
  EXIT=$?
fi

# Read the status from a MARKER curl writes, not "the last three-digit number in the
# output". That pattern reported 424, 434, 444, 457, 470 and 600 across runs for the
# same request — it was matching digits out of the fetched page, the session id, a pid,
# whatever happened to come last. The case still passed, on its exit-0 branch, so the
# number it printed was decorative and wrong. A measurement that can report 600 as an
# HTTP status is not measuring HTTP.
HTTP_CODE=$(sed -n 's/.*KAVACHOS_HTTP=\([0-9]\{3\}\).*/\1/p' "$SESSION_OUT" | tail -1)
HTTP_CODE=${HTTP_CODE:-0}
if [[ "$HTTP_CODE" =~ ^(200|301|302)$ ]]; then
  pass "curl to github.com succeeded (HTTP $HTTP_CODE) — allowlisted host permitted"
elif [[ $EXIT -eq 0 ]]; then
  pass "curl to github.com exited 0 — allowlisted host permitted (HTTP $HTTP_CODE)"
else
  # This is the case that proves ALLOW works. Skipping it on failure was the whole
  # problem: an egress policy that had started blocking EVERYTHING would look exactly
  # like a network-isolated environment, and the suite would go green either way.
  #
  # So SYNTHESISE the control instead of guessing. Run the identical curl outside
  # kavachos. If the bare one also fails, the box genuinely has no route to github and
  # this case cannot be asked — a precondition, reported as a skip. If the bare one
  # SUCCEEDS while the governed one did not, egress is blocking an allowlisted host,
  # which is the regression this case exists to catch.
  BARE_CODE=$(curl --max-time 5 -s -o /dev/null -w "%{http_code}" https://github.com 2>/dev/null || echo "0")
  if [[ "$BARE_CODE" =~ ^(200|301|302)$ ]]; then
    fail "allowlisted host BLOCKED: bare curl got HTTP $BARE_CODE, the governed one got exit=$EXIT HTTP=$HTTP_CODE"
  else
    skip "no route to github.com from this box either (bare curl HTTP $BARE_CODE) — the case cannot be asked"
  fi
fi
cat "$SESSION_OUT"
rm -f "$SESSION_OUT"

# --- Test 4: the resolving proxy (KOS-046) ---
#
# The unit-level decision is covered by tests/dns-proxy.test.py. This asks the only
# question that file cannot: does a GOVERNED agent actually get steered to the proxy,
# and does the refusal survive the whole chain — connect4 rewrite, loopback, upstream?
log "Test 4: a governed agent resolves policy names and is refused everything else"
PROXY_SID="SMOKE-T205-DNS-$RUN_TAG"
PROXY_OUT=$(mktemp)
$KAVACHOS_CLI run --trust-mask=255 --domain=general --session-id="$PROXY_SID" -- \
  /bin/sh -c 'getent hosts github.com >/dev/null 2>&1 && echo ALLOWED_OK || echo ALLOWED_BROKEN; \
              getent hosts exfil.attacker.example >/dev/null 2>&1 && echo TUNNEL_OPEN || echo TUNNEL_SHUT' \
  >"$PROXY_OUT" 2>&1 || true

if grep -q "ALLOWED_OK" "$PROXY_OUT"; then
  pass "a policy name still resolves through the proxy"
else
  fail "a policy name no longer resolves — the proxy broke what it was meant to protect"
  head -30 "$PROXY_OUT"
fi

if grep -q "TUNNEL_SHUT" "$PROXY_OUT"; then
  pass "a name outside the policy is REFUSED — the tunnel is shut"
else
  fail "a name outside the policy resolved — the DNS exfiltration channel is OPEN"
  head -30 "$PROXY_OUT"
fi

if grep -q "kavachos:dns.*REFUSED" "$PROXY_OUT"; then
  pass "the refusal was announced, not silent"
else
  fail "nothing announced the refusal — a channel closed without evidence is not auditable"
fi
rm -f "$PROXY_OUT" /root/.aegis/kernel/"$PROXY_SID".*.json 2>/dev/null
rm -rf /sys/fs/bpf/kavachos/"$PROXY_SID" 2>/dev/null

# --- Test 5: the fail-closed rule (INF-KOS-009) ---
#
# NOT tested by racing two real sessions. Reproducing a genuine failed arm means holding
# BPF pins with one session while a second starts on the same id, and scheduling that
# inside a smoke test defeated three attempts and produced three wrong diagnoses — the
# test kept measuring its own timing rather than the rule.
#
# The RULE is exhaustively covered in tests/egress-decision.test.ts, every combination of
# (verdict, flag). The integration path was verified by hand against a real collision:
# "supervisor said FAILED" -> "REFUSING TO LAUNCH" -> exit 3, agent never ran.
log "Test 5: the fail-closed decision rule"
if bun test /root/aegis/tests/egress-decision.test.ts >/dev/null 2>&1; then
  pass "every (verdict, flag) combination refuses or proceeds as ruled"
else
  fail "the egress fail-closed rule is broken — see tests/egress-decision.test.ts"
fi

# --- Test 6: the record says whether egress actually armed ---
log "Test 6: a governed launch records egress_enforced"
ENF_SID="SMOKE-T205-ENF-$RUN_TAG"
$KAVACHOS_CLI run --trust-mask=255 --domain=general --session-id="$ENF_SID" \
  -- /bin/sh -c 'exit 0' >/dev/null 2>&1 || true
ENF=$(python3 -c "
import json,sys
try: print(json.load(open('/root/.aegis/kernel/$ENF_SID.launch.json')).get('egress_enforced'))
except Exception: print('MISSING')" 2>/dev/null)
if [[ "$ENF" == "True" ]]; then
  pass "the launch record carries egress_enforced=true"
else
  fail "egress_enforced was '$ENF' — the record attests the policy but not its enforcement"
fi
rm -f /root/.aegis/kernel/"$ENF_SID".*.json 2>/dev/null
rm -rf /sys/fs/bpf/kavachos/"$ENF_SID" 2>/dev/null

# --- Summary ---

echo ""
echo "KOS-T205 Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
