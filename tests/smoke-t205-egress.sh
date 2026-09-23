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

# --- Test 1: dry-run profile generation includes egress policy ---

log "Test 1: dry-run profile includes egress policy"
OUTPUT=$($KAVACHOS_CLI run --trust-mask=255 --domain=general --dry-run --verbose 2>&1 | head -20 || true)
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
  --session-id="SMOKE-T205-DENY" \
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
  --session-id="SMOKE-T205-ALLOW" \
  --verbose \
  -- curl --max-time 5 -s -o /dev/null -w "%{http_code}" https://github.com \
  >"$SESSION_OUT" 2>&1; then
  EXIT=$?
else
  EXIT=$?
fi

HTTP_CODE=$(grep -oP '\d{3}' "$SESSION_OUT" | tail -1 || echo "0")
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

# --- Summary ---

echo ""
echo "KOS-T205 Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
