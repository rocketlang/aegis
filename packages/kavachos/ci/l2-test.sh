#!/usr/bin/env bash
# KavachOS L2 smoke test — cgroup-BPF egress firewall, on a real kernel.
#
# L2 loads BPF into the kernel and attaches to the cgroup2 tree, so it mutates shared kernel
# state. It runs ONLY on a disposable/ephemeral host (an ephemeral CI runner, or a throwaway VM
# torn down after) — never a live/shared box. That is the first act below: a fail-closed refusal.
#
# Tests the PUBLISHED @xshieldai/agent-kernel (pass its install dir), as root.
# Usage: sudo bash l2-test.sh <installed-pkg-dir>
# Exit:  0 pass · 1 a check failed · 2 refused (not a disposable host, or usage) · 3 environment

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# ── run only on a disposable host (fail-closed) ──────────────────────────────────────────────
disposable=false
{ [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${KAVACH_L2_DISPOSABLE:-}" = "1" ]; } && disposable=true
live=false
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:4850/health" 2>/dev/null && live=true
[ -d /root/.ankr/state ] && live=true
if [ "$disposable" != true ] || [ "$live" = true ]; then
  echo "[L2] REFUSING: runs only on a disposable host (need GITHUB_ACTIONS=true or KAVACH_L2_DISPOSABLE=1, and no live-box fingerprints). disposable=$disposable live=$live" >&2
  exit 2
fi

PKG="${1:-${AK_PKG:-}}"
[ -n "$PKG" ] || { echo "[L2] usage: sudo bash l2-test.sh <installed-pkg-dir>"; exit 2; }
CLI="$PKG/dist/kavachos.js"; EGRESS="$PKG/dist/cgroup-egress.py"
for f in "$CLI" "$EGRESS"; do [ -f "$f" ] || { echo "[L2] env — missing $f"; exit 3; }; done
[ "$(id -u)" = 0 ] || { echo "[L2] env — must run as root"; exit 3; }
for t in bun python3 clang bpftool; do command -v "$t" >/dev/null || { echo "[L2] env — need $t"; exit 3; }; done
grep -q cgroup2 /proc/filesystems || { echo "[L2] env — no cgroup v2"; exit 3; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/l2-XXXXXX")"; HOME_T="$WORK/home"; mkdir -p "$HOME_T"
SID="L2CI$$"; DENY_IP="1.1.1.1"; DENY_PORT="443"
cleanup(){ rmdir "/sys/fs/cgroup/kavachos/$SID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
probe(){ python3 "$HERE/connect-probe.py" "$1" "$2"; }

pass=0; fail=0
ok(){ echo "  [PASS] $1 — $2"; pass=$((pass+1)); }
no(){ echo "  [FAIL] $1 — $2"; fail=$((fail+1)); }

echo "=== KavachOS L2 smoke test — $(hostname) kernel $(uname -r) ==="
echo "package: $PKG"

# 1) control: with no egress cgroup, the deny target is reachable (so a later EPERM is the firewall)
CTRL="$(probe "$DENY_IP" "$DENY_PORT")"
[ "$CTRL" = OK ] && ok "L2-01 control reachable" "connect $DENY_IP:$DENY_PORT OK outside any cgroup" \
                 || no "L2-01 control reachable" "expected OK, got $CTRL"

# 2) generate a real egress policy via the published runner (dry-run writes the egress policy file)
DR="$(HOME="$HOME_T" bun "$CLI" run true --trust-mask=0xFF --domain=general --dry-run 2>/dev/null)"
POL="$(printf '%s' "$DR" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("egressPolicyPath",""))' 2>/dev/null)"
[ -n "$POL" ] && [ -f "$POL" ] || { echo "[L2] env — dry-run produced no egress policy"; echo "$DR" | head -3; exit 3; }
echo "  policy: $POL (allow: $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("allow",[])))' "$POL"))"

# 3) arm: --prepare must write a cgroup path (not UNAVAILABLE/FAILED)
READY="$WORK/ready"; rm -f "$READY"
python3 "$EGRESS" "$SID" "$POL" --prepare "$READY" >"$WORK/egress.log" 2>&1 &
SUP=$!
CG=""; for _ in $(seq 1 40); do [ -s "$READY" ] && { CG="$(tr -d '\r' < "$READY")"; break; }; sleep 0.25; done
if [ "${CG#/sys/fs/cgroup/kavachos/}" != "$CG" ]; then
  ok "L2-02 arm" "cgroup-BPF compiled, loaded and attached on a real kernel ($CG)"
  # 4) default-deny: a process INSIDE the cgroup is EPERM'd to the non-allowlisted IP
  DENY="$(bash -c 'echo $$ > "$1/cgroup.procs"; exec python3 "$2" "$3" "$4"' _ "$CG" "$HERE/connect-probe.py" "$DENY_IP" "$DENY_PORT")"
  [ "$DENY" = "ERR:EPERM" ] && ok "L2-03 default-deny enforced" "connect $DENY_IP:$DENY_PORT (not allowlisted) refused EPERM inside the cgroup" \
                           || no "L2-03 default-deny enforced" "expected ERR:EPERM, got $DENY"
else
  no "L2-02 arm" "no cgroup produced (verdict: ${CG:-none}); see egress.log"; sed -n '1,20p' "$WORK/egress.log"
fi
kill "$SUP" 2>/dev/null; wait "$SUP" 2>/dev/null; rmdir "/sys/fs/cgroup/kavachos/$SID" 2>/dev/null || true

# 5) Falco rules generate (rule_count > 0)
FR="$(HOME="$HOME_T" bun "$CLI" generate --trust-mask=0xFF --domain=maritime 2>/dev/null | sed -n 's/.*Falco rules:[[:space:]]*\([0-9]\+\).*/\1/p' | head -1)"
{ [ -n "$FR" ] && [ "$FR" -gt 0 ]; } && ok "L2-04 Falco rules generated" "maritime: $FR rules" \
                                    || no "L2-04 Falco rules generated" "expected >0, got ${FR:-none}"

echo "  --- stated: allow-path (a permitted host proceeds) depends on the compiled allowlist; default-deny + the reachable control is the enforcement claim. Falco RUNTIME detection is a follow-up. ---"
echo "=== L2: $pass pass · $fail fail ==="
[ "$fail" -eq 0 ]
