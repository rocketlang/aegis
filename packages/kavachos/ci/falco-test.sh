#!/usr/bin/env bash
# KavachOS L2 — Falco RUNTIME detection (not just rule generation).
# Loads the PUBLISHED package's generated Falco rules, trips one at runtime, and confirms Falco
# fires an alert naming a KavachOS rule. Disposable host only (mutates kernel state via the probe).
#
# Usage: sudo bash falco-test.sh <installed-pkg-dir>
# Exit:  0 a KavachOS rule fired · 1 none fired · 2 refused (not disposable) · 3 environment
set -uo pipefail

disposable=false
{ [ "${GITHUB_ACTIONS:-}" = "true" ] || [ "${KAVACH_L2_DISPOSABLE:-}" = "1" ]; } && disposable=true
live=false
curl -s -o /dev/null --max-time 2 "http://127.0.0.1:4850/health" 2>/dev/null && live=true
[ -d /root/.ankr/state ] && live=true
{ [ "$disposable" = true ] && [ "$live" = false ]; } || { echo "[falco] REFUSING: disposable host only (disposable=$disposable live=$live)"; exit 2; }

PKG="${1:-${AK_PKG:-}}"; CLI="$PKG/dist/kavachos.js"
[ -f "$CLI" ] || { echo "[falco] env — missing $CLI"; exit 3; }
[ "$(id -u)" = 0 ] || { echo "[falco] env — must run as root"; exit 3; }
command -v falco >/dev/null || { echo "[falco] env — falco not installed"; exit 3; }
command -v bun   >/dev/null || { echo "[falco] env — bun not on PATH (sudo)"; exit 3; }

W="$(mktemp -d "${TMPDIR:-/tmp}/falco-XXXXXX")"; HOME_T="$W/home"; mkdir -p "$HOME_T"; trap 'rm -rf "$W"' EXIT

# Generate the rules the published package emits for a domain (general → base rules incl. the
# CRITICAL exfil rule and the credential-read rule).
HOME="$HOME_T" bun "$CLI" generate --trust-mask=0xFF --domain=general --out="$W/r" >/dev/null 2>&1
RULES="$W/r.falco.yaml"
[ -f "$RULES" ] || { echo "[falco] no rules generated"; exit 3; }
echo "[falco] rules: $(grep -c '^- rule:' "$RULES") from the published package"

# Start Falco on the modern eBPF probe, loading ONLY our rules, JSON events to a file.
falco -o engine.kind=modern_ebpf \
      -r "$RULES" \
      -o json_output=true -o stdout_output.enabled=true \
      -o priority=informational \
      >"$W/falco.out" 2>"$W/falco.err" &
FPID=$!

# Wait for the probe to attach (Falco prints readiness to stderr), then a cushion.
ready=no
for _ in $(seq 1 40); do
  grep -qiE "Falco initialized|starting internal|enabled event sources|Events detected|run_result|Loading rules" "$W/falco.err" 2>/dev/null && { ready=yes; break; }
  kill -0 "$FPID" 2>/dev/null || break
  sleep 1
done
echo "[falco] probe ready=$ready"
sleep 4

# Trip (1) the exfil rule — execve with cmdline containing curl; (2) the credential-read rule.
curl --version >/dev/null 2>&1 || true
printf 'x\n' > "$W/seed.env"; cat "$W/seed.env" >/dev/null 2>&1
sleep 5

kill "$FPID" 2>/dev/null; wait "$FPID" 2>/dev/null

if grep -qE "kavachos_(exfil_command|credential_read|unexpected_execve)" "$W/falco.out" "$W/falco.err" 2>/dev/null; then
  echo "[falco] PASS — KavachOS rule(s) fired at runtime:"
  grep -ohE "kavachos_[a-z_]+" "$W/falco.out" "$W/falco.err" 2>/dev/null | sort -u | sed 's/^/   · /'
  exit 0
fi
echo "[falco] FAIL — no KavachOS rule fired."
echo "--- falco.err (tail) ---"; tail -25 "$W/falco.err" 2>/dev/null
echo "--- falco.out (tail) ---"; tail -10 "$W/falco.out" 2>/dev/null
exit 1
