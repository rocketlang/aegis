#!/usr/bin/env bash
# aegis red-team — LAUNCHER-MEASURED attestation (KOS-048, 2026-10-08).
#
# Closes the self-measurement gap: the LAUNCHER measures the agent's code/config before exec, so a
# compromised agent can't self-report a clean digest. Proves (1) the launcher's Python measure matches
# the TS `aegis attest` digest byte-for-byte (one portable baseline across pin tool and enforcer), and
# (2) the before-exec gate refuses a tampered agent (exit 3) while passing an intact one, and refuses a
# half-configured attestation. Hermetic — hashing + the real functions, no root/libseccomp path run.
#
# GAP = a tampered agent would exec, or the two languages disagree on the digest. 0 = all hold.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
APPLY="$ROOT/src/kernel/apply-seccomp.py"
echo "=== aegis red-team · launcher-measured attestation ==="
command -v python3 >/dev/null || { echo "BROKE — python3 not found"; exit 3; }
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }

D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
printf 'export const run=()=>1;\n' > "$D/agent.js"
printf '{"scope":"read-only"}\n'   > "$D/config.json"
printf "%s\n%s\n" "$D/agent.js" "$D/config.json" > "$D/manifest.txt"

gaps=0
SAFE(){ [ "$1" = 0 ] && { echo "  [safe] $2"; } || { echo "  [GAP ] $2"; gaps=$((gaps+1)); }; }  # $1 = shell exit of the assertion (0 = held)

# TS pin (the operator's `aegis attest` path) vs Python launcher measure — must agree
TSD="$("$BUN" -e 'import {measureFiles} from "./src/core/attest.ts"; console.log(measureFiles(process.argv.slice(1)).digest)' "$D/agent.js" "$D/config.json" 2>/dev/null)"
PYD="$(python3 "$APPLY" --attest-measure "$D/agent.js" "$D/config.json" 2>/dev/null)"
[ -n "$TSD" ] && [ "$TSD" = "$PYD" ]; SAFE $? "TS pin digest == launcher (Python) digest — one baseline is portable (${TSD:0:12}…)"

gate(){ # args: baseline ; env MANIFEST set by caller
  python3 - "$APPLY" <<'PY' 2>/dev/null
import importlib.util,sys
spec=importlib.util.spec_from_file_location("m",sys.argv[1]); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m._attest_before_exec(); print("EXEC-PROCEEDED")
PY
}

# 1) intact agent + correct baseline → gate lets exec proceed
out="$(KAVACHOS_ATTEST_MANIFEST="$D/manifest.txt" KAVACHOS_ATTEST_BASELINE="$PYD" gate)"; rc=$?
[ "$rc" = 0 ] && echo "$out" | grep -q EXEC-PROCEEDED; SAFE $? "intact agent attests → exec proceeds"

# 2) tampered config → gate refuses to exec (exit 3)
printf '{"scope":"admin"}\n' > "$D/config.json"
KAVACHOS_ATTEST_MANIFEST="$D/manifest.txt" KAVACHOS_ATTEST_BASELINE="$PYD" gate >/dev/null 2>&1; rc=$?
[ "$rc" = 3 ]; SAFE $? "tampered config → launcher REFUSES to exec (exit 3), before the agent runs"
printf '{"scope":"read-only"}\n' > "$D/config.json"

# 3) half-configured (baseline, no manifest) → refuse
KAVACHOS_ATTEST_BASELINE="$PYD" gate >/dev/null 2>&1; rc=$?
[ "$rc" = 3 ]; SAFE $? "half-configured attestation → refuse (need both manifest and baseline)"

# 4) not configured → gate is a no-op (attestation is opt-in)
out="$(gate)"; rc=$?
[ "$rc" = 0 ] && echo "$out" | grep -q EXEC-PROCEEDED; SAFE $? "attestation not configured → no-op (opt-in), exec proceeds"

echo
echo "  attestation-launcher: $gaps gap(s)$([ $gaps -eq 0 ] && echo ' — the launcher measures the agent and refuses a tampered one ✓ (ceiling: the launcher/host itself needs hardware attestation)' || echo ' (RED until fixed)')"
exit $(( gaps > 0 ? 1 : 0 ))
