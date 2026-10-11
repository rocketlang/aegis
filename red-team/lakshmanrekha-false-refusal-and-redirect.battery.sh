#!/usr/bin/env bash
# aegis red-team — @xshieldai/lakshmanrekha: an answer is not a refusal, and the key follows no redirect.
#
# Runs lakshmanrekha-false-refusal-and-redirect.probe.ts against an INSTALLED copy of the package, never against
# the source tree. Loopback only.
#
#   ./red-team/lakshmanrekha-false-refusal-and-redirect.battery.sh                 the copy packed from this repository
#   LR_VERSION=0.4.0 ./red-team/lakshmanrekha-false-refusal-and-redirect.battery.sh   that version from the npm registry
#
# Red on 0.4.0, green from 0.4.1. Exit: 0 no gap · 1 a gap · 3 broke, or the probe did not run all its cases.
set -u
EXPECT_CASES=17
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · lakshmanrekha: an answer is not a refusal; the key follows no redirect ==="
[ -x "$BUN" ] && command -v npm >/dev/null || { echo "BROKE — bun or npm not found"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/lr-probe.XXXXXX")"; trap 'rm -rf "$T"' EXIT
echo '{"name":"t","private":true}' > "$T/package.json"
if [ -n "${LR_VERSION:-}" ]; then
  WHAT="@xshieldai/lakshmanrekha@$LR_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/lakshmanrekha" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not pack packages/lakshmanrekha"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"
  [ -n "$WHAT" ] || { echo "BROKE — no tarball was made"; exit 3; }
fi
( cd "$T" && npm i --ignore-scripts --no-fund --no-audit "$WHAT" >/dev/null 2>&1 ) || { echo "BROKE — install failed ($WHAT)"; exit 3; }
echo "version: $(node -p "require('$T/node_modules/@xshieldai/lakshmanrekha/package.json').version") ($SRC)"
cp "$HERE/lakshmanrekha-false-refusal-and-redirect.probe.ts" "$T/probe.ts"
OUT="$( cd "$T" && HOME="$T" "$BUN" "$T/probe.ts" 2>&1 )"; rc=$?
echo "$OUT"
# The probe's own word that it reached its end, and how many cases it ran. Without it an exit code proves nothing.
ran="$(echo "$OUT" | sed -n 's/^RESULT cases=\([0-9][0-9]*\) gaps=[0-9][0-9]*.*/\1/p' | tail -1)"
if [ "${ran:-0}" -lt "$EXPECT_CASES" ]; then echo "BROKE — the probe ran ${ran:-0} case(s), expected at least $EXPECT_CASES"; rc=3; fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc"
exit $rc
