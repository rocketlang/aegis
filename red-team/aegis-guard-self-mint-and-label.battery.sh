#!/usr/bin/env bash
# atma-pariksha — ADVERSARIAL battery for @xshieldai/aegis-guard (reproduces an Oct-2026 review's findings).
# Red test: GAP lines = the exploit succeeded. RED until the code is fixed, then it goes green.
# Tests the PUBLISHED package, in a throwaway HOME (the signing key + store land there, disposable).
set -u
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
PROBE="$(cd "$(dirname "$0")" && pwd)/aegis-guard-self-mint-and-label.probe.ts"
echo "=== Adversarial battery · @xshieldai/aegis-guard ==="
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/advbat-ag.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/home/.aegis"
echo "installing @xshieldai/aegis-guard (published copy)…"
( cd "$TMP" && npm i @xshieldai/aegis-guard --prefix "$TMP" >/dev/null 2>&1 ) || { echo "BROKE — install failed"; exit 3; }
echo "version: $(node -p "require('$TMP/node_modules/@xshieldai/aegis-guard/package.json').version")"

cp "$PROBE" "$TMP/probe.ts"
( cd "$TMP" && HOME="$TMP/home" "$BUN" "$TMP/probe.ts" )
rc=$?
echo "EXIT=$rc   (0 = all gaps closed · 1 = gaps reproduced, RED until fixed)"
exit $rc
