#!/usr/bin/env bash
# aegis red-team — the package AS NPM INSTALLS IT (2026-10-10, aegis 2.16.1).
#
# Every test in this repository runs the repository's own copy of the @xshieldai/* packages (tsconfig paths).
# What a user gets is different: the published tarball, with its dependencies resolved from the registry.
# 2.16.0 shipped with a dashboard that could not start from an install, and no test here could see it.
#
# This packs the working tree, installs the tarball into an empty folder (dependencies from the registry, so it
# needs the network), and then: lists the @xshieldai versions that were actually installed, checks the three
# entry points still bundle, starts the DASHBOARD from the install on a spare port in a temporary home, and runs
# one ledger command. It also checks the dashboard REFUSES to start without AEGIS_MINT_AUTHORITY=1 and says why:
# since aegis-guard 0.6.0 minting is an authority action, and a silent start would hide that.
#
# Exit: 0 it installs and runs · 1 something that works in the repository does not work installed · 3 broke.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; PORT="${TEST_PORT:-48996}"
T="$(mktemp -d /tmp/aegis-installed-XXXXXX)"; chmod 700 "$T"; trap 'rm -rf "$T"' EXIT
echo "=== aegis red-team · the package as npm installs it ==="
[ -x "$BUN" ] && command -v npm >/dev/null || { echo "BROKE — bun or npm not found"; exit 3; }
( cd "$REPO" && npm pack --silent --pack-destination "$T" >/dev/null 2>"$T/pack.err" ) || { echo "BROKE — npm pack failed: $(tail -1 "$T/pack.err")"; exit 3; }
TGZ="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; [ -n "$TGZ" ] || { echo "BROKE — no tarball"; exit 3; }
mkdir -p "$T/app" "$T/home/.aegis"; cd "$T/app" && npm init -y >/dev/null 2>&1
npm install "$TGZ" --no-audit --no-fund >"$T/install.log" 2>&1 || { echo "BROKE — npm install failed: $(tail -2 "$T/install.log" | tr '\n' ' ')"; exit 3; }
PKG="$T/app/node_modules/@xshieldai/aegis"; fail=0
echo "installed: $(for p in aegis aegis-guard chitta-detect hanumang-mandate lakshmanrekha; do printf '%s@%s ' "$p" "$(node -p "require('$T/app/node_modules/@xshieldai/$p/package.json').version" 2>/dev/null)"; done)"
for e in src/cli/index.ts src/dashboard/server.ts src/monitor/index.ts; do
  if "$BUN" build "$PKG/$e" --target=bun --outdir "$T/b" >"$T/build.log" 2>&1; then echo "  [ok]   $e bundles"; else echo "  [GAP]  $e does not bundle: $(grep -m1 -i 'error' "$T/build.log" | cut -c1-150)"; fail=1; fi
done
HOME="$T/home" "$BUN" -e 'import { loadConfig } from "'"$PKG"'/src/core/config.ts"; import { writeFileSync } from "fs"; const c = loadConfig(); c.dashboard = { ...c.dashboard, port: '"$PORT"' }; writeFileSync(process.env.HOME + "/.aegis/config.json", JSON.stringify(c));' >/dev/null 2>&1
start() { ( cd "$T/app" && exec env HOME="$T/home" "$@" timeout 20 "$BUN" "$PKG/src/dashboard/server.ts" >"$T/dash.log" 2>&1 ) & pid=$!
  up=""; for _ in $(seq 1 40); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done; }
start AEGIS_MINT_AUTHORITY=1
if [ -n "$up" ]; then echo "  [ok]   the dashboard starts from the install and answers /health"; else echo "  [GAP]  the dashboard does not start from the install: $(sed 's/\x1b\[[0-9;]*m//g' "$T/dash.log" | grep -m1 -i -E 'error|not found' | cut -c1-170)"; fail=1; fi
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; for _ in $(seq 1 20); do ss -ltn 2>/dev/null | grep -q ":$PORT " || break; sleep 0.25; done
start AEGIS_NOTHING=1
if [ -z "$up" ] && grep -q 'AEGIS_MINT_AUTHORITY' "$T/dash.log"; then echo "  [ok]   without AEGIS_MINT_AUTHORITY=1 it refuses to start and names the setting"
elif [ -n "$up" ]; then echo "  [GAP]  the dashboard started without declaring itself the minting authority"; fail=1
else echo "  [GAP]  it did not start, and did not say it wants AEGIS_MINT_AUTHORITY: $(sed 's/\x1b\[[0-9;]*m//g' "$T/dash.log" | grep -m1 -i error | cut -c1-150)"; fail=1; fi
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
out="$("$BUN" "$PKG/src/cli/index.ts" ledger-anchor 2>&1)"; rc=$?
if [ "$rc" = 2 ] && echo "$out" | grep -q 'COULD NOT ANCHOR'; then echo "  [ok]   a ledger command runs from the install (exit 2 with no log named, as it should)"; else echo "  [GAP]  ledger-anchor from the install: exit $rc"; fail=1; fi
echo "EXIT=$fail   (0 = installs and runs · 1 = works in the repository, not when installed · 3 = broke)"
exit $fail
