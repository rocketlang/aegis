#!/usr/bin/env bash
# aegis red-team — @xshieldai/aegis-guard: one approval must not fit two different acts (11 October 2026).
#
# Runs aegis-guard-action-digest.probe.ts against an INSTALLED copy of the package, never against the source
# tree, in a throwaway directory with a throwaway signing key.
#
#   ./red-team/aegis-guard-action-digest.battery.sh            the copy packed from this repository
#   GUARD_VERSION=0.6.0 ./red-team/aegis-guard-action-digest.battery.sh    that version from the npm registry
#
# Red on 0.6.0 and earlier (the digest guessed a spelling for values JSON cannot carry), green from 0.6.1.
# Exit: 0 every different act is refused · 1 a gap · 3 broke.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"
echo "=== aegis red-team · aegis-guard: one approval, one act ==="
[ -x "$BUN" ] && command -v npm >/dev/null || { echo "BROKE — bun or npm not found"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/guard-digest.XXXXXX")"; trap 'rm -rf "$T"' EXIT
echo '{"name":"t","private":true}' > "$T/package.json"
if [ -n "${GUARD_VERSION:-}" ]; then
  WHAT="@xshieldai/aegis-guard@$GUARD_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/aegis-guard" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not pack packages/aegis-guard"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"
  [ -n "$WHAT" ] || { echo "BROKE — no tarball was made"; exit 3; }
fi
( cd "$T" && npm i --ignore-scripts --no-fund --no-audit "$WHAT" >/dev/null 2>&1 ) || { echo "BROKE — install failed ($WHAT)"; exit 3; }
echo "version: $(node -p "require('$T/node_modules/@xshieldai/aegis-guard/package.json').version") ($SRC)"
cp "$HERE/aegis-guard-action-digest.probe.ts" "$T/probe.ts"
( cd "$T" && HOME="$T" "$BUN" "$T/probe.ts" ); rc=$?
echo "EXIT=$rc"
exit $rc
