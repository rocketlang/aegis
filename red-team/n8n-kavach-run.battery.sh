#!/usr/bin/env bash
# aegis red-team — @xshieldai/n8n-nodes: Kavach Run must hand the binary's arguments to kavachos as arguments.
#
# Runs n8n-kavach-run.probe.cjs against an INSTALLED copy of the package, outside n8n, with a stand-in `kavachos`
# first on PATH that only records the words it was started with and prints a version. Nothing is launched under
# enforcement. Needs the network for the install (n8n-workflow, for the node's error type).
#
#   ./red-team/n8n-kavach-run.battery.sh                    the copy packed from this repository
#   N8N_VERSION=1.2.0 ./red-team/n8n-kavach-run.battery.sh   that version from the npm registry
#
# Red on 1.2.0, green from 1.3.0. Exit: 0 no gap · 1 a gap · 3 broke, or the probe did not run all its cases.
set -u
EXPECT_CASES=5
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
echo "=== aegis red-team · n8n Kavach Run: the binary's arguments are arguments ==="
command -v node >/dev/null && command -v npm >/dev/null || { echo "BROKE — node or npm not found"; exit 3; }
[ "$(uname -s)" = Linux ] || { echo "BROKE — the node only wraps on Linux; run this there"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/n8n-run.XXXXXX")"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app" "$T/bin" "$T/work"; echo '{"name":"t","private":true}' > "$T/app/package.json"
if [ -n "${N8N_VERSION:-}" ]; then WHAT="@xshieldai/n8n-nodes@$N8N_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/n8n-nodes-kavachos" && { [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; } && npm run build >/dev/null 2>"$T/build.err" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not build and pack packages/n8n-nodes-kavachos: $(tail -1 "$T/build.err" 2>/dev/null)"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"; [ -n "$WHAT" ] || { echo "BROKE — no tarball"; exit 3; }
fi
# --legacy-peer-deps and --ignore-scripts: the peer (n8n-workflow) is installed by hand, without its native builds.
( cd "$T/app" && npm i --legacy-peer-deps --ignore-scripts --no-fund --no-audit "$WHAT" n8n-workflow >/dev/null 2>"$T/inst.err" ) || { echo "BROKE — install failed ($WHAT): $(tail -1 "$T/inst.err")"; exit 3; }
PKG="$T/app/node_modules/@xshieldai/n8n-nodes"
echo "version: $(node -p "require('$PKG/package.json').version") ($SRC)"
# The stand-in: `kavachos version` prints the version the probe chose; any other call is recorded and exits 0.
cat > "$T/bin/kavachos" <<STANDIN
#!/usr/bin/env node
const fs = require("fs"), a = process.argv.slice(2);
if (a[0] === "version" || a[0] === "--version") { console.log("kavachos " + fs.readFileSync("$T/work/version.txt", "utf8").trim() + " (stand-in)"); process.exit(0); }
fs.writeFileSync("$T/work/argv.json", JSON.stringify(a)); console.log("stand-in ran");
STANDIN
chmod +x "$T/bin/kavachos"
OUT="$( cd "$T/app" && PATH="$T/bin:$PATH" node "$HERE/n8n-kavach-run.probe.cjs" "$PKG" "$T/work" 2>&1 )"; rc=$?
echo "$OUT"
ran="$(echo "$OUT" | sed -n 's/^RESULT cases=\([0-9][0-9]*\) gaps=[0-9][0-9]*.*/\1/p' | tail -1)"
if [ "${ran:-0}" -lt "$EXPECT_CASES" ]; then echo "BROKE — the probe ran ${ran:-0} case(s), expected at least $EXPECT_CASES"; rc=3; fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc"
exit $rc
