#!/usr/bin/env bash
# aegis red-team — @xshieldai/n8n-nodes-kavachos (was @xshieldai/n8n-nodes): Kavach Run and Kavach Gate say what happened, and do not hang n8n.
#
# 1.3.0: the binary's arguments go to kavachos as arguments. 1.4.0: a refused or unconstrained launch is not
# reported as enforced; a long command neither stops n8n nor runs for ever; only the gate's boolean true is an allow.
#
# Runs n8n-kavach-run.probe.cjs against an INSTALLED copy of the package, outside n8n, with a stand-in `kavachos`
# first on PATH that only records the words it was started with and prints a version. Nothing is launched under
# enforcement. Needs the network for the install (n8n-workflow, for the node's error type).
#
#   ./red-team/n8n-kavach-run.battery.sh                    the copy packed from this repository
#   N8N_VERSION=1.5.0 ./red-team/n8n-kavach-run.battery.sh   that version from the npm registry
#   N8N_PACKAGE=@xshieldai/n8n-nodes N8N_VERSION=1.2.0 …     a version under the old name
#
# 1.5.2: an argument in quotes is one word.
# Red on 1.2.0 and 1.3.0, two gaps on 1.4.0 to 1.5.1 (the quotes), green from 1.5.2. Exit: 0 no gap · 1 a gap · 3 broke, or the probe did not run all its cases.
set -u
EXPECT_CASES=35
# The package was @xshieldai/n8n-nodes through 1.4.1: N8N_PACKAGE=@xshieldai/n8n-nodes N8N_VERSION=1.4.1 runs that one.
NAME="${N8N_PACKAGE:-@xshieldai/n8n-nodes-kavachos}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
echo "=== aegis red-team · n8n Kavach Run and Kavach Gate: say what happened, and do not hang ==="
command -v node >/dev/null && command -v npm >/dev/null || { echo "BROKE — node or npm not found"; exit 3; }
[ "$(uname -s)" = Linux ] || { echo "BROKE — the node only wraps on Linux; run this there"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/n8n-run.XXXXXX")"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/app" "$T/bin" "$T/work"; echo '{"name":"t","private":true}' > "$T/app/package.json"
if [ -n "${N8N_VERSION:-}" ]; then WHAT="$NAME@$N8N_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/n8n-nodes-kavachos" && { [ -d node_modules ] || npm ci --ignore-scripts --no-audit --no-fund >/dev/null 2>&1; } && npm run build >/dev/null 2>"$T/build.err" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not build and pack packages/n8n-nodes-kavachos: $(tail -1 "$T/build.err" 2>/dev/null)"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"; [ -n "$WHAT" ] || { echo "BROKE — no tarball"; exit 3; }
fi
# --legacy-peer-deps and --ignore-scripts: the peer (n8n-workflow) is installed by hand, without its native builds.
( cd "$T/app" && npm i --legacy-peer-deps --ignore-scripts --no-fund --no-audit "$WHAT" n8n-workflow >/dev/null 2>"$T/inst.err" ) || { echo "BROKE — install failed ($WHAT): $(tail -1 "$T/inst.err")"; exit 3; }
PKG="$T/app/node_modules/$NAME"
echo "version: $(node -p "require('$PKG/package.json').version") ($SRC)"
# The stand-in: `kavachos version` prints the version the probe chose; any other call is recorded, and then
# behaves as mode.txt says, in kavachos's own words (the lines are the ones src/kavachos-cli.ts and
# src/kernel/runner.ts print).
cat > "$T/bin/kavachos" <<STANDIN
#!/usr/bin/env node
const fs = require("fs"), a = process.argv.slice(2);
if (a[0] === "version" || a[0] === "--version") { console.log("kavachos " + fs.readFileSync("$T/work/version.txt", "utf8").trim() + " (stand-in)"); process.exit(0); }
fs.writeFileSync("$T/work/argv.json", JSON.stringify(a));
let mode = "ok"; try { mode = fs.readFileSync("$T/work/mode.txt", "utf8").trim(); } catch {}
if (mode === "refuse") { console.error("[kavachos:egress] REFUSING TO LAUNCH — the supervisor could not arm"); console.error("[kavachos] launch refused: egress:FAILED"); process.exit(3); }
if (mode === "unconstrained") { console.error("[kavachos:egress] NOT egress-constrained — supervisor said UNAVAILABLE"); console.error("[kavachos:measure] egress_enforced=false recorded — this launch is not egress-governed"); console.log("stand-in ran"); process.exit(0); }
if (mode === "agent-exit-3") { console.log("the command itself ended with 3"); process.exit(3); }
if (mode === "sleep") { setTimeout(() => process.exit(0), 30000); }
else if (mode === "bigout") { const b = "x".repeat(1024 * 1024); let n = 0; const w = () => { while (n < 8) { n++; if (!process.stdout.write(b)) { process.stdout.once("drain", w); return; } } process.stdout.end(); }; w(); }
else { console.log("stand-in ran"); }
STANDIN
chmod +x "$T/bin/kavachos"
OUT="$( cd "$T/app" && PATH="$T/bin:$PATH" node "$HERE/n8n-kavach-run.probe.cjs" "$PKG" "$T/work" 2>&1 )"; rc=$?
echo "$OUT"
echo "--- what ships ---"
OUT3="$( cd "$T/app" && node -e '
const path=require("path"),fs=require("fs"),pkg=process.argv[1],m=require(path.join(pkg,"package.json"));let c=0,g=0;
for(const rel of m.n8n.nodes){const js=path.join(pkg,rel),cls=Object.values(require(js))[0],icon=String(new cls().description.icon||"");
  const f=icon.startsWith("file:")?path.join(path.dirname(js),icon.slice(5)):null,ok=!!f&&fs.existsSync(f)&&/<svg[\s>]/.test(fs.readFileSync(f,"utf8"));
  c++;if(!ok)g++;console.log("  ["+(ok?"safe":"GAP")+"] the icon "+path.basename(rel,".node.js")+" names is in the package — "+icon+(ok?"":" (missing)"));}
console.log("\nRESULT cases="+c+" gaps="+g);process.exit(g?1:0)' "$PKG" 2>&1 )"; rc3=$?
echo "$OUT3"
[ "$rc3" -gt "$rc" ] && rc=$rc3
OUT="$OUT
$OUT3"
echo "--- the gate node ---"
OUT2="$( cd "$T/app" && node "$HERE/n8n-kavach-gate.probe.cjs" "$PKG" 2>&1 )"; rc2=$?
echo "$OUT2"
[ "$rc2" -gt "$rc" ] && rc=$rc2
OUT="$OUT
$OUT2"
ran="$(echo "$OUT" | sed -n 's/^RESULT cases=\([0-9][0-9]*\) gaps=[0-9][0-9]*.*/\1/p' | awk '{s+=$1} END {print s}')"
if [ "${ran:-0}" -lt "$EXPECT_CASES" ]; then echo "BROKE — the probe ran ${ran:-0} case(s), expected at least $EXPECT_CASES"; rc=3; fi
[ "$rc" -gt 1 ] && rc=3
echo "EXIT=$rc"
exit $rc
