#!/usr/bin/env bash
# aegis red-team — @xshieldai/n8n-nodes-kavachos inside a real n8n (2026-10-12).
#
# n8n-kavach-run.battery.sh loads the nodes' code outside n8n. This one starts n8n itself, asks n8n's own
# community-packages installer for the package (and for the old name, which it must refuse), and runs the four
# nodes in workflows through n8n's REST interface, reading each saved execution.
#
#   Kavach Gate, Budget, Audit   against a real Aegis dashboard started from this repository in a temporary home
#   Kavach Run                    with a stand-in `kavachos` that only records the words it was started with.
#                                 NOTHING is launched under kernel enforcement; that is not what this shows.
#
# n8n runs in a container (the current n8n needs a newer Node than this box has), on the host's loopback only,
# with a temporary data folder. Needs docker, bun, node, curl, root (the container writes as uid 1000), and the
# network (the image, and the package from the npm registry: only a PUBLISHED version can be tested this way).
#
#   ./red-team/n8n-inside-n8n.battery.sh                      the version in packages/n8n-nodes-kavachos/package.json
#   N8N_VERSION=1.5.1 N8N_IMAGE=n8nio/n8n:2.42.7 ./red-team/n8n-inside-n8n.battery.sh
#
# One gap on 1.5.1 (an argument in quotes was cut at its space), green from 1.5.2.
# Exit: 0 no gap · 1 a gap · 3 broke, or not every case ran.
set -u
EXPECT_CASES=23
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
NAME="@xshieldai/n8n-nodes-kavachos"; OLD="@xshieldai/n8n-nodes"
VER="${N8N_VERSION:-$(node -p "require('$REPO/packages/n8n-nodes-kavachos/package.json').version" 2>/dev/null)}"
IMAGE="${N8N_IMAGE:-n8nio/n8n:2.42.7}"; NPORT="${N8N_PORT:-45678}"; APORT="${AEGIS_PORT:-48996}"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; CN="kavach-n8n-battery-$$"; pid=""
echo "=== aegis red-team · the Kavach nodes inside a real n8n ==="
for c in docker node curl; do command -v $c >/dev/null || { echo "BROKE — $c not found"; exit 3; }; done
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
[ "$(id -u)" = 0 ] || { echo "BROKE — run as root (the container writes into the temporary folder as uid 1000)"; exit 3; }
for p in $NPORT $APORT; do ss -ltn 2>/dev/null | grep -q ":$p " && { echo "BROKE — port $p is in use (set N8N_PORT / AEGIS_PORT)"; exit 3; }; done
T="$(mktemp -d "${TMPDIR:-/tmp}/n8n-inside.XXXXXX")"; chmod 711 "$T"
trap 'docker rm -f "$CN" >/dev/null 2>&1; [ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/n8n" "$T/kv/bin" "$T/kv/work" "$T/home/.aegis"; chown -R 1000:1000 "$T/n8n" "$T/kv/work"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull -q "$IMAGE" >/dev/null 2>&1 || { echo "BROKE — could not get the image $IMAGE"; exit 3; }

# The stand-in: `kavachos version` answers 2.6.1; any other call is recorded and then behaves as mode.txt says,
# in kavachos's own words (the lines src/kavachos-cli.ts and src/kernel/runner.ts print).
cat > "$T/kv/bin/kavachos" <<'STANDIN'
#!/usr/bin/env node
const fs = require("fs"), a = process.argv.slice(2);
if (a[0] === "version" || a[0] === "--version") { console.log("kavachos 2.6.1 (stand-in)"); process.exit(0); }
fs.writeFileSync("/kv/work/argv.json", JSON.stringify(a));
let mode = "ok"; try { mode = fs.readFileSync("/kv/work/mode.txt", "utf8").trim(); } catch {}
if (mode === "refuse") { console.error("[kavachos:egress] REFUSING TO LAUNCH — the supervisor could not arm"); console.error("[kavachos] launch refused: egress:FAILED"); process.exit(3); }
if (mode === "unconstrained") { console.error("[kavachos:egress] NOT egress-constrained — supervisor said UNAVAILABLE"); console.error("[kavachos:measure] egress_enforced=false recorded — this launch is not egress-governed"); console.log("stand-in ran"); process.exit(0); }
if (mode === "sleep") { setTimeout(() => process.exit(0), 60000); }
else console.log("stand-in ran");
STANDIN
chmod 755 "$T/kv/bin/kavachos"

# A real Aegis dashboard, password and adapters' token set, in the temporary home.
umask 077; PW="live-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$T/tok"
HOME="$T/home" "$BUN" -e 'import { loadConfig } from "'"$REPO"'/src/core/config.ts"; import { readFileSync, writeFileSync } from "fs"; const c = loadConfig(); c.dashboard = { ...c.dashboard, port: '"$APORT"', host: "127.0.0.1", auth: { enabled: true, username: "captain", password: "'"$PW"'", api_token: readFileSync("'"$T"'/tok", "utf8") } }; writeFileSync(process.env.HOME + "/.aegis/config.json", JSON.stringify(c));' >/dev/null 2>&1 || { echo "BROKE — could not write the temporary Aegis configuration"; exit 3; }
( cd "$REPO" && exec env HOME="$T/home" AEGIS_MINT_AUTHORITY=1 timeout 900 "$BUN" src/dashboard/server.ts >"$T/dash.log" 2>&1 ) & pid=$!
up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$APORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
[ -n "$up" ] || { echo "BROKE — the Aegis dashboard did not start"; exit 3; }

docker run -d --rm --name "$CN" --network host --stop-timeout 5 \
  -e N8N_PORT="$NPORT" -e N8N_LISTEN_ADDRESS=127.0.0.1 -e N8N_SECURE_COOKIE=false -e N8N_DIAGNOSTICS_ENABLED=false \
  -e N8N_VERSION_NOTIFICATIONS_ENABLED=false -e N8N_PERSONALIZATION_ENABLED=false -e N8N_TEMPLATES_ENABLED=false \
  -e PATH=/kv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -v "$T/n8n:/home/node/.n8n" -v "$T/kv:/kv" "$IMAGE" >/dev/null 2>"$T/run.err" || { echo "BROKE — the n8n container did not start: $(tail -1 "$T/run.err")"; exit 3; }
B="http://127.0.0.1:$NPORT"; c=""
for _ in $(seq 1 90); do c="$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$B/healthz")"; [ "$c" = 200 ] && break; sleep 2; done
[ "$c" = 200 ] || { echo "BROKE — n8n did not answer"; exit 3; }
# /healthz answers before the REST interface does: until then every address answers 200 "n8n is starting up".
ready=""; for _ in $(seq 1 90); do curl -s -m 3 "$B/rest/settings" | head -c 1 | grep -q '{' && { ready=1; break; }; sleep 2; done
[ -n "$ready" ] || { echo "BROKE — n8n's REST interface did not come up"; exit 3; }
echo "n8n: $(docker exec "$CN" n8n --version 2>/dev/null | tail -1) ($IMAGE), node $(docker exec "$CN" node -v 2>/dev/null) · package: $NAME@$VER from the npm registry · aegis: this repository at $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null)"

OPW="Own3r-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"; J="$T/jar"; s=""
for _ in $(seq 1 15); do s="$(curl -s -m 20 -c "$J" -H 'Content-Type: application/json' -H 'browser-id: probe' -d "{\"email\":\"probe@example.org\",\"firstName\":\"Probe\",\"lastName\":\"Run\",\"password\":\"$OPW\"}" -o "$T/owner.json" -w '%{http_code}' "$B/rest/owner/setup")"; [ "$s" = 200 ] && grep -q '"email"' "$T/owner.json" && break; s="$s (no owner in the answer)"; sleep 2; done
[ "$s" = 200 ] || { echo "BROKE — could not create the instance owner (HTTP $s)"; exit 3; }
R() { curl -s -m 300 -b "$J" -H 'Content-Type: application/json' -H 'browser-id: probe' "$@"; }
cases=0; gaps=0
echo "--- n8n's own installer ---"
out="$(R -d "{\"name\":\"$OLD\"}" -w ' HTTP %{http_code}' "$B/rest/community-packages")"; cases=$((cases+1))
if echo "$out" | grep -q 'HTTP 400' && echo "$out" | grep -q 'n8n-nodes-'; then echo "  [ok] n8n refuses the old name $OLD — $(echo "$out" | cut -c1-110)"; else echo "  [GAP] n8n did not refuse the old name — $(echo "$out" | cut -c1-200)"; gaps=$((gaps+1)); fi
out="$(R -d "{\"name\":\"$NAME\",\"version\":\"$VER\"}" -w ' HTTP %{http_code}' "$B/rest/community-packages")"; cases=$((cases+1))
if echo "$out" | grep -q 'HTTP 200' && echo "$out" | grep -q "\"installedVersion\":\"$VER\""; then echo "  [ok] n8n installs $NAME $VER"; else echo "  [GAP] n8n did not install $NAME $VER — $(echo "$out" | cut -c1-300)"; gaps=$((gaps+1)); fi
echo "--- the nodes, run in workflows ---"
OUT="$(node "$HERE/n8n-inside-n8n.probe.cjs" "$B" "$J" "http://127.0.0.1:$APORT" "$T/tok" "$T/kv/work" 2>&1)"; rc=$?
echo "$OUT"
ran="$(echo "$OUT" | sed -n 's/^RESULT cases=\([0-9][0-9]*\) gaps=[0-9][0-9]*.*/\1/p')"; cases=$((cases + ${ran:-0}))
[ "$gaps" -gt 0 ] && [ "$rc" -lt 1 ] && rc=1
if [ "$cases" -lt "$EXPECT_CASES" ]; then echo "BROKE — $cases case(s) ran, expected at least $EXPECT_CASES"; rc=3; fi
[ "$rc" -gt 1 ] && rc=3
echo "cases=$cases"
echo "EXIT=$rc   (0 = no gap · 1 = a gap · 3 = broke)"
exit $rc
