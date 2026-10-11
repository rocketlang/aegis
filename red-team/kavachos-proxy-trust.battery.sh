#!/usr/bin/env bash
# aegis red-team — @xshieldai/agent-kernel: the proxy is trusted by its certificate, not by switching checking off.
#
# Through 2.5.0: (a) an agent launched under the proxy was given settings that switch certificate checking OFF
# for every host it talks to; (b) the proxy's certificate and key were two fixed names in /tmp, reused if already
# there, so whoever wrote them first chose the key; (c) the proxy listened on every interface; (d) the certificate
# named neither localhost nor 127.0.0.1, so no client could verify it even when told to trust it.
#
# This starts the proxy from an INSTALLED copy, in a temporary home, on a spare port, with its upstream pointed at
# a closed port. Nothing is launched under enforcement (the launcher is asked for dry runs only). On a version
# before the fix the proxy writes two files in /tmp; this removes them afterwards, and will not run at all if
# they are already there (they would be someone's running proxy).
#
#   ./red-team/kavachos-proxy-trust.battery.sh                   the copy packed from this repository
#   AK_VERSION=2.5.0 ./red-team/kavachos-proxy-trust.battery.sh   that version from the npm registry
#
# Red on 2.5.0, green from 2.6.0. Exit: 0 no gap · 1 a gap · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 10 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; PORT="${TEST_PORT:-48980}"
OLD_CRT=/tmp/kavachos-proxy.crt; OLD_KEY=/tmp/kavachos-proxy.key
echo "=== aegis red-team · kavachos proxy: trusted by its certificate, checking left on ==="
for c in node npm openssl curl ss; do command -v "$c" >/dev/null || { echo "BROKE — $c not found"; exit 3; }; done
[ -x "$BUN" ] || { echo "BROKE — bun not found"; exit 3; }
[ -e "$OLD_CRT" ] || [ -e "$OLD_KEY" ] && { echo "BROKE — $OLD_CRT or $OLD_KEY exists: a proxy of an older version may be running here; not touching it"; exit 3; }
ss -ltn 2>/dev/null | grep -q ":$PORT " && { echo "BROKE — port $PORT is in use (set TEST_PORT)"; exit 3; }
T="$(mktemp -d "${TMPDIR:-/tmp}/ak-proxy.XXXXXX")"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -f "$OLD_CRT" "$OLD_KEY"; rm -rf "$T"' EXIT
mkdir -p "$T/app" "$T/home"; echo '{"name":"t","private":true}' > "$T/app/package.json"
if [ -n "${AK_VERSION:-}" ]; then WHAT="@xshieldai/agent-kernel@$AK_VERSION"; SRC="the npm registry"
else
  ( cd "$REPO/packages/kavachos" && "$BUN" run build >/dev/null 2>"$T/build.err" && npm pack --ignore-scripts --pack-destination "$T" >/dev/null 2>&1 ) || { echo "BROKE — could not build and pack packages/kavachos: $(tail -1 "$T/build.err")"; exit 3; }
  WHAT="$(ls "$T"/*.tgz 2>/dev/null | head -1)"; SRC="packed from this repository"; [ -n "$WHAT" ] || { echo "BROKE — no tarball"; exit 3; }
fi
( cd "$T/app" && npm i --ignore-scripts --no-fund --no-audit "$WHAT" >/dev/null 2>&1 ) || { echo "BROKE — install failed ($WHAT)"; exit 3; }
CLI="$T/app/node_modules/@xshieldai/agent-kernel/dist/kavachos.js"; [ -f "$CLI" ] || { echo "BROKE — no dist/kavachos.js"; exit 3; }
echo "version: $(node -p "require('$T/app/node_modules/@xshieldai/agent-kernel/package.json').version") ($SRC)"
fail=0; ok() { echo "  [safe] $1"; }; gap() { echo "  [GAP]  $1"; fail=1; }
E=(env -u KAVACHOS_PROXY_CA -u KAVACHOS_PROXY_HOST -u NODE_EXTRA_CA_CERTS -u SSL_CERT_FILE HOME="$T/home" AEGIS_HOME="$T/home/.aegis" ANKR_STATE_DIR="$T/home/state")
start() { ( cd "$T/home" && exec "${E[@]}" timeout 60 "$BUN" "$CLI" proxy start --port="$PORT" --upstream=http://127.0.0.1:9 >"$T/proxy.log" 2>&1 ) & pid=$!
  up=""; for _ in $(seq 1 80); do ss -ltn 2>/dev/null | grep -q ":$PORT " && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
  [ -n "$up" ] || { echo "BROKE — the proxy did not start: $(tail -2 "$T/proxy.log" | tr '\n' ' ' | cut -c1-200)"; exit 3; }; }
stop() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; pid=""; for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$PORT " || break; sleep 0.25; done; }
served() { echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2; }
dry() { ( cd "$T/home" && "${E[@]}" KAVACHOS_PROXY_URL="https://localhost:$PORT" timeout 60 "$BUN" "$CLI" run --dry-run -- echo hi 2>/dev/null ) | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{let o;try{o=JSON.parse(s.slice(s.indexOf("{")))}catch{o={}}for(const k of process.argv[1].split("."))o=o?.[k];console.log(o===undefined||o===null?"":typeof o==="object"?JSON.stringify(o):String(o))})' "$1"; }

# 1. What ships. A setting that switches certificate checking off must not be in the launcher at all.
n="$(grep -c -E 'NODE_TLS_REJECT_UNAUTHORIZED|PYTHONHTTPSVERIFY' "$CLI")"
[ "$n" = 0 ] && ok "the shipped launcher holds no setting that switches certificate checking off" || gap "the shipped launcher sets certificate checking off for the agent ($n line(s) name NODE_TLS_REJECT_UNAUTHORIZED / PYTHONHTTPSVERIFY)"

# 2-6. The proxy as it starts.
start
l="$(ss -ltn 2>/dev/null | grep ":$PORT " | awk '{print $4}' | tr '\n' ' ')"
case "$l" in "127.0.0.1:$PORT ") ok "the proxy listens on this machine only ($l)";; *) gap "the proxy listens on: $l";; esac
if [ -e "$OLD_CRT" ] || [ -e "$OLD_KEY" ]; then gap "the proxy keeps its certificate and key under fixed names in /tmp"; CRT="$OLD_CRT"; KEY="$OLD_KEY"
else CRT="$T/home/.aegis/kernel/proxy/proxy.crt"; KEY="$T/home/.aegis/kernel/proxy/proxy.key"; [ -f "$CRT" ] && [ -f "$KEY" ] && ok "nothing is written in /tmp; the pair is under the aegis home" || { echo "BROKE — no certificate found where either version keeps it"; exit 3; }; fi
m="$(stat -c '%a' "$(dirname "$KEY")") $(stat -c '%a' "$KEY")"
[ "$m" = "700 600" ] && ok "the key is readable by its owner only, in a folder only the owner can enter ($m)" || gap "folder and key modes are $m (wanted 700 600)"
san="$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2>/dev/null | tail -1 | tr -d ' ')"
case "$san" in *DNS:localhost*IPAddress:127.0.0.1*) ok "the certificate names localhost and 127.0.0.1";; *) gap "the certificate names no host a client could check it against (subjectAltName: '${san:-none}')";; esac
r="$(NODE_EXTRA_CA_CERTS="$CRT" node -e 'fetch("https://localhost:'"$PORT"'/proxy/health").then(r=>r.json()).then(j=>console.log(j.ok===true?"verified":"odd")).catch(e=>console.log("refused:"+(e.cause?.code||e.message)))')"
[ "$r" = verified ] && ok "a client with checking ON and only this certificate added reaches the proxy" || gap "a client with checking on, told to trust this certificate, still cannot verify the proxy ($r)"
r="$(env -u NODE_EXTRA_CA_CERTS node -e 'fetch("https://localhost:'"$PORT"'/proxy/health").then(()=>console.log("accepted")).catch(e=>console.log("refused"))')"
[ "$r" = refused ] && ok "control: a client that was not given the certificate refuses the proxy" || { echo "BROKE — a client with no trust in the proxy accepted it; the case above proves nothing"; exit 3; }

# 7. What the launcher hands the agent, asked as a dry run.
c="$(dry proxy.certificateChecking)"; e="$(dry proxy.environment)"
[ "$c" = on ] && [ "$e" = '["CURL_CA_BUNDLE","NODE_EXTRA_CA_CERTS","REQUESTS_CA_BUNDLE","SSL_CERT_FILE"]' ] && ok "under the proxy the agent is handed trust roots, with checking on ($e)" || gap "the launcher does not report how the agent will trust the proxy (checking '$c', environment '$e')"
stop

# 8. A pair that was already lying there must not be used.
openssl req -x509 -newkey rsa:2048 -keyout "$T/planted.key" -out "$T/planted.crt" -days 1 -nodes -subj "/CN=someone-else" >/dev/null 2>&1 || { echo "BROKE — could not make a stand-in pair"; exit 3; }
for d in "$(dirname "$CRT")"; do mkdir -p "$d"; cp "$T/planted.crt" "$CRT"; cp "$T/planted.key" "$KEY"; done
start
[ "$(served)" != "$(fp "$T/planted.crt")" ] && [ -n "$(served)" ] && ok "a pair that was already in place is replaced: the proxy serves a fresh certificate" || gap "the proxy serves the certificate and key it found lying in place (whoever wrote them first holds the key)"
stop

# 9. No certificate to hand over: the launcher must say so and still not switch checking off.
rm -f "$T/home/.aegis/kernel/proxy/proxy.crt" "$OLD_CRT"
p="$(dry proxy.certificatePresent)"; e="$(dry proxy.environment)"
[ "$p" = false ] && [ "$e" = '[]' ] && ok "with no certificate to hand over the agent gets nothing extra, and checking stays on" || gap "with no certificate: present '$p', environment '$e'"
echo "EXIT=$fail   (0 = no gap · 1 = a gap · 3 = broke)"
exit $fail
