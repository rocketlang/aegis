#!/usr/bin/env bash
# aegis red-team — @xshieldai/varuna: what the server answers over HTTP, pinned (2026-10-12, written on
# fastify 4 before the move to fastify 5; the one line that differs is marked below).
#
# Starts the built server (dist/main.js, under node) on 127.0.0.1, a spare port, in a temporary folder, three
# times: with a token, without one, and once more to meet the rate limit. Every address the service would call
# out to (threat feed, shore, notifier, model proxy, knowledge store) is pointed at a closed port, so nothing
# leaves this process. Needs packages/varuna built (npm install && npm run build there).
#
#   VARUNA_DIR=<an installed copy> ./red-team/varuna-http-behaviour.battery.sh    run against that copy
#   VARUNA_RECORD=1 ...                                                           rewrite the route baseline
#
# Part 2 asks every route in varuna-routes.txt and compares status and content type with
# varuna-routes.baseline.txt. Exit: 0 every answer is the pinned one · 1 an answer changed · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 60 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"; DIR="${VARUNA_DIR:-$REPO/packages/varuna}"
PORT="${TEST_PORT:-48984}"; TOKEN="battery-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
T="$(mktemp -d /tmp/varuna-http-XXXXXX)"; chmod 700 "$T"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
echo "=== aegis red-team · varuna: what the server answers over HTTP ==="
command -v node >/dev/null && command -v curl >/dev/null || { echo "BROKE — node or curl not found"; exit 3; }
[ -f "$DIR/dist/main.js" ] || { echo "BROKE — $DIR/dist/main.js is missing (npm install && npm run build in packages/varuna)"; exit 3; }
ver() { ( cd "$DIR" && node -e 'console.log(require(require.resolve("'"$1"'/package.json")).version)' 2>/dev/null ) || echo '?'; }
[ "$(ver fastify)" != '?' ] || { echo "BROKE — fastify is not installed for $DIR"; exit 3; }
echo "copy: $DIR · fastify $(ver fastify), @fastify/cors $(ver @fastify/cors), @fastify/rate-limit $(ver @fastify/rate-limit)"
B="http://127.0.0.1:$PORT"; fail=0; J='Content-Type: application/json'; DEAD="http://127.0.0.1:9"
# start <extra env…> — NODE_ENV is deliberately NOT set: a plain start must work.
start() {
  ss -ltn 2>/dev/null | grep -q ":$PORT " && { echo "BROKE — port $PORT is in use (set TEST_PORT)"; exit 3; }
  ( cd "$T" && exec env -u NODE_ENV -u VARUNA_API_TOKEN -u HOST -u CORS_ORIGIN -u VARUNA_ALLOW_OPEN PORT="$PORT" LOG_LEVEL=warn VARUNA_EDGE_DIR="$T/edge" MONITOR_INTERVAL_MS=3600000 \
      TAXII_URL="$DEAD" SHIP8X_URL="$DEAD" HANUMANG_URL="$DEAD" AI_PROXY_URL="$DEAD" ANKRCLAW_URL="$DEAD" GRANTHX_URL="$DEAD" "$@" timeout 120 node "$DIR/dist/main.js" >"$T/srv.log" 2>&1 ) & pid=$!
  up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "$B/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
}
stop() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; pid=""; for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$PORT " || break; sleep 0.25; done; }
ask() { S="$(curl -s -m 8 -o "$T/b" -D "$T/h.raw" -w '%{http_code}' --path-as-is "$@")"; tr -d '\r' < "$T/h.raw" | sed 's/^\([A-Za-z-]*\):/\L\1:/' > "$T/h"; }
hdr() { sed -n "s/^$1: //p" "$T/h" | head -1; }
get() { node -e 'let o=JSON.parse(require("fs").readFileSync("'"$T/b"'","utf8"));for(const k of process.argv[1].split("."))o=o?.[k];console.log(o===undefined?"":typeof o==="object"?JSON.stringify(o):o)' "$1" 2>/dev/null; }
pin() { if printf '%s' "$2" | grep -q -x -E "$3"; then echo "  [ok]   $1 — $2"; else echo "  [GAP]  $1 — got '$2', pinned '$3'"; fail=1; fi; }

# ── 1. with a token ───────────────────────────────────────────────────────────────────────────────────────────
start VARUNA_API_TOKEN="$TOKEN"
[ -n "$up" ] || { echo "BROKE — the server did not start with a token and no NODE_ENV: $(grep -m1 -i -E 'error' "$T/srv.log" | cut -c1-200)"; exit 3; }
A="Authorization: Bearer $TOKEN"
ask "$B/health";                                  pin "/health is public and reports the installed version" "$S $(get status) $(get version)" "200 ok $(node -p "require('$DIR/package.json').version" | sed 's/\./\\./g')"
ask -I "$B/health";                               pin "HEAD /health answers" "$S" '200'
ask "$B/health?x=1";                              pin "/health with a query is still public" "$S" '200'
# Since fastify 5 a ";" is part of the path, not the start of a query. Either way it is not /health to the guard.
ask "$B/health;x=1";                              pin "/health;x=1 without a token is not let through" "$S" '401'
ask "$B/health/";                                 pin "/health/ without a token is not let through" "$S" '401'
ask "$B/api/v2/forja/state";                      pin "a route without a token is 401 as JSON" "$S $(hdr content-type | cut -d';' -f1) $(get error)" '401 application/json unauthorized'
ask -H "Authorization: Bearer ${TOKEN}x" "$B/api/v2/forja/state";   pin "a token with one character added is 401" "$S" '401'
ask -H "Authorization: bearer $TOKEN" "$B/api/v2/forja/state";      pin "the scheme word is matched exactly" "$S" '401'
ask -H "Authorization: $TOKEN" "$B/api/v2/forja/state";             pin "a token without the scheme is 401" "$S" '401'
ask -H "$J" -d '{}' "$B/api/v1/ingest/modbus";    pin "a writer without a token is 401" "$S" '401'
ask "$B/no/such/route";                           pin "an address that matches nothing, without a token, is 401" "$S" '401'
ask -H "$A" "$B/no/such/route";                   pin "an address that matches nothing, with the token, is 404" "$S" '404'
ask -H "$A" "$B/api/v2/forja/state";              pin "with the token the state face answers and reports the version" "$S $(get service_key) $(get version)" "200 xshieldai-varuna $(node -p "require('$DIR/package.json').version" | sed 's/\./\\./g')"
ask -H "$A" "$B/api/v2/forja/state;x=1";          pin "a semicolon is not read as a query (fastify 4 answered 200)" "$S" '404'
ask -H 'Origin: https://example.org' "$B/health"; pin "cross-origin is off unless asked for" "$S [$(hdr access-control-allow-origin)]" '200 \[\]'
ask "$B/health";                                  pin "the rate-limit headers are on" "$(hdr x-ratelimit-limit)" '60'
ask -H "$A" -H "$J" -d '{"x":' "$B/api/v1/ingest/modbus";           pin "broken JSON is a client error" "$S" '400'
ask -H "$A" -H "$J" -X POST "$B/api/v1/ingest/modbus";              pin "an empty JSON body is a client error" "$S" '400'
ask -H "$A" -H 'Content-Type: application/xml' -d '<x/>' "$B/api/v1/ingest/modbus"; pin "a body type the server does not read is refused as such" "$S" '415'
ask -H "$A" "$B/api/v1/posture/%zz";              pin "a malformed address is a client error" "$S" '400'
stop

# ── 2. every route, without a token (loopback only) ───────────────────────────────────────────────────────────
start
[ -n "$up" ] || { echo "BROKE — the server did not start without a token"; exit 3; }
grep -q 'WITHOUT API auth' "$T/srv.log" && echo "  [ok]   without a token it says so on its log" || { echo "  [GAP]  it started without a token and did not say so"; fail=1; }
: > "$T/routes.now"
while read -r m p; do
  [ -n "$m" ] || continue
  q="$(printf '%s' "$p" | sed -E 's/:[A-Za-z]+/V1/g')"
  if [ "$m" = get ]; then r="$(curl -s -m 8 -o /dev/null -w '%{http_code} %{content_type}' "$B$q")"; else r="$(curl -s -m 8 -o /dev/null -w '%{http_code} %{content_type}' -X POST -H "$J" -d '{}' "$B$q")"; fi
  # The PDF route needs wkhtmltopdf on the machine: a PDF where it is installed, a 500 where it is not. Both are "as before".
  case "$p" in */pdf) case "$r" in '200 application/pdf'|'500 application/json'*) r='a PDF, or 500 without wkhtmltopdf';; esac;; esac
  echo "$m $p -> $r" >> "$T/routes.now"
done < "$HERE/varuna-routes.txt"
if [ -n "${VARUNA_RECORD:-}" ]; then cp "$T/routes.now" "$HERE/varuna-routes.baseline.txt"; echo "  (baseline rewritten: $(wc -l < "$T/routes.now") routes)"; fi
[ -f "$HERE/varuna-routes.baseline.txt" ] || { echo "BROKE — no route baseline (run once with VARUNA_RECORD=1)"; exit 3; }
while IFS= read -r line; do
  if grep -q -x -F -- "$line" "$HERE/varuna-routes.baseline.txt"; then echo "  [ok]   $line"; else echo "  [GAP]  $line — the baseline says: $(grep -F -- "${line%% -> *} -> " "$HERE/varuna-routes.baseline.txt" | sed 's/.* -> //')"; fail=1; fi
done < "$T/routes.now"
n="$(wc -l < "$T/routes.now")"; want="$(grep -c . "$HERE/varuna-routes.txt")"
[ "$n" = "$want" ] || { echo "BROKE — asked $n routes, the list has $want"; exit 3; }
ask "$B/health";                                  pin "the server is still up after every route" "$S" '200'
stop

# ── 3. the rate limit, and refusing to start open ─────────────────────────────────────────────────────────────
start
codes="$(for _ in $(seq 1 61); do curl -s -m 3 -o /dev/null -w '%{http_code}\n' "$B/health"; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
pin "the 61st request in a minute is refused (the readiness checks count too)" "$codes" ' ?[0-9]+ 200; ?[0-9]+ 429;'
ask "$B/health";                                  pin "a refused request is 429 with the limit named" "$S $(get error)" '429 rate_limit_exceeded'
stop
out="$( cd "$T" && env -u NODE_ENV -u VARUNA_API_TOKEN -u VARUNA_ALLOW_OPEN PORT="$PORT" HOST=0.0.0.0 timeout 10 node "$DIR/dist/main.js" 2>&1 )"; rc=$?
pin "on every interface with no token it refuses to start, and says why" "$([ "$rc" != 0 ] && [ "$rc" != 124 ] && echo refused || echo "started-or-hung($rc)") $(printf '%s' "$out" | grep -c 'refusing to start')" 'refused [1-9][0-9]*'
echo "EXIT=$fail   (0 = every answer is the pinned one · 1 = an answer changed · 3 = broke)"
exit $fail
