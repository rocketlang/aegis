#!/usr/bin/env bash
# aegis red-team — what the dashboard answers over HTTP, pinned (2026-10-12, before the move to fastify 5).
#
# dashboard-login-check.battery.sh asks WHETHER a route is refused. This one pins HOW the server answers: where a
# refusal sends the browser, what a login sets and where it lands, what a logout clears, the type a static file is
# served with, what a malformed or climbing address gets, and what a body the server cannot read gets. These are
# the answers a new major version of the web framework can change without any line of ours changing.
#
# It starts the real dashboard from this repository with a password set, in a temporary home on a spare port.
# Nothing it sends changes anything outside that temporary home: the one writing route it calls (the waitlist) is
# called only with a body that is refused before anything is written.
#
# Exit: 0 every answer is the pinned one · 1 an answer changed · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 36 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; PORT="${TEST_PORT:-48995}"
T="$(mktemp -d /tmp/aegis-http-behaviour-XXXXXX)"; chmod 700 "$T"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
echo "=== aegis red-team · what the dashboard answers over HTTP ==="
[ -x "$BUN" ] && command -v curl >/dev/null || { echo "BROKE — bun or curl not found"; exit 3; }
ss -ltn 2>/dev/null | grep -q ":$PORT " && { echo "BROKE — port $PORT is in use (set TEST_PORT)"; exit 3; }
echo "framework: fastify $(node -p "require('$REPO/node_modules/fastify/package.json').version" 2>/dev/null || echo '?'), @fastify/static $(node -p "require('$REPO/node_modules/@fastify/static/package.json').version" 2>/dev/null || echo '?')"
mkdir -p "$T/home/.aegis"; PW="red-team-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HOME="$T/home" "$BUN" -e 'import { loadConfig } from "'"$REPO"'/src/core/config.ts"; import { writeFileSync } from "fs"; const c = loadConfig(); c.dashboard = { ...c.dashboard, port: '"$PORT"', host: "127.0.0.1", auth: { enabled: true, username: "captain", password: "'"$PW"'" } }; writeFileSync(process.env.HOME + "/.aegis/config.json", JSON.stringify(c));' >/dev/null 2>&1 || { echo "BROKE — could not write the temporary configuration"; exit 3; }
( cd "$REPO" && exec env HOME="$T/home" AEGIS_MINT_AUTHORITY=1 timeout 90 "$BUN" src/dashboard/server.ts >"$T/dash.log" 2>&1 ) & pid=$!
up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
[ -n "$up" ] || { echo "BROKE — the dashboard did not start: $(sed 's/\x1b\[[0-9;]*m//g' "$T/dash.log" | grep -m1 -i -E 'error|refus' | cut -c1-170)"; exit 3; }
B="http://127.0.0.1:$PORT"; fail=0

# ask <name> <curl arguments…> — leaves the status in $S, the headers (lower-cased names, no CR) in $T/h, the body in $T/b.
ask() { S="$(curl -s -m 5 -o "$T/b" -D "$T/h.raw" -w '%{http_code}' --path-as-is "$@")"; tr -d '\r' < "$T/h.raw" | sed 's/^\([A-Za-z-]*\):/\L\1:/' > "$T/h"; }
hdr() { sed -n "s/^$1: //p" "$T/h" | head -1; }
# pin <what> <got> <extended regular expression the answer must match in full>
pin() { if printf '%s' "$2" | grep -q -x -E "$3"; then echo "  [ok]   $1 — $2"; else echo "  [GAP]  $1 — got '$2', pinned '$3'"; fail=1; fi; }

# ── without a session ─────────────────────────────────────────────────────────────────────────────────────────
ask -H 'Accept: text/html' "$B/";                 pin "a browser without a session is sent to the login page" "$S $(hdr location)" '302 /login'
ask "$B/api/status";                              pin "an API call without a session gets 401 as JSON" "$S $(hdr content-type | cut -d';' -f1) $(cat "$T/b")" '401 application/json \{"error":"session expired"\}'
ask -H 'Accept: application/json' "$B/suite";     pin "a page asked for as JSON without a session gets 401, not a redirect" "$S" '401'
ask "$B/login";                                   pin "the login page is served as HTML" "$S $(hdr content-type | cut -d';' -f1)" '200 text/html'
ask -I "$B/health";                               pin "HEAD /health answers" "$S" '200'
ask "$B/health/";                                 pin "a trailing slash reaches the same route" "$S" '200'

# ── logging in and out ────────────────────────────────────────────────────────────────────────────────────────
ask --data-urlencode "username=captain" --data-urlencode "password=wrong-$PW" "$B/login"
pin "a wrong password gets 401 and no cookie" "$S [$(hdr set-cookie)]" '401 \[\]'
ask --data-urlencode "username=captain" --data-urlencode "password=$PW" "$B/login"
cookie="$(hdr set-cookie | sed -n 's/^\(aegis_sid=[^;]*\).*/\1/p')"
pin "the right password (a form) gets a session cookie and lands on /" "$S $(hdr location) $([ -n "$cookie" ] && echo cookie || echo no-cookie)" '302 / cookie'
pin "the session cookie is HttpOnly and SameSite" "$(hdr set-cookie | grep -o -i -E 'httponly|samesite=[a-z]+' | tr 'A-Z\n' 'a-z ' | sed 's/ $//')" 'httponly samesite=(lax|strict)'
ask -H 'Host: aegis.example.org' --data-urlencode "username=captain" --data-urlencode "password=$PW" "$B/login"
pin "behind the public name a login lands inside the app" "$S $(hdr location)" '302 /dashboard/'
ask -H 'Content-Type: application/json' -d "{\"username\":\"captain\",\"password\":\"$PW\"}" "$B/login"
pin "the right password sent as JSON is accepted too" "$S $(hdr location)" '302 /'
ask "$B/logout";                                  pin "logging out clears the cookie and sends to the login page" "$S $(hdr location) $(hdr set-cookie | grep -q -i -E 'max-age=0|expires=thu, 01 jan 1970' && echo cleared || echo not-cleared)" '302 /login cleared'

# ── with a session ────────────────────────────────────────────────────────────────────────────────────────────
C="Cookie: $cookie"
ask -H "$C" "$B/";                                pin "with a session / is the dashboard page" "$S $(hdr content-type | cut -d';' -f1)" '200 text/html'
ask -H "$C" "$B/index.html";                      pin "with a session /index.html is served" "$S $(hdr content-type | cut -d';' -f1)" '200 text/html'
ask -H "$C" "$B/api/status";                      pin "with a session an API route answers JSON" "$S $(hdr content-type | cut -d';' -f1)" '200 application/json'
ask -H "$C" "$B/no/such/route";                   pin "with a session an address that matches nothing is 404" "$S" '404'
ask -H "Cookie: aegis_sid=${cookie#aegis_sid=}x" "$B/api/status"; pin "a cookie with one character added is refused" "$S" '401'

# ── static files ──────────────────────────────────────────────────────────────────────────────────────────────
ask "$B/aegis.css";                               pin "the style sheet is public and served as CSS" "$S $(hdr content-type | cut -d';' -f1)" '200 text/css'
ask "$B/aegis.js";                                pin "the script is public and served as JavaScript" "$S $(hdr content-type | cut -d';' -f1)" '200 (application|text)/javascript'
ask -H "$C" "$B/.env";                            pin "a dot file is not served, even with a session" "$S" '40[34]'
for p in '/../package.json' '/..%2fpackage.json' '/%2e%2e/package.json' '/%2e%2e%2f%2e%2e%2fpackage.json' '/static/../../package.json' '/aegis.css/../../server.ts'; do
  ask -H "$C" "$B$p";                             pin "a climbing address gets nothing from outside the static folder: $p" "$S $(grep -c -E '"name"|import ' "$T/b")" '(400|403|404) 0'
done

# ── addresses and bodies the server cannot read ───────────────────────────────────────────────────────────────
for p in '/%zz' '/api/status%' '/api/%ff%fe'; do
  ask "$B$p";                                     pin "a malformed address without a session gets no content: $p" "$S" '(400|401|404|302)'
done
ask -H "$C" "$B/%zz";                             pin "a malformed address with a session is a plain client error" "$S" '(400|404)'
ask -H 'Content-Type: application/json' -d '{"email":"not-an-address"}' "$B/api/early-access"
pin "the waitlist refuses a bad address before writing anything" "$S" '400'
ask -H 'Content-Type: application/json' -d '{"email":' "$B/api/early-access";   pin "broken JSON is a client error, not a crash" "$S" '400'
ask -H 'Content-Type: application/json' -X POST "$B/api/early-access";          pin "an empty JSON body is a client error" "$S" '400'
ask -H 'Content-Type: application/xml' -d '<x/>' "$B/api/early-access";         pin "a body type the server does not read is refused as such" "$S" '415'
ask -X OPTIONS -H 'Origin: https://example.org' -H 'Access-Control-Request-Method: POST' "$B/api/demo/run"
pin "a cross-origin preflight is answered, with no credentials allowed" "$S [$(hdr access-control-allow-credentials)]" '204 \[\]'
ask "$B/health";                                  pin "the server is still up after all of the above" "$S" '200'
echo "EXIT=$fail   (0 = every answer is the pinned one · 1 = an answer changed · 3 = broke)"
exit $fail
