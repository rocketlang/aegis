#!/usr/bin/env bash
# aegis red-team — @xshieldai/nallasetu: what the server answers over HTTP, pinned, and who may reach it (2026-10-12, written on
# fastify 4 before the move to fastify 5; the one line that differs is marked below).
#
# Starts the real server from packages/nallasetu on 127.0.0.1, a spare port, in a temporary home (its registry
# and sessions live under the home), with its event address pointed at a closed port so nothing reaches a bus.
# Needs packages/nallasetu/node_modules (bun install there).
#
#   NALLASETU_DIR=<an installed copy> ./red-team/nallasetu-http-behaviour.battery.sh    run against that copy
#
# Exit: 0 every answer is the pinned one · 1 an answer changed · 3 broke.
set -u
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 50 "$0" "$@"   # green only if the cases ran
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"; DIR="${NALLASETU_DIR:-$REPO/packages/nallasetu}"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; PORT="${TEST_PORT:-48990}"
T="$(mktemp -d /tmp/nallasetu-http-XXXXXX)"; chmod 700 "$T"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
echo "=== aegis red-team · nallasetu: what the server answers over HTTP ==="
[ -x "$BUN" ] && command -v curl >/dev/null || { echo "BROKE — bun or curl not found"; exit 3; }
ver() { ( cd "$DIR" && "$BUN" -e 'console.log(require(require.resolve("'"$1"'/package.json")).version)' 2>/dev/null ) || echo '?'; }
[ "$(ver fastify)" != '?' ] || { echo "BROKE — fastify is not installed for $DIR (run bun install there)"; exit 3; }
echo "copy: $DIR · fastify $(ver fastify), @fastify/helmet $(ver @fastify/helmet), @fastify/cors $(ver @fastify/cors)"
ss -ltn 2>/dev/null | grep -q ":$PORT " && { echo "BROKE — port $PORT is in use (set TEST_PORT)"; exit 3; }
# start <extra env…> — the server on 127.0.0.1 in the temporary home; its events go to a closed port.
start() { ( cd "$DIR" && exec env -u NALLASETU_API_TOKEN -u NALLASETU_ALLOW_OPEN -u NALLASETU_CORS_ORIGIN HOME="$T" PORT="$PORT" NALLASETU_HOST=127.0.0.1 SUPER_EVENTS_URL="http://127.0.0.1:9/none" LOG_LEVEL=warn "$@" timeout 90 "$BUN" src/server.ts >"$T/srv.log" 2>&1 ) & pid=$!
  up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done; }
stop() { kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; pid=""; for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$PORT " || break; sleep 0.25; done; }
start
[ -n "$up" ] || { echo "BROKE — the server did not start: $(grep -m1 -i -E 'error|err' "$T/srv.log" | cut -c1-200)"; exit 3; }
ss -ltn 2>/dev/null | grep ":$PORT " | grep -q '127.0.0.1' || { echo "BROKE — the server is not listening on 127.0.0.1 only (NALLASETU_HOST is not honoured by this copy)"; exit 3; }
B="http://127.0.0.1:$PORT"; fail=0; J='Content-Type: application/json'
ask() { S="$(curl -s -m 5 -o "$T/b" -D "$T/h.raw" -w '%{http_code}' --path-as-is "$@")"; tr -d '\r' < "$T/h.raw" | sed 's/^\([A-Za-z-]*\):/\L\1:/' > "$T/h"; }
hdr() { sed -n "s/^$1: //p" "$T/h" | head -1; }
get() { "$BUN" -e 'let o=JSON.parse(require("fs").readFileSync("'"$T/b"'","utf8"));for(const k of process.argv[1].split("."))o=o?.[k];console.log(o===undefined?"":typeof o==="object"?JSON.stringify(o):o)' "$1" 2>/dev/null; }
pin() { if printf '%s' "$2" | grep -q -x -E "$3"; then echo "  [ok]   $1 — $2"; else echo "  [GAP]  $1 — got '$2', pinned '$3'"; fail=1; fi; }

# ── reading routes ────────────────────────────────────────────────────────────────────────────────────────────
ask "$B/health";                                  pin "/health answers JSON" "$S $(hdr content-type | cut -d';' -f1) $(get status) $(get service)" '200 application/json ok nallasetu'
pin "/health reports the version that is installed" "$(get version)" "$(cd "$DIR" && "$BUN" -e 'console.log(require("./package.json").version)' | sed 's/\./\\./g')"
ask -I "$B/health";                               pin "HEAD /health answers" "$S" '200'
ask "$B/health/";                                 pin "a trailing slash is a different address" "$S" '404'
# Since fastify 5 a ";" is part of the path, not the start of a query (fastify 4 answered 200).
ask "$B/health;x=1";                              pin "a semicolon is not read as a query: /health;x=1 matches no route" "$S" '404'
ask "$B/health?x=1";                              pin "a query string does not change the route" "$S" '200'
ask "$B/api/v2/forja/state";                      pin "the state face names the service and its protocol" "$S $(get service) $(get protocol)" '200 nallasetu nallasetu/0\.1'
ask "$B/api/v2/forja/trust/agent-x";              pin "the trust face answers for a name" "$S $(get agent_id)" '200 agent-x'
ask "$B/api/v2/forja/proof";                      pin "the proof face counts its rules" "$S $(get total_rules)" '200 35'
ask "$B/api/v2/nallasetu/pramana/tip";            pin "the chain tip answers" "$S" '200'
ask "$B/api/v2/nallasetu/sessions/no-such-id";    pin "an unknown session is 404" "$S $(get error)" '404 Session not found'
ask "$B/no/such/route";                           pin "an address that matches nothing is 404" "$S" '404'

# ── the headers every answer carries ──────────────────────────────────────────────────────────────────────────
ask "$B/health"
pin "helmet's headers are on" "$(hdr x-content-type-options) $(hdr x-frame-options) $(hdr strict-transport-security | cut -d';' -f1)" 'nosniff SAMEORIGIN max-age=[0-9]+'
pin "no content-security-policy is sent (switched off in the server)" "[$(hdr content-security-policy)]" '\[\]'
ask -H 'Origin: https://example.org' "$B/health"; pin "cross-origin is off unless an origin is named (0.4.0)" "$S [$(hdr access-control-allow-origin)]" '200 \[\]'

# ── the handshake ─────────────────────────────────────────────────────────────────────────────────────────────
ask -H "$J" -d '{}' "$B/api/v2/nallasetu/handshake";                 pin "a handshake with nothing in it is 400 and names the rule" "$S $(get rule_ref)" '400 NLS-001'
ask -H "$J" -d '{"initiator":{"agent_id":"battery-a","trust_mask":255},"responder_id":"nallasetu-v0","scope_mask":15}' "$B/api/v2/nallasetu/handshake"
SID="$(get session.session_id)"
pin "a handshake between two known parties issues a session" "$S $(get decision) $(get session.session_mask) $(get _meta.trust_mask_applied)" '201 session_issued 15 15'
ask -H "$J" -d '{"initiator":{"agent_id":"battery-a","trust_mask":255},"responder_id":"nallasetu-v0","scope_mask":0}' "$B/api/v2/nallasetu/handshake"
pin "nothing in common is 409" "$S $(get decision)" '409 no_common_capability'
ask "$B/api/v2/nallasetu/sessions/$SID";          pin "the issued session can be looked up and is active" "$S $(get status) $(get session_mask)" '200 active 15'
ask -H "$J" -d '{}' "$B/api/v2/nallasetu/sessions/$SID/revoke";      pin "a revoke without the named consent is 400" "$S $(get rule_ref)" '400 CA-002'
ask -X POST "$B/api/v2/nallasetu/sessions/$SID/revoke";              pin "a revoke with no body at all is 400, not a crash" "$S" '400'
ask -H "$J" -d '{"confirm_revoke_session":true}' "$B/api/v2/nallasetu/sessions/no-such-id/revoke"; pin "revoking an unknown session is 404" "$S" '404'
ask -H "$J" -d '{"confirm_revoke_session":true,"reason":"battery"}' "$B/api/v2/nallasetu/sessions/$SID/revoke"; pin "a revoke with consent is done and carries a receipt" "$S $(get decision) $(get receipt.outcome)" '200 session_revoked revoked'
ask -H "$J" -d '{"confirm_revoke_session":true}' "$B/api/v2/nallasetu/sessions/$SID/revoke"; pin "a second revoke is 409" "$S" '409'
ask "$B/api/v2/nallasetu/sessions/$SID";          pin "the session now reads revoked" "$S $(get status)" '200 revoked'
ask -X POST "$B/api/v2/nallasetu/sessions/expire-stale";             pin "expire-stale answers a count" "$S $(get expired)" '200 [0-9]+'
ask -H "$J" -d '{}' "$B/api/v2/forja/sense/emit";                    pin "a sense event without a type is 400" "$S" '400'
ask -H "$J" -d '{"event_type":"x","payload":{}}' "$B/api/v2/forja/sense/emit"; pin "a sense event with a type is accepted" "$S $(get accepted)" '202 true'

# ── bodies and addresses the server cannot read ───────────────────────────────────────────────────────────────
ask -H "$J" -d '{"initiator":' "$B/api/v2/nallasetu/handshake";      pin "broken JSON is a client error" "$S" '400'
ask -H "$J" -X POST "$B/api/v2/nallasetu/handshake";                 pin "an empty JSON body is a client error" "$S" '400'
ask -H 'Content-Type: application/xml' -d '<x/>' "$B/api/v2/nallasetu/handshake"; pin "a body type the server does not read is refused as such" "$S" '415'
ask "$B/api/v2/nallasetu/sessions/%zz";           pin "a malformed address is a client error" "$S" '400'
ask "$B/health";                                  pin "the server is still up after all of the above" "$S" '200'
grep -q 'WITHOUT authentication' "$T/srv.log" && echo "  [ok]   without a token it says so on its log" || { echo "  [GAP]  it runs without a token and does not say so"; fail=1; }
stop

# ── with a token: every route but /health asks who is calling (0.4.0) ─────────────────────────────────────────
TOKEN="battery-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"; A="Authorization: Bearer $TOKEN"
start NALLASETU_API_TOKEN="$TOKEN" NALLASETU_CORS_ORIGIN=https://partner.example
[ -n "$up" ] || { echo "BROKE — the server did not start with a token: $(grep -m1 -i -E 'error|refus' "$T/srv.log" | cut -c1-200)"; exit 3; }
HS='{"initiator":{"agent_id":"battery-b","trust_mask":255},"responder_id":"nallasetu-v0","scope_mask":15}'
ask "$B/health";                                  pin "/health stays open with a token set" "$S" '200'
ask "$B/health;x=1";                              pin "/health;x=1 is not /health: refused without the token" "$S" '401'
ask -H "$J" -d "$HS" "$B/api/v2/nallasetu/handshake";                pin "a handshake without the token is refused, and no session is issued" "$S $(get error) [$(get session.session_id)]" '401 unauthorized \[\]'
ask "$B/api/v2/nallasetu/sessions/any-id";        pin "a session lookup without the token is refused" "$S" '401'
ask -H "$J" -d '{"confirm_revoke_session":true}' "$B/api/v2/nallasetu/sessions/any-id/revoke"; pin "a revoke without the token is refused" "$S" '401'
ask -X POST "$B/api/v2/nallasetu/sessions/expire-stale";             pin "the maintenance call without the token is refused" "$S" '401'
ask "$B/api/v2/forja/state";                      pin "the state face without the token is refused" "$S" '401'
ask "$B/no/such/route";                           pin "an address that matches nothing, without the token, is refused" "$S" '401'
ask -H "Authorization: Bearer ${TOKEN}x" "$B/api/v2/forja/state";    pin "a token with one character added is refused" "$S" '401'
ask -H "Authorization: bearer $TOKEN" "$B/api/v2/forja/state";       pin "the scheme word is matched exactly" "$S" '401'
ask -H "$A" -H "$J" -d "$HS" "$B/api/v2/nallasetu/handshake";        pin "with the token a handshake issues a session" "$S $(get decision)" '201 session_issued'
SID2="$(get session.session_id)"
ask -H "$A" "$B/api/v2/nallasetu/sessions/$SID2"; pin "with the token the session can be read" "$S $(get status)" '200 active'
ask -H "$A" -H 'Origin: https://partner.example' "$B/api/v2/forja/state"; pin "the named origin is allowed, and only it" "$S $(hdr access-control-allow-origin)" '200 https://partner.example'
stop

# ── starting open is a decision, not a default ────────────────────────────────────────────────────────────────
out="$( cd "$DIR" && env -u NALLASETU_API_TOKEN -u NALLASETU_ALLOW_OPEN HOME="$T" PORT="$PORT" NALLASETU_HOST=0.0.0.0 SUPER_EVENTS_URL="http://127.0.0.1:9/none" timeout 10 "$BUN" src/server.ts 2>&1 )"; rc=$?
pin "on every interface with no token it refuses to start, and says why" "$([ "$rc" = 1 ] && echo refused || echo "started-or-hung($rc)") $(printf '%s' "$out" | grep -c 'REFUSING TO START')" 'refused 1'
out="$( cd "$DIR" && env -u NALLASETU_ALLOW_OPEN HOME="$T" PORT="$PORT" NALLASETU_HOST=127.0.0.1 NALLASETU_API_TOKEN=short SUPER_EVENTS_URL="http://127.0.0.1:9/none" timeout 10 "$BUN" src/server.ts 2>&1 )"; rc=$?
pin "a token too short to be one refuses the start" "$([ "$rc" = 1 ] && echo refused || echo "started-or-hung($rc)") $(printf '%s' "$out" | grep -c 'at least 24')" 'refused 1'
out="$( cd "$DIR" && env -u NALLASETU_API_TOKEN -u NALLASETU_ALLOW_OPEN -u NALLASETU_HOST HOME="$T" PORT="$PORT" SUPER_EVENTS_URL="http://127.0.0.1:9/none" LOG_LEVEL=warn timeout 6 "$BUN" src/server.ts 2>&1 & for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep ":$PORT " && break; sleep 0.1; done; wait )"
pin "with no address named it listens on this machine only" "$(printf '%s' "$out" | grep ":$PORT " | awk '{print $4}' | head -1)" "127\.0\.0\.1:$PORT"
echo "EXIT=$fail   (0 = every answer is the pinned one · 1 = an answer changed · 3 = broke)"
exit $fail
