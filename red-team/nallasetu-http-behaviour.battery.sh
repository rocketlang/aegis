#!/usr/bin/env bash
# aegis red-team — @xshieldai/nallasetu: what the server answers over HTTP, pinned (2026-10-12, written on
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
[ -n "${RAN_INNER:-}" ] || exec "$(cd "$(dirname "$0")" && pwd)/lib/ran.sh" 34 "$0" "$@"   # green only if the cases ran
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
( cd "$DIR" && exec env HOME="$T" PORT="$PORT" NALLASETU_HOST=127.0.0.1 SUPER_EVENTS_URL="http://127.0.0.1:9/none" LOG_LEVEL=warn timeout 90 "$BUN" src/server.ts >"$T/srv.log" 2>&1 ) & pid=$!
up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
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
ask -H 'Origin: https://example.org' "$B/health"; pin "a cross-origin read is allowed, without credentials" "$(hdr access-control-allow-origin) [$(hdr access-control-allow-credentials)]" 'https://example.org \[\]'
ask -X OPTIONS -H 'Origin: https://example.org' -H 'Access-Control-Request-Method: POST' "$B/api/v2/nallasetu/handshake"; pin "a cross-origin preflight is answered" "$S" '204'

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
echo "EXIT=$fail   (0 = every answer is the pinned one · 1 = an answer changed · 3 = broke)"
exit $fail
