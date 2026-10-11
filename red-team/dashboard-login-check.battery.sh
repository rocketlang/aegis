#!/usr/bin/env bash
# aegis red-team — the dashboard's login check (2026-10-11, aegis 2.16.3).
#
# Through 2.16.2 the session guard decided "public or not" by comparing the WHOLE request address, query string
# included, against a list. Two faults followed:
#   - an address that ENDED in .js/.css/.png/.ico was let through as a static file, and a query string counts as
#     the end: any protected address with "?x=.js" (or ";x=.js", or a route parameter ending ".js") skipped the login;
#   - a public page with anything after it ("/demo?utm_source=…", "/demo/") was not on the list and got the login page.
# The guard now decides on the route the server matched (src/dashboard/public-routes.ts).
#
# This starts the real dashboard from this repository with a password set, in a temporary home on a spare port, and
# asks without a session. It only sends GET requests to reading routes: on a faulty build a request DOES get through,
# so nothing here may be a route that changes anything.
#
# Exit: 0 every protected route refuses and every public route answers · 1 a gap · 3 broke.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
BUN="$(command -v bun || echo /root/.bun/bin/bun)"; PORT="${TEST_PORT:-48997}"
T="$(mktemp -d /tmp/aegis-login-check-XXXXXX)"; chmod 700 "$T"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
echo "=== aegis red-team · the dashboard's login check ==="
[ -x "$BUN" ] && command -v curl >/dev/null || { echo "BROKE — bun or curl not found"; exit 3; }
ss -ltn 2>/dev/null | grep -q ":$PORT " && { echo "BROKE — port $PORT is in use (set TEST_PORT)"; exit 3; }
mkdir -p "$T/home/.aegis"; PW="red-team-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')"
HOME="$T/home" "$BUN" -e 'import { loadConfig } from "'"$REPO"'/src/core/config.ts"; import { writeFileSync } from "fs"; const c = loadConfig(); c.dashboard = { ...c.dashboard, port: '"$PORT"', host: "127.0.0.1", auth: { enabled: true, username: "captain", password: "'"$PW"'" } }; writeFileSync(process.env.HOME + "/.aegis/config.json", JSON.stringify(c));' >/dev/null 2>&1
( cd "$REPO" && exec env HOME="$T/home" AEGIS_MINT_AUTHORITY=1 timeout 60 "$BUN" src/dashboard/server.ts >"$T/dash.log" 2>&1 ) & pid=$!
up=""; for _ in $(seq 1 60); do curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/health" && { up=1; break; }; kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
[ -n "$up" ] || { echo "BROKE — the dashboard did not start: $(sed 's/\x1b\[[0-9;]*m//g' "$T/dash.log" | grep -m1 -i -E 'error|refus' | cut -c1-170)"; exit 3; }
B="http://127.0.0.1:$PORT"; fail=0
code() { curl -s -m 5 -o /dev/null -w '%{http_code}' --path-as-is "$@"; }

# The control: with no session a protected route refuses, and with one it answers. Without this, "refused" below
# could mean "the route does not exist".
c="$(code "$B/api/status")"
[ "$c" = 401 ] && echo "  [ok]   control: /api/status without a session is refused (401)" || { echo "  [GAP]  control: /api/status without a session answered $c"; fail=1; }
cookie="$(curl -s -m 5 -o /dev/null -D - --data-urlencode "username=captain" --data-urlencode "password=$PW" "$B/login" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(aegis_sid=[^;]*\).*/\1/p')"
c="$(code -H "Cookie: $cookie" "$B/api/status")"
[ -n "$cookie" ] && [ "$c" = 200 ] && echo "  [ok]   control: /api/status with a session answers (200)" || { echo "  [GAP]  control: logging in and asking /api/status answered $c"; fail=1; }

# Protected reading routes, dressed up as static files. Each must be refused: 401, or 302 to the login page.
for p in \
  '/api/status?x=.js' '/api/status?x=.css' '/api/status?x=.png' '/api/status?x=.ico' \
  '/api/status;x=.js' '/api/status?.js' '/api/status/?x=.js' '/%61pi/status?x=.js' \
  '/api/config?x=.js' '/api/sessions?x=.js' '/api/events?x=.js' '/api/alerts?x=.js' '/api/universe?x=.js' \
  '/api/v1/tenants?x=.js' '/api/v1/tenants/a.js' '/api/v1/cost-tree?x=.js' '/api/v2/valves?x=.js' '/api/v2/valve/a.js' \
  '/api/v2/enforcement/audit?x=.js' '/api/v2/enforcement/approvals/pending?x=.js' '/api/v2/forja/state?x=.js' \
  '/api/firewall/overview?x=.js' '/agent/a.js' '/firewall?x=.js' '/suite?x=.js' \
  '/?x=.js' '/index.html?x=.js' '/index.html;.js' '/index.html' '/' ; do
  c="$(code "$B$p")"
  if [ "$c" = 401 ] || [ "$c" = 302 ]; then echo "  [ok]   refused ($c): $p"; else echo "  [GAP]  not refused ($c): $p"; fail=1; fi
done

# Public pages and files, as they are really asked for. Each must answer 200 without a session.
for p in '/health' '/health?x=1' '/login' '/demo' '/demo?utm_source=linkedin&utm_medium=post' '/demo/' '/demo/?utm_source=linkedin' \
  '/control-center?x=1' '/api/demo/health' '/api/demo/health?x=1' '/api/acc/health' '/aegis.css' '/aegis.js' '/aegis.js?v=2' \
  '/api/approvals' '/api/approvals?x=1' '/api/v1/kavach/audit?limit=1' '/api/v1/kavach/health' '/api/v2/enforcement/signing-key' ; do
  c="$(code "$B$p")"
  if [ "$c" = 200 ]; then echo "  [ok]   public (200): $p"; else echo "  [GAP]  a public address did not answer ($c): $p"; fail=1; fi
done
# An address no route matches is refused like any other, and a cross-origin preflight to a public route still works.
c="$(code "$B/no-such-page.js")"; d="$(code "$B/no/such/page?x=.js")"
if { [ "$c" = 302 ] || [ "$c" = 401 ] || [ "$c" = 404 ]; } && { [ "$d" = 302 ] || [ "$d" = 401 ]; }; then echo "  [ok]   addresses that match nothing: $c and $d"; else echo "  [GAP]  addresses that match nothing answered $c and $d"; fail=1; fi
c="$(code -X OPTIONS -H 'Origin: https://example.org' -H 'Access-Control-Request-Method: POST' "$B/api/demo/run")"
[ "$c" = 204 ] && echo "  [ok]   a cross-origin preflight to /api/demo/run is answered (204)" || { echo "  [GAP]  a cross-origin preflight to /api/demo/run answered $c"; fail=1; }
echo "EXIT=$fail   (0 = protected routes refuse and public ones answer · 1 = a gap · 3 = broke)"
exit $fail
