// SPDX-License-Identifier: AGPL-3.0-only
// AEGIS Dashboard — which routes answer without a session.
//
// The decision is made on the ROUTE THE SERVER MATCHED (fastify's `request.routeOptions.url`, e.g.
// "/api/v1/tenants/:id"), never on the request address. Through 2.16.2 it was made on the whole
// address, query string included, so "/api/status?x=.js" ended in ".js" and passed as a static file,
// and "/demo?utm_source=…" was not "/demo" and got the login page. An address can be written many
// ways (query, ";", percent-encoding, a trailing slash); the matched route is the one thing the guard
// and the handler cannot disagree about.
//
// WHICH routes are public is unchanged from 2.16.2. Adding one here is an authorization decision.

const EXACT = new Set([
  "/health",
  "/metrics",
  "/login",
  "/logout",
  "/kavachos",                       // public landing page (KOS-093)
  "/commands",
  "/demo",                           // Tier 3 public playground
  "/mcp",                            // AF-T-703 external honeypot manifest — bait only, founder-directed public (AGT-018)
  "/early-access",                   // AEGIS waitlist page (public, GTM Phase 0)
  "/api/early-access",               // waitlist signup POST
  "/control-center",                 // Tier 3: public read-only cockpit (already SSE)
  "/api/approvals/webhook",
  "/api/v1/kavach/health",
  "/api/v1/kavach/state",
  "/api/v1/kavach/gate",
  // @rule:KGT-002 — PUBLIC key for approval-JWT verification (KGT-T1.1); key material
  // here is the public half only, verifier services fetch it without a browser session
  "/api/v2/enforcement/signing-key",
]);

const PREFIX = [
  "/api/demo/",                      // /api/demo/run + /api/demo/health
  "/api/acc/",
  "/api/v1/kavach/audit",
  "/api/v2/authorize",
  "/api/v1/aegis/authorize",
  "/api/v1/aegis/sdt",
  // ASE endpoints: called from hooks, AI Proxy, and agent frameworks — no browser session
  // @rule:ASE-001 @rule:ASE-011
  "/api/v1/aegis/session",
  "/api/bg-agents",
  // Machine-law: called from agent frameworks before planning — no browser session
  "/api/v2/machine-law/",
];

// The static-file route serves src/dashboard/static only. A style sheet, script or image there is
// public; index.html (the dashboard itself) is not. One path segment, no query, no encoding.
const STATIC_ROUTE = "/*";
const STATIC_FILE = /^\/[A-Za-z0-9_-][A-Za-z0-9._-]*\.(css|js|ico|png)$/;

/**
 * @param method  the request method
 * @param route   the matched route pattern; undefined when nothing matched (a 404)
 * @param rawUrl  the request address as received, used only to name the file on the static route
 */
export function isPublicRoute(method: string, route: string | undefined, rawUrl: string): boolean {
  if (!route) return false;
  // A CORS preflight carries no cookie and runs no handler of ours: it is answered by the CORS plugin's own route.
  if (method === "OPTIONS" && route === "*") return true;
  if (route === STATIC_ROUTE) {
    const q = rawUrl.indexOf("?");
    return STATIC_FILE.test(q === -1 ? rawUrl : rawUrl.slice(0, q));
  }
  if (EXACT.has(route)) return true;
  if (route === "/api/approvals" && method === "GET") return true;
  return PREFIX.some((p) => route.startsWith(p));
}
