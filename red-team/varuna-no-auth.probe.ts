// SPDX-License-Identifier: AGPL-3.0-only
// aegis red-team — VARUNA no-auth (review finding, 2026-10-08).
//
// Before: the Varuna listener bound 0.0.0.0, set CORS '*', and had no auth — an open, cross-origin,
// unauthenticated WRITER (ingest) reachable from any interface. This probe drives the real security
// decisions and the real auth hook and proves the defaults are now closed:
//   - bind is loopback by default, not 0.0.0.0;
//   - CORS is off by default, not '*';
//   - off-box + no token => the server refuses to start;
//   - the auth hook refuses an UNauthenticated request on a writer route (401) and passes an
//     authenticated one; /health stays open.
//
// GAP = the exploit (open/cross-origin/unauth-write) still works. Exit 0 when all are closed.
// Runs against repo source (public): packages/varuna/src/security.ts. The hook is driven directly
// (it is a plain onRequest handler) so the probe is hermetic — no listener, no network.
import { resolveHost, resolveCorsOrigin, resolveAuth, makeAuthHook } from '../packages/varuna/src/security.js';

let gaps = 0;
const SAFE = (id: string, ok: boolean, detail: string) => { console.log(`  [${ok ? 'safe' : 'GAP '}] ${id} — ${detail}`); if (!ok) gaps++; };

// ── the closed defaults ───────────────────────────────────────────────────────
SAFE('bind is loopback by default', resolveHost({}) === '127.0.0.1',
  `resolveHost({}) = ${resolveHost({})} (was 0.0.0.0)`);
SAFE('CORS is off by default', resolveCorsOrigin({}) === false,
  `resolveCorsOrigin({}) = ${JSON.stringify(resolveCorsOrigin({}))} (was '*')`);
SAFE('off-box + no token refuses to start', resolveAuth({}, '0.0.0.0').mode === 'refuse',
  `resolveAuth({}, '0.0.0.0') = ${resolveAuth({}, '0.0.0.0').mode} — an open unauthenticated writer never starts`);
SAFE('loopback with no token is allowed (local dev)', resolveAuth({}, '127.0.0.1').mode === 'open-local',
  `resolveAuth({}, '127.0.0.1') = ${resolveAuth({}, '127.0.0.1').mode}`);
SAFE('a token makes auth active', resolveAuth({ VARUNA_API_TOKEN: 't' }, '0.0.0.0').mode === 'token',
  `resolveAuth with VARUNA_API_TOKEN on 0.0.0.0 = token (off-box is fine once authenticated)`);

// ── the real auth hook, driven directly ─────────────────────────────────────────
const TOKEN = 'red-team-secret';
const hook = makeAuthHook(TOKEN);
// A minimal stand-in for fastify's request/reply: the hook only uses method/url/headers and code()/send().
const run = async (method: string, url: string, authHeader?: string) => {
  let status = 200;
  const reply = { code(c: number) { status = c; return reply; }, send(_b: unknown) { return reply; } };
  const request = { method, url, headers: authHeader ? { authorization: authHeader } : {} };
  await hook(request as any, reply as any);
  return status;
};

SAFE('unauthenticated ingest is refused', (await run('POST', '/api/v1/ingest/modbus')) === 401,
  'POST /api/v1/ingest/modbus with no token → 401');
SAFE('wrong token is refused', (await run('POST', '/api/v1/ingest/modbus', 'Bearer nope')) === 401,
  'POST with a wrong bearer token → 401');
SAFE('correct token passes the gate', (await run('POST', '/api/v1/ingest/modbus', `Bearer ${TOKEN}`)) === 200,
  'POST with the right bearer token → not refused (the route then judges the body)');
SAFE('health stays open (no token)', (await run('GET', '/health')) === 200,
  'GET /health → open for liveness, no token needed');
SAFE('CORS preflight is not gated', (await run('OPTIONS', '/api/v1/ingest/modbus')) === 200,
  'OPTIONS preflight passes so CORS still works');

console.log(`\n  varuna-no-auth: ${gaps} gap(s)${gaps === 0 ? ' — open/cross-origin/unauth-write all closed ✓' : ' (RED until fixed)'}`);
process.exit(gaps > 0 ? 1 : 0);
