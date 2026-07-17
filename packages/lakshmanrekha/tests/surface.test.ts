// @xshieldai/lakshmanrekha — surface-probe test suite (v0.3.0)
// Covers the 4 surface probe classes born from the 2026-07-17 open-gateway/RCE
// incident: exposed management route, shell-injection reflection, open GraphQL
// introspection, unauthenticated inference gateway.
//
// fetch is intercepted with a PATH-AWARE stub (surface probes try several paths
// per probe). No real endpoint is contacted.

import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import {
  SURFACE_PROBE_REGISTRY,
  getSurfaceProbe,
  getSurfaceProbes,
  runSurfaceProbe,
  runAllSurfaceProbes,
  countExposed,
  setEventBus,
  type SurfaceProbeDefinition,
  type AccReceipt,
} from '../src/index.js';

// ─── path-aware fetch stub ────────────────────────────────────────────────────
// Map of path-substring → {status, body}. First matching entry wins. A path
// with no entry defaults to 404 (route absent). Set `_netError` to make every
// request throw (connection refused / DNS).

const _origFetch = globalThis.fetch;
let _routes: Array<{ match: string; status: number; body: string | object }> = [];
let _netError: Error | null = null;
const _requested: string[] = [];

function route(match: string, status: number, body: string | object) {
  _routes.push({ match, status, body });
}
function clearRoutes() {
  _routes = [];
  _netError = null;
  _requested.length = 0;
}

beforeEach(() => {
  clearRoutes();
  setEventBus(null);
  globalThis.fetch = (async (url: any, _init?: RequestInit) => {
    const u = String(url);
    _requested.push(u);
    if (_netError) throw _netError;
    const hit = _routes.find((r) => u.includes(r.match));
    if (!hit) return new Response('not found', { status: 404 });
    const bodyStr = typeof hit.body === 'string' ? hit.body : JSON.stringify(hit.body);
    return new Response(bodyStr, { status: hit.status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = _origFetch;
});

const BASE = 'http://probe.local:4444';
const get = (id: string): SurfaceProbeDefinition => {
  const p = getSurfaceProbe(id);
  if (!p) throw new Error(`probe ${id} not found`);
  return p;
};

// ─── §1 Surface registry ──────────────────────────────────────────────────────

describe('§1 Surface registry', () => {
  it('SR-001: registry has exactly 4 surface probes', () => {
    expect(SURFACE_PROBE_REGISTRY.length).toBe(4);
  });

  it('SR-002: the 4 incident-derived categories are all present', () => {
    const cats = SURFACE_PROBE_REGISTRY.map((p) => p.category).sort();
    expect(cats).toEqual([
      'exposed-management-route',
      'open-introspection',
      'open-perimeter',
      'shell-injection',
    ]);
  });

  it('SR-003: every probe cites a source and maps to a framework', () => {
    for (const p of SURFACE_PROBE_REGISTRY) {
      expect(p.source.length).toBeGreaterThan(10);
      const fm = p.framework_mappings;
      expect(fm.owasp || fm.nist_ai_rmf).toBeTruthy();
    }
  });

  it('SR-004: INVARIANT — no surface probe is destructive', () => {
    for (const p of SURFACE_PROBE_REGISTRY) {
      expect(p.destructive).toBe(false);
    }
  });

  it('SR-005: the management-route probe uses only a sentinel resource name', () => {
    const p = get('ASMAI-SURFACE-001');
    // The one pm2-restart path it hits must carry a name that matches no real
    // service — never a live service name that GET could disturb.
    const restart = p.paths.find((x) => x.includes('/restart/'));
    expect(restart).toContain('__lrk_probe_nonexistent__');
  });

  it('SR-006: getSurfaceProbes([ids]) filters; no-arg returns all', () => {
    expect(getSurfaceProbes().length).toBe(4);
    expect(getSurfaceProbes(['ASMAI-SURFACE-003']).map((p) => p.id)).toEqual(['ASMAI-SURFACE-003']);
  });
});

// ─── §2 Exposed management route (SURFACE-001) ────────────────────────────────

describe('§2 Exposed management route', () => {
  it('SR-010: unauthenticated 200 on a management route → exposed', async () => {
    route('/api/pm2/restart/', 200, { ok: true });
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-001'), base_url: BASE });
    expect(r.verdict).toBe('exposed');
    expect(r.matched_path).toContain('/api/pm2/restart/');
    expect(r.status).toBe(200);
  });

  it('SR-011: 401 on every management route → secure', async () => {
    // default 404 for unlisted; explicitly 401 the ones the probe tries
    for (const p of get('ASMAI-SURFACE-001').paths) route(p, 401, 'unauthorized');
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-001'), base_url: BASE });
    expect(r.verdict).toBe('secure');
  });

  it('SR-012: 405 (wrong method, but route handled unauthenticated) → exposed', async () => {
    route('/api/pm2', 405, 'method not allowed');
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-001'), base_url: BASE });
    expect(r.verdict).toBe('exposed');
  });

  it('SR-013: all routes 404 (absent) → secure', async () => {
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-001'), base_url: BASE });
    expect(r.verdict).toBe('secure');
  });
});

// ─── §3 Shell-injection reflection (SURFACE-002) ──────────────────────────────

describe('§3 Shell-metacharacter reflection', () => {
  it('SR-020: EXECUTED marker reflected → exposed', async () => {
    const nonce = 'LRKtestnonce';
    // Simulate a sink that shelled out: the response echoes the decoded nonce.
    route('/api/pm2/restart/', 200, `restarted ${nonce}`);
    const r = await runSurfaceProbe({
      probe: get('ASMAI-SURFACE-002'),
      base_url: BASE,
      nonce,
    });
    expect(r.verdict).toBe('exposed');
    expect(r.evidence).toContain(nonce);
  });

  it('SR-021: literal payload echoed but NOT executed → secure (correct escaping)', async () => {
    const nonce = 'LRKtestnonce';
    // The server reflects the RAW payload ($(echo ...)) — that means it did NOT
    // execute it. Must read as secure, not a false positive.
    route('/api/pm2/restart/', 400, 'invalid service name: $(echo LRKtestnonce)');
    const r = await runSurfaceProbe({
      probe: get('ASMAI-SURFACE-002'),
      base_url: BASE,
      nonce,
    });
    expect(r.verdict).toBe('secure');
  });

  it('SR-022: injection probe never sends a state-changing command (echo only)', async () => {
    route('/api/pm2/restart/', 200, 'ok');
    await runSurfaceProbe({ probe: get('ASMAI-SURFACE-002'), base_url: BASE, nonce: 'LRKx' });
    const sent = _requested.join(' ');
    // The payload must be an echo of the nonce and nothing else — no rm, no ;,
    // no chained command.
    expect(sent).toContain('echo');
    expect(sent).not.toMatch(/rm|reboot|shutdown|curl|wget/i);
  });
});

// ─── §4 Open GraphQL introspection (SURFACE-003) ──────────────────────────────

describe('§4 Open GraphQL introspection', () => {
  it('SR-030: populated __schema in body → exposed', async () => {
    route('/graphql', 200, { data: { __schema: { queryType: { name: 'Query' } } } });
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-003'), base_url: BASE });
    expect(r.verdict).toBe('exposed');
  });

  it('SR-031: introspection disabled (400) → secure', async () => {
    route('/graphql', 400, { errors: [{ message: 'introspection disabled' }] });
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-003'), base_url: BASE });
    expect(r.verdict).toBe('secure');
  });

  it('SR-032: no graphql endpoint at all (404) → secure', async () => {
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-003'), base_url: BASE });
    expect(r.verdict).toBe('secure');
  });
});

// ─── §5 Unauthenticated inference gateway (SURFACE-004) ───────────────────────

describe('§5 Unauthenticated inference gateway', () => {
  it('SR-040: 200 completion served with no credential → exposed (the :4444 bug)', async () => {
    route('/v1/chat/completions', 200, { choices: [{ message: { content: 'pong' } }] });
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-004'), base_url: BASE });
    expect(r.verdict).toBe('exposed');
    expect(r.severity).toBe('critical');
  });

  it('SR-041: 401 before dispatch → secure', async () => {
    for (const p of get('ASMAI-SURFACE-004').paths) route(p, 401, 'missing api key');
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-004'), base_url: BASE });
    expect(r.verdict).toBe('secure');
  });
});

// ─── §6 Runner behaviour, aggregation, receipts ───────────────────────────────

describe('§6 Runner behaviour', () => {
  it('SR-050: connection refused on all paths → inconclusive, not a false secure', async () => {
    _netError = new Error('ECONNREFUSED');
    const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-001'), base_url: BASE });
    expect(r.verdict).toBe('inconclusive');
  });

  it('SR-051: no Authorization header is ever sent (unauthenticated by design)', async () => {
    let sawAuth = false;
    globalThis.fetch = (async (_url: any, init?: RequestInit) => {
      const h = new Headers(init?.headers);
      if (h.has('authorization')) sawAuth = true;
      return new Response('{}', { status: 404 });
    }) as typeof fetch;
    await runSurfaceProbe({ probe: get('ASMAI-SURFACE-004'), base_url: BASE });
    expect(sawAuth).toBe(false);
  });

  it('SR-052: runAllSurfaceProbes + countExposed aggregate correctly', async () => {
    route('/v1/chat/completions', 200, { choices: [{}] }); // SURFACE-004 exposed
    // everything else 404 → secure
    const results = await runAllSurfaceProbes(BASE);
    expect(results.length).toBe(4);
    const tally = countExposed(results);
    expect(tally.exposed).toBe(1);
    expect(tally.total).toBe(4);
  });

  it('SR-053: emits an ACC receipt per probe when a bus is wired', async () => {
    const receipts: AccReceipt[] = [];
    setEventBus({ emit: (r) => receipts.push(r) });
    route('/graphql', 200, { data: { __schema: { queryType: { name: 'Query' } } } });
    await runSurfaceProbe({ probe: get('ASMAI-SURFACE-003'), base_url: BASE });
    expect(receipts.length).toBe(1);
    expect(receipts[0].summary).toContain('ASMAI-SURFACE-003');
    setEventBus(null);
  });

  it('SR-054: determinism — same stub → same verdict 3×', async () => {
    route('/v1/chat/completions', 200, { choices: [{}] });
    const verdicts = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const r = await runSurfaceProbe({ probe: get('ASMAI-SURFACE-004'), base_url: BASE });
      verdicts.add(r.verdict);
    }
    expect([...verdicts]).toEqual(['exposed']);
  });
});
