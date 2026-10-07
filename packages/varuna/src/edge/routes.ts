/**
 * Edge agent API — the Varuna Box's offline-first ledger + sync-on-connect.
 * @rule:VRN-EDGE-003 Ledger is viewable; sync is explicit and idempotent.
 */

import type { FastifyInstance } from 'fastify';

import { edgeStats, readAll, syncOnConnect, unsynced } from './ledger.js';

export async function registerEdgeRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/edge/ledger — the on-disk buffer (survives reboot)
  app.get<{ Querystring: { unsynced_only?: string } }>('/api/v1/edge/ledger', async (request) => {
    const _start = Date.now();
    const only = request.query.unsynced_only === 'true';
    const records = only ? unsynced() : readAll();
    return {
      stats: edgeStats(),
      count: records.length,
      records: records.slice(-200), // last 200
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // POST /api/v1/edge/sync — flush buffered records to shore when connectivity is back.
  // No-op if the shore is unreachable (mid-ocean) — records stay buffered.
  app.post('/api/v1/edge/sync', async () => {
    const _start = Date.now();
    const shoreUrl = process.env['SHIP8X_URL'] ?? null; // shore endpoint from env; null = offline
    const result = await syncOnConnect(shoreUrl);
    return {
      ...result,
      stats: edgeStats(),
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info('Edge routes registered: ledger + sync (VRN-EDGE-003)');
}
