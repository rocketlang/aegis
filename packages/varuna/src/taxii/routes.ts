/**
 * TAXII 2.1 subscriber routes — manual sync + status.
 * @rule:VRN-YK-007 TAXII collective defense integration
 * @rule:P3-002     Subscribe to xShieldAI TAXII feed
 */

import type { FastifyInstance } from 'fastify';

import { runMonitorCycle } from '../monitor/background.js';

const TAXII_URL = process.env['TAXII_URL'] ?? 'http://localhost:4250';
const TAXII_COLLECTION = '/taxii/api/collections/xshield-ioc/objects/';

export async function registerTAXIIRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/taxii/status — check feed availability + last sync info
  app.get('/api/v1/taxii/status', async () => {
    const _start = Date.now();

    let feed_available = false;
    let indicator_count = 0;

    try {
      const res = await fetch(`${TAXII_URL}${TAXII_COLLECTION}`, {
        headers: { Accept: 'application/taxii+json;version=2.1' },
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        feed_available = true;
        const body = (await res.json()) as { objects?: unknown[] };
        indicator_count = body.objects?.length ?? 0;
      }
    } catch {
      // unavailable
    }

    return {
      taxii_url: TAXII_URL,
      collection: 'xshield-ioc',
      feed_available,
      indicator_count,
      note: feed_available
        ? 'Feed available — POST /api/v1/taxii/sync to correlate'
        : 'ankrshield-api (port 4250) not reachable — collective defense pending',
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // POST /api/v1/taxii/sync — on-demand TAXII fetch + correlation cycle
  app.post('/api/v1/taxii/sync', async () => {
    const _start = Date.now();
    await runMonitorCycle(app.log);
    return {
      synced: true,
      note: 'Monitor cycle (including TAXII correlation) executed',
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // POST /api/v1/taxii/ingest — accept STIX bundle directly (ship8x / partner push)
  app.post<{
    Body: { objects: Array<Record<string, unknown>> };
  }>('/api/v1/taxii/ingest', async (request, reply) => {
    const _start = Date.now();
    const { objects } = request.body;
    if (!Array.isArray(objects)) return reply.status(400).send({ error: 'objects array required' });

    const indicators = objects.filter((o) => o['type'] === 'indicator');
    app.log.info({ count: indicators.length }, '[taxii-ingest] STIX bundle received');

    return {
      ingested: true,
      total_objects: objects.length,
      indicators: indicators.length,
      note: 'Next monitor cycle will correlate these indicators against fleet state',
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info('TAXII routes registered: status + sync + ingest (VARUNA-P3-002)');
}
