/**
 * NMEA ingest + query routes.
 * @rule:VRN-032 NMEA 0183 security
 */

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

import { observeNMEA } from './detector.js';
import { parseNMEA } from './parser.js';

export async function registerNMEARoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-032 Ingest NMEA 0183 sentence from passive monitoring agent
  app.post<{
    Body: { vessel_id: string; sentence: string; timestamp?: number };
  }>('/api/v1/ingest/nmea', async (request, reply) => {
    const _start = Date.now();
    const { vessel_id, sentence } = request.body;
    const timestamp = request.body.timestamp ?? Date.now();

    if (!vessel_id || !sentence) {
      return reply.status(400).send({ error: 'vessel_id and sentence are required' });
    }

    const parsed = parseNMEA(sentence);
    if (!parsed) {
      return reply
        .status(400)
        .send({ error: 'invalid_nmea', message: 'Sentence must start with $' });
    }

    const anomaly = observeNMEA(app.log, vessel_id, parsed, timestamp);
    const vessel = getVessel(vessel_id);

    return {
      ingested: true,
      vessel_id,
      sentence_type: parsed.sentence_type,
      talker_id: parsed.talker_id,
      checksum_valid: parsed.checksum_valid,
      baseline_locked: vessel.nmeaBaselineLocked,
      talker_count: vessel.nmeaTalkerBaseline.size,
      anomaly_detected: !!anomaly,
      anomaly: anomaly ?? null,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/nmea/anomalies/:vesselId
  app.get<{ Params: { vesselId: string }; Querystring: { limit?: string } }>(
    '/api/v1/nmea/anomalies/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const limit = parseInt(request.query.limit ?? '50');

      return {
        vessel_id: request.params.vesselId,
        total: vessel.nmeaAnomalies.length,
        anomalies: [...vessel.nmeaAnomalies].reverse().slice(0, limit),
        talkers_known: [...vessel.nmeaTalkerBaseline.keys()],
        baseline_locked: vessel.nmeaBaselineLocked,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('NMEA routes registered: ingest + anomalies (VARUNA-P1-005 to P1-006)');
}
