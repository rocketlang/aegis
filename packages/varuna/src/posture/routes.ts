/**
 * Vessel posture summary — aggregates all detection signals into a score.
 * @rule:VRN-050 Posture is a living score, updated continuously.
 * @rule:CA-004 _meta on every resolver.
 */

import type { FastifyInstance } from 'fastify';

import { getVessel, listVessels } from '../store/vessel.js';

import { computePostureScore } from './scorer.js';

export async function registerPostureRoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-050 Living posture score per vessel
  app.get<{ Params: { vesselId: string } }>('/api/v1/posture/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel_id = request.params.vesselId;
    const vessel = getVessel(vessel_id);

    const { score, band: posture_band, findings } = computePostureScore(vessel);
    vessel.postureScore = score;

    return {
      vessel_id,
      posture_score: score,
      posture_band,
      findings_count: {
        critical: findings.filter((f) => f.severity === 'CRITICAL').length,
        warn: findings.filter((f) => f.severity === 'WARN').length,
      },
      findings,
      iacs_ur_e26:
        vessel.modbusBaselineLocked && vessel.nmeaBaselineLocked && !vessel.topology?.flat_network
          ? 'PARTIAL'
          : 'NOT_ASSESSED',
      recent_events: vessel.senseEvents.slice(-10).map((e) => ({
        event_type: e.event_type,
        severity: e.severity,
        timestamp: new Date(e.timestamp).toISOString(),
      })),
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/posture — fleet-wide summary
  app.get('/api/v1/posture', async () => {
    const _start = Date.now();
    const vessels = listVessels();
    const summary = vessels.map((vid) => {
      const v = getVessel(vid);
      return { vessel_id: vid, posture_score: v.postureScore, event_count: v.senseEvents.length };
    });
    return {
      vessel_count: vessels.length,
      vessels: summary,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/events/:vesselId — SENSE event log
  app.get<{ Params: { vesselId: string }; Querystring: { limit?: string; severity?: string } }>(
    '/api/v1/events/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const limit = parseInt(request.query.limit ?? '50');
      const { severity } = request.query;

      let events = [...vessel.senseEvents].reverse();
      if (severity) events = events.filter((e) => e.severity === severity.toUpperCase());
      events = events.slice(0, limit);

      return {
        vessel_id: request.params.vesselId,
        total: vessel.senseEvents.length,
        returned: events.length,
        events,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('Posture routes registered: score + events (VARUNA-P1 living score)');
}
