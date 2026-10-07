/**
 * Protocol security posture routes.
 * @rule:P2-002 Protocol-layer posture scoring (VRN-026 to VRN-040)
 * @rule:CA-004 _meta on every resolver
 */

import type { FastifyInstance } from 'fastify';

import { getVessel } from '../store/vessel.js';

import { runProtocolScorer } from './scorer.js';

export async function registerProtocolRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/protocol/posture/:vesselId
  app.get<{ Params: { vesselId: string } }>(
    '/api/v1/protocol/posture/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const posture = runProtocolScorer(vessel);

      return {
        vessel_id: request.params.vesselId,
        protocol_posture: {
          pass: posture.pass,
          partial: posture.partial,
          fail: posture.fail,
          unknown: posture.unknown,
          total: posture.results.length,
        },
        results: posture.results,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('Protocol posture routes registered (VARUNA-P2-002)');
}
