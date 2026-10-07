/**
 * Evidence pack routes — VRN + IACS UR + MITRE ATT&CK ICS.
 * @rule:VRN-047 Three-column evidence pack
 * @rule:P2-004  Evidence pack generation
 * @rule:CA-004  _meta on every resolver
 */

import type { FastifyInstance } from 'fastify';

import { runIACSScorer } from '../iacs/scorer.js';
import { getVessel } from '../store/vessel.js';

import { buildEvidencePack, buildTriggeredEvidencePack } from './pack.js';

export async function registerEvidenceRoutes(app: FastifyInstance): Promise<void> {
  // GET /api/v1/evidence/:vesselId?triggered_only=true
  app.get<{
    Params: { vesselId: string };
    Querystring: { triggered_only?: string };
  }>('/api/v1/evidence/:vesselId', async (request) => {
    const _start = Date.now();
    const vessel = getVessel(request.params.vesselId);

    // Run IACS scorer first to populate audit results
    if (vessel.iacs_audit.length === 0) runIACSScorer(vessel);

    const triggered_only = request.query.triggered_only !== 'false';
    const pack = triggered_only ? buildTriggeredEvidencePack(vessel) : buildEvidencePack(vessel);

    return {
      vessel_id: request.params.vesselId,
      triggered_only,
      evidence_count: pack.length,
      evidence: pack,
      legend: {
        columns: ['vrn_rule', 'iacs_clause', 'mitre_technique_id', 'finding'],
        note: 'triggered=true entries have FAIL or PARTIAL status',
      },
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info('Evidence routes registered: three-column pack (VARUNA-P2-004)');
}
