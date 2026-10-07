/**
 * Factor-seam routes — the watchable posture surface (VRN-P1 + widgetization).
 *
 *   GET  /api/v2/posture/:vesselId   → live normalized posture (factors: severity+actor+data_source)
 *   POST /api/v2/testbed/run         → run the owned testbed, return the posture it produced (gated act)
 *   GET  /api/v2/capabilities        → real route bindings for rest-forge → widgets → PWA
 *
 * @rule:VRN-ARCH-007 every response carries data_source   @rule:VRN-041 testbed-only active test
 */

import type { FastifyInstance } from 'fastify';

import { buildVesselPosture } from './posture.js';
import { runTestbed } from './testbed.js';

// Real capability → route bindings. rest-forge reads `run` ("METHOD /route") to compile
// slugs; reads become live widgets, the testbed run is a governed (high-risk) act.
const CAPABILITIES = [
  { id: 'ASSESS_VESSEL_OT_POSTURE', run: 'GET /api/v2/posture/:vesselId', kind: 'read' },
  { id: 'MONITOR_MODBUS_ANOMALIES', run: 'GET /api/v1/modbus/anomalies/:vesselId', kind: 'read' },
  { id: 'BUILD_MODBUS_BASELINE', run: 'GET /api/v1/modbus/baseline/:vesselId', kind: 'read' },
  { id: 'SCORE_IACS_UR_E26_COMPLIANCE', run: 'GET /api/v1/iacs/:vesselId', kind: 'read' },
  { id: 'GENERATE_POSTURE_REPORT_CARD', run: 'GET /api/v1/report/:vesselId', kind: 'read' },
  { id: 'RUN_TESTBED_OT_SIMULATION', run: 'POST /api/v2/testbed/run', kind: 'act' },
  { id: 'INGEST_MODBUS_FRAME', run: 'POST /api/v1/ingest/modbus', kind: 'act' },
];

export async function registerFactorRoutes(app: FastifyInstance): Promise<void> {
  // live normalized posture — the read widget.
  app.get<{ Params: { vesselId: string } }>('/api/v2/posture/:vesselId', async (req) => {
    const _start = Date.now();
    const posture = buildVesselPosture(req.params.vesselId, {
      data_source: 'testbed',
      authorised_sources: ['10.0.0.5'],
    });
    return {
      vessel_id: req.params.vesselId,
      data_source: 'testbed',
      ...posture,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // run the owned testbed — a governed ACT (testbed-only). Returns the posture it produced.
  app.post('/api/v2/testbed/run', async () => {
    const _start = Date.now();
    const run = runTestbed('demo');
    return {
      ...run,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // capability surface for rest-forge (real route bindings → widgets → PWA).
  app.get('/api/v2/capabilities', async () => ({
    service: 'xshieldai-varuna',
    data_source: 'testbed',
    live: CAPABILITIES,
    _meta: { computed_at: new Date().toISOString() },
  }));

  app.log.info(
    'Factor-seam routes registered: /api/v2/posture, /api/v2/testbed/run, /api/v2/capabilities'
  );
}
