/**
 * Modbus ingest + query routes.
 * @rule:VRN-026 Modbus/TCP security controls
 * @rule:VRN-041 Never write to live vessel OT — these endpoints only accept observed frames
 */

import type { FastifyInstance } from 'fastify';

import { emitSense } from '../sense/emit.js';
import { getVessel } from '../store/vessel.js';

import { checkFcAllowlist, checkRunawayDiesel, observeModbus } from './detector.js';

export async function registerModbusRoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-026 Ingest a passively observed Modbus frame
  // @rule:VRN-041 Passive observation only — Varuna never writes to OT
  app.post<{
    Body: {
      vessel_id: string;
      src_ip: string;
      unit_id: number;
      function_code: number;
      register: number;
      value: number;
      timestamp?: number;
      maintenance_whitelist?: string[];
    };
  }>('/api/v1/ingest/modbus', async (request, reply) => {
    const _start = Date.now();
    const {
      vessel_id,
      src_ip,
      unit_id,
      function_code,
      register,
      value,
      maintenance_whitelist = [],
    } = request.body;
    const timestamp = request.body.timestamp ?? Date.now();

    if (!vessel_id || !src_ip) {
      return reply.status(400).send({ error: 'vessel_id and src_ip are required' });
    }

    const frame = { src_ip, unit_id, function_code, register, value, timestamp };

    // @rule:VRN-044 Check runaway-diesel FIRST — highest priority
    const runaway = checkRunawayDiesel(app.log, vessel_id, frame);

    // @rule:VRN-026 Baseline observe / anomaly detect
    const baselineAnomaly = observeModbus(vessel_id, frame);

    // @rule:VRN-009 FC allowlist check
    const allowlistAnomaly = checkFcAllowlist(app.log, vessel_id, frame, maintenance_whitelist);

    if (baselineAnomaly) {
      emitSense(app.log, {
        event_type: 'vrn.modbus.anomaly.detected',
        vessel_id,
        rule_id: baselineAnomaly.rule_id,
        severity: baselineAnomaly.severity,
        before_snapshot: { tuple_in_baseline: false },
        after_snapshot: { anomaly_type: baselineAnomaly.anomaly_type },
        delta: { src_ip, unit_id, function_code, register, value },
      });
    }

    const vessel = getVessel(vessel_id);

    return {
      ingested: true,
      vessel_id,
      baseline_locked: vessel.modbusBaselineLocked,
      baseline_tuples: vessel.modbusBaseline.size,
      anomaly_detected: !!(baselineAnomaly || allowlistAnomaly),
      runaway_diesel_alert: runaway,
      anomaly: baselineAnomaly ?? allowlistAnomaly ?? null,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v1/modbus/baseline/:vesselId
  app.get<{ Params: { vesselId: string } }>(
    '/api/v1/modbus/baseline/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      return {
        vessel_id: request.params.vesselId,
        locked: vessel.modbusBaselineLocked,
        observation_started: new Date(vessel.modbusBaselineStarted).toISOString(),
        tuple_count: vessel.modbusBaseline.size,
        tuples: [...vessel.modbusBaseline.values()],
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  // GET /api/v1/modbus/anomalies/:vesselId
  app.get<{ Params: { vesselId: string }; Querystring: { severity?: string; limit?: string } }>(
    '/api/v1/modbus/anomalies/:vesselId',
    async (request) => {
      const _start = Date.now();
      const vessel = getVessel(request.params.vesselId);
      const { severity, limit = '50' } = request.query;

      let anomalies = [...vessel.modbusAnomalies].reverse();
      if (severity) anomalies = anomalies.filter((a) => a.severity === severity.toUpperCase());
      anomalies = anomalies.slice(0, parseInt(limit));

      return {
        vessel_id: request.params.vesselId,
        total: vessel.modbusAnomalies.length,
        returned: anomalies.length,
        anomalies,
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: 1,
        },
      };
    }
  );

  app.log.info('Modbus routes registered: ingest + baseline + anomalies (VARUNA-P1-001 to P1-004)');
}
