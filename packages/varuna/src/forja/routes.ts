/**
 * Forja Protocol v2.0 — Varuna Maritime OT Posture
 * @rule:FP-003 Forja-Native by Default
 *
 * STATE  — vessel posture manifest + IACS capability flags
 * TRUST  — role-based permissions per maritime role
 * SENSE  — OT anomaly + posture change event bus
 * PROOF  — @rule: annotation coverage across VRN-001 to VRN-050
 *
 * Implements: VARUNA-P0-001 to VARUNA-P0-004
 */

import type { FastifyInstance } from 'fastify';

import { scanProof } from './proof.js';

// ─── Capability constants (synced with codex.json) ───────────────────────────

// @rule:VRN-050 Posture is a living score — can_answer reflects continuous capability
const CAN_ANSWER = [
  'What is the OT cyber posture score for this vessel?',
  'Does this vessel comply with IACS UR E26/E27?',
  'Which VRN rules does this vessel fail?',
  "Has this vessel's Modbus bus shown anomalous write patterns?",
  'What is the runaway-diesel risk for this engine configuration?',
  "Is this vessel's NMEA bus showing injection anomalies?",
  'What is the AIS integrity status for this vessel?',
  "What protocol security gaps exist on this vessel's bridge network?",
  'Is this vessel ready for P&I cyber renewal assessment?',
  "What is the vessel's IACS UR E26 compliance gap?",
];

const CAN_DO = [
  'ASSESS_VESSEL_OT_POSTURE',
  'SCORE_IACS_UR_E26_COMPLIANCE',
  'MONITOR_MODBUS_ANOMALIES',
  'DETECT_NMEA_INJECTION',
  'DETECT_AIS_SPOOFING',
  'DETECT_RUNAWAY_DIESEL_SEQUENCE',
  'GENERATE_POSTURE_REPORT_CARD',
  'MAP_VESSEL_PROTOCOL_SURFACE',
  'SCORE_VESSEL_PROTOCOL_SECURITY',
  'VALIDATE_OT_PENTEST_SCOPE',
  'BUILD_MODBUS_BASELINE',
  'CORRELATE_BRIDGE_PROTOCOL_ANOMALIES',
];

// @rule:VRN-015 Continuous monitoring emits events for every state change
const EMITS = [
  'vrn.modbus.anomaly.detected',
  'vrn.nmea.injection.suspected',
  'vrn.ais.spoofing.detected',
  'vrn.runaway_diesel.precursor.detected',
  'vrn.posture.score.computed',
  'vrn.posture.degraded',
  'vrn.iacs_compliance.gap.found',
  'vrn.safety_system.integrity.alert',
  'vrn.vendor_laptop.connection.detected',
  'vrn.pentest.scope.validated',
];

// ─── Trust bitmask values (from @ankr/trust-constants — BMK-004) ─────────────
// READ=1 QUERY=2 WRITE=4 EXECUTE=8 APPROVE=16 AUDIT=32 ADMIN=64
// @rule:BMK-004 bit positions from @ankr/trust-constants — defined inline until
// trust-constants is added to ankrshield workspace dependencies
const PERM = {
  READ: 1,
  QUERY: 2,
  WRITE: 4,
  EXECUTE: 8,
  APPROVE: 16,
  AUDIT: 32,
  ADMIN: 64,
} as const;

// @rule:VRN-005 Crew cyber roles must be named — TRUST differentiates by named role
const ROLE_PERMISSIONS: Record<string, { mask: number; can_do: string[] }> = {
  p_and_i_auditor: {
    mask: PERM.READ | PERM.QUERY | PERM.AUDIT, // 35
    can_do: [
      'ASSESS_VESSEL_OT_POSTURE',
      'SCORE_IACS_UR_E26_COMPLIANCE',
      'GENERATE_POSTURE_REPORT_CARD',
    ],
  },
  dpa: {
    mask: PERM.READ | PERM.QUERY | PERM.WRITE | PERM.EXECUTE | PERM.AUDIT, // 47
    can_do: CAN_DO,
  },
  technical_superintendent: {
    mask: PERM.READ | PERM.QUERY | PERM.WRITE | PERM.EXECUTE, // 15
    can_do: CAN_DO.filter((c) => c !== 'VALIDATE_OT_PENTEST_SCOPE'),
  },
  captain: {
    mask: PERM.READ | PERM.QUERY, // 3
    can_do: ['ASSESS_VESSEL_OT_POSTURE', 'SCORE_IACS_UR_E26_COMPLIANCE'],
  },
  crew_cyber_officer: {
    mask: PERM.READ | PERM.QUERY | PERM.EXECUTE, // 11
    can_do: [
      'MONITOR_MODBUS_ANOMALIES',
      'DETECT_NMEA_INJECTION',
      'DETECT_AIS_SPOOFING',
      'DETECT_RUNAWAY_DIESEL_SEQUENCE',
    ],
  },
};

// ─── Routes ───────────────────────────────────────────────────────────────────

export async function registerForjaRoutes(app: FastifyInstance): Promise<void> {
  // @rule:VRN-001 OT asset inventory is gate zero — STATE declares what Varuna knows
  // VARUNA-P0-001: GET /api/v2/forja/state
  app.get('/api/v2/forja/state', async () => {
    const _start = Date.now();
    return {
      service_key: 'xshieldai-varuna',
      version: '0.1.0',
      forja_version: '2.0',
      product_family: 'xShieldAI Maritime',
      can_answer: CAN_ANSWER,
      can_do: CAN_DO,
      emits: EMITS,
      depends_on: ['xshieldai', 'ship8x', 'superdomain', 'ai-proxy'],
      trust_mask: 1,
      k_mask: 255,
      // @rule:VRN-ARCH-007 honesty floor — every runtime DetectorResult/factor/card/tile
      // carries data_source ∈ {testbed, live_vessel}; never imply a live-vessel scan on
      // testbed data. Phase 0: no detectors shipped yet → runtime surface is BUILDING.
      data_source: {
        current: 'testbed',
        available: ['testbed', 'live_vessel'],
        live_capture: false,
        note: 'Phase 0 — detector-registry pre-build (dashboard BUILDING). Live-vessel capture lands at Phase 4 (source-swap only, VRN-YK-011); the flip is backed by a real capture, never asserted.',
      },
      lifecycle_status: 'phase-0-forja-wire',
      regulatory_anchors: [
        'IACS UR E26',
        'IACS UR E27',
        'NIST CSF v2.0',
        'IEC 62443-2-1',
        'NIST SP 800-82r3',
      ],
      iacs_compliance: {
        ur_e26: 'not_assessed',
        ur_e27: 'not_assessed',
        capabilities_scored: 0,
        capabilities_total: 25,
        note: 'Phase 1 build required for live scoring',
      },
      protocol_coverage: {
        engine_protocols: [
          'Modbus/TCP',
          'Modbus/RTU',
          'CANbus',
          'MAN CEAS/WOIS/K-Chief',
          'IEC 62443 zones',
          'AMS',
        ],
        bridge_protocols: [
          'NMEA 0183',
          'NMEA 2000',
          'IEC 61162-450',
          'AIS',
          'GPS/GNSS',
          'ECDIS ENC',
          'VDR',
          'GMDSS',
          'Autopilot',
        ],
        monitoring_status: 'not_started',
      },
      // @rule:CA-004 _meta on every resolver
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // GET /api/v2/forja/state/:vesselId — per-vessel posture snapshot
  app.get<{ Params: { vesselId: string } }>('/api/v2/forja/state/:vesselId', async (request) => {
    const _start = Date.now();
    return {
      service_key: 'xshieldai-varuna',
      vessel_id: request.params.vesselId,
      can_answer: CAN_ANSWER,
      can_do: CAN_DO,
      posture_score: null,
      iacs_compliance: { ur_e26: 'not_assessed', ur_e27: 'not_assessed' },
      note: 'Phase 1 build required for live vessel posture scoring',
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  // @rule:VRN-005 Crew cyber roles named, not assumed — TRUST differentiates
  // VARUNA-P0-002: GET /api/v2/forja/trust/:userId
  app.get<{ Params: { userId: string }; Querystring: { role?: string } }>(
    '/api/v2/forja/trust/:userId',
    async (request, reply) => {
      const _start = Date.now();
      const role = request.query.role ?? 'captain';

      const perms = ROLE_PERMISSIONS[role];
      if (!perms) {
        return reply.status(400).send({
          error: 'unknown_role',
          message: `Role '${role}' not recognised. Known roles: ${Object.keys(ROLE_PERMISSIONS).join(', ')}`,
        });
      }

      return {
        user_id: request.params.userId,
        role,
        trust_mask: perms.mask,
        can_do: perms.can_do,
        can_access_posture_history: (perms.mask & PERM.AUDIT) !== 0,
        can_trigger_assessment: (perms.mask & PERM.EXECUTE) !== 0,
        can_generate_report_card: perms.can_do.includes('GENERATE_POSTURE_REPORT_CARD'),
        _meta: {
          computed_at: new Date().toISOString(),
          duration_ms: Date.now() - _start,
          trust_mask_applied: perms.mask,
        },
      };
    }
  );

  // @rule:VRN-015 Continuous monitoring emits events on every posture state change
  // @rule:CA-003 SENSE payload must include before_snapshot + after_snapshot + delta
  // VARUNA-P0-003: POST /api/v2/forja/sense/emit
  app.post<{
    Body: {
      event_type: string;
      vessel_id: string;
      before_snapshot: Record<string, unknown>;
      after_snapshot: Record<string, unknown>;
      delta: Record<string, unknown>;
      rule_id?: string;
      timestamp_utc?: string;
    };
  }>('/api/v2/forja/sense/emit', async (request, reply) => {
    const {
      event_type,
      vessel_id,
      before_snapshot,
      after_snapshot,
      delta: _delta,
      rule_id,
      timestamp_utc,
    } = request.body;

    if (!EMITS.includes(event_type)) {
      return reply.status(400).send({
        error: 'unknown_event',
        message: `Event '${event_type}' not in declared EMITS. Known: ${EMITS.join(', ')}`,
      });
    }

    if (!vessel_id) {
      return reply.status(400).send({
        error: 'missing_vessel_id',
        message: 'vessel_id is required on all VRN SENSE events',
      });
    }

    if (before_snapshot === undefined || after_snapshot === undefined) {
      return reply.status(400).send({
        error: 'missing_snapshots',
        message:
          'CA-003: before_snapshot and after_snapshot are required on all vrn.* SENSE events',
      });
    }

    // @rule:VRN-019 Safety system integrity events are CRITICAL severity
    const isSafetyEvent =
      event_type === 'vrn.runaway_diesel.precursor.detected' ||
      event_type === 'vrn.safety_system.integrity.alert';

    app.log.info(
      { event_type, vessel_id, rule_id, is_safety: isSafetyEvent },
      'VRN SENSE event emitted'
    );

    return {
      emitted: true,
      event_type,
      vessel_id,
      rule_id: rule_id ?? null,
      severity: isSafetyEvent ? 'CRITICAL' : 'INFO',
      timestamp_utc: timestamp_utc ?? new Date().toISOString(),
    };
  });

  // @rule:FP-004 Code Implements Rules — PROOF enforces annotation coverage
  // VARUNA-P0-004: GET /api/v2/forja/proof
  app.get('/api/v2/forja/proof', async () => {
    const _start = Date.now();
    const proof = scanProof();
    return {
      service_key: 'xshieldai-varuna',
      logics_doc: 'xshieldai-varuna--logics--formal--2026-05-05.md',
      files_total: proof.files_total,
      files_annotated: proof.files_annotated,
      file_coverage_pct: proof.file_coverage_pct,
      vrn_code_implementable: proof.vrn_code_implementable,
      vrn_procedural_count: proof.vrn_procedural_count,
      vrn_annotated_of_implementable: proof.vrn_annotated_of_implementable,
      vrn_coverage_pct: proof.vrn_coverage_pct,
      rules_annotated: proof.unique_rule_ids.length,
      annotation_count_total: proof.annotation_count_total,
      coverage_pct: proof.coverage_pct,
      proof_status: proof.proof_status,
      annotation_target: 0.9,
      vrn_shastra_annotated: proof.vrn_shastra_annotated,
      vrn_yukti_annotated: proof.vrn_yukti_annotated,
      other_rule_ids: proof.other_rule_ids,
      missing_vrn_implementable: proof.missing_vrn_implementable,
      _meta: {
        computed_at: new Date().toISOString(),
        duration_ms: Date.now() - _start,
        trust_mask_applied: 1,
      },
    };
  });

  app.log.info(
    'Forja v2.0 routes registered: STATE + TRUST + SENSE + PROOF (VARUNA-P0-001 to P0-004)'
  );
}
