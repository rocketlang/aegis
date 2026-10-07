/**
 * runaway-sequence — the flagship catastrophic factor.
 *
 * The two-coil detector lives in ../modbus/detector.ts#checkRunawayDiesel (air-shutoff
 * disable + HC-detector suppress within 60s). When it fires, this adapter mints the
 * single CATASTROPHIC PostureFactor that dominates the posture — the engine = catastrophe
 * wedge. Consequence-weighted: one of these saturates the deduction to 100.
 *
 * @rule:VRN-ARCH-004 *ToFactors seam   @rule:VRN-019 safety integrity   @rule:VRN-044 two-coil runaway
 */

import {
  type Actor,
  type FactorAdapterMeta,
  type FactorContext,
  type PostureFactor,
} from './types.js';

export const meta: FactorAdapterMeta = {
  verb: 'DETECT_RUNAWAY_DIESEL_SEQUENCE',
  rules: ['VRN-019', 'VRN-044', 'VRN-ARCH-003'],
};

/** The delta the two-coil detector observed (mirrors its SENSE `delta`). */
export interface RunawayPrecursor {
  id: string;
  vessel_id: string;
  air_shutoff_address: number;
  hc_detector_address: number;
  air_shutoff_src: string;
  hc_detector_src: string;
  window_ms: number;
  detected_at: number;
}

function classifyActor(p: RunawayPrecursor, ctx: FactorContext): { actor: Actor; reason: string } {
  const srcs = [p.air_shutoff_src, p.hc_detector_src];
  const known = srcs.every((s) => ctx.authorised_sources?.includes(s));
  if (known)
    return {
      actor: 'insider',
      reason: 'both coil writes from authorised station(s) — sabotage or compromised credential',
    };
  if (srcs.some((s) => ctx.authorised_sources?.includes(s)))
    return {
      actor: 'unknown',
      reason: 'mixed authorised/unknown sources across the two coil writes',
    };
  return {
    actor: 'outsider',
    reason: 'safety-coil writes from source(s) outside the authorised set',
  };
  // rogue_agent: set by the HanumanG correlation in VRN-P1-8, never here.
}

export function runawayToFactor(p: RunawayPrecursor, ctx: FactorContext): PostureFactor {
  const { actor, reason } = classifyActor(p, ctx);
  return {
    id: p.id,
    threat: 'runaway_diesel_precursor',
    summary:
      `Runaway-diesel precursor — air-shutoff coil 0x${p.air_shutoff_address.toString(16)} disabled AND ` +
      `HC-detector coil 0x${p.hc_detector_address.toString(16)} suppressed within ${Math.round(p.window_ms / 1000)}s`,
    severity: 'catastrophic',
    actor,
    data_source: ctx.data_source,
    vrn_ref: ['VRN-019', 'VRN-044'],
    iacs_capability: 'UR E26 §6 safety-system integrity (independent protection)',
    mitre_technique: 'T0831', // Manipulation of Control
    evidence: {
      precursor_id: p.id,
      air_shutoff: { address: p.air_shutoff_address, src: p.air_shutoff_src },
      hc_detector: { address: p.hc_detector_address, src: p.hc_detector_src },
      window_ms: p.window_ms,
      before_snapshot: { air_shutoff_coil: 'ENABLED', hc_detector: 'ACTIVE' },
      after_snapshot: { air_shutoff_coil: 'DISABLED', hc_detector: 'SUPPRESSED' },
    },
    attribution: { src: `${p.air_shutoff_src},${p.hc_detector_src}`, reason },
    detected_at: p.detected_at,
  };
}
