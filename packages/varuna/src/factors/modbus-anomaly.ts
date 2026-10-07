/**
 * modbus-anomaly — map the existing ModbusAnomaly results → normalized PostureFactors.
 *
 * The detection logic already lives in ../modbus/detector.ts (7-day baseline, FC
 * allowlist, always-alert FCs). This is the THIN seam that gives those findings the
 * consequence-weighted severity + actor axis + data_source the card/dashboard/reconciler
 * read. No re-detection here — adapter only (VRN-ARCH-004, VRN-YK-008 inherit-don't-invent).
 *
 * @rule:VRN-ARCH-004 *ToFactors seam   @rule:VRN-026 modbus controls   @rule:VRN-009 FC filtering
 */

import type { ModbusAnomaly } from '../store/vessel.js';

import {
  type Actor,
  type FactorAdapterMeta,
  type FactorContext,
  type PostureFactor,
  type Severity,
} from './types.js';

/** Code-truth capability this family declares (read by the reconciler). */
export const meta: FactorAdapterMeta = {
  verb: 'MONITOR_MODBUS_ANOMALIES',
  rules: ['VRN-026', 'VRN-009', 'VRN-043', 'VRN-ARCH-002'],
};

// anomaly_type → consequence severity. A diagnostic/safety-touching command outranks a
// merely-unknown tuple; none of these alone is catastrophic (that is runaway-sequence).
const SEVERITY: Record<string, Severity> = {
  always_alert_fc: 'serious', // FC 08 diagnostic — can reset/halt a controller
  fc_allowlist_violation: 'serious', // a write FC from a non-maintenance source
  broadcast_write: 'moderate', // unit-id 0 broadcast write
  unknown_tuple: 'moderate', // post-baseline tuple never seen in 7-day lock
};

const THREAT: Record<string, PostureFactor['threat']> = {
  always_alert_fc: 'modbus_always_alert_fc',
  fc_allowlist_violation: 'modbus_fc_violation',
  broadcast_write: 'modbus_broadcast_write',
  unknown_tuple: 'modbus_unknown_tuple',
};

// MITRE ATT&CK for ICS — write/command anomalies map to Unauthorized Command Message.
const MITRE: Record<string, string> = {
  always_alert_fc: 'T0855', // Unauthorized Command Message
  fc_allowlist_violation: 'T0855',
  broadcast_write: 'T0806', // Brute Force I/O (broadcast)
  unknown_tuple: 'T0830', // Adversary-in-the-Middle / unexpected comms
};

/**
 * Classify WHO from the finding shape only (VRN-YK-012). An authorised station acting
 * out of policy → insider; an unattributable/unknown source → outsider; ambiguous →
 * unknown. `rogue_agent` is NEVER set here — it requires the HanumanG correlation (P1-8).
 */
function classifyActor(
  src: string | undefined,
  ctx: FactorContext
): { actor: Actor; reason: string } {
  if (src && ctx.authorised_sources?.includes(src)) {
    return { actor: 'insider', reason: 'authorised station acting outside policy/cadence' };
  }
  if (src) {
    return { actor: 'outsider', reason: 'write/command from a source not in the authorised set' };
  }
  return { actor: 'unknown', reason: 'source not attributable from frame' };
}

export function modbusAnomaliesToFactors(
  anomalies: ModbusAnomaly[],
  ctx: FactorContext
): PostureFactor[] {
  return anomalies.map((a) => {
    const severity = SEVERITY[a.anomaly_type] ?? 'nuisance';
    const { actor, reason } = classifyActor(a.tuple?.src_ip, ctx);
    return {
      id: a.id,
      threat: THREAT[a.anomaly_type] ?? 'modbus_unknown_tuple',
      summary: `Modbus ${a.anomaly_type.replace(/_/g, ' ')} — unit ${a.tuple.unit_id} fc ${a.tuple.function_code} reg 0x${a.tuple.register.toString(16)}`,
      severity,
      actor,
      data_source: ctx.data_source,
      vrn_ref: [a.rule_id],
      iacs_capability: 'UR E26 §4 network segmentation & access control',
      mitre_technique: MITRE[a.anomaly_type],
      evidence: { anomaly_id: a.id, tuple: a.tuple, value: a.value, source_severity: a.severity },
      attribution: { src: a.tuple?.src_ip, reason },
      detected_at: a.detected_at,
    };
  });
}
