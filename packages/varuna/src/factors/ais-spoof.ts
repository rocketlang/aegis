/**
 * ais-spoof — map AIS/GPS spoof findings → PostureFactors.
 * Detection lives in ../ais/detector.ts (observeAIS/observeGPS: MMSI anomaly, position
 * jump, SAR-type, GPS spoof). Those return transient findings; routes build the normalized
 * AisFinding below and pass it here.
 * @rule:VRN-ARCH-004 *ToFactors seam   @rule:VRN-035 AIS spoofing   @rule:VRN-036 GPS spoofing
 */

import {
  type Actor,
  type FactorAdapterMeta,
  type FactorContext,
  type PostureFactor,
  type Severity,
} from './types.js';

export const meta: FactorAdapterMeta = {
  verb: 'DETECT_AIS_SPOOFING',
  rules: ['VRN-035', 'VRN-036', 'VRN-YK-005'],
};

/** Normalized AIS/GPS finding (built by routes from the detector return). */
export interface AisFinding {
  id: string;
  vessel_id: string;
  type: 'invalid_mmsi_zero' | 'duplicate_mmsi' | 'position_jump' | 'sar_from_surface' | 'gps_spoof';
  detail: string;
  mmsi?: number;
  jump_nm?: number;
  detected_at: number;
}

const SEVERITY: Record<AisFinding['type'], Severity> = {
  gps_spoof: 'serious', // own-ship position falsified — navigation hazard
  position_jump: 'serious',
  duplicate_mmsi: 'moderate',
  sar_from_surface: 'moderate',
  invalid_mmsi_zero: 'nuisance',
};

const THREAT: Record<AisFinding['type'], PostureFactor['threat']> = {
  gps_spoof: 'gps_spoof',
  position_jump: 'ais_spoof',
  duplicate_mmsi: 'ais_spoof',
  sar_from_surface: 'ais_spoof',
  invalid_mmsi_zero: 'ais_invalid_mmsi',
};

export function aisFindingsToFactors(findings: AisFinding[], ctx: FactorContext): PostureFactor[] {
  return findings.map((f) => {
    // AIS/GPS spoofing is RF-injected — actor is outsider unless a bridge-correlation
    // tree later attributes it; never insider from shape alone.
    const actor: Actor = 'outsider';
    return {
      id: f.id,
      threat: THREAT[f.type],
      summary: `AIS/GPS ${f.type.replace(/_/g, ' ')} — ${f.detail}`,
      severity: SEVERITY[f.type],
      actor,
      data_source: ctx.data_source,
      vrn_ref: f.type === 'gps_spoof' ? ['VRN-036'] : ['VRN-035'],
      iacs_capability: 'UR E26 §5 position/navigation source integrity',
      mitre_technique: 'T0856', // Spoof Reporting Message
      evidence: {
        finding_id: f.id,
        type: f.type,
        mmsi: f.mmsi,
        jump_nm: f.jump_nm,
        detail: f.detail,
      },
      attribution: {
        reason: 'AIS/GPS injection — RF-attributable only via bridge-correlation tree (Phase 3)',
      },
      detected_at: f.detected_at,
    };
  });
}
