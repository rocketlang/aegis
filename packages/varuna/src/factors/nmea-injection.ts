/**
 * nmea-injection — map existing NMEAAnomaly results → PostureFactors.
 * Detection lives in ../nmea/detector.ts (talker-ID baseline + critical-sentence watchlist).
 * @rule:VRN-ARCH-004 *ToFactors seam   @rule:VRN-032 NMEA security   @rule:VRN-040 heading injection
 */

import type { NMEAAnomaly } from '../store/vessel.js';

import {
  type Actor,
  type FactorAdapterMeta,
  type FactorContext,
  type PostureFactor,
  type Severity,
} from './types.js';

export const meta: FactorAdapterMeta = {
  verb: 'DETECT_NMEA_INJECTION',
  rules: ['VRN-032', 'VRN-040', 'VRN-045'],
};

// A spoofed heading/critical sentence can drive the autopilot — serious. An unexpected
// talker that is not a critical sentence is moderate.
const CRITICAL_SENTENCES = new Set(['HEHDT', 'GPGGA', 'IIRSA', 'HEROT', 'GPRMC']);

export function nmeaAnomaliesToFactors(
  anomalies: NMEAAnomaly[],
  ctx: FactorContext
): PostureFactor[] {
  return anomalies.map((a) => {
    const isCritical =
      a.severity === 'CRITICAL' || CRITICAL_SENTENCES.has(a.sentence_type?.replace(/^\$/, ''));
    const severity: Severity = isCritical ? 'serious' : 'moderate';
    // An injected sentence from an unrecognised talker reads as outsider; a known talker
    // emitting an unexpected sentence reads as insider; otherwise unknown.
    const actor: Actor =
      a.anomaly_type === 'unknown_talker'
        ? 'outsider'
        : a.anomaly_type === 'unexpected_sentence'
          ? 'insider'
          : 'unknown';
    return {
      id: a.id,
      threat: a.anomaly_type === 'unknown_talker' ? 'nmea_unknown_talker' : 'nmea_injection',
      summary: `NMEA ${a.anomaly_type.replace(/_/g, ' ')} — talker ${a.talker_id} sentence ${a.sentence_type}`,
      severity,
      actor,
      data_source: ctx.data_source,
      vrn_ref: [a.rule_id],
      iacs_capability: 'UR E26 §5 bridge network integrity',
      mitre_technique: 'T0856', // Spoof Reporting Message
      evidence: {
        anomaly_id: a.id,
        talker_id: a.talker_id,
        sentence_type: a.sentence_type,
        source_severity: a.severity,
      },
      attribution: { src: a.talker_id, reason: `talker-id classification: ${a.anomaly_type}` },
      detected_at: a.detected_at,
    };
  });
}
