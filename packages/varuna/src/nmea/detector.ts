/**
 * NMEA talker-ID anomaly detection + critical sentence watchlist.
 * @rule:VRN-032 NMEA 0183 security
 * @rule:VRN-040 Autopilot heading injection detection
 * @rule:VRN-045 NMEA injection via port-side access
 */

import { randomUUID } from 'crypto';

import type { FastifyBaseLogger } from 'fastify';

import { emitSense } from '../sense/emit.js';
import { getVessel, type NMEAAnomaly } from '../store/vessel.js';

import { CRITICAL_SENTENCE_WATCHLIST, type ParsedNMEA } from './parser.js';

// @rule:VRN-032 Baseline observation window before locking talker-ID registry
const NMEA_BASELINE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24-hour talker baseline

export function observeNMEA(
  log: FastifyBaseLogger,
  vessel_id: string,
  parsed: ParsedNMEA,
  timestamp: number
): NMEAAnomaly | null {
  const vessel = getVessel(vessel_id);

  // Checksum failure is always an anomaly
  if (!parsed.checksum_valid) {
    return recordNMEAAnomaly(log, vessel_id, {
      sentence_type: parsed.sentence_type,
      talker_id: parsed.talker_id,
      anomaly_type: 'checksum_failure',
      rule_id: 'VRN-032',
      severity: 'WARN',
      detected_at: timestamp,
    });
  }

  const existing = vessel.nmeaTalkerBaseline.get(parsed.talker_id);

  if (!vessel.nmeaBaselineLocked) {
    const elapsed = timestamp - (existing?.first_seen ?? timestamp);
    if (elapsed >= NMEA_BASELINE_WINDOW_MS) vessel.nmeaBaselineLocked = true;

    if (existing) {
      existing.sentence_types.add(parsed.sentence_type);
      existing.last_seen = timestamp;
      existing.count++;
    } else {
      vessel.nmeaTalkerBaseline.set(parsed.talker_id, {
        talker_id: parsed.talker_id,
        sentence_types: new Set([parsed.sentence_type]),
        first_seen: timestamp,
        last_seen: timestamp,
        count: 1,
      });
    }
    return null;
  }

  // Baseline locked — detect anomalies

  // @rule:VRN-032 Unknown talker ID
  if (!existing) {
    const isCriticalSentence = CRITICAL_SENTENCE_WATCHLIST.has(parsed.sentence_type);
    const severity: NMEAAnomaly['severity'] = isCriticalSentence ? 'CRITICAL' : 'WARN';
    const rule_id = isCriticalSentence ? 'VRN-040' : 'VRN-032';

    return recordNMEAAnomaly(log, vessel_id, {
      sentence_type: parsed.sentence_type,
      talker_id: parsed.talker_id,
      anomaly_type: isCriticalSentence ? 'critical_sentence_injection' : 'unknown_talker',
      rule_id,
      severity,
      detected_at: timestamp,
    });
  }

  // Known talker — check if this sentence type was in their baseline
  if (!existing.sentence_types.has(parsed.sentence_type)) {
    const isCriticalSentence = CRITICAL_SENTENCE_WATCHLIST.has(parsed.sentence_type);
    if (isCriticalSentence) {
      return recordNMEAAnomaly(log, vessel_id, {
        sentence_type: parsed.sentence_type,
        talker_id: parsed.talker_id,
        anomaly_type: 'critical_sentence_new_type',
        rule_id: 'VRN-032',
        severity: 'WARN',
        detected_at: timestamp,
      });
    }
  }

  // Update known talker
  existing.sentence_types.add(parsed.sentence_type);
  existing.last_seen = timestamp;
  existing.count++;

  return null;
}

function recordNMEAAnomaly(
  log: FastifyBaseLogger,
  vessel_id: string,
  fields: Omit<NMEAAnomaly, 'id' | 'vessel_id'>
): NMEAAnomaly {
  const vessel = getVessel(vessel_id);
  const anomaly: NMEAAnomaly = { id: randomUUID(), vessel_id, ...fields };
  vessel.nmeaAnomalies.push(anomaly);
  if (vessel.nmeaAnomalies.length > 1000) vessel.nmeaAnomalies.shift();

  // @rule:VRN-045 NMEA injection is a SENSE event
  emitSense(log, {
    event_type: 'vrn.nmea.injection.suspected',
    vessel_id,
    rule_id: anomaly.rule_id,
    severity: anomaly.severity,
    before_snapshot: { talker_known: false },
    after_snapshot: { anomaly_type: anomaly.anomaly_type, sentence_type: anomaly.sentence_type },
    delta: { talker_id: anomaly.talker_id },
  });

  return anomaly;
}
