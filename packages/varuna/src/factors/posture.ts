/**
 * buildVesselPosture — the bridge from stored detector state → the factor seam.
 *
 * Reads what the existing detectors already recorded on the vessel (modbusAnomalies,
 * runaway SENSE events, nmeaAnomalies, gpsAnomalies) and runs each through its
 * `*ToFactors` adapter, then aggregates. This is the one place the report card, the
 * dashboard, and the /posture route read — normalized, severity+actor weighted.
 *
 * @rule:VRN-ARCH-004 detectors → factors via the seam   @rule:VRN-ARCH-010 severity+actor
 */

import { getVessel } from '../store/vessel.js';

import { aggregateFactors, type VesselPosture } from './aggregate.js';
import { aisFindingsToFactors, type AisFinding } from './ais-spoof.js';
import { modbusAnomaliesToFactors } from './modbus-anomaly.js';
import { nmeaAnomaliesToFactors } from './nmea-injection.js';
import { runawayToFactor, type RunawayPrecursor } from './runaway-sequence.js';
import type { FactorContext, PostureFactor } from './types.js';

/** Pull runaway-diesel precursors out of the stored SENSE events. */
function runawayPrecursors(vesselId: string): RunawayPrecursor[] {
  const vessel = getVessel(vesselId);
  return vessel.senseEvents
    .filter((e) => e.event_type === 'vrn.runaway_diesel.precursor.detected')
    .map((e) => {
      const d = e.delta as Record<string, number | string>;
      return {
        id: e.id,
        vessel_id: vesselId,
        air_shutoff_address: Number(d.air_shutoff_address ?? 1),
        hc_detector_address: Number(d.hc_detector_address ?? 16),
        air_shutoff_src: String(d.air_shutoff_src ?? 'unknown'),
        hc_detector_src: String(d.hc_detector_src ?? 'unknown'),
        window_ms: Number(d.window_ms ?? 60000),
        detected_at: e.timestamp,
      };
    });
}

/** Map the vessel's GPS anomalies into the normalized AIS finding shape. */
function aisFindings(vesselId: string): AisFinding[] {
  const vessel = getVessel(vesselId);
  return vessel.gpsAnomalies.map((g, i) => ({
    id: `${vesselId}-gps-${i}-${g.detected_at}`,
    vessel_id: vesselId,
    type:
      g.type === 'gps_spoof' || g.type === 'position_jump'
        ? (g.type as AisFinding['type'])
        : 'position_jump',
    detail: g.detail,
    detected_at: g.detected_at,
  }));
}

export function buildVesselPosture(vesselId: string, ctx: FactorContext): VesselPosture {
  const vessel = getVessel(vesselId);
  const factors: PostureFactor[] = [
    ...runawayPrecursors(vesselId).map((p) => runawayToFactor(p, ctx)),
    ...modbusAnomaliesToFactors(vessel.modbusAnomalies, ctx),
    ...nmeaAnomaliesToFactors(vessel.nmeaAnomalies, ctx),
    ...aisFindingsToFactors(aisFindings(vesselId), ctx),
  ];
  return aggregateFactors(factors);
}
