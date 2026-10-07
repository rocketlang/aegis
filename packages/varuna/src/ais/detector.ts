/**
 * AIS MMSI anomaly detection + GPS position-jump + bridge correlation.
 * @rule:VRN-035 AIS spoofing detection (SHP-008 cross-reference)
 * @rule:VRN-036 GPS/GNSS spoofing signature detection
 * @rule:VRN-YK-005 Bridge protocol correlation tree
 */

import type { FastifyBaseLogger } from 'fastify';

import { emitSense } from '../sense/emit.js';
import { getVessel, type GpsPosition } from '../store/vessel.js';

// @rule:VRN-036 Position jump threshold: 200m per update cycle indicates spoofing
const POSITION_JUMP_THRESHOLD_NM = 0.108; // 200m ≈ 0.108 NM
// @rule:VRN-035 Bridge correlation discrepancy threshold
const GPS_AIS_DISCREPANCY_THRESHOLD_NM = 0.1;
// @rule:VRN-035 Position jump threshold for AIS
const AIS_POSITION_JUMP_THRESHOLD_NM = 0.5;

// Haversine distance in nautical miles
function haversineNm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 3440.065;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) * Math.cos((lat2 * Math.PI) / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ─── AIS MMSI anomaly monitor ─────────────────────────────────────────────────

export interface AISMessage {
  vessel_id: string; // vessel that received this AIS message
  mmsi: string;
  msg_type: number; // AIS message type 1-27
  lat: number;
  lon: number;
  timestamp: number;
  own_ship?: boolean; // true = this vessel's own AIS transponder
}

export function observeAIS(
  log: FastifyBaseLogger,
  msg: AISMessage
): { anomaly: boolean; type?: string; detail?: string } {
  const vessel = getVessel(msg.vessel_id);

  // @rule:VRN-035 MMSI 0 = invalid
  if (msg.mmsi === '0' || msg.mmsi === '000000000') {
    emitSense(log, {
      event_type: 'vrn.ais.spoofing.detected',
      vessel_id: msg.vessel_id,
      rule_id: 'VRN-035',
      severity: 'WARN',
      before_snapshot: { mmsi_valid: true },
      after_snapshot: { mmsi_valid: false, mmsi: msg.mmsi },
      delta: { anomaly_type: 'invalid_mmsi_zero' },
    });
    return { anomaly: true, type: 'invalid_mmsi_zero', detail: 'MMSI 0 observed' };
  }

  // @rule:VRN-035 SAR aircraft (type 9) from surface position
  if (msg.msg_type === 9 && Math.abs(msg.lat) < 80) {
    emitSense(log, {
      event_type: 'vrn.ais.spoofing.detected',
      vessel_id: msg.vessel_id,
      rule_id: 'VRN-035',
      severity: 'WARN',
      before_snapshot: { sar_aircraft_at_surface: false },
      after_snapshot: { sar_aircraft_at_surface: true, mmsi: msg.mmsi },
      delta: { anomaly_type: 'sar_aircraft_surface_position', lat: msg.lat, lon: msg.lon },
    });
    return {
      anomaly: true,
      type: 'sar_aircraft_surface_position',
      detail: `SAR aircraft MMSI ${msg.mmsi} at surface position`,
    };
  }

  const existing = vessel.mmsiRegistry.get(msg.mmsi);

  if (existing) {
    // @rule:VRN-035 Position jump > 0.5 NM per update
    const dist = haversineNm(existing.lat, existing.lon, msg.lat, msg.lon);
    if (dist > AIS_POSITION_JUMP_THRESHOLD_NM) {
      emitSense(log, {
        event_type: 'vrn.ais.spoofing.detected',
        vessel_id: msg.vessel_id,
        rule_id: 'VRN-035',
        severity: 'WARN',
        before_snapshot: { lat: existing.lat, lon: existing.lon },
        after_snapshot: { lat: msg.lat, lon: msg.lon },
        delta: { mmsi: msg.mmsi, jump_nm: Math.round(dist * 1000) / 1000 },
      });
      // Update position
      existing.lat = msg.lat;
      existing.lon = msg.lon;
      existing.last_seen = msg.timestamp;
      existing.msg_count++;
      return {
        anomaly: true,
        type: 'position_jump',
        detail: `MMSI ${msg.mmsi} jumped ${dist.toFixed(3)} NM`,
      };
    }
    existing.lat = msg.lat;
    existing.lon = msg.lon;
    existing.last_seen = msg.timestamp;
    existing.msg_count++;
  } else {
    vessel.mmsiRegistry.set(msg.mmsi, {
      mmsi: msg.mmsi,
      lat: msg.lat,
      lon: msg.lon,
      last_seen: msg.timestamp,
      msg_count: 1,
    });
  }

  if (msg.own_ship) {
    vessel.ownShipMmsi = msg.mmsi;
    vessel.lastAisPosition = { lat: msg.lat, lon: msg.lon, timestamp: msg.timestamp };
    // Run bridge correlation
    checkBridgeCorrelation(log, msg.vessel_id);
  }

  return { anomaly: false };
}

// ─── GPS position-jump detector ──────────────────────────────────────────────

// @rule:VRN-036 GPS spoofing signature: position jump inconsistent with vessel dynamics
export function observeGPS(
  log: FastifyBaseLogger,
  vessel_id: string,
  pos: GpsPosition
): { anomaly: boolean; jump_nm?: number } {
  const vessel = getVessel(vessel_id);
  const last = vessel.lastGpsPosition;

  if (last) {
    const dist = haversineNm(last.lat, last.lon, pos.lat, pos.lon);
    if (dist > POSITION_JUMP_THRESHOLD_NM) {
      vessel.gpsAnomalies.push({
        type: 'position_jump',
        detail: `GPS jumped ${dist.toFixed(3)} NM`,
        detected_at: pos.timestamp,
      });

      emitSense(log, {
        event_type: 'vrn.ais.spoofing.detected',
        vessel_id,
        rule_id: 'VRN-036',
        severity: 'WARN',
        before_snapshot: { lat: last.lat, lon: last.lon },
        after_snapshot: { lat: pos.lat, lon: pos.lon },
        delta: {
          jump_nm: Math.round(dist * 1000) / 1000,
          threshold_nm: POSITION_JUMP_THRESHOLD_NM,
        },
      });

      vessel.lastGpsPosition = pos;
      checkBridgeCorrelation(log, vessel_id);
      return { anomaly: true, jump_nm: dist };
    }
  }

  vessel.lastGpsPosition = pos;
  checkBridgeCorrelation(log, vessel_id);
  return { anomaly: false };
}

// ─── Bridge protocol correlation ─────────────────────────────────────────────

// @rule:VRN-YK-005 Cross-validate GPS position vs AIS own-ship position
function checkBridgeCorrelation(log: FastifyBaseLogger, vessel_id: string): void {
  const vessel = getVessel(vessel_id);
  const gps = vessel.lastGpsPosition;
  const ais = vessel.lastAisPosition;

  if (!gps || !ais) return;

  // Only correlate if timestamps are within 30 seconds of each other
  if (Math.abs(gps.timestamp - ais.timestamp) > 30_000) return;

  const dist = haversineNm(gps.lat, gps.lon, ais.lat, ais.lon);

  if (dist > GPS_AIS_DISCREPANCY_THRESHOLD_NM) {
    emitSense(log, {
      event_type: 'vrn.ais.spoofing.detected',
      vessel_id,
      rule_id: 'VRN-036',
      severity: 'WARN',
      before_snapshot: { gps_ais_consistent: true },
      after_snapshot: { gps_ais_consistent: false },
      delta: {
        gps_position: { lat: gps.lat, lon: gps.lon },
        ais_position: { lat: ais.lat, lon: ais.lon },
        discrepancy_nm: Math.round(dist * 1000) / 1000,
        threshold_nm: GPS_AIS_DISCREPANCY_THRESHOLD_NM,
      },
    });
  }
}
