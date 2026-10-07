/**
 * Protocol security posture scorer — VRN-026 to VRN-040.
 * @rule:P2-002 Protocol-layer posture scoring
 * @rule:VRN-026 Modbus TCP security controls
 * @rule:VRN-032 NMEA 0183 security
 * @rule:VRN-033 AIS integrity
 */

import type { ComplianceStatus, ProtocolAuditResult, VesselState } from '../store/vessel.js';

export interface ProtocolPosture {
  pass: number;
  partial: number;
  fail: number;
  unknown: number;
  results: ProtocolAuditResult[];
}

function check(
  protocol: string,
  rule_id: string,
  status: ComplianceStatus,
  detail: string
): ProtocolAuditResult {
  return { protocol, rule_id, status, detail };
}

// @rule:P2-002 Score VRN-026 to VRN-040 from observed vessel state
export function runProtocolScorer(vessel: VesselState): ProtocolPosture {
  const results: ProtocolAuditResult[] = [];

  // ── Modbus ────────────────────────────────────────────────────────────────
  // VRN-026 Modbus baseline
  if (vessel.modbusBaseline.size === 0) {
    results.push(check('Modbus', 'VRN-026', 'FAIL', 'No Modbus traffic observed'));
  } else if (!vessel.modbusBaselineLocked) {
    results.push(
      check(
        'Modbus',
        'VRN-026',
        'PARTIAL',
        `Baseline in progress: ${vessel.modbusBaseline.size} tuples`
      )
    );
  } else {
    const crits = vessel.modbusAnomalies.filter((a) => a.severity === 'CRITICAL').length;
    results.push(
      check(
        'Modbus',
        'VRN-026',
        crits > 0 ? 'FAIL' : 'PASS',
        crits > 0
          ? `${crits} CRITICAL anomalies since lock`
          : `Locked: ${vessel.modbusBaseline.size} tuples`
      )
    );
  }

  // VRN-027 Broadcast write detection
  {
    const bc = vessel.modbusAnomalies.filter((a) => a.anomaly_type === 'broadcast_write').length;
    results.push(
      check(
        'Modbus',
        'VRN-027',
        bc > 0 ? 'FAIL' : vessel.modbusBaseline.size === 0 ? 'UNKNOWN' : 'PASS',
        bc > 0 ? `${bc} broadcast writes to unit_id=0xFF` : 'No broadcast write anomalies'
      )
    );
  }

  // VRN-009 FC allowlist
  {
    const fc = vessel.modbusAnomalies.filter(
      (a) => a.anomaly_type === 'fc_not_in_allowlist'
    ).length;
    results.push(
      check(
        'Modbus',
        'VRN-009',
        fc > 0 ? 'FAIL' : vessel.modbusBaseline.size === 0 ? 'UNKNOWN' : 'PASS',
        fc > 0 ? `${fc} disallowed function codes detected` : 'All observed FC within allowlist'
      )
    );
  }

  // VRN-044 Runaway diesel (Modbus coil attack)
  {
    const rd = vessel.senseEvents.filter(
      (e) => e.event_type === 'vrn.runaway_diesel.precursor.detected'
    ).length;
    results.push(
      check(
        'Modbus',
        'VRN-044',
        rd > 0 ? 'FAIL' : vessel.modbusBaselineLocked ? 'PASS' : 'PARTIAL',
        rd > 0 ? 'RUNAWAY DIESEL PRECURSOR DETECTED' : 'Runaway-diesel detection active'
      )
    );
  }

  // ── NMEA ──────────────────────────────────────────────────────────────────
  // VRN-032 Checksum validation + talker baseline
  {
    const cf = vessel.nmeaAnomalies.filter((a) => a.anomaly_type === 'checksum_failure').length;
    if (vessel.nmeaTalkerBaseline.size === 0) {
      results.push(check('NMEA', 'VRN-032', 'UNKNOWN', 'No NMEA traffic observed'));
    } else if (cf > 0) {
      results.push(
        check('NMEA', 'VRN-032', 'FAIL', `${cf} checksum failures — data integrity compromised`)
      );
    } else {
      results.push(
        check(
          'NMEA',
          'VRN-032',
          vessel.nmeaBaselineLocked ? 'PASS' : 'PARTIAL',
          vessel.nmeaBaselineLocked
            ? `Talker baseline locked: ${vessel.nmeaTalkerBaseline.size} talkers`
            : `Baseline in progress: ${vessel.nmeaTalkerBaseline.size} talkers`
        )
      );
    }
  }

  // VRN-040 Autopilot heading injection
  {
    const inj = vessel.nmeaAnomalies.filter(
      (a) => a.rule_id === 'VRN-040' || a.anomaly_type === 'critical_sentence_injection'
    ).length;
    if (vessel.nmeaTalkerBaseline.size === 0) {
      results.push(check('NMEA', 'VRN-040', 'UNKNOWN', 'No NMEA traffic observed'));
    } else {
      results.push(
        check(
          'NMEA',
          'VRN-040',
          inj > 0 ? 'FAIL' : vessel.nmeaBaselineLocked ? 'PASS' : 'PARTIAL',
          inj > 0
            ? `${inj} critical sentence injection events`
            : 'Navigation sentence injection detection active'
        )
      );
    }
  }

  // VRN-045 NMEA injection via port access
  {
    const portInj = vessel.nmeaAnomalies.filter(
      (a) => a.anomaly_type === 'critical_sentence_injection'
    ).length;
    results.push(
      check(
        'NMEA',
        'VRN-045',
        portInj > 0 ? 'FAIL' : vessel.nmeaTalkerBaseline.size === 0 ? 'UNKNOWN' : 'PASS',
        portInj > 0
          ? `${portInj} port-side injection events detected`
          : 'No port-side injection detected'
      )
    );
  }

  // ── AIS / GPS ─────────────────────────────────────────────────────────────
  // VRN-033 AIS MMSI registry
  {
    const aisAnoms = vessel.gpsAnomalies.filter((a) => a.type.startsWith('ais')).length;
    if (vessel.mmsiRegistry.size === 0) {
      results.push(check('AIS', 'VRN-033', 'UNKNOWN', 'No AIS traffic observed'));
    } else {
      results.push(
        check(
          'AIS',
          'VRN-033',
          aisAnoms > 0 ? 'FAIL' : 'PASS',
          aisAnoms > 0
            ? `${aisAnoms} AIS integrity anomalies`
            : `${vessel.mmsiRegistry.size} vessels in registry`
        )
      );
    }
  }

  // VRN-036 GPS spoofing detection
  {
    const gpsJumps = vessel.gpsAnomalies.filter((a) => a.type === 'gps_position_jump').length;
    if (!vessel.lastGpsPosition) {
      results.push(check('GPS', 'VRN-036', 'UNKNOWN', 'No GPS data received'));
    } else {
      results.push(
        check(
          'GPS',
          'VRN-036',
          gpsJumps > 0 ? 'FAIL' : 'PASS',
          gpsJumps > 0 ? `${gpsJumps} GPS position jumps detected` : 'GPS position stable'
        )
      );
    }
  }

  // VRN-038 GPS-AIS bridge correlation
  {
    const disc = vessel.gpsAnomalies.filter((a) => a.type === 'gps_ais_discrepancy').length;
    if (!vessel.lastGpsPosition || !vessel.lastAisPosition) {
      results.push(check('GPS', 'VRN-038', 'UNKNOWN', 'Requires both GPS and AIS data'));
    } else {
      results.push(
        check(
          'GPS',
          'VRN-038',
          disc > 0 ? 'FAIL' : 'PASS',
          disc > 0 ? `${disc} GPS/AIS position discrepancies` : 'GPS/AIS positions correlate'
        )
      );
    }
  }

  // ── Topology ──────────────────────────────────────────────────────────────
  // VRN-002 Zone segmentation
  {
    if (!vessel.topology) {
      results.push(check('Topology', 'VRN-002', 'UNKNOWN', 'No topology imported'));
    } else if (vessel.topology.flat_network) {
      results.push(
        check(
          'Topology',
          'VRN-002',
          'FAIL',
          `Flat network: ${vessel.topology.zones?.length ?? 0} zone(s) — E27 §5.2 requires ≥2`
        )
      );
    } else {
      const unenforced = (vessel.topology.conduits ?? []).filter((c) => !c.enforced).length;
      results.push(
        check(
          'Topology',
          'VRN-002',
          unenforced > 0 ? 'PARTIAL' : 'PASS',
          unenforced > 0
            ? `${unenforced} unenforced conduits`
            : `${vessel.topology.zones.length} zones, all conduits enforced`
        )
      );
    }
  }

  // VRN-029 Vendor laptop
  {
    const critical = vessel.senseEvents.filter(
      (e) => e.event_type === 'vrn.vendor_laptop.connection.detected' && e.severity === 'CRITICAL'
    ).length;
    const warn = vessel.senseEvents.filter(
      (e) => e.event_type === 'vrn.vendor_laptop.connection.detected' && e.severity === 'WARN'
    ).length;
    results.push(
      check(
        'Topology',
        'VRN-029',
        critical > 0 ? 'FAIL' : warn > 0 ? 'PARTIAL' : 'PASS',
        critical > 0
          ? `${critical} CRITICAL vendor OT connections`
          : warn > 0
            ? `${warn} vendor connections (maintenance window)`
            : 'No unauthorized device connections'
      )
    );
  }

  vessel.protocol_audit = results;

  return {
    pass: results.filter((r) => r.status === 'PASS').length,
    partial: results.filter((r) => r.status === 'PARTIAL').length,
    fail: results.filter((r) => r.status === 'FAIL').length,
    unknown: results.filter((r) => r.status === 'UNKNOWN').length,
    results,
  };
}
