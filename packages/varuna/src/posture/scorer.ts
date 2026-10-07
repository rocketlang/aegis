/**
 * Shared posture score computation — used by posture routes, report card, and background monitor.
 * @rule:VRN-050 Posture is a living score, updated continuously.
 */

import type { VesselState } from '../store/vessel.js';

export interface PostureFinding {
  rule_id: string;
  severity: 'CRITICAL' | 'WARN' | 'INFO';
  description: string;
  deduction: number;
}

export interface PostureResult {
  score: number;
  band: 'GREEN' | 'AMBER' | 'RED';
  findings: PostureFinding[];
}

// @rule:VRN-050 Deduction model — shared across all scoring contexts
export function computePostureScore(vessel: VesselState): PostureResult {
  const findings: PostureFinding[] = [];

  const criticalModbus = vessel.modbusAnomalies.filter((a) => a.severity === 'CRITICAL').length;
  const warnModbus = vessel.modbusAnomalies.filter((a) => a.severity === 'WARN').length;
  if (criticalModbus > 0)
    findings.push({
      rule_id: 'VRN-026',
      severity: 'CRITICAL',
      description: `${criticalModbus} critical Modbus anomalies`,
      deduction: Math.min(30, criticalModbus * 10),
    });
  if (warnModbus > 0)
    findings.push({
      rule_id: 'VRN-026',
      severity: 'WARN',
      description: `${warnModbus} Modbus anomalies`,
      deduction: Math.min(10, warnModbus * 2),
    });
  if (!vessel.modbusBaselineLocked && vessel.modbusBaseline.size > 0)
    findings.push({
      rule_id: 'VRN-026',
      severity: 'INFO',
      description: 'Modbus baseline observation in progress',
      deduction: 5,
    });

  const criticalNMEA = vessel.nmeaAnomalies.filter((a) => a.severity === 'CRITICAL').length;
  if (criticalNMEA > 0)
    findings.push({
      rule_id: 'VRN-032',
      severity: 'CRITICAL',
      description: `${criticalNMEA} NMEA injection events`,
      deduction: Math.min(25, criticalNMEA * 10),
    });

  if (vessel.gpsAnomalies.length > 0)
    findings.push({
      rule_id: 'VRN-036',
      severity: 'WARN',
      description: `${vessel.gpsAnomalies.length} GPS anomalies`,
      deduction: Math.min(15, vessel.gpsAnomalies.length * 5),
    });

  if (!vessel.topology)
    findings.push({
      rule_id: 'VRN-002',
      severity: 'WARN',
      description: 'No zone/conduit topology imported',
      deduction: 10,
    });
  else if (vessel.topology.flat_network)
    findings.push({
      rule_id: 'VRN-008',
      severity: 'CRITICAL',
      description: 'Flat network — no zone segmentation',
      deduction: 20,
    });

  const runaway = vessel.senseEvents.find(
    (e) => e.event_type === 'vrn.runaway_diesel.precursor.detected'
  );
  if (runaway)
    findings.push({
      rule_id: 'VRN-044',
      severity: 'CRITICAL',
      description: 'RUNAWAY DIESEL PRECURSOR — two-coil sequence',
      deduction: 100,
    });

  const totalDeduction = Math.min(
    100,
    findings.reduce((s, f) => s + f.deduction, 0)
  );
  const score = Math.max(0, 100 - totalDeduction);
  const band = score >= 80 ? 'GREEN' : score >= 50 ? 'AMBER' : 'RED';

  return { score, band, findings };
}
