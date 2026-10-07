/**
 * IACS UR E26/E27 — 25-capability compliance definitions + assessment logic.
 * @rule:VRN-001 IACS UR E26/E27 compliance as the vessel cyber standard
 * @rule:P2-001  Assess each capability from observed vessel state
 */

import type { ComplianceStatus, VesselState } from '../store/vessel.js';

export interface CapabilityDefinition {
  cap_id: string;
  name: string;
  iacs_clause: string;
  rule_id: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  description: string;
  assess: (vessel: VesselState, now: number) => { status: ComplianceStatus; evidence: string };
}

// @rule:VRN-047 Three-column evidence: VRN rule + IACS clause + MITRE ATT&CK ICS
export const IACS_CAPABILITIES: CapabilityDefinition[] = [
  {
    cap_id: 'CAP-01',
    name: 'OT Asset Inventory',
    iacs_clause: 'E26 §3.1.1',
    rule_id: 'VRN-001',
    mitre_technique_id: 'T0845',
    mitre_technique_name: 'Program Upload',
    description: 'Enumeration of all OT systems and network connectivity',
    assess: (v) => {
      if (v.topology)
        return {
          status: 'PARTIAL',
          evidence: `Topology imported: ${v.topology.zones?.length ?? 0} zones, ${v.topology.conduits?.length ?? 0} conduits`,
        };
      return { status: 'UNKNOWN', evidence: 'No topology imported — cannot assess inventory' };
    },
  },
  {
    cap_id: 'CAP-02',
    name: 'Network Zone Segmentation',
    iacs_clause: 'E26 §3.2.1',
    rule_id: 'VRN-002',
    mitre_technique_id: 'T0869',
    mitre_technique_name: 'Standard Application Layer Protocol',
    description: 'IEC 62443 zone/conduit model — zones must be ≥2',
    assess: (v) => {
      if (!v.topology) return { status: 'UNKNOWN', evidence: 'No topology imported' };
      if (v.topology.flat_network)
        return {
          status: 'FAIL',
          evidence: `Flat network: only ${v.topology.zones?.length ?? 0} zone(s) found — IACS UR E27 §5.2 requires ≥2`,
        };
      return { status: 'PASS', evidence: `${v.topology.zones.length} zones defined` };
    },
  },
  {
    cap_id: 'CAP-03',
    name: 'Conduit Enforcement',
    iacs_clause: 'E26 §3.2.2',
    rule_id: 'VRN-003',
    mitre_technique_id: 'T0869',
    mitre_technique_name: 'Standard Application Layer Protocol',
    description: 'All conduits between zones enforced by a security control',
    assess: (v) => {
      if (!v.topology) return { status: 'UNKNOWN', evidence: 'No topology imported' };
      const total = v.topology.conduits?.length ?? 0;
      const unenforced = (v.topology.conduits ?? []).filter((c) => !c.enforced).length;
      if (total === 0) return { status: 'UNKNOWN', evidence: 'No conduits defined' };
      if (unenforced === 0) return { status: 'PASS', evidence: `All ${total} conduits enforced` };
      if (unenforced < total)
        return { status: 'PARTIAL', evidence: `${unenforced}/${total} conduits unenforced` };
      return { status: 'FAIL', evidence: `All ${total} conduits unenforced` };
    },
  },
  {
    cap_id: 'CAP-04',
    name: 'Least Privilege Access',
    iacs_clause: 'E26 §3.3.1',
    rule_id: 'VRN-006',
    mitre_technique_id: 'T0859',
    mitre_technique_name: 'Valid Accounts',
    description: 'Minimum required permissions granted to OT accounts',
    assess: () => ({
      status: 'UNKNOWN',
      evidence: 'Requires external access control evidence — passive monitoring cannot assess',
    }),
  },
  {
    cap_id: 'CAP-05',
    name: 'Audit Logging',
    iacs_clause: 'E26 §3.4.1',
    rule_id: 'VRN-007',
    mitre_technique_id: 'T0862',
    mitre_technique_name: 'Supply Chain Attack',
    description: 'All OT access and command events logged with timestamps',
    assess: (v) => {
      if (v.senseEvents.length > 0)
        return { status: 'PASS', evidence: `${v.senseEvents.length} SENSE events captured` };
      return { status: 'PARTIAL', evidence: 'SENSE pipeline active but no events captured yet' };
    },
  },
  {
    cap_id: 'CAP-06',
    name: 'Modbus Protocol Security',
    iacs_clause: 'E27 §4.1.1',
    rule_id: 'VRN-026',
    mitre_technique_id: 'T0855',
    mitre_technique_name: 'Unauthorized Command Message',
    description: 'Modbus traffic baseline established and monitored for anomalies',
    assess: (v) => {
      if (!v.modbusBaselineLocked && v.modbusBaseline.size === 0)
        return { status: 'FAIL', evidence: 'No Modbus traffic observed — baseline not started' };
      if (!v.modbusBaselineLocked)
        return {
          status: 'PARTIAL',
          evidence: `Baseline observation in progress: ${v.modbusBaseline.size} tuples observed`,
        };
      const critAnoms = v.modbusAnomalies.filter((a) => a.severity === 'CRITICAL').length;
      if (critAnoms > 0)
        return {
          status: 'FAIL',
          evidence: `Baseline locked — ${critAnoms} CRITICAL Modbus anomalies detected`,
        };
      return {
        status: 'PASS',
        evidence: `Baseline locked: ${v.modbusBaseline.size} tuples, ${v.modbusAnomalies.length} anomalies`,
      };
    },
  },
  {
    cap_id: 'CAP-07',
    name: 'Function Code Allowlisting',
    iacs_clause: 'E27 §4.1.2',
    rule_id: 'VRN-009',
    mitre_technique_id: 'T0855',
    mitre_technique_name: 'Unauthorized Command Message',
    description: 'Only read-class FC (01–04) permitted outside maintenance windows',
    assess: (v) => {
      const allowlistAnoms = v.modbusAnomalies.filter(
        (a) => a.rule_id === 'VRN-009' || a.anomaly_type === 'fc_not_in_allowlist'
      ).length;
      if (v.modbusBaseline.size === 0)
        return { status: 'UNKNOWN', evidence: 'No Modbus traffic observed' };
      if (allowlistAnoms > 0)
        return { status: 'FAIL', evidence: `${allowlistAnoms} FC allowlist violations detected` };
      return { status: 'PASS', evidence: 'No FC allowlist violations detected' };
    },
  },
  {
    cap_id: 'CAP-08',
    name: 'Safety System Write Integrity',
    iacs_clause: 'E27 §4.1.3',
    rule_id: 'VRN-044',
    mitre_technique_id: 'T0831',
    mitre_technique_name: 'Manipulation of Control',
    description: 'Write commands to safety-class registers monitored (air-shutoff, HC detector)',
    assess: (v) => {
      const runaway = v.senseEvents.find(
        (e) => e.event_type === 'vrn.runaway_diesel.precursor.detected'
      );
      if (runaway)
        return {
          status: 'FAIL',
          evidence: 'RUNAWAY DIESEL PRECURSOR DETECTED — two-coil sequence confirmed',
        };
      if (v.recentCoilWrites.length > 0)
        return {
          status: 'PARTIAL',
          evidence: `${v.recentCoilWrites.length} coil writes observed — monitoring active`,
        };
      if (v.modbusBaselineLocked)
        return {
          status: 'PASS',
          evidence: 'Modbus monitoring active — no safety system anomalies',
        };
      return { status: 'UNKNOWN', evidence: 'Modbus baseline not yet established' };
    },
  },
  {
    cap_id: 'CAP-09',
    name: 'NMEA Message Integrity',
    iacs_clause: 'E27 §4.2.1',
    rule_id: 'VRN-032',
    mitre_technique_id: 'T0856',
    mitre_technique_name: 'Spoof Reporting Message',
    description: 'NMEA XOR checksum validation + talker-ID baseline active',
    assess: (v) => {
      const checksumFails = v.nmeaAnomalies.filter(
        (a) => a.anomaly_type === 'checksum_failure'
      ).length;
      if (v.nmeaTalkerBaseline.size === 0)
        return { status: 'UNKNOWN', evidence: 'No NMEA traffic observed' };
      if (checksumFails > 0)
        return { status: 'FAIL', evidence: `${checksumFails} NMEA checksum failures detected` };
      if (!v.nmeaBaselineLocked)
        return {
          status: 'PARTIAL',
          evidence: `Talker baseline in progress: ${v.nmeaTalkerBaseline.size} talkers`,
        };
      return {
        status: 'PASS',
        evidence: `Talker baseline locked: ${v.nmeaTalkerBaseline.size} talkers — checksums valid`,
      };
    },
  },
  {
    cap_id: 'CAP-10',
    name: 'Navigation Injection Detection',
    iacs_clause: 'E27 §4.2.2',
    rule_id: 'VRN-040',
    mitre_technique_id: 'T0856',
    mitre_technique_name: 'Spoof Reporting Message',
    description: 'Critical NMEA sentences (GPGGA/GPRMC/HEHDT) monitored for injection',
    assess: (v) => {
      const injections = v.nmeaAnomalies.filter(
        (a) => a.anomaly_type === 'critical_sentence_injection' || a.rule_id === 'VRN-040'
      ).length;
      if (v.nmeaTalkerBaseline.size === 0)
        return { status: 'UNKNOWN', evidence: 'No NMEA traffic observed' };
      if (injections > 0)
        return {
          status: 'FAIL',
          evidence: `${injections} critical NMEA injection events detected`,
        };
      if (!v.nmeaBaselineLocked)
        return { status: 'PARTIAL', evidence: 'NMEA monitoring active — baseline not yet locked' };
      return {
        status: 'PASS',
        evidence: 'NMEA baseline locked — no navigation sentence injection detected',
      };
    },
  },
  {
    cap_id: 'CAP-11',
    name: 'AIS Data Integrity',
    iacs_clause: 'E27 §4.3.1',
    rule_id: 'VRN-033',
    mitre_technique_id: 'T0856',
    mitre_technique_name: 'Spoof Reporting Message',
    description: 'AIS MMSI registry maintained, invalid MMSIs detected',
    assess: (v) => {
      if (v.mmsiRegistry.size === 0)
        return { status: 'UNKNOWN', evidence: 'No AIS traffic observed' };
      const aisAnoms = v.gpsAnomalies.filter(
        (a) => a.type.includes('ais') || a.type.includes('mmsi')
      ).length;
      if (aisAnoms > 0)
        return { status: 'FAIL', evidence: `${aisAnoms} AIS integrity anomalies detected` };
      return {
        status: 'PASS',
        evidence: `AIS monitoring active: ${v.mmsiRegistry.size} vessels in registry`,
      };
    },
  },
  {
    cap_id: 'CAP-12',
    name: 'GPS Spoofing Detection',
    iacs_clause: 'E27 §4.3.2',
    rule_id: 'VRN-036',
    mitre_technique_id: 'T0830',
    mitre_technique_name: 'Man in the Middle',
    description: 'GPS position jump detection active',
    assess: (v) => {
      const gpsJumps = v.gpsAnomalies.filter((a) => a.type === 'gps_position_jump').length;
      if (!v.lastGpsPosition) return { status: 'UNKNOWN', evidence: 'No GPS data received' };
      if (gpsJumps > 0)
        return {
          status: 'FAIL',
          evidence: `${gpsJumps} GPS position jumps detected — spoofing suspected`,
        };
      return { status: 'PASS', evidence: `GPS monitoring active — position stable` };
    },
  },
  {
    cap_id: 'CAP-13',
    name: 'Bridge System GPS/AIS Correlation',
    iacs_clause: 'E27 §4.3.3',
    rule_id: 'VRN-038',
    mitre_technique_id: 'T0830',
    mitre_technique_name: 'Man in the Middle',
    description: 'GPS vs AIS own-ship position discrepancy detection',
    assess: (v) => {
      const discrepancies = v.gpsAnomalies.filter((a) => a.type === 'gps_ais_discrepancy').length;
      if (!v.lastGpsPosition || !v.lastAisPosition)
        return { status: 'UNKNOWN', evidence: 'Requires both GPS and AIS data' };
      if (discrepancies > 0)
        return {
          status: 'FAIL',
          evidence: `${discrepancies} GPS/AIS position discrepancies detected`,
        };
      return { status: 'PASS', evidence: 'GPS/AIS correlation active — no discrepancy detected' };
    },
  },
  {
    cap_id: 'CAP-14',
    name: 'Vendor Laptop / New Device Detection',
    iacs_clause: 'E26 §3.5.1',
    rule_id: 'VRN-029',
    mitre_technique_id: 'T0860',
    mitre_technique_name: 'Wireless Compromise',
    description: 'New device connections to OT VLAN during non-maintenance windows detected',
    assess: (v) => {
      const vendorEvents = v.senseEvents.filter(
        (e) => e.event_type === 'vrn.vendor_laptop.connection.detected' && e.severity === 'CRITICAL'
      ).length;
      if (vendorEvents > 0)
        return {
          status: 'FAIL',
          evidence: `${vendorEvents} CRITICAL vendor laptop events on OT VLAN`,
        };
      const warnEvents = v.senseEvents.filter(
        (e) => e.event_type === 'vrn.vendor_laptop.connection.detected'
      ).length;
      if (warnEvents > 0)
        return {
          status: 'PARTIAL',
          evidence: `${warnEvents} vendor device connections (maintenance window)`,
        };
      return { status: 'PASS', evidence: 'No unauthorized device connections detected' };
    },
  },
  {
    cap_id: 'CAP-15',
    name: 'OT Network Monitoring Active',
    iacs_clause: 'E26 §3.6.1',
    rule_id: 'VRN-010',
    mitre_technique_id: 'T0840',
    mitre_technique_name: 'Network Connection Enumeration',
    description: 'Continuous passive monitoring of OT network traffic',
    assess: (v) => {
      const totalSignals = v.modbusBaseline.size + v.nmeaTalkerBaseline.size + v.mmsiRegistry.size;
      if (totalSignals === 0)
        return { status: 'FAIL', evidence: 'No OT traffic observed on any protocol' };
      return {
        status: 'PASS',
        evidence: `Monitoring active: ${v.modbusBaseline.size} Modbus tuples, ${v.nmeaTalkerBaseline.size} NMEA talkers, ${v.mmsiRegistry.size} AIS targets`,
      };
    },
  },
  {
    cap_id: 'CAP-16',
    name: 'Runaway Diesel Attack Detection',
    iacs_clause: 'E27 §4.1.4',
    rule_id: 'VRN-044',
    mitre_technique_id: 'T0831',
    mitre_technique_name: 'Manipulation of Control',
    description:
      'Two-coil attack sequence: air-shutoff (reg 0x0001) + HC detector suppress (reg 0x0010)',
    assess: (v) => {
      const runaway = v.senseEvents.find(
        (e) => e.event_type === 'vrn.runaway_diesel.precursor.detected'
      );
      if (runaway)
        return {
          status: 'FAIL',
          evidence:
            'RUNAWAY DIESEL PRECURSOR: air-shutoff and HC suppressor disable sequence confirmed',
        };
      if (v.modbusBaselineLocked)
        return {
          status: 'PASS',
          evidence: 'Modbus baseline locked — runaway diesel detection active',
        };
      return { status: 'PARTIAL', evidence: 'Detection logic active — Modbus baseline pending' };
    },
  },
  {
    cap_id: 'CAP-17',
    name: 'NMEA Port-Side Injection Detection',
    iacs_clause: 'E27 §4.2.3',
    rule_id: 'VRN-045',
    mitre_technique_id: 'T0856',
    mitre_technique_name: 'Spoof Reporting Message',
    description: 'Port-side physical NMEA injection detected via unknown talker analysis',
    assess: (v) => {
      const portInjections = v.nmeaAnomalies.filter(
        (a) => a.anomaly_type === 'critical_sentence_injection'
      ).length;
      if (v.nmeaTalkerBaseline.size === 0)
        return { status: 'UNKNOWN', evidence: 'No NMEA traffic observed' };
      if (portInjections > 0)
        return {
          status: 'FAIL',
          evidence: `${portInjections} critical NMEA injection events — physical port access suspected`,
        };
      return { status: 'PASS', evidence: 'No port-side injection events detected' };
    },
  },
  {
    cap_id: 'CAP-18',
    name: 'Modbus Broadcast Detection',
    iacs_clause: 'E27 §4.1.5',
    rule_id: 'VRN-027',
    mitre_technique_id: 'T0840',
    mitre_technique_name: 'Network Connection Enumeration',
    description: 'Modbus broadcast writes (unit_id=0xFF) detected',
    assess: (v) => {
      const broadcastAnoms = v.modbusAnomalies.filter(
        (a) => a.anomaly_type === 'broadcast_write'
      ).length;
      if (v.modbusBaseline.size === 0)
        return { status: 'UNKNOWN', evidence: 'No Modbus traffic observed' };
      if (broadcastAnoms > 0)
        return { status: 'FAIL', evidence: `${broadcastAnoms} Modbus broadcast write anomalies` };
      return { status: 'PASS', evidence: 'No broadcast write anomalies detected' };
    },
  },
  {
    cap_id: 'CAP-19',
    name: 'Patch Management Process',
    iacs_clause: 'E26 §3.3.2',
    rule_id: 'VRN-004',
    mitre_technique_id: 'T0800',
    mitre_technique_name: 'Activate Firmware Update Mode',
    description: 'OT system patch currency process — requires external documentation',
    assess: () => ({
      status: 'UNKNOWN',
      evidence: 'Requires external patch management evidence — passive monitoring cannot assess',
    }),
  },
  {
    cap_id: 'CAP-20',
    name: 'Incident Response Plan',
    iacs_clause: 'E26 §3.7.1',
    rule_id: 'VRN-015',
    mitre_technique_id: 'T0881',
    mitre_technique_name: 'Service Stop',
    description: 'Documented IR plan for OT cyber incidents',
    assess: () => ({
      status: 'UNKNOWN',
      evidence: 'Requires external IR plan documentation — cannot assess from traffic',
    }),
  },
  {
    cap_id: 'CAP-21',
    name: 'OT Configuration Baseline',
    iacs_clause: 'E26 §3.1.2',
    rule_id: 'VRN-013',
    mitre_technique_id: 'T0843',
    mitre_technique_name: 'Program Download',
    description: 'Known-good configuration baseline established for OT systems',
    assess: (v) => {
      if (v.modbusBaselineLocked && v.nmeaBaselineLocked)
        return {
          status: 'PASS',
          evidence: 'Modbus and NMEA baselines locked — configuration fingerprint established',
        };
      if (v.modbusBaseline.size > 0 || v.nmeaTalkerBaseline.size > 0)
        return { status: 'PARTIAL', evidence: 'Baseline observation in progress' };
      return { status: 'FAIL', evidence: 'No traffic baseline observed' };
    },
  },
  {
    cap_id: 'CAP-22',
    name: 'Supply Chain Risk Management',
    iacs_clause: 'E26 §3.8.1',
    rule_id: 'VRN-016',
    mitre_technique_id: 'T0882',
    mitre_technique_name: 'Theft of Operational Information',
    description: 'OT component supply chain risk assessment',
    assess: () => ({ status: 'UNKNOWN', evidence: 'Requires external supply chain documentation' }),
  },
  {
    cap_id: 'CAP-23',
    name: 'Remote Access Control',
    iacs_clause: 'E26 §3.3.3',
    rule_id: 'VRN-005',
    mitre_technique_id: 'T0886',
    mitre_technique_name: 'Remote Services',
    description: 'Remote access to OT systems controlled and monitored',
    assess: () => ({
      status: 'UNKNOWN',
      evidence: 'Requires external remote access policy evidence',
    }),
  },
  {
    cap_id: 'CAP-24',
    name: 'AIS SAR Aircraft Detection',
    iacs_clause: 'E27 §4.3.4',
    rule_id: 'VRN-035',
    mitre_technique_id: 'T0856',
    mitre_technique_name: 'Spoof Reporting Message',
    description: 'SAR aircraft (type-9) appearing at surface level detected',
    assess: (v) => {
      const sarAnoms = v.gpsAnomalies.filter((a) => a.type === 'sar_aircraft_surface').length;
      if (v.mmsiRegistry.size === 0)
        return { status: 'UNKNOWN', evidence: 'No AIS traffic observed' };
      if (sarAnoms > 0)
        return {
          status: 'FAIL',
          evidence: `${sarAnoms} SAR aircraft at surface altitude anomalies`,
        };
      return { status: 'PASS', evidence: 'AIS vessel type validation active — no SAR anomalies' };
    },
  },
  {
    cap_id: 'CAP-25',
    name: 'Cyber Risk Assessment Documented',
    iacs_clause: 'E26 §3.1.3',
    rule_id: 'VRN-001',
    mitre_technique_id: 'T0882',
    mitre_technique_name: 'Theft of Operational Information',
    description: 'Formal cyber risk assessment conducted and documented',
    assess: (v) => {
      if (v.postureScore !== null)
        return {
          status: 'PARTIAL',
          evidence: `Automated posture score: ${v.postureScore}/100 — formal risk assessment requires human review`,
        };
      return { status: 'UNKNOWN', evidence: 'No posture assessment conducted yet' };
    },
  },
];
