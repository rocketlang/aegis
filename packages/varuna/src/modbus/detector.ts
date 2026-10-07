/**
 * Modbus anomaly detection — baseline deviation, FC allowlist, runaway-diesel.
 * @rule:VRN-026 Modbus/TCP security controls
 * @rule:VRN-019 Safety system integrity monitoring
 * @rule:VRN-044 Runaway-diesel two-coil sequence is the flagship detection
 */

import { randomUUID } from 'crypto';

import type { FastifyBaseLogger } from 'fastify';

import { emitSense } from '../sense/emit.js';
import { getVessel, tupleKey, type ModbusAnomaly, type ModbusTuple } from '../store/vessel.js';

// ─── Config ───────────────────────────────────────────────────────────────────

// @rule:VRN-041 Coil addresses are vessel-specific — configure per vessel before testing
const DEFAULT_SAFETY_COILS = {
  air_shutoff: 0x0001, // Air-shutoff flap coil (disable = write 0x0000)
  hc_detector: 0x0010, // HC detector suppress coil (disable = write 0x0000)
};

// @rule:VRN-026 FC 08 sub-01 (diagnostic reset) is always CRITICAL
const ALWAYS_ALERT_FC = new Set([8]);
const COIL_DISABLE_VALUE = 0x0000;
const FC_WRITE_SINGLE_COIL = 5;
const BASELINE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const RUNAWAY_DIESEL_WINDOW_MS = 60_000; // 60-second detection window

// ─── Baseline ─────────────────────────────────────────────────────────────────

// @rule:VRN-026 D-01: Build a 7-day passively observed baseline
export function observeModbus(
  vessel_id: string,
  frame: {
    src_ip: string;
    unit_id: number;
    function_code: number;
    register: number;
    value: number;
    timestamp: number;
  }
): ModbusAnomaly | null {
  const vessel = getVessel(vessel_id);
  const tuple: ModbusTuple = {
    src_ip: frame.src_ip,
    unit_id: frame.unit_id,
    function_code: frame.function_code,
    register: frame.register,
  };
  const key = tupleKey(tuple);

  // Check baseline window — lock after 7 days
  if (!vessel.modbusBaselineLocked) {
    const elapsed = frame.timestamp - vessel.modbusBaselineStarted;
    if (elapsed >= BASELINE_WINDOW_MS) vessel.modbusBaselineLocked = true;
  }

  if (!vessel.modbusBaselineLocked) {
    // Still observing — record tuple
    const existing = vessel.modbusBaseline.get(key);
    if (existing) {
      const cadence = frame.timestamp - existing.last_seen;
      existing.cadence_avg_ms = Math.round(
        (existing.cadence_avg_ms * existing.count + cadence) / (existing.count + 1)
      );
      existing.last_seen = frame.timestamp;
      existing.count++;
    } else {
      vessel.modbusBaseline.set(key, {
        ...tuple,
        count: 1,
        first_seen: frame.timestamp,
        last_seen: frame.timestamp,
        cadence_avg_ms: 0,
      });
    }
    return null;
  }

  // Baseline locked — check for anomalies
  return checkAnomaly(vessel_id, tuple, frame.value, frame.timestamp);
}

// ─── Anomaly checker ─────────────────────────────────────────────────────────

// @rule:VRN-026 D-02 to D-05: Flag any tuple not in baseline + always-alert list
function checkAnomaly(
  vessel_id: string,
  tuple: ModbusTuple,
  value: number,
  timestamp: number
): ModbusAnomaly | null {
  const vessel = getVessel(vessel_id);
  const key = tupleKey(tuple);

  let anomaly_type: string | null = null;
  let severity: ModbusAnomaly['severity'] = 'WARN';
  const rule_id = 'VRN-026';

  if (ALWAYS_ALERT_FC.has(tuple.function_code)) {
    // @rule:VRN-026 FC 08 = diagnostic command — always alert
    anomaly_type = 'always_alert_fc';
    severity = 'CRITICAL';
  } else if (tuple.unit_id === 0) {
    // @rule:VRN-026 Unit ID 0 = Modbus broadcast — always alert
    anomaly_type = 'broadcast_write';
    severity = 'WARN';
  } else if (!vessel.modbusBaseline.has(key)) {
    anomaly_type = 'unknown_tuple';
    severity = 'WARN';
  }

  if (!anomaly_type) return null;

  const anomaly: ModbusAnomaly = {
    id: randomUUID(),
    vessel_id,
    tuple,
    value,
    anomaly_type,
    rule_id,
    severity,
    detected_at: timestamp,
  };

  vessel.modbusAnomalies.push(anomaly);
  if (vessel.modbusAnomalies.length > 1000) vessel.modbusAnomalies.shift();

  return anomaly;
}

// ─── Runaway-diesel two-coil sequence detector ───────────────────────────────

// @rule:VRN-019 Safety system integrity — a coil state change is a safety event
// @rule:VRN-044 Two-coil runaway-diesel: air-shutoff disable + HC suppress within 60s
export function checkRunawayDiesel(
  log: FastifyBaseLogger,
  vessel_id: string,
  frame: {
    src_ip: string;
    unit_id: number;
    function_code: number;
    register: number;
    value: number;
    timestamp: number;
  },
  safetyCoils = DEFAULT_SAFETY_COILS
): boolean {
  if (frame.function_code !== FC_WRITE_SINGLE_COIL) return false;
  if (frame.value !== COIL_DISABLE_VALUE) return false;

  const vessel = getVessel(vessel_id);
  const isAirShutoff = frame.register === safetyCoils.air_shutoff;
  const isHcDetector = frame.register === safetyCoils.hc_detector;

  if (!isAirShutoff && !isHcDetector) return false;

  // Record this coil write
  vessel.recentCoilWrites.push({
    coil_address: frame.register,
    value: frame.value,
    src_ip: frame.src_ip,
    timestamp: frame.timestamp,
  });

  // Evict writes older than 60s
  const cutoff = frame.timestamp - RUNAWAY_DIESEL_WINDOW_MS;
  vessel.recentCoilWrites = vessel.recentCoilWrites.filter((w) => w.timestamp >= cutoff);

  // Check if both coils disabled within the window
  const airShutoffDisabled = vessel.recentCoilWrites.find(
    (w) => w.coil_address === safetyCoils.air_shutoff
  );
  const hcDetectorDisabled = vessel.recentCoilWrites.find(
    (w) => w.coil_address === safetyCoils.hc_detector
  );

  if (!airShutoffDisabled || !hcDetectorDisabled) return false;

  // @rule:VRN-044 Both coils disabled — CRITICAL
  emitSense(log, {
    event_type: 'vrn.runaway_diesel.precursor.detected',
    vessel_id,
    rule_id: 'VRN-044',
    severity: 'CRITICAL',
    before_snapshot: { air_shutoff_coil: 'ENABLED', hc_detector: 'ACTIVE' },
    after_snapshot: { air_shutoff_coil: 'DISABLED', hc_detector: 'SUPPRESSED' },
    delta: {
      air_shutoff_address: safetyCoils.air_shutoff,
      hc_detector_address: safetyCoils.hc_detector,
      air_shutoff_src: airShutoffDisabled.src_ip,
      hc_detector_src: hcDetectorDisabled.src_ip,
      window_ms: RUNAWAY_DIESEL_WINDOW_MS,
    },
  });

  // Clear window after alert to prevent duplicate firing
  vessel.recentCoilWrites = [];

  return true;
}

// ─── FC allowlist enforcer ────────────────────────────────────────────────────

// @rule:VRN-009 Function-code filtering at zone boundary
// @rule:VRN-026 FC allowlist per zone
const DEFAULT_ALLOWED_FC = new Set([1, 2, 3, 4]); // Read-only FCs
const MAINTENANCE_FC = new Set([5, 6, 15, 16]); // Write FCs — only from whitelisted IPs

export function checkFcAllowlist(
  log: FastifyBaseLogger,
  vessel_id: string,
  frame: {
    src_ip: string;
    unit_id: number;
    function_code: number;
    register: number;
    value: number;
    timestamp: number;
  },
  maintenanceWhitelist: string[] = []
): ModbusAnomaly | null {
  if (DEFAULT_ALLOWED_FC.has(frame.function_code)) return null;

  if (MAINTENANCE_FC.has(frame.function_code) && maintenanceWhitelist.includes(frame.src_ip))
    return null;

  const vessel = getVessel(vessel_id);
  const tuple: ModbusTuple = {
    src_ip: frame.src_ip,
    unit_id: frame.unit_id,
    function_code: frame.function_code,
    register: frame.register,
  };

  const anomaly: ModbusAnomaly = {
    id: randomUUID(),
    vessel_id,
    tuple,
    value: frame.value,
    anomaly_type: 'fc_allowlist_violation',
    rule_id: 'VRN-009',
    severity: ALWAYS_ALERT_FC.has(frame.function_code) ? 'CRITICAL' : 'WARN',
    detected_at: frame.timestamp,
  };

  vessel.modbusAnomalies.push(anomaly);
  if (vessel.modbusAnomalies.length > 1000) vessel.modbusAnomalies.shift();

  emitSense(log, {
    event_type: 'vrn.modbus.anomaly.detected',
    vessel_id,
    rule_id: 'VRN-009',
    severity: anomaly.severity,
    before_snapshot: { fc_allowed: false },
    after_snapshot: { fc_violation: true, function_code: frame.function_code },
    delta: { src_ip: frame.src_ip, function_code: frame.function_code },
  });

  return anomaly;
}
