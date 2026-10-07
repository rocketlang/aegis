/**
 * In-memory vessel state store.
 * Phase 1 — replaced by Postgres in Phase 2.
 */

export interface ModbusTuple {
  src_ip: string;
  unit_id: number;
  function_code: number;
  register: number;
}

export interface ModbusBaselineEntry extends ModbusTuple {
  count: number;
  first_seen: number;
  last_seen: number;
  cadence_avg_ms: number;
}

export interface ModbusAnomaly {
  id: string;
  vessel_id: string;
  tuple: ModbusTuple;
  value: number;
  anomaly_type: string;
  rule_id: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
  detected_at: number;
}

export interface CoilWrite {
  coil_address: number;
  value: number; // 0x0000 = disable, 0xFF00 = enable
  src_ip: string;
  timestamp: number;
}

export interface NMEATalkerEntry {
  talker_id: string;
  sentence_types: Set<string>;
  first_seen: number;
  last_seen: number;
  count: number;
}

export interface NMEAAnomaly {
  id: string;
  vessel_id: string;
  sentence_type: string;
  talker_id: string;
  anomaly_type: string;
  rule_id: string;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
  detected_at: number;
}

export interface MMSIRecord {
  mmsi: string;
  lat: number;
  lon: number;
  last_seen: number;
  msg_count: number;
}

export interface GpsPosition {
  lat: number;
  lon: number;
  timestamp: number;
}

export interface SenseEvent {
  id: string;
  event_type: string;
  vessel_id: string;
  rule_id: string | null;
  severity: 'INFO' | 'WARN' | 'CRITICAL';
  before_snapshot: Record<string, unknown>;
  after_snapshot: Record<string, unknown>;
  delta: Record<string, unknown>;
  timestamp: number;
}

export interface VesselTopology {
  vessel_id: string;
  zones: Array<{ name: string; type: string; systems: string[] }>;
  conduits: Array<{ from: string; to: string; enforced: boolean }>;
  imported_at: number;
  flat_network: boolean;
}

export interface VesselState {
  // Modbus
  modbusBaseline: Map<string, ModbusBaselineEntry>; // key = tuple hash
  modbusBaselineLocked: boolean;
  modbusBaselineStarted: number;
  modbusAnomalies: ModbusAnomaly[];
  recentCoilWrites: CoilWrite[]; // last 60s of FC05 coil writes

  // NMEA
  nmeaTalkerBaseline: Map<string, NMEATalkerEntry>; // key = talker_id
  nmeaBaselineLocked: boolean;
  nmeaAnomalies: NMEAAnomaly[];

  // AIS / GPS
  mmsiRegistry: Map<string, MMSIRecord>;
  ownShipMmsi: string | null;
  lastGpsPosition: GpsPosition | null;
  lastAisPosition: GpsPosition | null;
  gpsAnomalies: Array<{ type: string; detail: string; detected_at: number }>;

  // Topology
  topology: VesselTopology | null;

  // Posture
  postureScore: number | null;
  senseEvents: SenseEvent[];

  // Phase 2 — IACS compliance + score history
  iacs_audit: IACSCapabilityResult[];
  protocol_audit: ProtocolAuditResult[];
  score_history: ScoreHistoryEntry[];
}

const store = new Map<string, VesselState>();

export function getVessel(vessel_id: string): VesselState {
  if (!store.has(vessel_id)) {
    store.set(vessel_id, {
      modbusBaseline: new Map(),
      modbusBaselineLocked: false,
      modbusBaselineStarted: Date.now(),
      modbusAnomalies: [],
      recentCoilWrites: [],
      nmeaTalkerBaseline: new Map(),
      nmeaBaselineLocked: false,
      nmeaAnomalies: [],
      mmsiRegistry: new Map(),
      ownShipMmsi: null,
      lastGpsPosition: null,
      lastAisPosition: null,
      gpsAnomalies: [],
      topology: null,
      postureScore: null,
      senseEvents: [],
      iacs_audit: [],
      protocol_audit: [],
      score_history: [],
    });
  }
  return store.get(vessel_id)!;
}

export function listVessels(): string[] {
  return [...store.keys()];
}

/** Drop a vessel's state so a fresh testbed run starts clean (testbed harness only). */
export function resetVessel(vessel_id: string): void {
  store.delete(vessel_id);
}

export function tupleKey(t: ModbusTuple): string {
  return `${t.src_ip}:${t.unit_id}:${t.function_code}:${t.register}`;
}

// ─── Phase 2 types ────────────────────────────────────────────────────────────

export type ComplianceStatus = 'PASS' | 'PARTIAL' | 'FAIL' | 'UNKNOWN';

export interface IACSCapabilityResult {
  cap_id: string;
  name: string;
  iacs_clause: string;
  rule_id: string;
  status: ComplianceStatus;
  evidence: string;
  assessed_at: number;
}

export interface ProtocolAuditResult {
  protocol: string;
  rule_id: string;
  status: ComplianceStatus;
  detail: string;
}

export interface ScoreHistoryEntry {
  posture_score: number;
  posture_band: 'GREEN' | 'AMBER' | 'RED';
  iacs_pass: number;
  iacs_fail: number;
  checkpoint_at: number;
  trigger: string;
}

// @rule:P2-005 Append score history before any overwrite
export function appendScoreHistory(vessel: VesselState, entry: ScoreHistoryEntry): void {
  vessel.score_history.push(entry);
  if (vessel.score_history.length > 200) vessel.score_history.shift();
}
