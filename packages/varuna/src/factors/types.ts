/**
 * Varuna OT posture — the normalization seam (VRN-P0-2).
 *
 * The 05-05 detectors (modbus/nmea/ais) each return their own anomaly shape with a
 * coarse INFO|WARN|CRITICAL severity. This is the COMMON factor every detector maps
 * into via a `*ToFactors` adapter — so the report card, dashboard, and reconciler all
 * read ONE normalized surface, and the new strategic axes (consequence-weighted
 * severity + actor incl. rogue_agent) have a designed home.
 *
 * @rule:VRN-ARCH-010 every finding carries severity (consequence-weighted) + actor
 * @rule:VRN-ARCH-007 every finding carries data_source ∈ {testbed, live_vessel}
 * @rule:VRN-ARCH-004 detectors map results → factors through a stable *ToFactors seam
 */

/**
 * Consequence-weighted severity ladder (NOT a likelihood ladder). One catastrophic
 * finding outranks many nuisance findings — a disabled air-shutoff coil is not "more
 * frequent," it is "the engine runs away." @rule:VRN-ARCH-010
 */
export type Severity = 'catastrophic' | 'serious' | 'moderate' | 'nuisance';

/** Consequence weight per severity — drives card ordering + posture deduction. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  catastrophic: 100,
  serious: 60,
  moderate: 30,
  nuisance: 8,
};

/** Severity ordering for "worst-first" sorting. */
export const SEVERITY_RANK: Record<Severity, number> = {
  catastrophic: 3,
  serious: 2,
  moderate: 1,
  nuisance: 0,
};

/**
 * WHO is behind the finding.
 * - insider:      an authorised station/source acting off-cadence or out of policy
 * - outsider:     an unknown / injected / unattributable source
 * - rogue_agent:  a REGISTERED agent whose HanumanG posture has drifted, attributable
 *                 to this bus anomaly (WHAT × WHO correlation) — wired in VRN-P1-8
 * - unknown:      shape is ambiguous; never guess insider/outsider
 * @rule:VRN-ARCH-011 rogue_agent requires the two-signal correlation, never one alone
 */
export type Actor = 'insider' | 'outsider' | 'rogue_agent' | 'unknown';

/** Provenance of the data the finding was derived from. @rule:VRN-ARCH-007 */
export type DataSource = 'testbed' | 'live_vessel';

/**
 * A normalized posture finding. Every detector's `*ToFactors` adapter produces these.
 * The three reference columns (vrn_ref / iacs_capability / mitre_technique) make a
 * finding defensible to an operator, a class surveyor, and a P&I underwriter
 * respectively (VRN-047 three-column mapping).
 */
export interface PostureFactor {
  /** Stable id (carry the source anomaly id where there is one). */
  id: string;
  /** Machine-readable threat category. */
  threat:
    | 'modbus_unknown_tuple'
    | 'modbus_broadcast_write'
    | 'modbus_fc_violation'
    | 'modbus_always_alert_fc'
    | 'runaway_diesel_precursor'
    | 'nmea_injection'
    | 'nmea_unknown_talker'
    | 'ais_spoof'
    | 'ais_invalid_mmsi'
    | 'gps_spoof'
    | 'bridge_correlation_mismatch';
  /** Human-readable summary of the finding. */
  summary: string;
  /** Consequence-weighted severity (REQUIRED — INF-VRN-019 blocks a factor without it). */
  severity: Severity;
  /** WHO (REQUIRED — INF-VRN-019 blocks a factor without it). */
  actor: Actor;
  /** Provenance (REQUIRED — VRN-ARCH-007 honesty floor). */
  data_source: DataSource;
  /** VRN rule IDs this finding implements (operator column). */
  vrn_ref: string[];
  /** IACS UR E26/E27 capability touched (class-evidence column). */
  iacs_capability?: string;
  /** MITRE ATT&CK for ICS technique (P&I / underwriter column). */
  mitre_technique?: string;
  /** Pointer to the evidence (anomaly id, coil addresses, sentence, etc.). */
  evidence: Record<string, unknown>;
  /** Source-tuple / actor attribution detail used to classify `actor`. */
  attribution?: { src?: string; registered_agent_id?: string; reason: string };
  /** Epoch ms. */
  detected_at: number;
}

/**
 * INF-VRN-019 — a factor missing severity OR actor OR data_source is BLOCKED, not
 * silently shipped. Detectors fail loud; the honesty floor is not optional.
 */
export function isValidFactor(f: Partial<PostureFactor>): f is PostureFactor {
  return (
    !!f &&
    !!f.id &&
    !!f.threat &&
    typeof f.summary === 'string' &&
    !!f.severity &&
    !!f.actor &&
    (f.data_source === 'testbed' || f.data_source === 'live_vessel') &&
    Array.isArray(f.vrn_ref)
  );
}

/** Options threaded into every `*ToFactors` adapter. */
export interface FactorContext {
  /** Provenance to stamp on every produced factor (honesty floor). */
  data_source: DataSource;
  /** Source IPs known to be authorised maintenance/engineering stations. */
  authorised_sources?: string[];
}

/**
 * The contract a detector-family adapter exposes. The reconciler reads `verb` as the
 * code-truth capability declaration; the aggregator never needs to know the family.
 * @rule:VRN-ARCH-001 one file per threat family
 */
export interface FactorAdapterMeta {
  /** The codex can_do verb this family declares (code-truth, never hand-typed). */
  verb: string;
  /** VRN rules implemented in this family. */
  rules: string[];
}
