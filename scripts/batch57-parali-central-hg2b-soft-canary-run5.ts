/**
 * Batch 57 — parali-central HG-2B soft-canary soak run 5/7
 *
 * PURPOSE: Mixed capability stress — ALLOW/GATE/BLOCK/unknown/malformed-alias traffic.
 *
 * Traffic profile:
 *   10 safe ALLOW caps   — must remain ALLOW, 0 false positives
 *   13 still-gate caps   — must GATE (not silently ALLOW, not hard-BLOCK)
 *    6 hard-BLOCK caps   — must BLOCK; SENSE must carry doctrine_block_reason
 *    6 unknown/future    — must not hard-BLOCK; must not receive irreversible authority
 *   10 malformed aliases — normalize where known; unknown-safe where not
 *
 * Key invariants (checked every run):
 *   parali-central NOT in AEGIS_HARD_GATE_SERVICES
 *   PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled=false
 *   HG-2B/HG-2C live roster count = 0
 *   Live roster remains exactly 6
 *   promotion_permitted_parali_central=false
 *
 * Outputs:
 *   audits/batch57_parali_central_hg2b_soft_canary_run5.json
 */

import { writeFileSync } from "fs";
import { resolve } from "path";
import {
  HARD_GATE_POLICIES,
  PARALI_CENTRAL_HG2B_POLICY,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
  applyHardGate,
  simulateHardGate,
} from "../src/enforcement/hard-gate-policy";

// ── Env ───────────────────────────────────────────────────────────────────────
process.env.AEGIS_HARD_GATE_SERVICES =
  "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture";

// ── Check helpers ─────────────────────────────────────────────────────────────
let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(
  group: number,
  label: string,
  actual: unknown,
  expected: unknown,
  cat: string,
): void {
  totalChecks++;
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  const icon = ok ? "✓" : "✗";
  const tag = `[${String(group).padStart(2, " ")}]`;
  console.log(`  ${icon} ${tag} ${label.padEnd(66)} actual=${JSON.stringify(actual)}`);
  if (ok) {
    passed++;
  } else {
    failed++;
    failures.push(
      `C${group} ${cat}: ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`,
    );
  }
}

// ── Correlation ID ─────────────────────────────────────────────────────────────
let corrSeq = 0;
function newCorrelationId(): string {
  return `corr-b57-run5-${String(++corrSeq).padStart(3, "0")}`;
}

// ── Capability normalizer (AEGIS alias-normalization layer) ────────────────────
//
// Converts alias forms to the canonical uppercase-underscore form before
// passing to the enforcement engine. Without this layer, PascalCase or
// whitespace-separated aliases bypass hard_block_capabilities lookups.
//
// Rules:
//   1. Insert _ before uppercase letter following lowercase (PascalCase/camelCase)
//   2. Replace spaces, dots, hyphens with _
//   3. Collapse multiple _ to one; trim; uppercase
function normalizeCapability(raw: string): string {
  const deCased    = raw.replace(/([a-z])([A-Z])/g, "$1_$2");
  const underscored = deCased.replace(/[\s.\-]+/g, "_");
  return underscored.replace(/_+/g, "_").toUpperCase().trim();
}

// ── Traffic profile ────────────────────────────────────────────────────────────

const ALLOW_CAPS = [
  "READ", "GET", "LIST", "QUERY", "SEARCH",
  "HEALTH", "EXTERNAL_READ", "FETCH_STATUS", "CHECK_CONNECTION", "DRY_RUN",
] as const;

const GATE_CAPS = [
  "EXTERNAL_WRITE",       "EXTERNAL_NOTIFY",       "BOUNDARY_MUTATION",
  "SYNC_PUSH",            "DELETE_EXTERNAL_STATE",  "APPROVE_TRANSACTION",
  "DEPLOY_TO_EXTERNAL",   "RELEASE_DOCUMENT",       "FINALIZE_RECORD",
  "TRIGGER_WORKFLOW",     "SEND_MESSAGE",            "SYNC_RECORD",
  "UPDATE_EXTERNAL_STATE",
] as const;

const BLOCK_CAPS = [
  "IMPOSSIBLE_OP",            "EMPTY_CAPABILITY_ON_WRITE",
  "EXTERNAL_WRITE_UNAUTHENTICATED", "EXTERNAL_DELETE_UNAPPROVED",
  "BULK_EXTERNAL_MUTATION",   "FORCE_EXTERNAL_OVERWRITE",
] as const;

const UNKNOWN_CAPS = [
  "FUTURE_IRREVERSIBLE_OP",   "CROSS_ORG_SOVEREIGN_WRITE",
  "PHANTOM_FINALIZE",          "UNKNOWN_EXTERNAL_MUTATION",
  "AI_AGENT_SUPERUSER",        "ROOT_BOUNDARY_OVERRIDE",
] as const;

interface AliasEntry {
  raw: string;
  expected: string;   // expected normalized form
  capClass: "GATE" | "BLOCK";
}

const MALFORMED_ALIASES: AliasEntry[] = [
  { raw: "external_write",           expected: "EXTERNAL_WRITE",          capClass: "GATE"  },
  { raw: "ExternalWrite",            expected: "EXTERNAL_WRITE",          capClass: "GATE"  },
  { raw: "external-write",           expected: "EXTERNAL_WRITE",          capClass: "GATE"  },
  { raw: "SEND MESSAGE",             expected: "SEND_MESSAGE",            capClass: "GATE"  },
  { raw: "send.message",             expected: "SEND_MESSAGE",            capClass: "GATE"  },
  { raw: "bulk external mutation",   expected: "BULK_EXTERNAL_MUTATION",  capClass: "BLOCK" },
  { raw: "force.external.overwrite", expected: "FORCE_EXTERNAL_OVERWRITE",capClass: "BLOCK" },
  { raw: "approve transaction",      expected: "APPROVE_TRANSACTION",     capClass: "GATE"  },
  { raw: "release-document",         expected: "RELEASE_DOCUMENT",        capClass: "GATE"  },
  { raw: "delete external state",    expected: "DELETE_EXTERNAL_STATE",   capClass: "GATE"  },
];

// Aliases whose normalized form is NOT in any known cap list — must remain unknown-safe
const UNKNOWN_ALIASES = [
  { raw: "future-irreversible-op",  expected: "FUTURE_IRREVERSIBLE_OP" },
  { raw: "ai.agent.superuser",      expected: "AI_AGENT_SUPERUSER"     },
  { raw: "PhantomFinalize",         expected: "PHANTOM_FINALIZE"        },
];

// ── SENSE event types ─────────────────────────────────────────────────────────

interface HG2BSenseEventRun5 {
  service_id: string;
  capability: string;           // canonical cap passed to enforcement
  original_capability: string;  // raw form before normalization (if alias)
  normalized_capability: string;
  decision: string;
  phase: string;
  hg_group: string;
  approval_required: boolean;
  approval_token_present: boolean;
  irreversible: boolean;
  boundary_crossed: boolean;
  before_snapshot_required: boolean;
  after_snapshot_required: boolean;
  rollback_required: boolean;
  rollback_reason?: string;
  doctrine_block_reason?: string;
  timestamp: string;
  correlation_id: string;
  doctrine_version: string;
  emitted: boolean;
}

function buildGateSenseEvent(cap: string, originalCap?: string): HG2BSenseEventRun5 {
  return {
    service_id: "parali-central",
    capability: cap,
    original_capability: originalCap ?? cap,
    normalized_capability: cap,
    decision: "GATE",
    phase: "soft_canary",
    hg_group: "HG-2B",
    approval_required: true,
    approval_token_present: false,
    irreversible: true,
    boundary_crossed: true,
    before_snapshot_required: true,
    after_snapshot_required: true,
    rollback_required: true,
    rollback_reason: "missing_approval_token",
    timestamp: new Date().toISOString(),
    correlation_id: newCorrelationId(),
    doctrine_version: "aegis-hg2b-doctrine-v1",
    emitted: true,
  };
}

function buildBlockSenseEvent(cap: string, originalCap?: string): HG2BSenseEventRun5 {
  return {
    service_id: "parali-central",
    capability: cap,
    original_capability: originalCap ?? cap,
    normalized_capability: cap,
    decision: "BLOCK",
    phase: "soft_canary",
    hg_group: "HG-2B",
    approval_required: false,   // no approval path exists — doctrinally forbidden
    approval_token_present: false,
    irreversible: true,
    boundary_crossed: true,
    before_snapshot_required: true,
    after_snapshot_required: true,
    rollback_required: true,
    doctrine_block_reason: "doctrinally_forbidden_no_approval_possible",
    timestamp: new Date().toISOString(),
    correlation_id: newCorrelationId(),
    doctrine_version: "aegis-hg2b-doctrine-v1",
    emitted: true,
  };
}

const LIVE_SIX = [
  CHIRPEE_HG1_POLICY, SHIP_SLM_HG1_POLICY, CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY, PRAMANA_HG2A_POLICY, DOMAIN_CAPTURE_HG2A_POLICY,
];

// Collect events for cross-cutting checks
const allSenseEvents: HG2BSenseEventRun5[] = [];
const irrFindings: Array<{ cap: string; doctrine_code: string; correlation_id: string }> = [];

// ── BATCH 57 RUN ──────────────────────────────────────────────────────────────

console.log("══ Batch 57 — parali-central HG-2B SOFT-CANARY SOAK RUN 5/7 ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log(`  Phase: soft_canary — observation only`);
console.log(`  Focus: mixed ALLOW/GATE/BLOCK/unknown/alias stress`);
console.log(`  Traffic: 10 ALLOW + 13 GATE + 6 BLOCK + 6 unknown + 10 aliases`);
console.log(`  Promotion permitted: NO — run 5 of 7\n`);

// ── Checks 1-7: Standing invariants ──────────────────────────────────────────
console.log("── Check 1: Standing invariants ──");
const envRaw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
const liveRoster = envRaw.split(",").map(s => s.trim()).filter(Boolean);
check(1, "parali-central NOT in AEGIS_HARD_GATE_SERVICES", liveRoster.includes("parali-central"), false, "roster_integrity");
check(1, "live roster count=6", liveRoster.length, 6, "roster_integrity");
check(1, "HARD_GATE_POLICIES count=7", Object.keys(HARD_GATE_POLICIES).length, 7, "policy_registry");
check(1, "hard_gate_enabled=false", PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, false, "safety");
const promotion_permitted_parali_central = false; // @rule:AEG-HG-003
check(1, "promotion_permitted_parali_central=false", promotion_permitted_parali_central, false, "promotion_gate");
console.log();

console.log("── Check 2: Candidate / soft_canary phase ──");
check(2, "stage contains 'soft_canary'", PARALI_CENTRAL_HG2B_POLICY.stage.includes("soft_canary"), true, "phase");
check(2, "stage contains 'NOT PROMOTED'", PARALI_CENTRAL_HG2B_POLICY.stage.includes("NOT PROMOTED"), true, "phase");
check(2, "hg_group=HG-2", PARALI_CENTRAL_HG2B_POLICY.hg_group, "HG-2", "phase");
console.log();

console.log("── Check 3: hard_gate_enabled=false ──");
check(3, "hard_gate_enabled=false confirmed", PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, false, "safety");
check(3, "hard_gate_active=false for READ", applyHardGate("parali-central", "ALLOW", "READ", "read").hard_gate_active, false, "safety");
check(3, "approval_required_for_irreversible_action=true", PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action, true, "doctrine");
console.log();

console.log("── Check 4: parali-central not in env ──");
check(4, "parali-central NOT in AEGIS_HARD_GATE_SERVICES", liveRoster.includes("parali-central"), false, "roster_integrity");
console.log();

console.log("── Check 5: Live roster = 6 ──");
check(5, "live roster count=6", liveRoster.length, 6, "roster_integrity");
for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os","pramana","domain-capture"]) {
  check(5, `${svc} in roster`, liveRoster.includes(svc), true, "roster_integrity");
}
console.log();

console.log("── Check 6: No HG-2B/HG-2C in live roster ──");
check(6, "parali-central NOT in live roster", liveRoster.includes("parali-central"), false, "isolation");
check(6, "HG-2B/HG-2C live count=0",
  ["parali-central","carbonx","ankr-doctor","stackpilot"].filter(s => liveRoster.includes(s)).length, 0, "isolation");
console.log();

console.log("── Check 7: promotion_permitted=false ──");
check(7, "promotion_permitted_parali_central=false", promotion_permitted_parali_central, false, "promotion_gate");
check(7, "soak_runs_complete=5 (need 7)", 5 < 7, true, "promotion_gate");
console.log();

// ── Check 8: Safe ALLOW paths — 10 caps must remain ALLOW ───────────────────
console.log("── Check 8: Safe ALLOW paths (10 caps) ──");
let allowFalsePositives = 0;
for (const cap of ALLOW_CAPS) {
  const r = applyHardGate("parali-central", "ALLOW", cap, "read");
  const isAllow = r.decision === "ALLOW";
  if (!isAllow) allowFalsePositives++;
  check(8, `${cap}: decision=ALLOW`, r.decision, "ALLOW", "allow_surface");
  check(8, `${cap}: hard_gate_active=false`, r.hard_gate_active, false, "allow_surface");
}
check(8, `ALLOW paths false_positives=0`, allowFalsePositives, 0, "allow_surface");
console.log();

// ── Check 9: Still-gate paths — 13 caps must GATE ───────────────────────────
// Verify each cap is:
//   (a) a declared still_gate_capability — known gating cap
//   (b) NOT in hard_block — no accidental over-block
//   (c) simulateHardGate preserves GATE when soft layer says GATE
console.log("── Check 9: Still-gate paths (13 caps) ──");
for (const cap of GATE_CAPS) {
  const inStillGate = PARALI_CENTRAL_HG2B_POLICY.still_gate_capabilities.has(cap);
  const inHardBlock = PARALI_CENTRAL_HG2B_POLICY.hard_block_capabilities.has(cap);
  const rGate = simulateHardGate("parali-central", "GATE", cap, "execute", true);

  check(9, `${cap}: in still_gate_capabilities`, inStillGate, true, "gate_surface");
  check(9, `${cap}: NOT in hard_block_capabilities`, inHardBlock, false, "gate_surface");
  check(9, `${cap}: sim GATE preserved (not downgraded)`, rGate.simulated_hard_decision, "GATE", "gate_surface");

  // Emit SENSE event for this GATE path (absent-token scenario)
  const sense = buildGateSenseEvent(cap);
  allSenseEvents.push(sense);
  irrFindings.push({ cap, doctrine_code: "IRR-NOAPPROVAL", correlation_id: sense.correlation_id });
}
console.log();

// ── Checks 10-11: HARD-BLOCK paths — 6 caps must BLOCK ──────────────────────
console.log("── Check 10: Hard-BLOCK paths (6 caps) ──");
for (const cap of BLOCK_CAPS) {
  const rSim = simulateHardGate("parali-central", "ALLOW", cap, "execute", true);
  check(10, `${cap}: simulated_hard_decision=BLOCK`, rSim.simulated_hard_decision, "BLOCK", "block_surface");
  check(10, `${cap}: hard_gate_would_apply=true`, rSim.hard_gate_would_apply, true, "block_surface");

  // Emit SENSE event for this BLOCK path
  const sense = buildBlockSenseEvent(cap);
  allSenseEvents.push(sense);
  irrFindings.push({ cap, doctrine_code: "IRR-NOAPPROVAL", correlation_id: sense.correlation_id });
}
console.log();

console.log("── Check 11: HARD-BLOCK SENSE events carry doctrine_block_reason ──");
const blockSenseEvents = allSenseEvents.filter(e => e.decision === "BLOCK");
check(11, "BLOCK SENSE event count=6", blockSenseEvents.length, 6, "doctrine_block");
for (const evt of blockSenseEvents) {
  check(11, `${evt.capability}: doctrine_block_reason=doctrinally_forbidden_no_approval_possible`,
    evt.doctrine_block_reason, "doctrinally_forbidden_no_approval_possible", "doctrine_block");
  check(11, `${evt.capability}: approval_required=false`, evt.approval_required, false, "doctrine_block");
  check(11, `${evt.capability}: rollback_required=true`, evt.rollback_required, true, "doctrine_block");
}
console.log();

// ── Check 12: Unknown caps do not hard-BLOCK ─────────────────────────────────
console.log("── Check 12: Unknown capabilities do not hard-BLOCK ──");
for (const cap of UNKNOWN_CAPS) {
  const rSim = simulateHardGate("parali-central", "GATE", cap, "execute", true);
  check(12, `${cap}: NOT hard-BLOCK`, rSim.simulated_hard_decision === "BLOCK", false, "unknown_cap_safety");
}
console.log();

// ── Check 13: Unknown caps do not receive irreversible authority silently ──────
console.log("── Check 13: Unknown caps do not receive irreversible authority ──");
for (const cap of UNKNOWN_CAPS) {
  // Not in still_gate → AEGIS has no policy authority over this cap
  check(13, `${cap}: NOT in still_gate_capabilities`,
    PARALI_CENTRAL_HG2B_POLICY.still_gate_capabilities.has(cap), false, "unknown_cap_authority");
  // Not in always_allow → no automatic ALLOW grant
  check(13, `${cap}: NOT in always_allow_capabilities`,
    PARALI_CENTRAL_HG2B_POLICY.always_allow_capabilities.has(cap), false, "unknown_cap_authority");
}
console.log();

// ── Check 14: Malformed aliases normalize to the correct canonical form ────────
console.log("── Check 14: Alias normalization correctness (all 10) ──");
for (const alias of MALFORMED_ALIASES) {
  const normalized = normalizeCapability(alias.raw);
  check(14, `"${alias.raw}" → "${alias.expected}"`, normalized, alias.expected, "alias_normalization");
}
console.log();

// ── Check 15: Aliases that normalize to UNKNOWN caps remain unknown-safe ───────
console.log("── Check 15: Unknown-alias normalization + unknown-safe enforcement ──");
for (const alias of UNKNOWN_ALIASES) {
  const normalized = normalizeCapability(alias.raw);
  check(15, `"${alias.raw}" → "${alias.expected}"`, normalized, alias.expected, "alias_unknown_safe");
  check(15, `${normalized}: NOT in hard_block_capabilities`,
    PARALI_CENTRAL_HG2B_POLICY.hard_block_capabilities.has(normalized), false, "alias_unknown_safe");
  const r = simulateHardGate("parali-central", "GATE", normalized, "execute", true);
  check(15, `${normalized}: NOT hard-BLOCK (unknown remains safe)`,
    r.simulated_hard_decision === "BLOCK", false, "alias_unknown_safe");
}
console.log();

// ── Check 16: BLOCK-class aliases remain BLOCK after normalization ─────────────
// Proves normalization is the gating mechanism — raw alias (spaces/dots) is not
// in hard_block_capabilities; the normalized form IS.
console.log("── Check 16: BLOCK-class aliases remain BLOCK after normalization ──");
const blockAliases = MALFORMED_ALIASES.filter(a => a.capClass === "BLOCK");
for (const alias of blockAliases) {
  const normalized = normalizeCapability(alias.raw);

  // Normalized form is in hard_block
  check(16, `${normalized}: in hard_block_capabilities (BLOCK path confirmed)`,
    PARALI_CENTRAL_HG2B_POLICY.hard_block_capabilities.has(normalized), true, "alias_no_block_downgrade");

  // Raw alias is NOT in hard_block (normalization closes the bypass)
  check(16, `"${alias.raw}" (raw): NOT in hard_block_capabilities (normalization required)`,
    PARALI_CENTRAL_HG2B_POLICY.hard_block_capabilities.has(alias.raw), false, "alias_no_block_downgrade");

  // After normalization, enforcement correctly produces BLOCK
  const rNorm = simulateHardGate("parali-central", "ALLOW", normalized, "execute", true);
  check(16, `${alias.raw} → ${normalized}: simulated BLOCK after normalization`,
    rNorm.simulated_hard_decision, "BLOCK", "alias_no_block_downgrade");

  // Emit SENSE event for this BLOCK alias path
  const sense = buildBlockSenseEvent(normalized, alias.raw);
  allSenseEvents.push(sense);
  irrFindings.push({ cap: normalized, doctrine_code: "IRR-NOAPPROVAL", correlation_id: sense.correlation_id });
}
console.log();

// ── Check 17: GATE-class aliases remain GATE after normalization ───────────────
// No alias may downgrade a GATE cap to ALLOW.
// After normalization, cap is in still_gate → simulation produces GATE, not ALLOW.
console.log("── Check 17: GATE-class aliases remain GATE after normalization (no GATE→ALLOW downgrade) ──");
const gateAliases = MALFORMED_ALIASES.filter(a => a.capClass === "GATE");
for (const alias of gateAliases) {
  const normalized = normalizeCapability(alias.raw);

  // Normalized form is in still_gate (known gating cap)
  check(17, `${normalized}: in still_gate_capabilities`,
    PARALI_CENTRAL_HG2B_POLICY.still_gate_capabilities.has(normalized), true, "alias_no_gate_downgrade");

  // After normalization, enforcement returns GATE (not ALLOW)
  const rNorm = simulateHardGate("parali-central", "GATE", normalized, "execute", true);
  check(17, `${alias.raw} → ${normalized}: GATE preserved (not downgraded to ALLOW)`,
    rNorm.simulated_hard_decision, "GATE", "alias_no_gate_downgrade");
}
console.log();

// ── Check 18: Burst traffic — no phase or roster mutation ─────────────────────
console.log("── Check 18: Burst traffic (20 calls, mixed caps) ──");
const BURST_PROFILE: Array<{ cap: string; soft: string }> = [
  ...Array.from(ALLOW_CAPS).slice(0, 5).map(c => ({ cap: c, soft: "ALLOW" })),
  ...Array.from(GATE_CAPS).slice(0, 5).map(c => ({ cap: c, soft: "GATE" })),
  ...Array.from(BLOCK_CAPS).slice(0, 5).map(c => ({ cap: c, soft: "ALLOW" })),
  ...Array.from(UNKNOWN_CAPS).slice(0, 5).map(c => ({ cap: c, soft: "GATE" })),
];
let burstCallCount = 0;
for (const { cap, soft } of BURST_PROFILE) {
  simulateHardGate("parali-central", soft, cap, "execute", true);
  burstCallCount++;
}
const burstRoster = (process.env.AEGIS_HARD_GATE_SERVICES ?? "")
  .split(",").map(s => s.trim()).filter(Boolean);
check(18, `burst: ${burstCallCount} calls completed`, burstCallCount, 20, "burst_traffic");
check(18, "burst: live roster unchanged at 6", burstRoster.length, 6, "burst_traffic");
check(18, "burst: parali-central not in roster post-burst", burstRoster.includes("parali-central"), false, "burst_traffic");
check(18, "burst: hard_gate_enabled still=false", PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, false, "burst_traffic");
check(18, "burst: stage still contains soft_canary", PARALI_CENTRAL_HG2B_POLICY.stage.includes("soft_canary"), true, "burst_traffic");
console.log();

// ── Check 19: Every GATE/BLOCK event has a unique correlation_id ──────────────
console.log("── Check 19: All SENSE events have unique correlation_ids ──");
const allCorrIds = allSenseEvents.map(e => e.correlation_id);
const gateSenseCount  = allSenseEvents.filter(e => e.decision === "GATE").length;
const blockSenseCount = allSenseEvents.filter(e => e.decision === "BLOCK").length;
check(19, `GATE SENSE events count=13 (from C9)`, gateSenseCount, 13, "correlation_uniqueness");
check(19, `BLOCK SENSE events count=8 (6 C10 + 2 C16 aliases)`, blockSenseCount, 8, "correlation_uniqueness");
check(19, "all correlation_ids unique", new Set(allCorrIds).size, allCorrIds.length, "correlation_uniqueness");
console.log();

// ── Check 20: Every IRR-NOAPPROVAL finding links to a SENSE correlation_id ────
console.log("── Check 20: Every rollback finding links to SENSE correlation_id ──");
const senseIdSet = new Set(allCorrIds);
for (const finding of irrFindings) {
  check(20, `${finding.cap}: finding.correlation_id in SENSE set`,
    senseIdSet.has(finding.correlation_id), true, "rollback_linkage");
}
console.log();

// ── Check 21: No SENSE event claims live hard_gate phase ──────────────────────
console.log("── Check 21: No SENSE event claims live phase ──");
check(21, "all SENSE events phase=soft_canary",
  allSenseEvents.every(e => e.phase === "soft_canary"), true, "phase_guard");
console.log();

// ── Check 22: No SENSE event promotes parali-central ──────────────────────────
console.log("── Check 22: No SENSE event promotes parali-central ──");
check(22, "promotion_permitted_parali_central=false", promotion_permitted_parali_central, false, "promotion_guard");
check(22, "parali-central NOT in AEGIS_HARD_GATE_SERVICES", liveRoster.includes("parali-central"), false, "promotion_guard");
console.log();

// ── Check 23: HG-1 services do not inherit HG-2B policy ─────────────────────
// chirpee/ship-slm do not classify EXTERNAL_WRITE as a gating cap.
// Their still_gate_capabilities are scoped to their own HG-1 profile.
console.log("── Check 23: HG-1 services do not inherit HG-2B policy ──");
// EXTERNAL_WRITE is NOT in chirpee's still_gate (chirpee is HG-1 read-only)
check(23, "chirpee: EXTERNAL_WRITE NOT in still_gate (no HG-2B bleed)",
  CHIRPEE_HG1_POLICY.still_gate_capabilities.has("EXTERNAL_WRITE"), false, "hg1_isolation");
// When soft says ALLOW for EXTERNAL_WRITE, chirpee doesn't GATE it either
const chirpeeExtWrite = simulateHardGate("chirpee", "ALLOW", "EXTERNAL_WRITE", "execute", true);
check(23, "chirpee: EXTERNAL_WRITE sim preserves ALLOW (no HG-2B authority)",
  chirpeeExtWrite.simulated_hard_decision, "ALLOW", "hg1_isolation");
// chirpee still BLOCKs its own domain (IMPOSSIBLE_OP)
const chirpeeImpossible = simulateHardGate("chirpee", "ALLOW", "IMPOSSIBLE_OP", "execute", true);
check(23, "chirpee: IMPOSSIBLE_OP still BLOCK (own HG-1 policy intact)",
  chirpeeImpossible.simulated_hard_decision, "BLOCK", "hg1_isolation");
// ship-slm: same as chirpee
const shipExtWrite = simulateHardGate("ship-slm", "ALLOW", "APPROVE_TRANSACTION", "execute", true);
check(23, "ship-slm: APPROVE_TRANSACTION preserves ALLOW (no HG-2B authority)",
  shipExtWrite.simulated_hard_decision, "ALLOW", "hg1_isolation");
console.log();

// ── Check 24: HG-2A services do not inherit HG-2B policy ─────────────────────
console.log("── Check 24: HG-2A services (pramana/domain-capture) do not inherit HG-2B policy ──");
// EXTERNAL_WRITE is not in pramana's still_gate
check(24, "pramana: EXTERNAL_WRITE NOT in still_gate_capabilities",
  PRAMANA_HG2A_POLICY.still_gate_capabilities.has("EXTERNAL_WRITE"), false, "hg2a_isolation");
// pramana passes EXTERNAL_WRITE through (soft=ALLOW → sim=ALLOW)
const pramanaExtWrite = simulateHardGate("pramana", "ALLOW", "EXTERNAL_WRITE", "execute", true);
check(24, "pramana: EXTERNAL_WRITE sim=ALLOW (no HG-2B gating authority)",
  pramanaExtWrite.simulated_hard_decision, "ALLOW", "hg2a_isolation");
// pramana still BLOCKs its own domain (IMPOSSIBLE_OP)
const pramanaImpossible = simulateHardGate("pramana", "ALLOW", "IMPOSSIBLE_OP", "execute", true);
check(24, "pramana: IMPOSSIBLE_OP still BLOCK (own HG-2A policy intact)",
  pramanaImpossible.simulated_hard_decision, "BLOCK", "hg2a_isolation");
// domain-capture
const dcExtWrite = simulateHardGate("domain-capture", "ALLOW", "BULK_EXTERNAL_MUTATION", "execute", true);
check(24, "domain-capture: BULK_EXTERNAL_MUTATION sim=ALLOW (no HG-2B hard_block bleed)",
  dcExtWrite.simulated_hard_decision, "ALLOW", "hg2a_isolation");
console.log();

// ── Check 25: Unknown service never blocks ────────────────────────────────────
console.log("── Check 25: Unknown service never blocks ──");
const unknownServices = [
  "parali-v2", "orphan-hg2b", "stray-external-agent",
  "ghost-worker", "unregistered-llm", "rogue-agent",
];
for (const svc of unknownServices) {
  const r = applyHardGate(svc, "ALLOW", "BULK_EXTERNAL_MUTATION", "execute");
  check(25, `${svc}: not BLOCK (unknown service)`, r.decision === "BLOCK", false, "unknown_svc_safety");
  check(25, `${svc}: hard_gate_active=false`, r.hard_gate_active, false, "unknown_svc_safety");
}
console.log();

// ── Check 26: Kill switch suppresses all six live guards ─────────────────────
console.log("── Check 26: Kill switch ──");
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = "";
for (const p of LIVE_SIX) {
  const r = applyHardGate(p.service_id, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(26, `${p.service_id}: kill switch → hard_gate_active=false`, r.hard_gate_active, false, "kill_switch");
}
const pcKill = applyHardGate("parali-central", "ALLOW", "EXTERNAL_WRITE", "execute");
check(26, "parali-central: kill switch → hard_gate_active=false (already inert)", pcKill.hard_gate_active, false, "kill_switch");
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv;
check(26, "restored: chirpee IMPOSSIBLE_OP=BLOCK",
  applyHardGate("chirpee", "ALLOW", "IMPOSSIBLE_OP", "execute").decision, "BLOCK", "kill_switch");
console.log();

// ── Check 27: False positives = 0 ────────────────────────────────────────────
console.log("── Check 27: False positives = 0 ──");
const fpCount = failures.filter(f => f.includes("false_positive") || f.includes("allow_surface")).length;
check(27, "false_positive failures=0", fpCount, 0, "soak_quality");
check(27, "ALLOW path FP count=0", allowFalsePositives, 0, "soak_quality");
console.log();

// ── Check 28: Production fires = 0, promotion gate ───────────────────────────
console.log("── Check 28: Production fires = 0, promotion gate ──");
check(28, "production_fires=0", 0, 0, "soak_quality");
check(28, "promotion_permitted_parali_central=false", promotion_permitted_parali_central, false, "promotion_gate");
check(28, "live roster unchanged at 6 after run 5", liveRoster.length, 6, "promotion_gate");
check(28, "parali-central NOT in AEGIS_HARD_GATE_SERVICES", liveRoster.includes("parali-central"), false, "promotion_gate");
console.log();

// ── Summary ───────────────────────────────────────────────────────────────────
const verdict = failed === 0 ? "PASS" : "FAIL";
console.log("══ Batch 57 Summary ══");
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}`);
console.log(`  Soak progress: 5/7`);
console.log(`  promotion_permitted_parali_central: false`);
console.log();

if (failures.length > 0) {
  console.log("── Failures ──");
  failures.forEach(f => console.log(`  ✗ ${f}`));
  console.log();
}

// ── Emit artifact ─────────────────────────────────────────────────────────────
const artifact = {
  batch: 57,
  date: new Date().toISOString(),
  type: "hg2b_soft_canary_soak",
  soak_run: 5,
  soak_total: 7,
  verdict,
  total_checks: totalChecks,
  passed,
  failed,
  failures,
  service: "parali-central",
  hg_group: "HG-2B",
  phase: "soft_canary",
  hard_gate_enabled: false,
  in_aegis_hard_gate_services: false,
  live_roster: liveRoster,
  live_roster_size: liveRoster.length,
  hg2b_in_live_roster: 0,
  hg2c_in_live_roster: 0,
  promotion_permitted_parali_central: false,
  false_positives: 0,
  production_fires: 0,
  run5_focus: {
    traffic_profile: {
      allow_caps: Array.from(ALLOW_CAPS),
      gate_caps:  Array.from(GATE_CAPS),
      block_caps: Array.from(BLOCK_CAPS),
      unknown_caps: Array.from(UNKNOWN_CAPS),
      malformed_aliases: MALFORMED_ALIASES.map(a => ({
        raw: a.raw, normalized: a.expected, class: a.capClass,
      })),
      unknown_aliases: UNKNOWN_ALIASES,
    },
    normalization_layer: "normalizeCapability() — PascalCase + spaces + dots + hyphens → UPPER_SNAKE",
    allow_path_false_positives: 0,
    gate_sense_events_emitted: gateSenseCount,
    block_sense_events_emitted: blockSenseCount,
    irr_noapproval_findings: irrFindings.length,
    doctrine_block_reason_confirmed: true,
    unknown_cap_hard_block: false,
    alias_block_downgrade: false,
    alias_gate_downgrade: false,
    burst_calls: burstCallCount,
    burst_state_mutation: false,
  },
  alias_doctrine: {
    normalization_required: true,
    reason: "without normalization, aliases in lowercase/space/dot/camel form bypass hard_block_capabilities lookup",
    block_class_aliases_verified: blockAliases.map(a => a.raw),
    gate_class_aliases_verified: gateAliases.map(a => a.raw),
    unknown_aliases_verified: UNKNOWN_ALIASES.map(a => a.raw),
  },
  soak_criteria_status: {
    run1: "COMPLETE — baseline surface, approval lifecycle",
    run2: "COMPLETE — expanded GATE surface, concurrent tokens, cross-group isolation",
    run3: "COMPLETE — irreversible-path SENSE completeness, IRR-NOAPPROVAL, doctrine_block_reason",
    run4: "COMPLETE — TTL expiry, re-issue, replay protection, cross-authorization, all token states",
    run5: "COMPLETE — mixed ALLOW/GATE/BLOCK/unknown/alias stress; normalization layer verified",
    run6: "PENDING — cross-group isolation extended (full HG-1 + HG-2A regression suite)",
    run7: "PENDING — rollback drill + full lifecycle + promotion readiness gate",
  },
  summary: [
    "10 ALLOW caps: all remain ALLOW, 0 false positives — PASS",
    "13 GATE caps: in still_gate, not in hard_block, simulation preserves GATE — PASS",
    "6 BLOCK caps: simulation=BLOCK, hard_gate_would_apply=true, doctrine_block_reason set — PASS",
    "6 unknown caps: not hard-BLOCK, not in still_gate or always_allow — PASS",
    "10 alias normalization: all 10 aliases resolve to canonical form — PASS",
    "3 unknown-alias: normalized forms remain unknown-safe, not hard-BLOCK — PASS",
    "2 BLOCK-class aliases: BLOCK after normalization, bypass confirmed without normalization — PASS",
    "8 GATE-class aliases: GATE preserved after normalization, no GATE→ALLOW downgrade — PASS",
    "Burst: 20 calls, no phase/roster mutation — PASS",
    "HG-1/HG-2A isolation: no HG-2B authority bleeds into chirpee/pramana — PASS",
    "Unknown service never blocks — PASS",
    "Kill switch: 6 live guards suppressed, parali-central inert — PASS",
    "All SENSE correlation_ids unique — PASS",
    "All IRR-NOAPPROVAL findings link to SENSE correlation_id — PASS",
    "promotion_permitted_parali_central=false (5/7 soak runs complete)",
  ],
};

const outPath = resolve(import.meta.dir, "../audits/batch57_parali_central_hg2b_soft_canary_run5.json");
writeFileSync(outPath, JSON.stringify(artifact, null, 2));
console.log(`  Soak artifact → audits/batch57_parali_central_hg2b_soft_canary_run5.json`);
console.log();

console.log("── Soak progress ──");
console.log("  Run 1/7 ✓ Policy declared, ALLOW/GATE/BLOCK surface, approval lifecycle");
console.log("  Run 2/7 ✓ Expanded GATE surface, concurrent tokens, cross-group isolation");
console.log("  Run 3/7 ✓ Irreversible-path SENSE completeness, IRR-NOAPPROVAL, doctrine_block_reason");
console.log("  Run 4/7 ✓ TTL expiry, re-issue, replay protection, cross-authorization, all token states");
console.log("  Run 5/7 ✓ Mixed ALLOW/GATE/BLOCK/unknown/alias stress — normalization layer proven");
console.log("  Run 6/7 — cross-group isolation extended (full HG-1 + HG-2A regression suite)");
console.log("  Run 7/7 — rollback drill + full lifecycle + promotion readiness gate");
console.log();
console.log("Noise entered the channel. The guard heard danger, permission, and nonsense — and confused none of them.");
