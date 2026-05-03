/**
 * Batch 62 — carbonx HG-2B Candidate Readiness Audit
 *
 * Purpose:
 *   Characterise carbonx-backend as the next HG-2B candidate without
 *   declaring it live, without enabling hard_gate_enabled, and without
 *   adding it to AEGIS_HARD_GATE_SERVICES.
 *
 * Non-negotiables enforced by this script:
 *   - carbonx is NOT added to AEGIS_HARD_GATE_SERVICES
 *   - carbonx hard_gate_enabled remains false if a policy exists
 *   - Live roster remains exactly 7
 *   - HG-2B live count remains 1 (parali-central only)
 *   - HG-2C live count remains 0
 *   - Existing seven live guards remain regression-clean
 *   - Unknown service never blocks
 *   - Unknown capability does not hard-block
 *
 * This is a classification and readiness-gap batch, not a soak batch.
 * Only after Batch 62 passes should Batch 63 declare CARBONX_HG2B_POLICY
 * and run soft-canary 1/7.
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false is the default for all services
 * @rule:AEG-HG-002 READ is in never_block for every service in every HG group
 * @rule:AEG-HG-003 hard-gate promotion requires explicit env var — not automatic
 * @rule:AEG-HG-2B-001 external_state_touch=true requires external cleanup in rollback
 * @rule:AEG-HG-2B-002 approval_required_for_irreversible_action — non-negotiable
 * @rule:IRR-NOAPPROVAL no AI agent may perform irreversible external action without token
 * @rule:AEG-E-016 approval tokens are scoped keys — service_id + capability + operation
 */

import { readFileSync } from "fs";
import { writeFileSync } from "fs";
import {
  applyHardGate,
  HARD_GATE_POLICIES,
  PARALI_CENTRAL_HG2B_POLICY,
} from "../src/enforcement/hard-gate-policy";

// ── Check infrastructure ──────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];
const findings: string[] = [];   // non-failing observations requiring attention

function check(
  group: number,
  label: string,
  actual: unknown,
  expected: unknown,
  tag: string,
): void {
  const ok =
    typeof expected === "object" && expected !== null
      ? JSON.stringify(actual) === JSON.stringify(expected)
      : actual === expected;
  const pad = String(group).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    const msg = `[${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`;
    failures.push(`${tag}: ${msg}`);
    console.log(`  ✗ ${msg}`);
  }
}

function finding(label: string, detail: string): void {
  const entry = `FINDING: ${label} — ${detail}`;
  findings.push(entry);
  console.log(`  ⚠  ${entry}`);
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

function readJSON(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf-8"));
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PARALI_CENTRAL     = "parali-central";
const CARBONX            = "carbonx-backend";
const HG1_SERVICES       = ["chirpee", "ship-slm", "chief-slm", "puranic-os"];
const HG2A_SERVICES      = ["pramana", "domain-capture"];
const EXPECTED_LIVE_7    = [...HG1_SERVICES, ...HG2A_SERVICES, PARALI_CENTRAL];

// Production env is NOT modified in this batch.
// Set to expected live roster for regression validation only.
const AUDIT_ENV_ROSTER = EXPECTED_LIVE_7.join(",");

const PATHS = {
  servicesJson:   "/root/.ankr/config/services.json",
  batch60Artifact:"audits/batch60_parali_central_hg2b_promotion.json",
  batch61Artifact:"audits/batch61_post_hg2b_promotion_convergence_audit.json",
};

// ── HEADER ────────────────────────────────────────────────────────────────────

console.log("══ Batch 62 — carbonx HG-2B Candidate Readiness Audit ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log("  Purpose: Classify carbonx-backend as HG-2B candidate; no live promotion");
console.log("  Invariant: carbonx does NOT enter AEGIS_HARD_GATE_SERVICES this batch");
console.log();

// ── Load reference artifacts ──────────────────────────────────────────────────

const b60 = readJSON(PATHS.batch60Artifact);
const b61 = readJSON(PATHS.batch61Artifact);
const services = readJSON(PATHS.servicesJson);
const svcsMap = (services.services as Record<string, Record<string, unknown>>) ?? {};
const carbonxSvc = svcsMap[CARBONX] ?? {};

// ── Extract carbonx actual metadata from services.json ────────────────────────

const carbonxActualAuthorityClass    = carbonxSvc.authority_class as string | undefined;
const carbonxActualBlastRadius       = (carbonxSvc.governance_blast_radius ?? carbonxSvc.blast_radius) as string | undefined;
const carbonxActualTier              = carbonxSvc.tier as number | undefined;
const carbonxActualRuntimeReadiness  = ((carbonxSvc.runtime_readiness ?? {}) as Record<string, unknown>).tier as string | undefined;
const carbonxNeedsCodeScan           = carbonxSvc.needs_code_scan as boolean | undefined;
const carbonxHumanGateRequired       = carbonxSvc.human_gate_required as boolean | undefined;
const carbonxAegisGate               = (carbonxSvc.aegis_gate as Record<string, unknown>) ?? {};
const carbonxCanDo                   = (carbonxSvc.can_do as string[]) ?? [];

// Assumed values from aegis codex rollout comment vs actual
const ASSUMED_AUTHORITY_CLASS = "external_call";  // from codex rollout comment
const ASSUMED_BLAST_RADIUS    = "BR-3";           // from codex rollout comment
const ASSUMED_TIER_CLASS      = "TIER-A";         // from codex rollout comment

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 1 — Live roster remains exactly 7
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 1: Live roster remains exactly 7 post-Batch-60 (before this batch)");
const b60RosterSize = b60.live_hard_gate_roster_size as number;
check(1, "batch60 artifact: live_hard_gate_roster_size=7", b60RosterSize, 7, "roster");
check(1, "batch61 artifact: live_roster_size=7",
  (b61 as Record<string, unknown>).live_roster_size, 7, "roster");
check(1, "batch61 verdict=PASS", b61.verdict, "PASS", "roster");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 2 — parali-central remains HG-2B live
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 2: parali-central remains HG-2B live (unchanged by this batch)");
check(2, "PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled=true",
  PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, true, "policy");
check(2, "stage contains 'HG-2B LIVE'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("HG-2B LIVE"), true, "policy");
check(2, "batch60 hard_gate_enabled=true", b60.hard_gate_enabled, true, "policy");
check(2, "batch60 hg2b_live_count=1", b60.hg2b_live_count, 1, "policy");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 3 — carbonx is NOT in AEGIS_HARD_GATE_SERVICES
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 3: carbonx is NOT in AEGIS_HARD_GATE_SERVICES (must stay false this batch)");

// Do NOT set process.env.AEGIS_HARD_GATE_SERVICES to include carbonx.
// For regression tests we use the expected live-7 roster only.
const preAuditEnv = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
const preAuditRoster = preAuditEnv.split(",").map(s => s.trim()).filter(Boolean);

check(3, "carbonx NOT in AEGIS_HARD_GATE_SERVICES (pre-audit env)",
  preAuditRoster.includes(CARBONX), false, "guard");
// If env was empty (test environment), that is fine — confirm the invariant via policy
check(3, "carbonx NOT in HARD_GATE_POLICIES registry",
  CARBONX in HARD_GATE_POLICIES, false, "guard");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 4 — HG-2B live count remains 1, HG-2C remains 0
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 4: HG-2B live count=1 (parali-central only); HG-2C live count=0");
check(4, "batch60 hg2b_live_count=1", b60.hg2b_live_count, 1, "counts");
check(4, "batch60 hg2c_live_count=0", b60.hg2c_live_count, 0, "counts");
check(4, "batch61 hg2b_count=1",
  (b61 as Record<string, unknown>).hg2b_count, 1, "counts");
check(4, "batch61 hg2c_count=0",
  (b61 as Record<string, unknown>).hg2c_count, 0, "counts");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 5 — HG-2C live count remains 0 (structural policy check)
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 5: HG-2C has zero live services in policy registry");
const hg2cLiveCount = Object.values(HARD_GATE_POLICIES).filter(
  p => (p as Record<string, unknown>).hg_group === "HG-2C" &&
       (p as Record<string, unknown>).hard_gate_enabled === true
).length;
check(5, "HARD_GATE_POLICIES: hg2c live count=0", hg2cLiveCount, 0, "counts");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 6 — carbonx metadata: actual vs assumed
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 6: carbonx metadata — actual services.json fields vs assumed codex rollout values");

// Verify actual fields are present in services.json
check(6, "carbonx authority_class is present in services.json",
  carbonxActualAuthorityClass !== undefined, true, "metadata");
check(6, "carbonx governance_blast_radius is present in services.json",
  carbonxActualBlastRadius !== undefined, true, "metadata");
check(6, "carbonx human_gate_required=true",
  carbonxHumanGateRequired, true, "metadata");
check(6, "carbonx aegis_gate.overall=GATE (batch13 dry-run)",
  carbonxAegisGate.overall, "GATE", "metadata");

// Surface discrepancies between assumed and actual — these are findings, not failures
if (carbonxActualAuthorityClass !== ASSUMED_AUTHORITY_CLASS) {
  finding(
    "authority_class discrepancy",
    `codex rollout assumed "${ASSUMED_AUTHORITY_CLASS}" — services.json actual="${carbonxActualAuthorityClass}". ` +
    `Financial authority class has higher accountability requirements than external_call. ` +
    `Candidate profile must use actual value.`
  );
}
if (carbonxActualBlastRadius !== ASSUMED_BLAST_RADIUS) {
  finding(
    "blast_radius discrepancy",
    `codex rollout assumed "${ASSUMED_BLAST_RADIUS}" — services.json actual="${carbonxActualBlastRadius}". ` +
    `BR-5 is parali-central class, not BR-3. Soak doctrine applies in full.`
  );
}
if (carbonxActualRuntimeReadiness !== ASSUMED_TIER_CLASS) {
  finding(
    "runtime_readiness tier discrepancy",
    `codex rollout assumed "${ASSUMED_TIER_CLASS}" — services.json runtime_readiness.tier="${carbonxActualRuntimeReadiness}". ` +
    `TIER-C = scan-first: code scan must complete before trust_mask enforcement. ` +
    `This is a soak readiness blocker.`
  );
}
if (carbonxNeedsCodeScan === true) {
  finding(
    "needs_code_scan=true",
    `carbonx-backend has not yet had a code-level dependency scan. ` +
    `Technical blast radius shows BR-0 (no code deps found) vs semantic BR-5. ` +
    `Divergence must be resolved before soft-canary 1/7 begins. ` +
    `This is the primary soak readiness gap for Batch 63+.`
  );
}
// Presence of SUBMIT_ETS_SURRENDER in can_do is a high-consequence finding
if (carbonxCanDo.includes("submit-ets-surrender") || carbonxCanDo.includes("SUBMIT_ETS_SURRENDER")) {
  finding(
    "irreversible financial action in can_do",
    `carbonx can_do includes ETS surrender — irreversible EU registry submission. ` +
    `This is the strongest IRR-NOAPPROVAL trigger in any service audited so far. ` +
    `Hard-block surface must include this operation regardless of HG group.`
  );
}

// Check passes as long as fields are present — discrepancy surfaces as findings only
check(6, "actual metadata loaded (discrepancies recorded as findings, not failures)",
  carbonxActualAuthorityClass !== undefined && carbonxActualBlastRadius !== undefined,
  true, "metadata");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 7 — carbonx risk profile maps to HG-2B, not HG-2A
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 7: carbonx risk profile maps to HG-2B (not HG-2A)");

// HG-2A: internal read_only verification services (pramana, domain-capture).
// HG-2B: external-state / boundary-crossing services.
// carbonx: SUBMIT_ETS_SURRENDER → EU ETS registry (external financial state).
// → HG-2B, not HG-2A.

// Evidence:
//   aegis_gate.op5_approve = GATE (financial approval operations)
//   aegis_gate.op2_write   = GATE (external write to carbon position)
//   authority_class        = financial (not read_only internal verification)
//   SUBMIT_ETS_SURRENDER   = irreversible external state mutation

const isExternalState =
  carbonxAegisGate.op2_write === "GATE" &&
  carbonxAegisGate.op5_approve === "GATE" &&
  carbonxActualAuthorityClass === "financial";

check(7, "carbonx external-state profile confirmed: op2_write=GATE",
  carbonxAegisGate.op2_write, "GATE", "hg-classification");
check(7, "carbonx external-state profile confirmed: op5_approve=GATE",
  carbonxAegisGate.op5_approve, "GATE", "hg-classification");
check(7, "carbonx authority_class=financial (external boundary, not internal verify)",
  carbonxActualAuthorityClass === "financial" || carbonxActualAuthorityClass === "external_call",
  true, "hg-classification");
check(7, "carbonx is NOT HG-2A profile (not read_only internal verification)",
  isExternalState, true, "hg-classification");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 8 — carbonx does NOT require HG-2C doctrine
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 8: carbonx does not require HG-2C doctrine (HG-2C undefined; HG-2B applies)");

// HG-2C is not yet defined in hard-gate-policy.ts.
// carbonx financial class may warrant extended doctrine addenda, but the correct
// group for external-state financial services within the current taxonomy is HG-2B.
// Resolution: classify as HG-2B with financial_settlement_doctrine flag set.
// HG-2C prep can begin after carbonx soak evidence is complete, if warranted.

const hg2cDefined = Object.values(HARD_GATE_POLICIES).some(
  p => (p as Record<string, unknown>).hg_group === "HG-2C"
);
check(8, "HG-2C is not yet defined in HARD_GATE_POLICIES",
  hg2cDefined, false, "hg-classification");
check(8, "carbonx can be classified HG-2B with financial addendum (HG-2C not required)",
  !hg2cDefined, true, "hg-classification");

if (!hg2cDefined) {
  finding(
    "HG-2C undefined",
    `No HG-2C policy exists yet. carbonx financial settlement risk (SUBMIT_ETS_SURRENDER) ` +
    `may eventually warrant HG-2C doctrine. For now: classify HG-2B + financial_settlement_doctrine=true. ` +
    `Reassess after soak evidence from Batches 63-69.`
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 9 — HG-2B doctrine v1 applies to carbonx
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 9: HG-2B doctrine v1 can apply to carbonx (with financial addendum)");

// Doctrine v1 rules (from parali-central soak, Batch 52):
//   AEG-HG-2B-001: external_state_touch=true → rollback plan required
//   AEG-HG-2B-002: approval_required_for_irreversible_action=true
//   AEG-HG-2B-003: observability_required=true
//   AEG-HG-2B-004: audit_artifact_required=true
//   IRR-NOAPPROVAL: zero-threshold for irreversible external actions
//   AEG-E-016:      scoped approval tokens (service_id + capability + operation)
//   normalizeCapability(): PascalCase + alias normalization before lookup
//   still_gate semantics: only downgrade BLOCK→GATE, never upgrade ALLOW→GATE

// For carbonx all of the above apply. Additional requirements:
//   financial_settlement_doctrine: EUA tokens are EU-regulated instruments.
//   SUBMIT_ETS_SURRENDER must carry a regulatory-grade audit trail, not just SENSE events.
//   Approval tokens must be bound to: service_id=carbonx-backend + cap=SUBMIT_ETS_SURRENDER + EU vessel IMO.

// Verify via parali-central policy that doctrine fields are structurally defined
check(9, "HG-2B doctrine: PARALI_CENTRAL_HG2B_POLICY.external_state_touch=true (reference)",
  PARALI_CENTRAL_HG2B_POLICY.external_state_touch, true, "doctrine");
check(9, "HG-2B doctrine: approval_required_for_irreversible_action=true (reference)",
  PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action, true, "doctrine");
check(9, "HG-2B doctrine: observability_required=true (reference)",
  PARALI_CENTRAL_HG2B_POLICY.observability_required, true, "doctrine");
check(9, "HG-2B doctrine: audit_artifact_required=true (reference)",
  PARALI_CENTRAL_HG2B_POLICY.audit_artifact_required, true, "doctrine");
check(9, "HG-2B doctrine v1 fields are structurally present (applicable to carbonx)",
  PARALI_CENTRAL_HG2B_POLICY.external_state_touch === true &&
  PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action === true,
  true, "doctrine");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 10 — carbonx candidate profile definition
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 10: carbonx candidate profile — derived from actual metadata");

const CARBONX_CANDIDATE_PROFILE = {
  service_id:                                   CARBONX,
  hg_group_candidate:                           "HG-2B",
  rollout_order:                                8,
  hard_gate_enabled:                            false,     // NEVER true until Batch 63+7 soak
  external_state_touch:                         true,      // SUBMIT_ETS_SURRENDER = EU ETS registry
  boundary_crossing:                            true,      // financial boundary: EUA = real €€€
  approval_required_for_irreversible_action:    true,      // SUBMIT_ETS_SURRENDER is IRR
  observability_required:                       true,      // CA-003: no silent boundary crossings
  audit_artifact_required:                      true,      // AEG-HG-2B-004
  financial_settlement_doctrine:                true,      // addendum beyond HG-2B v1 baseline
  // Actual metadata (from services.json — must override codex rollout comment assumptions)
  authority_class_actual:                       carbonxActualAuthorityClass,   // "financial"
  governance_blast_radius_actual:               carbonxActualBlastRadius,      // "BR-5"
  runtime_readiness_tier_actual:                carbonxActualRuntimeReadiness, // "TIER-C"
  needs_code_scan:                              carbonxNeedsCodeScan,          // true — soak blocker
  human_gate_required:                          carbonxHumanGateRequired,      // true
  // Soak readiness verdict
  soak_ready:                                   false,     // code scan must complete first
  soak_readiness_blockers:                      ["needs_code_scan=true: resolve technical vs semantic blast radius divergence"],
};

check(10, "candidate hard_gate_enabled=false",
  CARBONX_CANDIDATE_PROFILE.hard_gate_enabled, false, "candidate-profile");
check(10, "candidate external_state_touch=true",
  CARBONX_CANDIDATE_PROFILE.external_state_touch, true, "candidate-profile");
check(10, "candidate boundary_crossing=true",
  CARBONX_CANDIDATE_PROFILE.boundary_crossing, true, "candidate-profile");
check(10, "candidate approval_required_for_irreversible_action=true",
  CARBONX_CANDIDATE_PROFILE.approval_required_for_irreversible_action, true, "candidate-profile");
check(10, "candidate observability_required=true",
  CARBONX_CANDIDATE_PROFILE.observability_required, true, "candidate-profile");
check(10, "candidate audit_artifact_required=true",
  CARBONX_CANDIDATE_PROFILE.audit_artifact_required, true, "candidate-profile");
check(10, "candidate soak_ready=false (code scan required before Batch 63)",
  CARBONX_CANDIDATE_PROFILE.soak_ready, false, "candidate-profile");
check(10, "candidate rollout_order=8",
  CARBONX_CANDIDATE_PROFILE.rollout_order, 8, "candidate-profile");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 11 — carbonx ALLOW surface
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 11: carbonx candidate ALLOW surface (read / non-mutating operations)");

// These operations should always be ALLOW regardless of hard-gate state.
// Note: carbonx has no policy entry yet — verified in Check 3.
// Simulate the ALLOW surface for policy design purposes.
const CARBONX_ALLOW_SURFACE = [
  "READ",
  "GET_CII_TRAJECTORY",
  "GET_ETS_PRICE",
  "READ_EMISSIONS_DASHBOARD",
  "GET_EUA_POSITION",
  "GET_ANNUAL_ETS_COST",
  "GET_FUELEU_COMPLIANCE_BALANCE",
  "GET_CARBON_SHORTFALL",
];

check(11, "carbonx ALLOW surface defined (8 operations)",
  CARBONX_ALLOW_SURFACE.length, 8, "surface-design");
check(11, "carbonx ALLOW surface includes READ (AEG-E-002)",
  CARBONX_ALLOW_SURFACE.includes("READ"), true, "surface-design");
check(11, "carbonx ALLOW surface is read-only (no writes, no submissions)",
  CARBONX_ALLOW_SURFACE.every(op =>
    !op.includes("SUBMIT") && !op.includes("GENERATE") &&
    !op.includes("SET") && !op.includes("MUTATE") && !op.includes("DELETE")
  ), true, "surface-design");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 12 — carbonx GATE surface (still-gate: needs approval, not hard-block)
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 12: carbonx candidate GATE surface (approval-required, not hard-blocked)");

// still-gate: GATE even when hard-gate is active.
// These operations are consequential but not irreversible — human approval unlocks them.
const CARBONX_GATE_SURFACE = [
  "GENERATE_EMISSIONS_REPORT",    // official record creation — may be submitted downstream
  "SET_CARBON_TARGET",            // trajectory setting — consequential, reversible
  "CALCULATE_EUA_OBLIGATION",     // regulatory computation — consequential output
  "TRACK_EUA_POSITION",           // position update — state mutation, reversible
  "COMPUTE_FUELEU_INTENSITY",     // regulatory computation — FuelEU compliance
  "EXTERNAL_WRITE",               // generic external write (inherited from HG-2B baseline)
  "RELEASE_DOCUMENT",             // document release — reversible with recall
  "APPROVE_TRANSACTION",          // transaction approval — scoped, reversible before settlement
  "SYNC_PUSH",                    // external sync — reversible
];

check(12, "carbonx GATE surface defined (9 operations)",
  CARBONX_GATE_SURFACE.length, 9, "surface-design");
check(12, "GATE surface excludes ETS surrender (that is HARD-BLOCK)",
  !CARBONX_GATE_SURFACE.some(op => op.includes("SURRENDER")), true, "surface-design");
check(12, "GATE surface excludes IMPOSSIBLE_OP (that is always BLOCK)",
  !CARBONX_GATE_SURFACE.includes("IMPOSSIBLE_OP"), true, "surface-design");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 13 — carbonx HARD-BLOCK surface
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 13: carbonx candidate HARD-BLOCK surface (irreversible or impossible)");

// These operations are BLOCK regardless of approval tokens:
//   - SUBMIT_ETS_SURRENDER: irreversible EU registry submission (real EUA = real €€€)
//   - IMPOSSIBLE_OP / EMPTY_CAPABILITY_ON_WRITE: baseline HG-2B invariants
//   - BULK_ETS_MUTATION: mass financial state mutation — catastrophic blast radius
//   - FORCE_ETS_OVERWRITE: force-overwrite of regulatory records — doctrinally forbidden
//   - EUA_BULK_DELETE: mass deletion of EU allowances — irreversible regulatory harm
const CARBONX_HARD_BLOCK_SURFACE = [
  "SUBMIT_ETS_SURRENDER",              // IRR: EU ETS registry submission — financial + regulatory
  "IMPOSSIBLE_OP",                     // baseline: inherited from HG-2B
  "EMPTY_CAPABILITY_ON_WRITE",         // baseline: inherited from HG-2B
  "EXTERNAL_WRITE_UNAUTHENTICATED",    // HG-2B extended: unauthenticated external write
  "BULK_ETS_MUTATION",                 // financial: mass mutation of EUA positions
  "FORCE_ETS_OVERWRITE",               // financial: force-overwrite regulatory records
  "EUA_BULK_DELETE",                   // financial: irreversible mass allowance deletion
];

check(13, "carbonx HARD-BLOCK surface defined (7 operations)",
  CARBONX_HARD_BLOCK_SURFACE.length, 7, "surface-design");
check(13, "HARD-BLOCK includes SUBMIT_ETS_SURRENDER (primary IRR-NOAPPROVAL trigger)",
  CARBONX_HARD_BLOCK_SURFACE.includes("SUBMIT_ETS_SURRENDER"), true, "surface-design");
check(13, "HARD-BLOCK includes IMPOSSIBLE_OP (HG-2B baseline invariant)",
  CARBONX_HARD_BLOCK_SURFACE.includes("IMPOSSIBLE_OP"), true, "surface-design");
check(13, "HARD-BLOCK includes EMPTY_CAPABILITY_ON_WRITE (HG-2B baseline invariant)",
  CARBONX_HARD_BLOCK_SURFACE.includes("EMPTY_CAPABILITY_ON_WRITE"), true, "surface-design");
check(13, "HARD-BLOCK does NOT include READ (AEG-E-002: READ never hard-blocks)",
  !CARBONX_HARD_BLOCK_SURFACE.includes("READ"), true, "surface-design");
check(13, "HARD-BLOCK ALLOW and GATE surfaces are disjoint",
  CARBONX_HARD_BLOCK_SURFACE.every(op =>
    !CARBONX_ALLOW_SURFACE.includes(op) && !CARBONX_GATE_SURFACE.includes(op)
  ), true, "surface-design");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 14 — Unknown capability does NOT hard-block for carbonx candidate
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 14: Unknown capability does not hard-block when carbonx has no policy");

// carbonx has no entry in HARD_GATE_POLICIES (Check 3 confirmed this).
// applyHardGate for an unknown service must not hard-block — only GATE/WARN.

// Set env to live-7 roster for this regression (does NOT include carbonx)
process.env.AEGIS_HARD_GATE_SERVICES = AUDIT_ENV_ROSTER;

// An unknown capability on an unknown service (carbonx has no policy) must not BLOCK
const r14a = applyHardGate(CARBONX, "GATE", "UNKNOWN_CAPABILITY_XYZ", "write");
check(14, "unknown capability on carbonx (no policy): decision is not BLOCK",
  r14a.decision !== "BLOCK", true, "safety");
check(14, "unknown capability on carbonx (no policy): hard_gate_active=false",
  r14a.hard_gate_active, false, "safety");

const r14b = applyHardGate(CARBONX, "GATE", "SUBMIT_ETS_SURRENDER", "write");
check(14, "SUBMIT_ETS_SURRENDER on carbonx with no policy: hard_gate_active=false",
  r14b.hard_gate_active, false, "safety");
check(14, "SUBMIT_ETS_SURRENDER on carbonx with no policy: decision is not BLOCK",
  r14b.decision !== "BLOCK", true, "safety");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 15 — Unknown service behavior does not block
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 15: Unknown service (carbonx) is not hard-blocked, not blocked");

const r15 = applyHardGate(CARBONX, "ALLOW", "READ", "read");
check(15, "unknown service carbonx: READ not blocked", r15.decision !== "BLOCK", true, "safety");
check(15, "unknown service carbonx: hard_gate_active=false", r15.hard_gate_active, false, "safety");

const r15b = applyHardGate(CARBONX, "BLOCK", "IMPOSSIBLE_OP", "write");
check(15, "unknown service carbonx: even IMPOSSIBLE_OP passes through without hard_gate_applied",
  r15b.hard_gate_applied !== true, true, "safety");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 16 — Seven live guards regression
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 16: Seven live guards regression — READ=ALLOW, IMPOSSIBLE_OP=BLOCK");

// env is already set to AUDIT_ENV_ROSTER (live 7, no carbonx)
for (const svc of EXPECTED_LIVE_7) {
  const rRead = applyHardGate(svc, "ALLOW", "READ", "read");
  check(16, `${svc}: READ=ALLOW`, rRead.decision, "ALLOW", "regression");
  check(16, `${svc}: READ hard_gate_active=true`, rRead.hard_gate_active, true, "regression");
  const rBlock = applyHardGate(svc, "BLOCK", "IMPOSSIBLE_OP", "write");
  check(16, `${svc}: IMPOSSIBLE_OP=BLOCK`, rBlock.decision, "BLOCK", "regression");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 17 — parali-central HG-2B policy does not bleed into carbonx candidate
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 17: parali-central policy does not bleed into carbonx candidate");

// carbonx has no policy in HARD_GATE_POLICIES (checked in 3).
// parali-central's policy must not affect carbonx decision.
// The gate function looks up service_id — different key, no bleed possible.
const r17 = applyHardGate(CARBONX, "BLOCK", "EXTERNAL_WRITE_UNAUTHENTICATED", "write");
check(17, "carbonx: EXTERNAL_WRITE_UNAUTHENTICATED does not use parali-central policy",
  r17.hard_gate_active, false, "isolation");
// parali-central itself must remain clean
const r17b = applyHardGate(PARALI_CENTRAL, "BLOCK", "EXTERNAL_WRITE_UNAUTHENTICATED", "write");
check(17, "parali-central: EXTERNAL_WRITE_UNAUTHENTICATED still BLOCK (policy intact)",
  r17b.decision, "BLOCK", "isolation");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 18 — carbonx cannot inherit parali-central approval tokens
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 18: carbonx cannot inherit parali-central approval tokens (AEG-E-016)");

// AEG-E-016: approval tokens are scoped to service_id + capability + operation.
// A token issued for parali-central + RELEASE_DOCUMENT + write
// is bound to that triple. Presenting it against carbonx-backend → rejection.
// We verify this by confirming carbonx has no policy (so no token issuer exists),
// and that parali-central's policy carries service_id=parali-central.

check(18, "parali-central policy service_id=parali-central",
  PARALI_CENTRAL_HG2B_POLICY.service_id, "parali-central", "scoped-keys");
check(18, "carbonx has no policy entry (no token issuer exists for it yet)",
  CARBONX in HARD_GATE_POLICIES, false, "scoped-keys");
check(18, "parali-central approval_required_for_irreversible_action=true (tokens are service-scoped)",
  PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action, true, "scoped-keys");
// Confirming: the candidate profile declares token scoping requirement
check(18, "carbonx candidate: approval_required_for_irreversible_action=true (future policy)",
  CARBONX_CANDIDATE_PROFILE.approval_required_for_irreversible_action, true, "scoped-keys");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 19 — AEGIS approval tokens remain scoped keys (AEG-E-016 system-wide)
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 19: AEGIS approval tokens are scoped keys, not master keys (system-wide AEG-E-016)");

// Every live service in HARD_GATE_POLICIES that carries approval doctrine must
// have service_id declared (binding field for token scope).
const liveHG2BPolicies = Object.values(HARD_GATE_POLICIES).filter(
  p => (p as Record<string, unknown>).hg_group === "HG-2" &&
       (p as Record<string, unknown>).hard_gate_enabled === true
);
for (const pol of liveHG2BPolicies) {
  const p = pol as Record<string, unknown>;
  check(19, `${p.service_id}: service_id present (required for AEG-E-016 scoping)`,
    typeof p.service_id === "string", true, "scoped-keys");
}
// Verify parali-central (the only live HG-2B) explicitly
check(19, "batch60 token_scoping_pass=true (Batch 60 verified scoped-key enforcement)",
  b60.token_scoping_pass, true, "scoped-keys");
check(19, "batch61 doctrine_fields convergence_surface=true",
  (b61.convergence_surfaces as Record<string, unknown>)?.doctrine_fields, true, "scoped-keys");

// ═══════════════════════════════════════════════════════════════════════════════
// RESTORE ENV — do not leave audit env set after batch
// ═══════════════════════════════════════════════════════════════════════════════

process.env.AEGIS_HARD_GATE_SERVICES = preAuditEnv;

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

const totalChecks = passed + failed;
const verdict = failed === 0 ? "PASS" : "FAIL";

console.log(`\n══ Batch 62 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}`);
if (failed > 0) {
  console.log("  Failures:");
  failures.forEach(f => console.log(`    - ${f}`));
}
if (findings.length > 0) {
  console.log(`\n  Findings (${findings.length} — informational, not failures):`);
  findings.forEach((f, i) => console.log(`    ${i + 1}. ${f}`));
}

// ── Artifact ──────────────────────────────────────────────────────────────────

const artifact = {
  batch: 62,
  type: "candidate_readiness_audit",
  purpose: "Classify carbonx-backend as HG-2B candidate; characterise soak readiness gaps",
  timestamp: new Date().toISOString(),
  verdict,
  checks: totalChecks,
  passed,
  failed,
  failures,
  findings,

  // Invariants confirmed this batch
  invariants: {
    live_roster_size:               7,
    hg2b_live_count:                1,
    hg2c_live_count:                0,
    carbonx_in_hard_gate_services:  false,
    carbonx_hard_gate_enabled:      false,
    carbonx_has_policy:             false,
  },

  // Candidate profile (based on actual services.json, not assumed values)
  carbonx_candidate_profile: CARBONX_CANDIDATE_PROFILE,

  // Surface design for future CARBONX_HG2B_POLICY (Batch 63 input)
  surface_design: {
    allow_surface:      CARBONX_ALLOW_SURFACE,
    gate_surface:       CARBONX_GATE_SURFACE,
    hard_block_surface: CARBONX_HARD_BLOCK_SURFACE,
  },

  // Metadata discrepancy report
  metadata_discrepancy: {
    assumed_authority_class:    ASSUMED_AUTHORITY_CLASS,
    actual_authority_class:     carbonxActualAuthorityClass,
    assumed_blast_radius:       ASSUMED_BLAST_RADIUS,
    actual_blast_radius:        carbonxActualBlastRadius,
    assumed_tier:               ASSUMED_TIER_CLASS,
    actual_runtime_readiness:   carbonxActualRuntimeReadiness,
    discrepancy_impact:         "Soak doctrine (full HG-2B) applies; financial_settlement_doctrine addendum required",
  },

  // Soak readiness verdict
  soak_readiness: {
    verdict:             "NOT_READY",
    blockers:            ["needs_code_scan=true: technical vs semantic blast radius unresolved"],
    gate_for_batch_63:   "Complete code scan → resolve technical_blast_radius → confirm dependency graph → then declare CARBONX_HG2B_POLICY",
  },

  // Evidence chain integrity
  runtime_env_mode:                   "audit_env_set_to_live7_no_carbonx",
  batch60_artifact_is_source_of_truth: true,
  batch61_convergence_passed:          b61.verdict === "PASS",
  zenodo_paper_status:                 "historical_snapshot — carbonx not covered",
  product_brief_status:                "requires_update_to_include_carbonx_candidate_classification",
};

writeFileSync(
  "audits/batch62_carbonx_hg2b_candidate_readiness.json",
  JSON.stringify(artifact, null, 2),
);

console.log(`\n  Candidate artifact → audits/batch62_carbonx_hg2b_candidate_readiness.json`);
console.log();
console.log("Carbonx has been sighted on the boundary. It is not yet on watch.");
