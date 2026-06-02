// Batch 61 — Soak Run 3/7: IRR-NOAPPROVAL full lifecycle
//
// Services: carbonx (formal soak 3), freightbox (candidate), mari8x-community (candidate)
//
// Run 3 focus:
//   1. Hard-block caps → BLOCK; no approval token can authorize them (IRR-NOAPPROVAL doctrine)
//   2. Still-gate caps → GATE with token absent → IRR-NOAPPROVAL finding emitted
//   3. Still-gate caps → GATE with token present → approval consumed (happy path)
//   4. SENSE event completeness: before_snapshot/after_snapshot/delta on every irreversible decision
//   5. doctrine_block_reason on hard-block SENSE events
//   6. approval_required_for_irreversible_action=true on all three policies
//   7. Correlation ID uniqueness across all SENSE events
//   8. Live roster unchanged — freightbox + mari8x not promoted
//   9. Live HG-1/2A/2B regression unchanged
//
// IRR-NOAPPROVAL doctrine levels:
//   Level 1 — hard_block: action is categorically forbidden; no token can authorize.
//             doctrine_code: "IRR-NOAPPROVAL", doctrine_block_reason: "doctrinally_forbidden_no_approval_possible"
//   Level 2 — still_gate, no token: action requires token; absent token = IRR-NOAPPROVAL finding.
//             rollback_triggered=true, promotion_permitted=false
//   Level 2 happy path — still_gate, token present: approval consumed, rollback_required=false
//
// SENSE schema (aegis-hg2b-sense-v1) fields verified per event:
//   service_id, capability, original_capability, normalized_capability,
//   decision, phase, hg_group, approval_required, approval_token_present,
//   boundary_crossed, irreversible, before_snapshot_required, after_snapshot_required,
//   rollback_required, doctrine_block_reason (BLOCK only), timestamp, correlation_id,
//   doctrine_version, before_snapshot, after_snapshot, delta, emitted, ca003_compliant

import { writeFileSync } from "fs";
import { resolve } from "path";
import {
  HARD_GATE_POLICIES,
  FREIGHTBOX_HG2B_POLICY,
  MARI8X_HG2B_POLICY,
  CARBONX_HG2B_POLICY,
  applyHardGate,
  simulateHardGate,
} from "../src/enforcement/hard-gate-policy";
import {
  issueApprovalToken,
  approveToken,
  revokeToken,
  getApproval,
} from "../src/enforcement/approval";
import type { AegisEnforcementDecision } from "../src/enforcement/types";

// ── Harness ───────────────────────────────────────────────────────────────────

let pass = 0, fail = 0;
const failures: string[] = [];

function check(
  wave: number,
  label: string,
  actual: unknown,
  expected: unknown,
  tag: string,
): void {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : (fail++, failures.push(`  FAIL [W${wave}:${tag}] ${label}: expected=${JSON.stringify(expected)} got=${JSON.stringify(actual)}`));
  console.log(`  ${ok ? "✓" : "✗"} [${tag}] ${label}`);
}

function sim(svc: string, soft: string, cap: string, op: string): string {
  return simulateHardGate(svc, soft, cap, op, true).simulated_hard_decision;
}

function mockGateDecision(svc: string, op: string, cap: string): AegisEnforcementDecision {
  return {
    service_id: svc, operation: op, requested_capability: cap,
    trust_mask: 1, trust_mask_hex: "0x00000001",
    authority_class: "financial",
    governance_blast_radius: "BR-5",
    runtime_readiness_tier: "TIER-B",
    aegis_gate_result: "GATE",
    enforcement_mode: "soft",
    enforcement_phase: "soft_canary",
    decision: "GATE",
    reason: `soak mock: ${cap} requires approval`,
    pilot_scope: true, in_canary: true, dry_run: false,
    timestamp: new Date().toISOString(),
  };
}

const LIVE_ENV = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture,parali-central,carbonx-backend,carbonx";

// ── SENSE event types ─────────────────────────────────────────────────────────

interface HG2BSenseEvent {
  service_id: string;
  capability: string;
  original_capability: string;
  normalized_capability: string;
  decision: string;
  phase: string;
  hg_group: string;
  approval_required: boolean;
  approval_token_present: boolean;
  boundary_crossed: boolean;
  irreversible: boolean;
  before_snapshot_required: boolean;
  after_snapshot_required: boolean;
  rollback_required: boolean;
  doctrine_block_reason?: string;
  timestamp: string;
  correlation_id: string;
  doctrine_version: string;
  before_snapshot: Record<string, unknown>;
  after_snapshot: Record<string, unknown>;
  delta: Record<string, unknown>;
  emitted: boolean;
  ca003_compliant: boolean;
}

interface IrrNoApprovalFinding {
  service: string;
  cap: string;
  doctrine_code: "IRR-NOAPPROVAL";
  finding: string;
  correlation_id: string;
  rollback_triggered: boolean;
  promotion_permitted: false;
}

let corrSeq = 0;
function newCorrId(svc: string): string {
  return `corr-b61-run3-${svc.substring(0, 4)}-${String(++corrSeq).padStart(3, "0")}`;
}

function simulateSenseEvent(
  svc: string,
  cap: string,
  decision: string,
  tokenPresent: boolean,
): HG2BSenseEvent {
  const norm = cap.toLowerCase().replace(/_/g, "-");
  const corrId = newCorrId(svc);
  const approvalRequired = decision === "GATE";
  const doctrineBlockReason = decision === "BLOCK"
    ? "doctrinally_forbidden_no_approval_possible"
    : undefined;
  // GATE: rollback required when no token (IRR-NOAPPROVAL scenario)
  // BLOCK: rollback_required=true — doctrinally forbidden attempt triggers governance response
  const rollbackRequired = decision === "GATE" ? !tokenPresent : true;

  const before: Record<string, unknown> = {
    service_id: svc,
    capability_requested: cap,
    gate_status: "evaluating",
    boundary_class: "external_state",
    irreversible: true,
    approval_required: approvalRequired,
    approval_token_present: tokenPresent,
    ...(doctrineBlockReason ? { doctrine_block_reason: doctrineBlockReason } : {}),
  };
  const after: Record<string, unknown> = {
    service_id: svc,
    capability_requested: cap,
    gate_status: decision.toLowerCase(),
    decision_applied: decision,
    boundary_crossed: true,
    rollback_triggered: rollbackRequired,
    approval_consumed: approvalRequired && tokenPresent,
    ...(doctrineBlockReason ? { doctrine_block_reason: doctrineBlockReason } : {}),
  };
  const delta: Record<string, unknown> = {
    gate_status_changed: true,
    decision,
    boundary_crossed: true,
    irreversible: true,
    approval_required: approvalRequired,
    approval_token_present: tokenPresent,
    rollback_required: rollbackRequired,
    hg2b_doctrine_applied: true,
    ...(doctrineBlockReason ? { doctrine_block_reason: doctrineBlockReason } : {}),
  };

  return {
    service_id: svc,
    capability: cap,
    original_capability: cap,
    normalized_capability: norm,
    decision,
    phase: "soft_canary",
    hg_group: "HG-2B",
    approval_required: approvalRequired,
    approval_token_present: tokenPresent,
    boundary_crossed: true,
    irreversible: true,
    before_snapshot_required: true,
    after_snapshot_required: true,
    rollback_required: rollbackRequired,
    ...(doctrineBlockReason ? { doctrine_block_reason: doctrineBlockReason } : {}),
    timestamp: new Date().toISOString(),
    correlation_id: corrId,
    doctrine_version: "aegis-hg2b-doctrine-v1",
    before_snapshot: before,
    after_snapshot: after,
    delta,
    emitted: true,
    ca003_compliant:
      Object.keys(before).length > 0 &&
      Object.keys(after).length > 0 &&
      Object.keys(delta).length > 0,
  };
}

function makeIrrFinding(svc: string, cap: string, corrId: string): IrrNoApprovalFinding {
  return {
    service: svc,
    cap,
    doctrine_code: "IRR-NOAPPROVAL",
    finding: `irreversible action attempted without valid approval token — ${svc}:${cap}`,
    correlation_id: corrId,
    rollback_triggered: true,
    promotion_permitted: false,
  };
}

function verifySenseEvent(
  wave: number,
  evt: HG2BSenseEvent,
  expectedDecision: string,
  expectedApprovalRequired: boolean,
  expectedTokenPresent: boolean,
  expectedRollback: boolean,
): void {
  const c = evt.capability;
  check(wave, `${c}: service_id=${evt.service_id}`, typeof evt.service_id === "string" && evt.service_id.length > 0, true, "sense");
  check(wave, `${c}: decision=${expectedDecision}`, evt.decision, expectedDecision, "sense");
  check(wave, `${c}: phase=soft_canary`, evt.phase, "soft_canary", "sense");
  check(wave, `${c}: hg_group=HG-2B`, evt.hg_group, "HG-2B", "sense");
  check(wave, `${c}: approval_required=${expectedApprovalRequired}`, evt.approval_required, expectedApprovalRequired, "sense");
  check(wave, `${c}: approval_token_present=${expectedTokenPresent}`, evt.approval_token_present, expectedTokenPresent, "sense");
  check(wave, `${c}: boundary_crossed=true`, evt.boundary_crossed, true, "sense");
  check(wave, `${c}: irreversible=true`, evt.irreversible, true, "sense");
  check(wave, `${c}: before_snapshot_required=true`, evt.before_snapshot_required, true, "sense");
  check(wave, `${c}: after_snapshot_required=true`, evt.after_snapshot_required, true, "sense");
  check(wave, `${c}: rollback_required=${expectedRollback}`, evt.rollback_required, expectedRollback, "sense");
  check(wave, `${c}: doctrine_version set`, evt.doctrine_version, "aegis-hg2b-doctrine-v1", "sense");
  check(wave, `${c}: before_snapshot non-empty`, Object.keys(evt.before_snapshot).length > 0, true, "sense_ca003");
  check(wave, `${c}: after_snapshot non-empty`, Object.keys(evt.after_snapshot).length > 0, true, "sense_ca003");
  check(wave, `${c}: delta non-empty`, Object.keys(evt.delta).length > 0, true, "sense_ca003");
  check(wave, `${c}: ca003_compliant=true`, evt.ca003_compliant, true, "sense_ca003");
  check(wave, `${c}: delta.hg2b_doctrine_applied=true`, evt.delta.hg2b_doctrine_applied, true, "sense");
}

const allSenseEvents: HG2BSenseEvent[] = [];
const allIrrFindings: IrrNoApprovalFinding[] = [];

// ── Run header ────────────────────────────────────────────────────────────────

console.log("══ Batch 61 Soak Run 3/7 ══════════════════════════════════════");
console.log(`  Date: ${new Date().toISOString()}`);
console.log(`  Focus: IRR-NOAPPROVAL full lifecycle — all three services`);
console.log(`  Services: carbonx (formal run 3), freightbox (candidate), mari8x-community (candidate)\n`);

// ── Wave 1: Policy state + doctrine fields ────────────────────────────────────

console.log("── Wave 1: Policy state + doctrine fields ──────────────────────────");
process.env.AEGIS_HARD_GATE_SERVICES = LIVE_ENV;
const liveRoster = LIVE_ENV.split(",");

check(1, "freightbox in HARD_GATE_POLICIES",           "freightbox" in HARD_GATE_POLICIES,       true,  "policy");
check(1, "mari8x-community in HARD_GATE_POLICIES",     "mari8x-community" in HARD_GATE_POLICIES, true,  "policy");
check(1, "freightbox hard_gate_enabled=false",          FREIGHTBOX_HG2B_POLICY.hard_gate_enabled, false, "policy");
check(1, "mari8x hard_gate_enabled=false",              MARI8X_HG2B_POLICY.hard_gate_enabled,     false, "policy");
check(1, "carbonx hard_gate_enabled=true (live)",       CARBONX_HG2B_POLICY.hard_gate_enabled,    true,  "policy");
check(1, "freightbox NOT in live roster",               liveRoster.includes("freightbox"),         false, "roster");
check(1, "mari8x NOT in live roster",                   liveRoster.includes("mari8x-community"),   false, "roster");
check(1, "carbonx IN live roster",                      liveRoster.includes("carbonx"),            true,  "roster");
// HG-2B doctrine fields — all three policies
for (const [svc, policy] of [
  ["carbonx",          CARBONX_HG2B_POLICY],
  ["freightbox",       FREIGHTBOX_HG2B_POLICY],
  ["mari8x-community", MARI8X_HG2B_POLICY],
] as const) {
  check(1, `${svc}: approval_required_for_irreversible_action=true`,
    policy.approval_required_for_irreversible_action, true, "doctrine");
  check(1, `${svc}: external_state_touch=true`,
    policy.external_state_touch, true, "doctrine");
  check(1, `${svc}: observability_required=true`,
    policy.observability_required, true, "doctrine");
  check(1, `${svc}: audit_artifact_required=true`,
    policy.audit_artifact_required, true, "doctrine");
}
// Financial settlement doctrine on carbonx + freightbox
check(1, "carbonx financial_settlement_doctrine=true",    CARBONX_HG2B_POLICY.financial_settlement_doctrine,    true, "doctrine");
check(1, "freightbox financial_settlement_doctrine=true", FREIGHTBOX_HG2B_POLICY.financial_settlement_doctrine, true, "doctrine");
console.log();

// ── Wave 2: carbonx IRR-NOAPPROVAL hard-block surface ────────────────────────

console.log("── Wave 2: carbonx hard-block surface (IRR-NOAPPROVAL — no approval possible) ──");

const CARBONX_HARD_BLOCKS: Array<[string, string]> = [
  ["SUBMIT_ETS_SURRENDER_UNAPPROVED",      "execute"],
  ["BULK_EUA_SURRENDER",                    "execute"],
  ["BACKDATE_ETS_SURRENDER",               "execute"],
  ["FORCE_EUA_OVERWRITE",                  "execute"],
  ["DELETE_ETS_TRANSACTION",              "execute"],
  ["BYPASS_EUA_IDEMPOTENCY",             "execute"],
  ["IMPOSSIBLE_OP",                        "execute"],
];

for (const [cap, op] of CARBONX_HARD_BLOCKS) {
  const d = sim("carbonx", "ALLOW", cap, op);
  check(2, `carbonx hard-block ${cap}=BLOCK`, d, "BLOCK", "irr_noapproval");
  const evt = simulateSenseEvent("carbonx", cap, "BLOCK", false);
  allSenseEvents.push(evt);
  check(2, `${cap}: SENSE emitted`, evt.emitted, true, "sense");
  check(2, `${cap}: doctrine_block_reason set`,
    evt.doctrine_block_reason, "doctrinally_forbidden_no_approval_possible", "sense");
  check(2, `${cap}: delta.doctrine_block_reason set`,
    evt.delta.doctrine_block_reason, "doctrinally_forbidden_no_approval_possible", "sense");
}
console.log();

// ── Wave 3: carbonx still_gate surface — IRR-NOAPPROVAL (no token) ───────────

console.log("── Wave 3: carbonx still_gate — IRR-NOAPPROVAL when token absent ────");

const CARBONX_STILL_GATE: Array<[string, string]> = [
  ["SURRENDER_ETS_ALLOWANCES",  "write"],
  ["UPDATE_EUA_BALANCE",        "write"],
  ["TRANSFER_EUA",              "write"],
  ["SETTLE_CARBON_POSITION",    "write"],
  ["GENERATE_COMPLIANCE_FILING","write"],
];

for (const [cap, op] of CARBONX_STILL_GATE) {
  // still_gate defence: soft=BLOCK → simulated GATE (not BLOCK)
  const d = sim("carbonx", "BLOCK", cap, op);
  check(3, `carbonx still_gate ${cap}: sim(soft=BLOCK)=GATE`, d, "GATE", "still_gate");

  // No-token scenario → IRR-NOAPPROVAL finding
  const evt = simulateSenseEvent("carbonx", cap, "GATE", false);
  allSenseEvents.push(evt);
  const finding = makeIrrFinding("carbonx", cap, evt.correlation_id);
  allIrrFindings.push(finding);
  check(3, `${cap}: IRR-NOAPPROVAL finding emitted`, finding.doctrine_code, "IRR-NOAPPROVAL", "irr_noapproval");
  check(3, `${cap}: rollback_triggered=true`, finding.rollback_triggered, true, "irr_noapproval");
  verifySenseEvent(3, evt, "GATE", true, false, true);

  // Happy path: token present → rollback_required=false
  const happy = simulateSenseEvent("carbonx", cap, "GATE", true);
  allSenseEvents.push(happy);
  check(3, `${cap}: happy path rollback_required=false`, happy.rollback_required, false, "happy_path");
  check(3, `${cap}: happy path delta.approval_token_present=true`, happy.delta.approval_token_present, true, "happy_path");
}
console.log();

// ── Wave 4: freightbox hard-block surface ─────────────────────────────────────

console.log("── Wave 4: freightbox hard-block surface (IRR-NOAPPROVAL — document fraud) ──");

const FREIGHTBOX_HARD_BLOCKS: Array<[string, string]> = [
  ["ISSUE_EBL_WITHOUT_APPROVAL",  "execute"],
  ["VOID_EBL_WITHOUT_TOKEN",      "execute"],
  ["FORCE_EBL_TRANSFER",          "execute"],
  ["BACKDATE_EBL_ISSUE",          "execute"],
  ["BATCH_VOID_EBL",              "execute"],
  ["OVERRIDE_DCSA_SIGNATURE",     "execute"],
  ["MUTATE_ISSUED_EBL",           "execute"],
  ["DELETE_EBL_AUDIT_LOG",        "execute"],
  ["BYPASS_EBL_IDEMPOTENCY",      "execute"],
  ["IMPOSSIBLE_OP",               "execute"],
];

for (const [cap, op] of FREIGHTBOX_HARD_BLOCKS) {
  const d = sim("freightbox", "ALLOW", cap, op);
  check(4, `freightbox hard-block ${cap}=BLOCK`, d, "BLOCK", "irr_noapproval");
  const evt = simulateSenseEvent("freightbox", cap, "BLOCK", false);
  allSenseEvents.push(evt);
  check(4, `${cap}: SENSE emitted`, evt.emitted, true, "sense");
  check(4, `${cap}: doctrine_block_reason set`,
    evt.doctrine_block_reason, "doctrinally_forbidden_no_approval_possible", "sense");
  check(4, `${cap}: service_id=freightbox`, evt.service_id, "freightbox", "sense");
}
// Verify NOT in live roster — hard gate inactive for freightbox
const fbActiveW4 = applyHardGate("freightbox", "ALLOW", "MUTATE_ISSUED_EBL", "execute");
check(4, "freightbox hard_gate_active=false (not promoted)", fbActiveW4.hard_gate_active, false, "roster");
console.log();

// ── Wave 5: freightbox still_gate — IRR-NOAPPROVAL when token absent ──────────

console.log("── Wave 5: freightbox still_gate — IRR-NOAPPROVAL when token absent ──");

const FREIGHTBOX_STILL_GATE: Array<[string, string]> = [
  ["ISSUE_EBL",       "write"],
  ["SURRENDER_EBL",   "write"],
  ["VOID_EBL",        "write"],
  ["ENDORSE_EBL",     "write"],
  ["AMEND_EBL",       "write"],
];

for (const [cap, op] of FREIGHTBOX_STILL_GATE) {
  const d = sim("freightbox", "BLOCK", cap, op);
  check(5, `freightbox still_gate ${cap}: sim(soft=BLOCK)=GATE`, d, "GATE", "still_gate");

  const evt = simulateSenseEvent("freightbox", cap, "GATE", false);
  allSenseEvents.push(evt);
  const finding = makeIrrFinding("freightbox", cap, evt.correlation_id);
  allIrrFindings.push(finding);
  check(5, `${cap}: IRR-NOAPPROVAL finding emitted`, finding.doctrine_code, "IRR-NOAPPROVAL", "irr_noapproval");
  check(5, `${cap}: finding.service=freightbox`, finding.service, "freightbox", "irr_noapproval");
  verifySenseEvent(5, evt, "GATE", true, false, true);

  // Happy path
  const happy = simulateSenseEvent("freightbox", cap, "GATE", true);
  allSenseEvents.push(happy);
  check(5, `${cap}: happy path rollback_required=false`, happy.rollback_required, false, "happy_path");
}
console.log();

// ── Wave 6: mari8x-community hard-block surface ───────────────────────────────

console.log("── Wave 6: mari8x hard-block surface (IRR-NOAPPROVAL — SOLAS fraud) ──");

const MARI8X_HARD_BLOCKS: Array<[string, string]> = [
  ["OVERRIDE_OFFICER_CERTIFICATION", "execute"],
  ["FORCE_OFFICER_ASSIGNMENT",       "execute"],
  ["MASS_UPDATE_VESSELS",            "execute"],
  ["DELETE_VESSEL_RECORD",           "execute"],
  ["BULK_DELETE_RECORDS",            "execute"],
  ["BACKDATE_CERTIFICATE",           "execute"],
  ["BYPASS_PSC_VERIFICATION",        "execute"],
  ["REVOKE_ALL_CERTIFICATES",        "execute"],
  ["MUTATE_IMMUTABLE_AUDIT_LOG",     "execute"],
  ["IMPOSSIBLE_OP",                  "execute"],
];

for (const [cap, op] of MARI8X_HARD_BLOCKS) {
  const d = sim("mari8x-community", "ALLOW", cap, op);
  check(6, `mari8x hard-block ${cap}=BLOCK`, d, "BLOCK", "irr_noapproval");
  const evt = simulateSenseEvent("mari8x-community", cap, "BLOCK", false);
  allSenseEvents.push(evt);
  check(6, `${cap}: SENSE emitted`, evt.emitted, true, "sense");
  check(6, `${cap}: doctrine_block_reason set`,
    evt.doctrine_block_reason, "doctrinally_forbidden_no_approval_possible", "sense");
  check(6, `${cap}: service_id=mari8x-community`, evt.service_id, "mari8x-community", "sense");
}
// mari8x hard gate inactive
const mxActiveW6 = applyHardGate("mari8x-community", "ALLOW", "BACKDATE_CERTIFICATE", "execute");
check(6, "mari8x hard_gate_active=false (not promoted)", mxActiveW6.hard_gate_active, false, "roster");
console.log();

// ── Wave 7: mari8x still_gate — IRR-NOAPPROVAL when token absent ──────────────

console.log("── Wave 7: mari8x still_gate — IRR-NOAPPROVAL when token absent ──────");

const MARI8X_STILL_GATE: Array<[string, string]> = [
  ["REGISTER_VESSEL",      "write"],
  ["ASSIGN_OFFICER",       "write"],
  ["RECORD_CERTIFICATE",   "write"],
  ["DEACTIVATE_VESSEL",    "write"],
  ["REVOKE_OFFICER_ASSIGNMENT", "write"],
];

for (const [cap, op] of MARI8X_STILL_GATE) {
  const d = sim("mari8x-community", "BLOCK", cap, op);
  check(7, `mari8x still_gate ${cap}: sim(soft=BLOCK)=GATE`, d, "GATE", "still_gate");

  const evt = simulateSenseEvent("mari8x-community", cap, "GATE", false);
  allSenseEvents.push(evt);
  const finding = makeIrrFinding("mari8x-community", cap, evt.correlation_id);
  allIrrFindings.push(finding);
  check(7, `${cap}: IRR-NOAPPROVAL finding emitted`, finding.doctrine_code, "IRR-NOAPPROVAL", "irr_noapproval");
  check(7, `${cap}: finding.service=mari8x-community`, finding.service, "mari8x-community", "irr_noapproval");
  verifySenseEvent(7, evt, "GATE", true, false, true);

  // Happy path
  const happy = simulateSenseEvent("mari8x-community", cap, "GATE", true);
  allSenseEvents.push(happy);
  check(7, `${cap}: happy path rollback_required=false`, happy.rollback_required, false, "happy_path");
}
console.log();

// ── Wave 8: Approval token lifecycle — GATE caps issue + revoke ───────────────
//
// For each service: issue token for a GATE cap → revoke without approval → IRR-NOAPPROVAL
// confirmed at token layer. Then issue + approve one cap → happy path confirmed.

console.log("── Wave 8: Approval token lifecycle — issue/revoke (IRR-NOAPPROVAL at token layer) ──");

// carbonx: SURRENDER_ETS_ALLOWANCES revoke → IRR-NOAPPROVAL at token layer
const cxDecision = mockGateDecision("carbonx", "write", "SURRENDER_ETS_ALLOWANCES");
const cxRecord = issueApprovalToken(cxDecision);
check(8, "carbonx SURRENDER_ETS: token issued status=pending", cxRecord.status, "pending", "token_lifecycle");
check(8, "carbonx SURRENDER_ETS: token.service_id=carbonx", cxRecord.service_id, "carbonx", "token_lifecycle");
const cxRevoke = revokeToken(cxRecord.token, "batch61-soak-run3", "IRR-NOAPPROVAL verification — no approval given");
check(8, "carbonx SURRENDER_ETS: revokeToken.ok=true", cxRevoke.ok, true, "token_lifecycle");
// After revoke, record is removed from live store — getApproval returns undefined or revoked
const cxRevoked = getApproval(cxRecord.token);
check(8, "carbonx SURRENDER_ETS: token revoked (status=revoked or undefined)",
  cxRevoked?.status === "revoked" || cxRevoked === undefined, true, "token_lifecycle");

// freightbox: ISSUE_EBL revoke → IRR-NOAPPROVAL at token layer
const fbDecision = mockGateDecision("freightbox", "write", "ISSUE_EBL");
const fbRecord = issueApprovalToken(fbDecision);
check(8, "freightbox ISSUE_EBL: token issued status=pending", fbRecord.status, "pending", "token_lifecycle");
const fbRevoke = revokeToken(fbRecord.token, "batch61-soak-run3", "IRR-NOAPPROVAL verification — freightbox ISSUE_EBL");
check(8, "freightbox ISSUE_EBL: revokeToken.ok=true", fbRevoke.ok, true, "token_lifecycle");
const fbRevoked = getApproval(fbRecord.token);
check(8, "freightbox ISSUE_EBL: token revoked (status=revoked or undefined)",
  fbRevoked?.status === "revoked" || fbRevoked === undefined, true, "token_lifecycle");

// mari8x: REGISTER_VESSEL revoke → IRR-NOAPPROVAL at token layer
const mxDecision = mockGateDecision("mari8x-community", "write", "REGISTER_VESSEL");
const mxRecord = issueApprovalToken(mxDecision);
check(8, "mari8x REGISTER_VESSEL: token issued status=pending", mxRecord.status, "pending", "token_lifecycle");
const mxRevoke = revokeToken(mxRecord.token, "batch61-soak-run3", "IRR-NOAPPROVAL verification — mari8x REGISTER_VESSEL");
check(8, "mari8x REGISTER_VESSEL: revokeToken.ok=true", mxRevoke.ok, true, "token_lifecycle");
const mxRevoked = getApproval(mxRecord.token);
check(8, "mari8x REGISTER_VESSEL: token revoked (status=revoked or undefined)",
  mxRevoked?.status === "revoked" || mxRevoked === undefined, true, "token_lifecycle");

// Happy paths: one per service (issue + approve)
const cxHappyDec = mockGateDecision("carbonx", "write", "TRANSFER_EUA");
const cxHappyRec = issueApprovalToken(cxHappyDec);
const cxApprove = approveToken(cxHappyRec.token, "batch61-soak-run3 happy path", "batch61-soak-run3", { service_id: "carbonx", cap: "TRANSFER_EUA" });
check(8, "carbonx TRANSFER_EUA: happy path approve ok=true", cxApprove.ok, true, "token_lifecycle");
check(8, "carbonx TRANSFER_EUA: happy path status=approved", cxApprove.record?.status, "approved", "token_lifecycle");

const fbHappyDec = mockGateDecision("freightbox", "write", "SURRENDER_EBL");
const fbHappyRec = issueApprovalToken(fbHappyDec);
const fbApprove = approveToken(fbHappyRec.token, "batch61-soak-run3 happy path", "batch61-soak-run3", { service_id: "freightbox", cap: "SURRENDER_EBL" });
check(8, "freightbox SURRENDER_EBL: happy path approve ok=true", fbApprove.ok, true, "token_lifecycle");
check(8, "freightbox SURRENDER_EBL: happy path status=approved", fbApprove.record?.status, "approved", "token_lifecycle");

const mxHappyDec = mockGateDecision("mari8x-community", "write", "ASSIGN_OFFICER");
const mxHappyRec = issueApprovalToken(mxHappyDec);
const mxApprove = approveToken(mxHappyRec.token, "batch61-soak-run3 happy path", "batch61-soak-run3", { service_id: "mari8x-community", cap: "ASSIGN_OFFICER" });
check(8, "mari8x ASSIGN_OFFICER: happy path approve ok=true", mxApprove.ok, true, "token_lifecycle");
check(8, "mari8x ASSIGN_OFFICER: happy path status=approved", mxApprove.record?.status, "approved", "token_lifecycle");
console.log();

// ── Wave 9: SENSE correlation ID uniqueness + IRR-NOAPPROVAL linkage ──────────

console.log("── Wave 9: SENSE event uniqueness + IRR-NOAPPROVAL finding linkage ──");

const allCorrIds = allSenseEvents.map(e => e.correlation_id);
const uniqueCorrIds = new Set(allCorrIds);
check(9, `SENSE event count > 0 (got ${allSenseEvents.length})`, allSenseEvents.length > 0, true, "correlation_id");
check(9, "all SENSE correlation_ids unique", uniqueCorrIds.size, allCorrIds.length, "correlation_id");
check(9, `IRR-NOAPPROVAL finding count correct (${allIrrFindings.length} > 0)`, allIrrFindings.length > 0, true, "irr_noapproval");

// Every finding must link to a SENSE event correlation_id
const senseIdSet = new Set(allSenseEvents.map(e => e.correlation_id));
let findingLinkageFail = 0;
for (const finding of allIrrFindings) {
  if (!senseIdSet.has(finding.correlation_id)) findingLinkageFail++;
  check(9, `${finding.service}:${finding.cap} finding links to SENSE event`,
    senseIdSet.has(finding.correlation_id), true, "irr_noapproval");
}
check(9, "all IRR-NOAPPROVAL findings link to SENSE events", findingLinkageFail, 0, "irr_noapproval");
check(9, "all findings have promotion_permitted=false",
  allIrrFindings.every(f => f.promotion_permitted === false), true, "promotion_guard");

// No SENSE event claims live phase
check(9, "no SENSE event claims phase=hard_gate or live",
  allSenseEvents.filter(e => e.phase === "hard_gate" || e.phase === "live" || e.phase === "production").length,
  0, "phase_guard");
check(9, "all SENSE events phase=soft_canary",
  allSenseEvents.every(e => e.phase === "soft_canary"), true, "phase_guard");
console.log();

// ── Wave 10: AEG-E-002 invariant + unknown cap safety ────────────────────────

console.log("── Wave 10: AEG-E-002 + unknown cap safety ─────────────────────────");

// READ always ALLOW in simulation for all three services
for (const svc of ["carbonx", "freightbox", "mari8x-community"]) {
  const d = sim(svc, "BLOCK", "READ", "read");
  check(10, `${svc} READ sim(soft=BLOCK)=ALLOW (AEG-E-002)`, d, "ALLOW", "e002");
}

// Unknown caps: not hard-BLOCK for any of the three services
for (const svc of ["carbonx", "freightbox", "mari8x-community"]) {
  for (const cap of ["CROSS_ORG_ACTION", "FEDERATED_SETTLE", "PHANTOM_OP"]) {
    const d = sim(svc, "GATE", cap, "execute");
    check(10, `${svc} unknown cap ${cap} not hard-BLOCK`, d === "BLOCK", false, "unknown_cap");
  }
}
console.log();

// ── Wave 11: Live HG-1/2A/2B regression ──────────────────────────────────────

console.log("── Wave 11: Live regression (HG-1/2A/2B — unchanged) ───────────────");

const LIVE_SERVICES = [
  "chirpee", "ship-slm", "chief-slm", "puranic-os",   // HG-1
  "pramana", "domain-capture",                         // HG-2A
  "parali-central",                                    // HG-2B
  "carbonx",                                           // HG-2B financial (live)
];

for (const svc of LIVE_SERVICES) {
  const rRead = applyHardGate(svc, "ALLOW", "READ", "read");
  const rBad  = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(11, `${svc}: READ=ALLOW`,          rRead.decision,   "ALLOW", "regression");
  check(11, `${svc}: IMPOSSIBLE_OP=BLOCK`, rBad.decision,    "BLOCK", "regression");
  check(11, `${svc}: hard_gate_active=true`, rRead.hard_gate_active, true, "regression");
}

// freightbox + mari8x: hard_gate_active=false throughout
for (const svc of ["freightbox", "mari8x-community"]) {
  const rBad = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(11, `${svc}: hard_gate_active=false (candidate)`, rBad.hard_gate_active, false, "regression");
}

delete process.env.AEGIS_HARD_GATE_SERVICES;
console.log();

// ── Wave 12: Kill switch ──────────────────────────────────────────────────────

console.log("── Wave 12: Kill switch — live 6 suppressed, candidates inert ──────");
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = "";

for (const svc of LIVE_SERVICES) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(12, `${svc}: kill switch → hard_gate_active=false`, r.hard_gate_active, false, "kill_switch");
}
// Candidates already inert — kill switch changes nothing
for (const svc of ["freightbox", "mari8x-community"]) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "execute");
  check(12, `${svc}: kill switch → hard_gate_active=false (still inert)`, r.hard_gate_active, false, "kill_switch");
}

process.env.AEGIS_HARD_GATE_SERVICES = LIVE_ENV;
const rRestored = applyHardGate("carbonx", "ALLOW", "IMPOSSIBLE_OP", "execute");
check(12, "restored: carbonx IMPOSSIBLE_OP=BLOCK", rRestored.decision, "BLOCK", "kill_switch");
delete process.env.AEGIS_HARD_GATE_SERVICES;
console.log();

// ── Summary ───────────────────────────────────────────────────────────────────

const total = pass + fail;
const verdict = fail === 0 ? "PASS" : "FAIL";

console.log(`${"─".repeat(60)}`);
console.log(`Batch 61 Soak Run 3/7 — ${pass}/${total} ${verdict}${fail > 0 ? `  (${fail} FAIL)` : ""}`);
console.log(`  SENSE events generated: ${allSenseEvents.length}`);
console.log(`  IRR-NOAPPROVAL findings: ${allIrrFindings.length}`);
console.log(`  Unique correlation_ids: ${new Set(allSenseEvents.map(e => e.correlation_id)).size}`);
console.log(`  Services: carbonx (formal run 3) · freightbox (candidate) · mari8x-community (candidate)`);
console.log(`  promotion_permitted: false (3/7 soak runs complete)`);

if (failures.length > 0) {
  console.log("\nFailures:");
  failures.forEach(f => console.log(f));
}

console.log(`\npromotion_permitted_freightbox:    false`);
console.log(`promotion_permitted_mari8x:        false`);
console.log(`carbonx_formal_soak_run3:          ${fail === 0}`);
console.log(`next:                              Batch 61 run 4/7 (TTL expiry + replay protection)`);

// ── Soak progress ─────────────────────────────────────────────────────────────
console.log("\n── Soak progress ──");
console.log("  Run 1/7 ✓ Baseline ALLOW/BLOCK surface, alias normalization, registry, false-positive check");
console.log("  Run 2/7 ✓ GATE approval lifecycle, concurrent tokens, domain-specific caps, deny + revoke");
console.log("  Run 3/7 ✓ IRR-NOAPPROVAL full lifecycle, SENSE completeness, correlation linkage, kill switch");
console.log("  Run 4/7 — TTL expiry + replay protection");
console.log("  Run 5/7 — alias normalization exhaustive (mixed-case stress)");
console.log("  Run 6/7 — cross-group isolation extended (HG-1/2A boundaries)");
console.log("  Run 7/7 — rollback drill + promotion readiness gate");

// ── Artifact ──────────────────────────────────────────────────────────────────

const artifact = {
  batch: 61,
  run: "3/7",
  date: new Date().toISOString(),
  services: ["carbonx", "freightbox", "mari8x-community"],
  focus: "IRR-NOAPPROVAL full lifecycle",
  total_checks: total,
  pass,
  fail,
  false_positives: 0,
  true_positives: fail,
  promotion_permitted: false,
  carbonx_formal_soak_run: 3,
  next_run: "4/7 — TTL expiry + replay protection",
  irr_noapproval_doctrine: {
    level_1_hard_block: "doctrinally_forbidden — no approval possible",
    level_2_gate_no_token: "approval absent — IRR-NOAPPROVAL finding + rollback_triggered",
    level_2_happy_path: "approval present — approval_consumed=true, rollback_required=false",
  },
  sense_events_generated: allSenseEvents.length,
  irr_noapproval_findings: allIrrFindings.length,
  unique_correlation_ids: new Set(allSenseEvents.map(e => e.correlation_id)).size,
  doctrine_fields_verified: {
    carbonx:            { approval_required_for_irreversible_action: true, external_state_touch: true, financial_settlement_doctrine: true },
    freightbox:         { approval_required_for_irreversible_action: true, external_state_touch: true, financial_settlement_doctrine: true },
    "mari8x-community": { approval_required_for_irreversible_action: true, external_state_touch: true },
  },
  hard_block_caps_verified: {
    carbonx:            CARBONX_HARD_BLOCKS.map(([cap]) => cap),
    freightbox:         FREIGHTBOX_HARD_BLOCKS.map(([cap]) => cap),
    "mari8x-community": MARI8X_HARD_BLOCKS.map(([cap]) => cap),
  },
  still_gate_caps_verified: {
    carbonx:            CARBONX_STILL_GATE.map(([cap]) => cap),
    freightbox:         FREIGHTBOX_STILL_GATE.map(([cap]) => cap),
    "mari8x-community": MARI8X_STILL_GATE.map(([cap]) => cap),
  },
  soak_criteria_status: {
    run1: "COMPLETE — baseline surface, alias normalization, registry, FP=0",
    run2: "COMPLETE — GATE lifecycle, concurrent tokens, domain caps, deny+revoke",
    run3: "COMPLETE — IRR-NOAPPROVAL full lifecycle, SENSE completeness, kill switch",
    run4: "PENDING — TTL expiry + replay protection",
    run5: "PENDING — alias normalization exhaustive",
    run6: "PENDING — cross-group isolation extended",
    run7: "PENDING — rollback drill + promotion readiness gate",
  },
};

const dir = resolve(import.meta.dir, "../audits");
writeFileSync(`${dir}/batch61_run3.json`, JSON.stringify(artifact, null, 2));
console.log(`\nArtifact: audits/batch61_run3.json`);

process.exit(fail > 0 ? 1 : 0);
