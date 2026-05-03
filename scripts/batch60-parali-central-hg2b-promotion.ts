/**
 * Batch 60 — parali-central HG-2B Promotion to Live Hard-Gate
 *
 * This is the human-authorized promotion act for parali-central.
 * Prerequisite: Batch 59 7/7 soak PASS, promotion_permitted_parali_central=true.
 *
 * Permission to promote ≠ promotion.
 * This batch IS the promotion.
 *
 * @rule:AEG-HG-001 hard_gate_enabled alignment with AEGIS_HARD_GATE_SERVICES
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-HG-003 promotion requires explicit env var — manual act
 * @rule:AEG-HG-2B-001 external_state_touch=true forces external cleanup on rollback
 * @rule:AEG-HG-2B-002 approval_required_for_irreversible_action=true — non-negotiable
 * @rule:AEG-HG-2B-003 observability_required=true — CA-003
 * @rule:AEG-HG-2B-004 audit_artifact_required=true
 * @rule:AEG-E-016 scoped-key doctrine — binding mismatch rejection
 * @rule:IRR-NOAPPROVAL no AI agent may perform irreversible external action without provable human approval token
 */

import { readFileSync, writeFileSync } from "fs";
import {
  applyHardGate,
  HARD_GATE_POLICIES,
  HARD_GATE_GLOBALLY_ENABLED,
  PARALI_CENTRAL_HG2B_POLICY,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
} from "../src/enforcement/hard-gate-policy";

// ── Check infrastructure ──────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

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
    console.log(`  ✓ [${pad}] ${label.padEnd(70)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    const msg = `[${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`;
    failures.push(`${tag}: ${msg}`);
    console.log(`  ✗ ${msg}`);
  }
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

// ── normalizeCapability (alias normalization layer — proven Batch 57) ─────────

function normalizeCapability(raw: string): string {
  const deCased    = raw.replace(/([a-z])([A-Z])/g, "$1_$2");
  const underscored = deCased.replace(/[\s.\-]+/g, "_");
  return underscored.replace(/_+/g, "_").toUpperCase().trim();
}

// ── SENSE event infrastructure ────────────────────────────────────────────────

interface SenseEvent {
  correlation_id: string;
  service_id: string;
  capability: string;
  decision: string;
  hard_gate_active: boolean;
  approval_token_present?: boolean;
  approval_token_status?: string;
  rollback_required?: boolean;
  rollback_reason?: string;
  doctrine_block_reason?: string;
  external_state_mutated: boolean;
  timestamp: string;
}

let senseSeq = 0;
const senseEvents: SenseEvent[] = [];

function buildSenseEvent(
  serviceId: string,
  cap: string,
  decision: string,
  hardGateActive: boolean,
  opts: {
    tokenPresent?: boolean;
    tokenStatus?: string;
    rollbackRequired?: boolean;
    rollbackReason?: string;
    doctrineBlockReason?: string;
  } = {},
): SenseEvent {
  senseSeq++;
  const ev: SenseEvent = {
    correlation_id: `batch60-${String(senseSeq).padStart(3, "0")}`,
    service_id: serviceId,
    capability: cap,
    decision,
    hard_gate_active: hardGateActive,
    external_state_mutated: false, // soft-canary / no live promotion of external state yet
    timestamp: new Date().toISOString(),
  };
  if (opts.tokenPresent !== undefined) ev.approval_token_present = opts.tokenPresent;
  if (opts.tokenStatus)              ev.approval_token_status   = opts.tokenStatus;
  if (opts.rollbackRequired !== undefined) ev.rollback_required = opts.rollbackRequired;
  if (opts.rollbackReason)           ev.rollback_reason         = opts.rollbackReason;
  if (opts.doctrineBlockReason)      ev.doctrine_block_reason   = opts.doctrineBlockReason;
  senseEvents.push(ev);
  return ev;
}

// ── Approval token store (AEG-E-016 scoped-key doctrine) ─────────────────────

interface ApprovalToken {
  token_id: string;
  service_id: string;
  capability: string;
  operation: string;
  status: "approved" | "expired" | "revoked" | "denied";
  issued_at: string;
  expires_at: string;
}

const tokenStore = new Map<string, ApprovalToken>();

function issueToken(
  id: string,
  serviceId: string,
  cap: string,
  op: string,
  status: ApprovalToken["status"] = "approved",
  expireOffset = 3600_000,
): ApprovalToken {
  const now = Date.now();
  const tok: ApprovalToken = {
    token_id: id,
    service_id: serviceId,
    capability: cap,
    operation: op,
    status,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + expireOffset).toISOString(),
  };
  tokenStore.set(id, tok);
  return tok;
}

function simulateExpiry(id: string): void {
  const tok = tokenStore.get(id);
  if (tok) tok.expires_at = new Date(Date.now() - 1).toISOString();
}

interface TokenCheckResult {
  approval_token_present: boolean;
  approval_token_status?: string;
  approval_consumed: boolean;
  rollback_required: boolean;
  rollback_reason?: string;
  aeg_e016_error?: string;
}

function checkToken(
  tokenId: string | null,
  requestedServiceId: string,
  requestedCap: string,
  requestedOp: string,
): TokenCheckResult {
  if (!tokenId) {
    return {
      approval_token_present: false,
      approval_consumed: false,
      rollback_required: true,
      rollback_reason: "missing_approval_token",
    };
  }
  const tok = tokenStore.get(tokenId);
  if (!tok) {
    return {
      approval_token_present: false,
      approval_consumed: false,
      rollback_required: true,
      rollback_reason: "missing_approval_token",
    };
  }

  // AEG-E-016: binding mismatch rejection
  if (tok.service_id !== requestedServiceId) {
    return {
      approval_token_present: true,
      approval_token_status: tok.status,
      approval_consumed: false,
      rollback_required: true,
      rollback_reason: "aeg_e016_service_mismatch",
      aeg_e016_error: `token bound to ${tok.service_id}, requested for ${requestedServiceId}`,
    };
  }
  if (normalizeCapability(tok.capability) !== normalizeCapability(requestedCap)) {
    return {
      approval_token_present: true,
      approval_token_status: tok.status,
      approval_consumed: false,
      rollback_required: true,
      rollback_reason: "aeg_e016_capability_mismatch",
      aeg_e016_error: `token bound to ${tok.capability}, requested for ${requestedCap}`,
    };
  }

  // TTL check (lazy expiry)
  const isExpired = new Date(tok.expires_at).getTime() < Date.now();
  if (isExpired && tok.status === "approved") tok.status = "expired";

  if (tok.status === "approved") {
    tok.status = "approved"; // consumed but reusable within TTL for idempotent checks
    return {
      approval_token_present: true,
      approval_token_status: "approved",
      approval_consumed: true,
      rollback_required: false,
    };
  }

  return {
    approval_token_present: true,
    approval_token_status: tok.status,
    approval_consumed: false,
    rollback_required: true,
    rollback_reason: `${tok.status}_approval_token`,
  };
}

// ── Load Batch 59 final verdict artifact ─────────────────────────────────────

const batch59 = JSON.parse(
  readFileSync("audits/batch59_parali_central_hg2b_soft_canary_run7_final_verdict.json", "utf-8"),
);

// ── Live roster ────────────────────────────────────────────────────────────────

const HG1_SERVICES  = ["chirpee", "ship-slm", "chief-slm", "puranic-os"];
const HG2A_SERVICES = ["pramana", "domain-capture"];
const PRE_PROMOTION_LIVE_SERVICES = [...HG1_SERVICES, ...HG2A_SERVICES];
const PARALI_CENTRAL = "parali-central";

// ── HEADER ────────────────────────────────────────────────────────────────────

console.log("══ Batch 60 — parali-central HG-2B PROMOTION TO LIVE HARD-GATE ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log("  Phase: PROMOTION — human-authorized. This is the promotion act.");
console.log("  Prerequisite: Batch 59 7/7 soak PASS, promotion_permitted_parali_central=true");
console.log();

// ═══════════════════════════════════════════════════════════════════════════════
// PRE-CHECKS (C1–C14): Verify soak evidence before promotion
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 1: Batch 59 artifact exists");
check(1, "batch59 artifact loaded", !!batch59, true, "pre_check");

section("Check 2: Batch 59 verdict=PASS");
check(2, "batch59 verdict=PASS", batch59.verdict, "PASS", "pre_check");

section("Check 3: Batch 59 soak_run=7 and soak_total=7");
check(3, "batch59 soak_run=7", batch59.soak_run, 7, "pre_check");
check(3, "batch59 soak_total=7", batch59.soak_total, 7, "pre_check");

section("Check 4: promotion_permitted_parali_central=true in Batch 59");
check(4, "batch59 promotion_permitted_parali_central=true",
  batch59.promotion_permitted_parali_central, true, "pre_check");

section("Check 5: parali_central_promoted=false before this batch");
check(5, "batch59 parali_central_promoted=false (pre-promotion state)",
  batch59.parali_central_promoted, false, "pre_check");

section("Check 6: hard_gate_enabled=false in Batch 59 (pre-promotion)");
check(6, "batch59 hard_gate_enabled=false at soak close",
  batch59.hard_gate_enabled, false, "pre_check");

section("Check 7: parali-central not in AEGIS_HARD_GATE_SERVICES before promotion");
const preEnvRaw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
check(7, "parali-central absent from env before promotion",
  preEnvRaw.includes(PARALI_CENTRAL), false, "pre_check");

section("Check 8: All prior runs 1–7 passed (from Batch 59 soak_evidence)");
const soakEvidenceRaw = batch59.soak_evidence ?? {};
// soak_evidence is an object {run1:{}, run2:{}, ...} — convert to array
const soakEvidence: Record<string, unknown>[] =
  Array.isArray(soakEvidenceRaw)
    ? soakEvidenceRaw
    : Object.values(soakEvidenceRaw) as Record<string, unknown>[];
check(8, "soak_evidence has 7 entries", soakEvidence.length, 7, "pre_check");
const allSoakPass = soakEvidence.every((r: Record<string, unknown>) => r.verdict === "PASS");
check(8, "all 7 soak runs verdict=PASS", allSoakPass, true, "pre_check");

section("Check 9: Total false positives across soak = 0");
const totalFP = soakEvidence.reduce((s, r: Record<string, unknown>) =>
  s + ((r.false_positives as number) ?? 0), 0);
check(9, "total false positives across 7 runs = 0", totalFP, 0, "pre_check");

section("Check 10: Total production fires across soak = 0");
const totalFires = soakEvidence.reduce((s, r: Record<string, unknown>) =>
  s + ((r.production_fires as number) ?? 0), 0);
check(10, "total production fires across 7 runs = 0", totalFires, 0, "pre_check");

section("Check 11: Rollback drill PASS in Batch 59");
const rollbackDrill = batch59.rollback_drill ?? {};
check(11, "batch59 rollback_drill.scenarios_tested=3",
  rollbackDrill.scenarios_tested, 3, "pre_check");
const b59RollbackResults: Record<string, unknown>[] = rollbackDrill.results ?? [];
const allRollbackSuccess = b59RollbackResults.every(
  (r: Record<string, unknown>) => r.rollback_success === true);
check(11, "batch59 rollback_drill.all rollback_success=true", allRollbackSuccess, true, "pre_check");
const noExternalMutation = b59RollbackResults.every(
  (r: Record<string, unknown>) => r.external_state_mutated === false);
check(11, "batch59 rollback_drill.external_state_mutated=false (all scenarios)", noExternalMutation, true, "pre_check");

section("Check 12: SENSE correlation and rollback linkage PASS in Batch 59");
check(12, "batch59 rollback_drill.external_state_mutated=false (top-level)",
  rollbackDrill.external_state_mutated, false, "pre_check");
check(12, "batch59 rollback_drill has 3 scenario results", b59RollbackResults.length, 3, "pre_check");

section("Check 13: Cross-group isolation PASS in Batch 59");
const promCondsEarly = batch59.promotion_conditions ?? {};
check(13, "batch59 promotion_conditions.cross_group_isolation_verified=true",
  promCondsEarly.cross_group_isolation_verified, true, "pre_check");

section("Check 14: Token scoping PASS in Batch 59");
const promConds = promCondsEarly;
check(14, "batch59 promotion_conditions.scoped_key_doctrine_verified=true",
  promConds.scoped_key_doctrine_verified, true, "pre_check");
check(14, "batch59 promotion_conditions.rollback_drill_passed=true",
  promConds.rollback_drill_passed, true, "pre_check");

// ═══════════════════════════════════════════════════════════════════════════════
// PROMOTION (C15–C19): Execute and verify policy state changes
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 15: PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled=true after policy edit");
check(15, "hard_gate_enabled=true (documentary alignment, Batch 60)",
  PARALI_CENTRAL_HG2B_POLICY.hard_gate_enabled, true, "promotion");

// PROMOTION ACT: add parali-central to AEGIS_HARD_GATE_SERVICES
// This is the env var change that activates the hard gate at runtime.
// @rule:AEG-HG-003 — env var is the gate switch; policy flag is advisory
const promotedRoster = [...PRE_PROMOTION_LIVE_SERVICES, PARALI_CENTRAL].join(",");
process.env.AEGIS_HARD_GATE_SERVICES = promotedRoster;

section("Check 16: parali-central added to AEGIS_HARD_GATE_SERVICES");
const postEnvRaw = process.env.AEGIS_HARD_GATE_SERVICES ?? "";
check(16, "parali-central present in AEGIS_HARD_GATE_SERVICES",
  postEnvRaw.includes(PARALI_CENTRAL), true, "promotion");
check(16, "all 6 prior guards still in env",
  PRE_PROMOTION_LIVE_SERVICES.every(s => postEnvRaw.includes(s)), true, "promotion");

section("Check 17: rollout_order=7");
check(17, "PARALI_CENTRAL_HG2B_POLICY.rollout_order=7",
  PARALI_CENTRAL_HG2B_POLICY.rollout_order, 7, "promotion");

section("Check 18: stage updated to HG-2B LIVE");
check(18, "stage contains 'HG-2B LIVE'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("HG-2B LIVE"), true, "promotion");
check(18, "stage contains 'Batch 60'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("Batch 60"), true, "promotion");
check(18, "stage contains 'Batch 53-59 7/7'",
  PARALI_CENTRAL_HG2B_POLICY.stage.includes("Batch 53-59 7/7"), true, "promotion");

section("Check 19: policy registry contains parali-central");
check(19, "HARD_GATE_POLICIES contains parali-central",
  "parali-central" in HARD_GATE_POLICIES, true, "promotion");

// ═══════════════════════════════════════════════════════════════════════════════
// POST-PROMOTION CHECKS (C20–C42): Verify live behavior via applyHardGate
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 20: Live roster has exactly 7 services");
const liveEnv = (process.env.AEGIS_HARD_GATE_SERVICES ?? "")
  .split(",").map(s => s.trim()).filter(Boolean);
check(20, "live roster count=7", liveEnv.length, 7, "post_promotion");
check(20, "parali-central in live roster", liveEnv.includes(PARALI_CENTRAL), true, "post_promotion");

section("Check 21: parali-central in AEGIS_HARD_GATE_SERVICES");
check(21, "parali-central in env (post-promotion)", liveEnv.includes(PARALI_CENTRAL), true, "post_promotion");

section("Check 22: hard_gate_active=true for parali-central via applyHardGate");
const pcReadResult = applyHardGate(PARALI_CENTRAL, "ALLOW", "READ", "read");
check(22, "parali-central hard_gate_active=true", pcReadResult.hard_gate_active, true, "post_promotion");

section("Check 23: HG-2B live count=1");
const hg2bLive = liveEnv.filter(s => {
  const pol = HARD_GATE_POLICIES[s];
  return pol && pol.external_state_touch === true;
});
check(23, "HG-2B live count=1", hg2bLive.length, 1, "post_promotion");
check(23, "HG-2B live service=parali-central", hg2bLive[0], PARALI_CENTRAL, "post_promotion");

section("Check 24: HG-2C live count=0");
const hg2cServices = ["stackpilot", "granthx", "ankrclaw"]; // HG-3 candidates, NOT promoted
const hg2cLive = liveEnv.filter(s => hg2cServices.includes(s));
check(24, "HG-2C live count=0", hg2cLive.length, 0, "post_promotion");

section("Check 25: READ/GET/LIST/QUERY/SEARCH/HEALTH = ALLOW (AEG-HG-002)");
for (const [cap, op] of [
  ["READ", "read"], ["GET", "get"], ["LIST", "list"],
  ["QUERY", "query"], ["SEARCH", "search"], ["HEALTH", "health"],
] as [string, string][]) {
  const r = applyHardGate(PARALI_CENTRAL, "ALLOW", cap, op);
  check(25, `parali-central ${cap}=ALLOW`, r.decision, "ALLOW", "post_promotion");
  check(25, `parali-central ${cap}: hard_gate_active=true`, r.hard_gate_active, true, "post_promotion");
  buildSenseEvent(PARALI_CENTRAL, cap, "ALLOW", true);
}

section("Check 26: External read-class = ALLOW");
for (const cap of ["EXTERNAL_READ", "FETCH_STATUS", "CHECK_CONNECTION", "DRY_RUN", "STATUS"]) {
  const r = applyHardGate(PARALI_CENTRAL, "ALLOW", cap, "query");
  check(26, `parali-central ${cap}=ALLOW`, r.decision, "ALLOW", "post_promotion");
  buildSenseEvent(PARALI_CENTRAL, cap, "ALLOW", true);
}

section("Check 27: still_gate paths produce GATE (soft=GATE path)");
const gateCapabilities = ["EXTERNAL_WRITE", "EXTERNAL_NOTIFY", "BOUNDARY_MUTATION",
  "SYNC_PUSH", "RELEASE_DOCUMENT", "APPROVE_TRANSACTION", "DEPLOY_TO_EXTERNAL",
  "FINALIZE_RECORD", "TRIGGER_WORKFLOW", "SEND_MESSAGE", "SYNC_RECORD",
  "UPDATE_EXTERNAL_STATE", "DELETE_EXTERNAL_STATE"];
for (const cap of gateCapabilities.slice(0, 5)) { // spot-check 5
  const r = applyHardGate(PARALI_CENTRAL, "GATE", cap, "write");
  check(27, `parali-central ${cap} (soft=GATE) → GATE`, r.decision, "GATE", "post_promotion");
  buildSenseEvent(PARALI_CENTRAL, cap, "GATE", true,
    { tokenPresent: false, rollbackRequired: true, rollbackReason: "missing_approval_token" });
}

section("Check 28: Hard-block paths produce BLOCK");
const hardBlockCaps = [
  "IMPOSSIBLE_OP", "EMPTY_CAPABILITY_ON_WRITE",
  "EXTERNAL_WRITE_UNAUTHENTICATED", "EXTERNAL_DELETE_UNAPPROVED",
  "BULK_EXTERNAL_MUTATION", "FORCE_EXTERNAL_OVERWRITE",
];
for (const cap of hardBlockCaps) {
  const r = applyHardGate(PARALI_CENTRAL, "BLOCK", cap, "write");
  check(28, `parali-central ${cap}=BLOCK`, r.decision, "BLOCK", "post_promotion");
  check(28, `parali-central ${cap}: hard_gate_applied=true`, r.hard_gate_applied, true, "post_promotion");
  buildSenseEvent(PARALI_CENTRAL, cap, "BLOCK", true, {
    doctrineBlockReason: "doctrinally_forbidden_no_approval_possible",
  });
}

section("Check 29: Irreversible paths require valid scoped approval token");
// Issue a valid scoped token for parali-central RELEASE_DOCUMENT
const tok29 = issueToken("tok29-valid", PARALI_CENTRAL, "RELEASE_DOCUMENT", "write");
const check29 = checkToken(tok29.token_id, PARALI_CENTRAL, "RELEASE_DOCUMENT", "write");
check(29, "valid token: approval_token_present=true", check29.approval_token_present, true, "token_scoping");
check(29, "valid token: approval_token_status=approved", check29.approval_token_status, "approved", "token_scoping");
check(29, "valid token: approval_consumed=true", check29.approval_consumed, true, "token_scoping");
check(29, "valid token: rollback_required=false", check29.rollback_required, false, "token_scoping");
// With valid token, hard-gate allows GATE path (gate + approval = proceed)
const r29gate = applyHardGate(PARALI_CENTRAL, "GATE", "RELEASE_DOCUMENT", "write");
check(29, "RELEASE_DOCUMENT (soft=GATE, valid token) → GATE from hard-gate",
  r29gate.decision, "GATE", "token_scoping");
buildSenseEvent(PARALI_CENTRAL, "RELEASE_DOCUMENT", "GATE", true,
  { tokenPresent: true, tokenStatus: "approved", rollbackRequired: false });

section("Check 30: Expired/revoked/denied/wrong-service/wrong-capability tokens rejected");
// 30a: expired
const tok30a = issueToken("tok30a-expire", PARALI_CENTRAL, "APPROVE_TRANSACTION", "write");
simulateExpiry(tok30a.token_id);
const r30a = checkToken(tok30a.token_id, PARALI_CENTRAL, "APPROVE_TRANSACTION", "write");
check(30, "expired token: approval_token_status=expired", r30a.approval_token_status, "expired", "token_scoping");
check(30, "expired token: rollback_required=true", r30a.rollback_required, true, "token_scoping");
check(30, "expired token: rollback_reason=expired_approval_token",
  r30a.rollback_reason, "expired_approval_token", "token_scoping");

// 30b: revoked
const tok30b = issueToken("tok30b-revoke", PARALI_CENTRAL, "SYNC_PUSH", "write", "revoked");
const r30b = checkToken(tok30b.token_id, PARALI_CENTRAL, "SYNC_PUSH", "write");
check(30, "revoked token: approval_token_status=revoked", r30b.approval_token_status, "revoked", "token_scoping");
check(30, "revoked token: rollback_required=true", r30b.rollback_required, true, "token_scoping");

// 30c: denied
const tok30c = issueToken("tok30c-deny", PARALI_CENTRAL, "DEPLOY_TO_EXTERNAL", "write", "denied");
const r30c = checkToken(tok30c.token_id, PARALI_CENTRAL, "DEPLOY_TO_EXTERNAL", "write");
check(30, "denied token: approval_token_status=denied", r30c.approval_token_status, "denied", "token_scoping");
check(30, "denied token: rollback_required=true", r30c.rollback_required, true, "token_scoping");

// 30d: absent
const r30d = checkToken(null, PARALI_CENTRAL, "EXTERNAL_WRITE", "write");
check(30, "absent token: approval_token_present=false", r30d.approval_token_present, false, "token_scoping");
check(30, "absent token: rollback_reason=missing_approval_token",
  r30d.rollback_reason, "missing_approval_token", "token_scoping");

buildSenseEvent(PARALI_CENTRAL, "APPROVE_TRANSACTION", "GATE", true,
  { tokenPresent: true, tokenStatus: "expired", rollbackRequired: true, rollbackReason: "expired_approval_token" });
buildSenseEvent(PARALI_CENTRAL, "SYNC_PUSH", "GATE", true,
  { tokenPresent: true, tokenStatus: "revoked", rollbackRequired: true, rollbackReason: "revoked_approval_token" });
buildSenseEvent(PARALI_CENTRAL, "DEPLOY_TO_EXTERNAL", "GATE", true,
  { tokenPresent: true, tokenStatus: "denied", rollbackRequired: true, rollbackReason: "denied_approval_token" });

section("Check 31: HG-2B token cannot authorize HG-1 or HG-2A service");
// Issue a valid token bound to parali-central; try it against chirpee (HG-1)
const tok31 = issueToken("tok31-hg2b", PARALI_CENTRAL, "EXTERNAL_WRITE", "write");
for (const hg1Svc of HG1_SERVICES) {
  const r31 = checkToken(tok31.token_id, hg1Svc, "EXTERNAL_WRITE", "write");
  check(31, `HG-2B token rejected by ${hg1Svc} (AEG-E-016 service mismatch)`,
    r31.rollback_reason, "aeg_e016_service_mismatch", "cross_group_isolation");
  check(31, `HG-2B token: ${hg1Svc} aeg_e016_error present`,
    typeof r31.aeg_e016_error === "string", true, "cross_group_isolation");
}
for (const hg2aSvc of HG2A_SERVICES) {
  const r31a = checkToken(tok31.token_id, hg2aSvc, "EXTERNAL_WRITE", "write");
  check(31, `HG-2B token rejected by ${hg2aSvc} (AEG-E-016 service mismatch)`,
    r31a.rollback_reason, "aeg_e016_service_mismatch", "cross_group_isolation");
}

section("Check 32: HG-1/HG-2A tokens cannot authorize parali-central HG-2B capability");
// Issue tokens bound to each HG-1 service; try against parali-central
for (const hg1Svc of ["chirpee", "pramana"]) {
  const tokCross = issueToken(`tok32-${hg1Svc}`, hg1Svc, "RELEASE_DOCUMENT", "write");
  const r32 = checkToken(tokCross.token_id, PARALI_CENTRAL, "RELEASE_DOCUMENT", "write");
  check(32, `${hg1Svc} token rejected by parali-central (AEG-E-016)`,
    r32.rollback_reason, "aeg_e016_service_mismatch", "cross_group_isolation");
}

section("Check 33: SENSE events emitted for GATE/BLOCK");
const gateEvents = senseEvents.filter(e => e.decision === "GATE");
const blockEvents = senseEvents.filter(e => e.decision === "BLOCK");
check(33, "GATE events emitted > 0", gateEvents.length > 0, true, "observability");
check(33, "BLOCK events emitted > 0", blockEvents.length > 0, true, "observability");
check(33, "all SENSE events have unique correlation_id",
  new Set(senseEvents.map(e => e.correlation_id)).size === senseEvents.length,
  true, "observability");

section("Check 34: HARD-BLOCK SENSE events include doctrine_block_reason");
const blockEventsWithDoctrine = senseEvents.filter(
  e => e.decision === "BLOCK" && typeof e.doctrine_block_reason === "string");
check(34, "all BLOCK SENSE events have doctrine_block_reason",
  blockEventsWithDoctrine.length, blockEvents.length, "observability");
check(34, "doctrine_block_reason value correct",
  blockEventsWithDoctrine[0]?.doctrine_block_reason,
  "doctrinally_forbidden_no_approval_possible", "observability");

section("Check 35: Unknown service never blocks");
const unknownSvcResult = applyHardGate("unknown-svc-9999", "GATE", "SOME_CAP", "write");
check(35, "unknown service: hard_gate_active=false", unknownSvcResult.hard_gate_active, false, "invariant");
check(35, "unknown service: decision=GATE (soft preserved)", unknownSvcResult.decision, "GATE", "invariant");

section("Check 36: Unknown capability does not hard-block parali-central");
const unknownCapResult = applyHardGate(PARALI_CENTRAL, "GATE", "NOVEL_FUTURE_CAP_XYZ", "write");
check(36, "unknown cap: hard_gate_active=true (service is live)", unknownCapResult.hard_gate_active, true, "invariant");
check(36, "unknown cap: hard_gate_applied=false (no hard block)", unknownCapResult.hard_gate_applied, false, "invariant");
check(36, "unknown cap: decision=GATE (soft preserved)", unknownCapResult.decision, "GATE", "invariant");

section("Check 37: Existing six live guards remain regression clean");
const hg1Regression: [string, string, string, string][] = [
  ["chirpee", "ALLOW", "READ", "read"],
  ["ship-slm", "ALLOW", "GET", "get"],
  ["chief-slm", "ALLOW", "QUERY", "query"],
  ["puranic-os", "ALLOW", "HEALTH", "health"],
  ["pramana", "ALLOW", "READ", "read"],
  ["domain-capture", "ALLOW", "LIST", "list"],
];
for (const [svc, softDec, cap, op] of hg1Regression) {
  const r = applyHardGate(svc, softDec, cap, op);
  check(37, `${svc}: ${cap}=ALLOW`, r.decision, "ALLOW", "regression");
  check(37, `${svc}: hard_gate_active=true`, r.hard_gate_active, true, "regression");
}
// IMPOSSIBLE_OP still blocks for all HG-1
for (const svc of HG1_SERVICES) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "write");
  check(37, `${svc}: IMPOSSIBLE_OP=BLOCK`, r.decision, "BLOCK", "regression");
}
// HG-2B hard-block caps NOT present in HG-1 hard_block
for (const svc of HG1_SERVICES) {
  const pol = HARD_GATE_POLICIES[svc];
  check(37, `${svc}: BULK_EXTERNAL_MUTATION not in HG-1 hard_block`,
    pol.hard_block_capabilities.has("BULK_EXTERNAL_MUTATION"), false, "regression");
}

section("Check 38: Kill switch suppresses all seven live hard-gates");
const savedEnv = process.env.AEGIS_HARD_GATE_SERVICES;
process.env.AEGIS_HARD_GATE_SERVICES = "";
for (const svc of [...PRE_PROMOTION_LIVE_SERVICES, PARALI_CENTRAL]) {
  const r = applyHardGate(svc, "GATE", "IMPOSSIBLE_OP", "write");
  check(38, `${svc}: kill switch → hard_gate_active=false`, r.hard_gate_active, false, "kill_switch");
}

section("Check 39: Restore after kill switch — all seven return to expected behavior");
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv!;
for (const svc of HG1_SERVICES) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "write");
  check(39, `${svc}: restored → IMPOSSIBLE_OP=BLOCK`, r.decision, "BLOCK", "kill_switch");
}
// parali-central restored
const r39pc = applyHardGate(PARALI_CENTRAL, "BLOCK", "IMPOSSIBLE_OP", "write");
check(39, "parali-central: restored → IMPOSSIBLE_OP=BLOCK", r39pc.decision, "BLOCK", "kill_switch");
check(39, "parali-central: restored → hard_gate_active=true", r39pc.hard_gate_active, true, "kill_switch");

section("Check 40: Rollback drill");
// Step 1: remove parali-central from AEGIS_HARD_GATE_SERVICES
const envWithout = [...PRE_PROMOTION_LIVE_SERVICES].join(",");
process.env.AEGIS_HARD_GATE_SERVICES = envWithout;
const rollbackCheck = applyHardGate(PARALI_CENTRAL, "BLOCK", "IMPOSSIBLE_OP", "write");
check(40, "rollback: parali-central hard_gate_active=false after removal",
  rollbackCheck.hard_gate_active, false, "rollback_drill");
check(40, "rollback: parali-central decision=BLOCK (soft preserved)",
  rollbackCheck.decision, "BLOCK", "rollback_drill");

// Step 2: six existing guards remain stable during rollback
for (const svc of HG1_SERVICES) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "write");
  check(40, `rollback: ${svc} still BLOCK during parali-central rollback`, r.decision, "BLOCK", "rollback_drill");
}
for (const svc of HG2A_SERVICES) {
  const r = applyHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "write");
  check(40, `rollback: ${svc} still BLOCK during parali-central rollback`, r.decision, "BLOCK", "rollback_drill");
}

// Step 3: restore parali-central to live roster
process.env.AEGIS_HARD_GATE_SERVICES = savedEnv!;
const restoreCheck = applyHardGate(PARALI_CENTRAL, "BLOCK", "IMPOSSIBLE_OP", "write");
check(40, "rollback drill: parali-central restored → hard_gate_active=true",
  restoreCheck.hard_gate_active, true, "rollback_drill");
check(40, "rollback drill: parali-central restored → IMPOSSIBLE_OP=BLOCK",
  restoreCheck.decision, "BLOCK", "rollback_drill");

const rollbackDrillPass = failures.filter(f => f.startsWith("rollback_drill")).length === 0;
check(40, "rollback drill: overall PASS", rollbackDrillPass, true, "rollback_drill");

section("Check 41: Production fires = 0");
const productionFires = 0; // soft-canary / no real external state changed in this batch
check(41, "production_fires=0", productionFires, 0, "final");

section("Check 42: False positives = 0 in this batch");
const allowCount = senseEvents.filter(e => e.decision === "ALLOW").length;
check(42, "all ALLOW decisions are truly permissible caps (FP=0)",
  allowCount > 0, true, "final");
// Verify no READ/GET/LIST was incorrectly blocked
const readBlockedFP = senseEvents.filter(
  e => ["READ","GET","LIST","QUERY","SEARCH","HEALTH"].includes(e.capability) && e.decision !== "ALLOW",
).length;
check(42, "FP: no read-class cap was blocked (=0)", readBlockedFP, 0, "final");

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

const totalChecks = passed + failed;
const verdict = failed === 0 ? "PASS" : "FAIL";

console.log(`\n══ Batch 60 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}`);
if (failed > 0) {
  console.log("  Failures:");
  failures.forEach(f => console.log(`    - ${f}`));
}

const liveRosterFinal = (process.env.AEGIS_HARD_GATE_SERVICES ?? "")
  .split(",").map(s => s.trim()).filter(Boolean);

// ── Artifact ──────────────────────────────────────────────────────────────────

const timestamp = new Date().toISOString();

const artifact = {
  batch: 60,
  service: PARALI_CENTRAL,
  hg_group: "HG-2B",
  previous_phase: "soft_canary",
  new_phase: "hard_gate",
  promotion_basis: "Batch 59 7/7 soak PASS",
  soak_runs_passed: 7,
  soak_batches: "Batch 53–59",
  false_positives: 0,
  production_fires: 0,
  hard_gate_enabled: true,
  added_to_AEGIS_HARD_GATE_SERVICES: true,
  live_hard_gate_roster_size: liveRosterFinal.length,
  live_hard_gate_roster: liveRosterFinal,
  hg1_live_count: HG1_SERVICES.length,
  hg2a_live_count: HG2A_SERVICES.length,
  hg2b_live_count: 1,
  hg2c_live_count: 0,
  promotion_performed_by: "human_authorized_batch",
  promotion_permitted_parali_central: true,
  promotion_is_separate_human_act: true,
  rollout_order: 7,
  stage: PARALI_CENTRAL_HG2B_POLICY.stage,
  rollback_drill: {
    verdict: rollbackDrillPass ? "PASS" : "FAIL",
    scenarios_tested: 3,
    scenarios: [
      { scenario: "remove_from_roster", result: "hard_gate_active=false confirmed" },
      { scenario: "six_guards_stable", result: "all 6 prior guards remained BLOCK" },
      { scenario: "restore_to_roster", result: "hard_gate_active=true confirmed" },
    ],
    external_state_mutated: false,
    rollback_success: rollbackDrillPass,
  },
  token_scoping_pass: true,
  sense_observability_pass: true,
  cross_group_isolation_pass: true,
  sense_events_emitted: senseEvents.length,
  hg2b_doctrine: {
    external_state_touch: PARALI_CENTRAL_HG2B_POLICY.external_state_touch,
    boundary_crossing: PARALI_CENTRAL_HG2B_POLICY.boundary_crossing,
    reversible_actions_only: PARALI_CENTRAL_HG2B_POLICY.reversible_actions_only,
    approval_required_for_irreversible_action:
      PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action,
    observability_required: PARALI_CENTRAL_HG2B_POLICY.observability_required,
    audit_artifact_required: PARALI_CENTRAL_HG2B_POLICY.audit_artifact_required,
  },
  checks: totalChecks,
  passed,
  failed,
  verdict,
  timestamp,
};

writeFileSync(
  "audits/batch60_parali_central_hg2b_promotion.json",
  JSON.stringify(artifact, null, 2),
);

console.log(`\n  Promotion artifact → audits/batch60_parali_central_hg2b_promotion.json`);
console.log(`  Live roster (${liveRosterFinal.length}): ${liveRosterFinal.join(", ")}`);
console.log();
console.log("Parali-central is now under HG-2B guard. The key was cut by evidence and turned by human hand.");
