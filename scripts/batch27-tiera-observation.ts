/**
 * Batch 27 — Full TIER-A 12-Service Observation Window
 *
 * Purpose: Normal operational traffic across all 12 TIER-A soft-canary services
 * after Batch 26 expanded from 6→12. Proves the full fleet holds formation under
 * representative load before the rough-weather window (Batch 28).
 *
 * Rules enforced throughout:
 *   - soft-canary only; no hard mode
 *   - no expansion beyond TIER-A
 *   - BLOCK → GATE in soft-canary (never hard-block)
 *   - READ always ALLOW (AEG-E-002)
 *   - unknown services → WARN/shadow, never BLOCK
 *   - non-TIER-A → monitor-only/shadow
 *   - approval lifecycle mandatory for GATE continuation
 *   - rollback drill passes across all 12
 *
 * Traffic waves:
 *   1. READ-heavy      (read/get/list/query/search/health)
 *   2. WRITE/UPDATE    (write/update/create/patch)
 *   3. EXECUTE/TOOL    (execute/trigger/emit — high risk)
 *   4. APPROVE/REVIEW  (approve/reject — high risk)
 *   5. DEPLOY/CRITICAL (deploy/delete — critical risk)
 *   6. BOUNDARY        (non-TIER-A, unknown, non-canary)
 */

import { evaluate } from "../src/enforcement/gate";
import {
  issueApprovalToken,
  approveToken,
  denyToken,
  revokeToken,
  getApproval,
  runRollbackDrill,
} from "../src/enforcement/approval";
import { getCanaryStatus } from "../src/enforcement/canary-status";
import { logDecision } from "../src/enforcement/logger";
import { loadRegistry } from "../src/enforcement/registry";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// ── Environment: soft mode, canary enabled ───────────────────────────────────

process.env.AEGIS_ENFORCEMENT_MODE = "soft";
process.env.AEGIS_RUNTIME_ENABLED = "true";
process.env.AEGIS_DRY_RUN = "false";
delete process.env.AEGIS_SOFT_CANARY_SERVICES; // use gate.ts default (all 12)

// ── Constants ─────────────────────────────────────────────────────────────────

const TIER_A_12 = [
  "granthx", "stackpilot", "ankrclaw",
  "carbonx", "parali-central", "pramana",
  "ankr-doctor", "domain-capture", "ship-slm",
  "chief-slm", "chirpee", "puranic-os",
] as const;

type TierA = typeof TIER_A_12[number];

const reg = loadRegistry();

// Per-service expected decision for HIGH-risk ops (execute/trigger/approve/reject)
// Gate triggers: human_gate_required, OR authority_class in [financial/governance/deploy], OR BR >= 3
function expectedHighDecision(svc: string): "GATE" | "ALLOW" {
  const e = reg[svc];
  if (!e) return "ALLOW";
  const highAuthority = ["financial", "governance", "deploy"].includes(e.authority_class);
  const highBlast = parseInt(e.governance_blast_radius.replace("BR-", "") || "0", 10) >= 3;
  if (e.human_gate_required || highAuthority || highBlast) return "GATE";
  return "ALLOW";
}

// ── Test harness ──────────────────────────────────────────────────────────────

let totalChecks = 0;
let passed = 0;
let failed = 0;
const failures: Array<{ label: string; expected: string; actual: string }> = [];

function check(label: string, actual: unknown, expected: unknown) {
  totalChecks++;
  const pass = String(actual) === String(expected);
  if (pass) {
    passed++;
    console.log(`  ✓ [PASS] ${label.padEnd(60)} actual=${actual}`);
  } else {
    failed++;
    failures.push({ label, expected: String(expected), actual: String(actual) });
    console.log(`  ✗ [FAIL] ${label.padEnd(60)} expected=${expected} actual=${actual}`);
  }
}

// Normalise approval function results to "accepted" / "rejected"
function okStatus(result: { ok: boolean }): "accepted" | "rejected" {
  return result.ok ? "accepted" : "rejected";
}

function req(svc: string, op: string, cap = "default_capability", caller = "batch27-obs") {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: caller, session_id: `b27-${svc}-${op}`,
  });
  logDecision(d); // @rule:AEG-E-005 — feed decision log so getCanaryStatus can read soft_canary entries
  return d;
}

function phase(d: ReturnType<typeof evaluate>): string {
  return `${d.decision}/${d.enforcement_phase}`;
}

// ── Decision + approval lifecycle counters ────────────────────────────────────

const decisionCounts: Record<string, Record<string, number>> = {};
for (const s of TIER_A_12) {
  decisionCounts[s] = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0, READ_GATES: 0 };
}

function tally(svc: string, d: ReturnType<typeof evaluate>, isRead = false) {
  if (!decisionCounts[svc]) return;
  decisionCounts[svc][d.decision] = (decisionCounts[svc][d.decision] ?? 0) + 1;
  if (isRead && d.decision !== "ALLOW") decisionCounts[svc].READ_GATES++;
}

const approvalCounts = { issued: 0, approved: 0, denied: 0, revoked: 0, expired: 0, consumed: 0 };

// ── Wave 1: READ-heavy traffic ────────────────────────────────────────────────

console.log("\n── Wave 1: READ-heavy operational traffic ──");
const readOps = ["read", "get", "list", "query", "search", "health"];
for (const svc of TIER_A_12) {
  for (const op of readOps) {
    const d = req(svc, op);
    tally(svc, d, true);
    check(`${svc}/${op}: ALLOW/soft_canary`, phase(d), "ALLOW/soft_canary");
  }
}

// ── Wave 2: WRITE / UPDATE normal operations ──────────────────────────────────

console.log("\n── Wave 2: WRITE/UPDATE normal operations ──");
const writeOps = ["write", "update", "create", "patch"];
for (const svc of TIER_A_12) {
  for (const op of writeOps) {
    const d = req(svc, op);
    tally(svc, d);
    // medium risk — no GATE trigger fires for any of the 12 → ALLOW
    check(`${svc}/${op}: ALLOW/soft_canary`, phase(d), "ALLOW/soft_canary");
  }
}

// ── Wave 3: EXECUTE / TOOL_CALL (high risk) ───────────────────────────────────

console.log("\n── Wave 3: EXECUTE/TOOL_CALL (high risk) ──");
const executeOps = ["execute", "trigger", "emit"];
const gateTokensW3: Array<{ svc: string; op: string; token: string }> = [];

for (const svc of TIER_A_12) {
  const exp = expectedHighDecision(svc);
  for (const op of executeOps) {
    const d = req(svc, op);
    tally(svc, d);
    check(`${svc}/${op}: ${exp}/soft_canary`, phase(d), `${exp}/soft_canary`);
    if (d.decision === "GATE" && d.approval_token) {
      gateTokensW3.push({ svc, op, token: d.approval_token });
      approvalCounts.issued++;
    }
  }
}

// ── Wave 4: APPROVE / REVIEW governance actions (high risk) ──────────────────

console.log("\n── Wave 4: APPROVE/REVIEW governance actions ──");
const approveOps = ["approve", "reject"];
const gateTokensW4: Array<{ svc: string; op: string; token: string }> = [];

for (const svc of TIER_A_12) {
  const exp = expectedHighDecision(svc);
  for (const op of approveOps) {
    const d = req(svc, op);
    tally(svc, d);
    check(`${svc}/${op}: ${exp}/soft_canary`, phase(d), `${exp}/soft_canary`);
    if (d.decision === "GATE" && d.approval_token) {
      gateTokensW4.push({ svc, op, token: d.approval_token });
      approvalCounts.issued++;
    }
  }
}

// ── Wave 5: DEPLOY / HIGH-RISK critical actions ───────────────────────────────

console.log("\n── Wave 5: DEPLOY/CRITICAL actions ──");
const criticalOps = ["deploy", "delete"];
const gateTokensW5: Array<{ svc: string; op: string; token: string }> = [];

for (const svc of TIER_A_12) {
  for (const op of criticalOps) {
    const d = req(svc, op);
    tally(svc, d);
    check(`${svc}/${op}: GATE/soft_canary`, phase(d), "GATE/soft_canary");
    if (d.decision === "GATE" && d.approval_token) {
      gateTokensW5.push({ svc, op, token: d.approval_token });
      approvalCounts.issued++;
    }
  }
}

// ── Wave 6: Boundary checks ───────────────────────────────────────────────────

console.log("\n── Wave 6: Boundary checks ──");

// Non-TIER-A service → shadow
const freightboxD = req("freightbox", "write");
check(`non-TIER-A (freightbox): shadow enforcement`, freightboxD.enforcement_phase, "shadow");
check(`non-TIER-A (freightbox): in_canary=false`, freightboxD.in_canary, false);

// Unknown service → WARN/shadow, never BLOCK
const unknownD = req("svc-b27-unknown-xyz", "execute");
check(`unknown service: WARN (not BLOCK)`, unknownD.decision, "WARN");
check(`unknown service: shadow phase`, unknownD.enforcement_phase, "shadow");
check(`unknown service: in_canary=false`, unknownD.in_canary, false);

// Non-canary TIER-B/TIER-C → shadow
const mariD = req("mari8x-community", "deploy");
check(`non-canary (mari8x): shadow enforcement`, mariD.enforcement_phase, "shadow");
check(`non-canary (mari8x): not BLOCK`, mariD.decision !== "BLOCK", true);

// READ on a TIER-A service always ALLOW even with garbage capability
const readBadCap = evaluate({
  service_id: "granthx", operation: "read", requested_capability: "!@#$invalid",
  caller_id: "b27-boundary", session_id: "b27-boundary-read-bad-cap",
});
check(`READ bad-cap: still ALLOW`, readBadCap.decision, "ALLOW");
check(`READ bad-cap: phase soft_canary`, readBadCap.enforcement_phase, "soft_canary");

// WRITE on unknown service → WARN (not GATE/BLOCK)
const writeMissD = req("non-existent-svc-27", "write");
check(`WRITE unknown: WARN`, writeMissD.decision, "WARN");
check(`WRITE unknown: shadow`, writeMissD.enforcement_phase, "shadow");

// Verify non-TIER-A and unknown services don't receive approval_token
check(`non-TIER-A: no approval_token`, freightboxD.approval_token, undefined);
check(`unknown-svc: no approval_token`, unknownD.approval_token, undefined);

// ── Approval lifecycle — Wave 3 tokens (execute/trigger/emit) ────────────────
//
// approveToken(token, approval_reason, approved_by, binding?)
// denyToken(token, denial_reason, denied_by)
// revokeToken(token, revoked_by, revoke_reason)

console.log("\n── Approval lifecycle — Wave 3 (execute/trigger) ──");

if (gateTokensW3.length >= 2) {
  const { svc: s1, op: o1, token: t1 } = gateTokensW3[0];
  const { svc: s2, op: o2, token: t2 } = gateTokensW3[1];

  // Approve t1
  const a1 = approveToken(t1, "verified by on-call", "operations-lead@ankr");
  check(`W3-approve ${s1}/${o1}: accepted`, okStatus(a1), "accepted");
  if (a1.ok) approvalCounts.approved++;

  // Deny t2
  const dn2 = denyToken(t2, "capability not authorised for this window", "security-gate@ankr");
  check(`W3-deny ${s2}/${o2}: accepted`, okStatus(dn2), "accepted");
  if (dn2.ok) approvalCounts.denied++;

  // Replay t1 (now approved/consumed) → rejected (AEG-E-015)
  const replay1 = approveToken(t1, "retry after consume", "ops@ankr");
  check(`W3-replay consumed: rejected (AEG-E-015)`, okStatus(replay1), "rejected");

  // Replay t2 (denied) → rejected (AEG-E-017)
  const replay2 = approveToken(t2, "retry after deny", "ops@ankr");
  check(`W3-replay denied: rejected (AEG-E-017)`, okStatus(replay2), "rejected");
}

// Cross-service binding check (AEG-E-016)
if (gateTokensW3.length >= 4) {
  const { token: tA } = gateTokensW3[2];
  const recA = getApproval(tA)!;
  const wrongSvc = recA.service_id === "granthx" ? "stackpilot" : "granthx";
  const wrongBind = approveToken(tA, "approve for different service", "ops@ankr", { service_id: wrongSvc });
  check(`W3-wrong-binding: rejected (AEG-E-016)`, okStatus(wrongBind), "rejected");
}

// Blank approval reason → rejected (AEG-E-014)
if (gateTokensW3.length >= 5) {
  const { token: tBlank } = gateTokensW3[4];
  const blankR = approveToken(tBlank, "   ", "ops@ankr");
  check(`W3-blank-reason: rejected (AEG-E-014)`, okStatus(blankR), "rejected");
}

// ── Approval lifecycle — Wave 4 tokens (approve/reject ops) ──────────────────

console.log("\n── Approval lifecycle — Wave 4 (governance gate) ──");

if (gateTokensW4.length >= 2) {
  const { svc: s3, op: o3, token: t3 } = gateTokensW4[0];
  const { svc: s4, op: o4, token: t4 } = gateTokensW4[1];

  // Approve t3 with audit-quality reason
  const a3 = approveToken(t3, `governance review approved — ${s3}/${o3} cleared for window`, "governance-officer@ankr");
  check(`W4-approve ${s3}/${o3}: accepted`, okStatus(a3), "accepted");
  if (a3.ok) approvalCounts.approved++;

  // Revoke t4 (AEG-E-018) — revokeToken(token, revoked_by, revoke_reason)
  const rv4 = revokeToken(t4, "security-lead@ankr", "override: governance window closed early");
  check(`W4-revoke ${s4}/${o4}: accepted`, okStatus(rv4), "accepted");
  if (rv4.ok) approvalCounts.revoked++;

  // Revoke t4 again → rejected (already revoked)
  const rvv4 = revokeToken(t4, "ops@ankr", "second revoke attempt");
  check(`W4-revoke-again: rejected (AEG-E-018)`, okStatus(rvv4), "rejected");

  // Blank revoke_reason → rejected
  if (gateTokensW4.length >= 3) {
    const { token: tBR } = gateTokensW4[2];
    const blankRev = revokeToken(tBR, "ops@ankr", "   ");
    check(`W4-blank-revoke-reason: rejected (AEG-E-018)`, okStatus(blankRev), "rejected");

    // Blank revoked_by → rejected
    const blankBy = revokeToken(tBR, "   ", "valid reason");
    check(`W4-blank-revoked_by: rejected (AEG-E-018)`, okStatus(blankBy), "rejected");
  }
}

// ── Approval lifecycle — Wave 5 tokens (deploy/critical) ─────────────────────

console.log("\n── Approval lifecycle — Wave 5 (deploy/critical) ──");

if (gateTokensW5.length >= 2) {
  const { svc: s5, op: o5, token: t5 } = gateTokensW5[0];
  const { svc: _s6, token: t6 } = gateTokensW5[1];

  // Full approve cycle: approve → record status becomes "approved"
  const a5 = approveToken(t5, `deploy window authorised — ${s5}/${o5}`, "deploy-captain@ankr");
  check(`W5-approve ${s5}/${o5}: accepted`, okStatus(a5), "accepted");
  if (a5.ok) approvalCounts.approved++;

  // Verify record status is "approved" after approveToken
  const rec5 = getApproval(t5);
  check(`W5-token-status: approved`, rec5?.status, "approved");

  // Simulate expiry on t6 by backdating expires_at
  const rec6 = getApproval(t6);
  if (rec6) {
    rec6.expires_at = new Date(Date.now() - 2000).toISOString();
    approvalCounts.expired++;
  }
  const expiredApprove = approveToken(t6, "try after expiry", "ops@ankr");
  check(`W5-expired-token: rejected (AEG-E-013)`, okStatus(expiredApprove), "rejected");

  // Approve a 3rd Wave 5 token
  if (gateTokensW5.length >= 3) {
    const { svc: s7, op: o7, token: t7 } = gateTokensW5[2];
    const a7 = approveToken(t7, `${s7}/${o7} window approved`, "captain@ankr");
    check(`W5-approve ${s7}/${o7}: accepted`, okStatus(a7), "accepted");
    if (a7.ok) approvalCounts.approved++;

    // Deny a 4th Wave 5 token
    if (gateTokensW5.length >= 4) {
      const { svc: s8, op: o8, token: t8 } = gateTokensW5[3];
      const dn8 = denyToken(t8, `${s8}/${o8} — outside maintenance window`, "sec@ankr");
      check(`W5-deny ${s8}/${o8}: accepted`, okStatus(dn8), "accepted");
      if (dn8.ok) approvalCounts.denied++;
    }
  }
}

// ── Additional: no READ gate fires across any wave ────────────────────────────

console.log("\n── READ gate invariant — all 12 services ──");
let readGateTotal = 0;
for (const s of TIER_A_12) readGateTotal += decisionCounts[s].READ_GATES;
check(`zero READ gates across all 12 services`, readGateTotal, 0);

// ── Additional: no hard BLOCK in soft-canary ─────────────────────────────────

console.log("\n── No hard BLOCK in soft-canary — all 12 services ──");
let hardBlockTotal = 0;
for (const s of TIER_A_12) hardBlockTotal += decisionCounts[s].BLOCK;
check(`zero BLOCK decisions in soft-canary (all 12)`, hardBlockTotal, 0);

// ── Additional: read_only + low-BR not over-gated (correctness invariant) ────

console.log("\n── read_only low-BR not over-gated ──");
const lowBrSvcs = ["ship-slm", "chief-slm", "chirpee", "puranic-os"] as const;
for (const s of lowBrSvcs) {
  const wd = req(s, "write");
  check(`${s}/write: ALLOW (not over-gated)`, wd.decision, "ALLOW");
  const ed = req(s, "execute");
  check(`${s}/execute: ALLOW (BR-0/1 + read_only)`, ed.decision, "ALLOW");
}

// ── Regression: original 6-service expectations unchanged ────────────────────

console.log("\n── Regression — original 6-service window ──");
const orig6 = ["granthx", "stackpilot", "ankrclaw", "carbonx", "parali-central", "pramana"] as const;
for (const s of orig6) {
  const rd = req(s, "read");
  const wd = req(s, "write");
  const dd = req(s, "deploy");
  check(`${s}: READ=ALLOW/soft_canary`, phase(rd), "ALLOW/soft_canary");
  check(`${s}: WRITE=ALLOW/soft_canary`, phase(wd), "ALLOW/soft_canary");
  check(`${s}: DEPLOY=GATE/soft_canary`, phase(dd), "GATE/soft_canary");
}

// ── Canary status: 12-service scope ──────────────────────────────────────────

console.log("\n── Canary status — 12-service scope ──");
const status = getCanaryStatus([...TIER_A_12]);
check(`status: 12/12 service stats`, status.service_stats.length, 12);
check(`status: no_read_gates`, status.success_criteria.no_read_gates, true);
check(`status: no_unknown_service_blocks`, status.success_criteria.no_unknown_service_blocks, true);
check(`status: no_token_replay_successes`, status.success_criteria.no_token_replay_successes, true);
check(`status: no_approval_without_reason`, status.success_criteria.no_approval_without_reason, true);
check(`status: no_revoke_without_reason`, status.success_criteria.no_revoke_without_reason, true);
check(`status: rollback_drill_passed not false`, status.success_criteria.rollback_drill_passed !== false, true);
check(`status: decision_log_has_canary_entries`, status.success_criteria.decision_log_has_canary_entries, true);

// ── Rollback drill — all 12 services ─────────────────────────────────────────

console.log("\n── Rollback drill — all 12 TIER-A services ──");
const drill = runRollbackDrill(
  evaluate,
  [...TIER_A_12],
  [{ operation: "deploy", requested_capability: "CI_DEPLOY" }],
);
check(`drill_verdict: PASS`, drill.verdict, "PASS");

for (const svc of TIER_A_12) {
  const sc = drill.services_checked.find(s => s.service_id === svc);
  check(`${svc}: shadow after kill`, sc?.phase_after_kill, "shadow");
  check(`${svc}: no tokens while killed`, sc?.tokens_issued, false);
}

// ── Final canary status post-drill ───────────────────────────────────────────

console.log("\n── Final status post-drill ──");
const finalStatus = getCanaryStatus([...TIER_A_12]);
check(`final: all_criteria_met`, finalStatus.success_criteria.all_criteria_met, true);
check(`final: rollback_drill_passed`, finalStatus.success_criteria.rollback_drill_passed, true);
check(`final: 12/12 services`, finalStatus.service_stats.length, 12);

// ── Decision summary table ─────────────────────────────────────────────────────

console.log("\n── Decision summary by service ──");
console.log("  Service            ALLOW  WARN  GATE  BLOCK  READ_GATES");
for (const s of TIER_A_12) {
  const c = decisionCounts[s];
  console.log(
    `  ${s.padEnd(18)} ${String(c.ALLOW).padStart(5)} ${String(c.WARN).padStart(5)} ` +
    `${String(c.GATE).padStart(5)} ${String(c.BLOCK).padStart(6)} ${String(c.READ_GATES).padStart(10)}`
  );
}

// ── Summary ───────────────────────────────────────────────────────────────────

console.log("\n══ Summary ══");
console.log(`  Total checks:    ${totalChecks}`);
console.log(`  PASS:            ${passed}`);
console.log(`  FAIL:            ${failed}`);
console.log(`  ready_to_expand: ${finalStatus.success_criteria.all_criteria_met && failed === 0}`);

// ── Artifacts ─────────────────────────────────────────────────────────────────

const OUT = "/root/.aegis";
mkdirSync(OUT, { recursive: true });

const summary = [
  `# Batch 27 — Full TIER-A Observation Window`,
  `Date: ${new Date().toISOString()}`,
  ``,
  `## Fleet`,
  `Services: ${TIER_A_12.join(", ")}`,
  ``,
  `## Traffic Waves`,
  `1. READ-heavy (read/get/list/query/search/health × 12) — all ALLOW`,
  `2. WRITE/UPDATE (write/update/create/patch × 12) — all ALLOW (medium, no gate triggers)`,
  `3. EXECUTE/TOOL_CALL (execute/trigger/emit × 12) — GATE where BR≥3 or governance authority`,
  `4. APPROVE/REVIEW (approve/reject × 12) — same profile as EXECUTE`,
  `5. DEPLOY/CRITICAL (deploy/delete × 12) — GATE all (critical always gates)`,
  `6. BOUNDARY — non-TIER-A/unknown/non-canary remain shadow/WARN`,
  ``,
  `## Results`,
  `Total checks: ${totalChecks}`,
  `PASS: ${passed}`,
  `FAIL: ${failed}`,
  ``,
  `## Approval lifecycle`,
  `issued:   ${approvalCounts.issued}`,
  `approved: ${approvalCounts.approved}`,
  `denied:   ${approvalCounts.denied}`,
  `revoked:  ${approvalCounts.revoked}`,
  `expired:  ${approvalCounts.expired}`,
  `consumed: ${approvalCounts.consumed}`,
  ``,
  `## Invariants`,
  `READ gates fired: ${readGateTotal} (must be 0)`,
  `Hard BLOCKs in soft-canary: ${hardBlockTotal} (must be 0)`,
  `Rollback drill: ${drill.verdict}`,
  `All criteria met: ${finalStatus.success_criteria.all_criteria_met}`,
  ``,
  `## Decision counts per service`,
  `Service            ALLOW  WARN  GATE  BLOCK  READ_GATES`,
  ...TIER_A_12.map(s => {
    const c = decisionCounts[s];
    return `${s.padEnd(18)} ${String(c.ALLOW).padStart(5)} ${String(c.WARN).padStart(5)} ${String(c.GATE).padStart(5)} ${String(c.BLOCK).padStart(6)} ${String(c.READ_GATES).padStart(10)}`;
  }),
  ``,
  `## Status`,
  `ready_to_expand: ${finalStatus.success_criteria.all_criteria_met && failed === 0}`,
  `Next: Batch 28 — 12-service rough-weather edge window`,
].join("\n");

writeFileSync(join(OUT, "batch27_tiera_observation_summary.md"), summary);
writeFileSync(join(OUT, "batch27_decision_counts.json"), JSON.stringify(decisionCounts, null, 2));
writeFileSync(join(OUT, "batch27_approval_counts.json"), JSON.stringify(approvalCounts, null, 2));
writeFileSync(join(OUT, "batch27_blockers.json"), JSON.stringify({
  failed_checks: failures,
  read_gate_total: readGateTotal,
  hard_block_total: hardBlockTotal,
  drill_verdict: drill.verdict,
  all_criteria_met: finalStatus.success_criteria.all_criteria_met,
}, null, 2));

console.log("\n── Artifacts ──");
console.log(`  ${join(OUT, "batch27_tiera_observation_summary.md")}`);
console.log(`  ${join(OUT, "batch27_decision_counts.json")}`);
console.log(`  ${join(OUT, "batch27_approval_counts.json")}`);
console.log(`  ${join(OUT, "batch27_blockers.json")}`);
console.log(`\n  Full TIER-A 12-service observation: ${failed === 0 ? "CLEAN — Batch 28 rough-weather is next." : `${failed} FAILURES — fix before proceeding.`}`);
