#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 22 — Mixed edge-case canary observation
// Final validation window before expanding soft canary from 3 to 6 services.
//
// Tests:
//   1. Normal traffic (READ/WRITE/APPROVE)
//   2. High-risk traffic (DELETE/AI_EXECUTE/TOOL_CALL/ROLLOUT)
//   3. Bad-input traffic (unknown cap, lowercase, empty, unknown svc, non-canary)
//   4. Approval lifecycle edge cases (expired/replay/denied/revoked/binding/blank)
//   5. Rollback drill after all traffic
//
// Produces:
//   .aegis/batch22_edge_observation_summary.md
//   .aegis/batch22_edge_decision_counts.json
//   .aegis/batch22_edge_failures.json

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// ── Live canary flags ─────────────────────────────────────────────────────────
process.env.AEGIS_RUNTIME_ENABLED         = "true";
process.env.AEGIS_ENFORCEMENT_MODE        = "soft";
process.env.AEGIS_DRY_RUN                 = "false";
process.env.AEGIS_SOFT_CANARY_SERVICES    = "granthx,stackpilot,ankrclaw";

const HOME = process.env.HOME ?? "/root";
const AEGIS_DIR = join(HOME, ".aegis");
if (!existsSync(AEGIS_DIR)) mkdirSync(AEGIS_DIR, { recursive: true });
process.env.AEGIS_DECISION_LOG_PATH  = join(AEGIS_DIR, "aegis_decisions.log");
process.env.AEGIS_APPROVAL_LOG_PATH  = join(AEGIS_DIR, "aegis_approval.log");

// ── Import AFTER env is set ───────────────────────────────────────────────────
const { evaluate } = await import("../src/enforcement/gate");
const { logDecision } = await import("../src/enforcement/logger");
const { getCanaryStatus } = await import("../src/enforcement/canary-status");
const {
  approveToken, denyToken, revokeToken, getApproval,
  issueApprovalToken, runRollbackDrill,
} = await import("../src/enforcement/approval");

// ── Types ─────────────────────────────────────────────────────────────────────
interface CheckResult {
  category: string;
  label: string;
  passed: boolean;
  actual: string;
  expected: string;
  detail?: string;
}

const checks: CheckResult[] = [];

function check(
  category: string,
  label: string,
  passed: boolean,
  actual: string,
  expected: string,
  detail?: string,
): void {
  checks.push({ category, label, passed, actual, expected, detail });
  const mark = passed ? "✓" : "✗";
  const status = passed ? "PASS" : "FAIL";
  console.log(`  ${mark} [${status}] ${label.padEnd(55)} actual=${actual}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Normal traffic
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Normal traffic (READ / WRITE / APPROVE) ──");
const CANARY = ["granthx", "stackpilot", "ankrclaw"];

const normalOps = [
  { operation: "read",    requested_capability: "READ",    expectPhase: "soft_canary", expectDecision: "ALLOW" },
  { operation: "write",   requested_capability: "WRITE",   expectPhase: "soft_canary", expectDecision: "ALLOW" },
  { operation: "approve", requested_capability: "APPROVE", expectPhase: "soft_canary", expectDecision: "GATE"  },
];

for (const svc of CANARY) {
  for (const op of normalOps) {
    const d = evaluate({ service_id: svc, operation: op.operation, requested_capability: op.requested_capability, caller_id: "b22-normal" });
    logDecision(d);
    check("normal", `${svc}/${op.operation}`, d.decision === op.expectDecision && d.enforcement_phase === op.expectPhase,
      `${d.decision}/${d.enforcement_phase}`, `${op.expectDecision}/${op.expectPhase}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. High-risk traffic
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. High-risk traffic (DELETE / AI_EXECUTE / TOOL_CALL / ROLLOUT) ──");
const highRiskOps = [
  { operation: "delete",    requested_capability: "delete",    expectDecision: "GATE" },
  { operation: "ai-execute",requested_capability: "ai_execute",expectDecision: "GATE" },
  { operation: "tool_call", requested_capability: "tool_call", expectDecision: "GATE" },
  { operation: "rollout",   requested_capability: "rollout",   expectDecision: "GATE" },
  { operation: "deploy",    requested_capability: "DEPLOY",    expectDecision: "GATE" },
  { operation: "execute",   requested_capability: "EXECUTE",   expectDecision: "GATE" },
];

for (const op of highRiskOps) {
  const d = evaluate({ service_id: "granthx", operation: op.operation, requested_capability: op.requested_capability, caller_id: "b22-highrisk" });
  logDecision(d);
  // In soft_canary: BLOCK→GATE, GATE stays GATE, ALLOW stays ALLOW — never hard BLOCK
  const noHardBlock = d.decision !== "BLOCK";
  check("high_risk", `granthx/${op.operation}`, noHardBlock && d.decision === op.expectDecision,
    `${d.decision}/${d.enforcement_phase}`, `${op.expectDecision}/soft_canary`,
    `normalized_cap=${d.requested_capability}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Bad-input traffic
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. Bad-input traffic ──");

// 3a. Unknown capability → normalised to uppercase, classified medium, should ALLOW or GATE (not BLOCK)
{
  const d = evaluate({ service_id: "granthx", operation: "frob", requested_capability: "FROB_UNKNOWN", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "unknown_capability: no hard BLOCK", d.decision !== "BLOCK",
    d.decision, "ALLOW|WARN|GATE", `cap normalised to ${d.requested_capability}`);
}

// 3b. Lowercase capability → normalised, same behaviour
{
  const d = evaluate({ service_id: "stackpilot", operation: "write", requested_capability: "write", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "lowercase_capability: normalises correctly", d.requested_capability === "WRITE",
    d.requested_capability, "WRITE");
}

// 3c. Alias capability: run_agent → AI_EXECUTE
{
  const d = evaluate({ service_id: "granthx", operation: "run_agent", requested_capability: "run_agent", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "alias run_agent → AI_EXECUTE: normalised", d.requested_capability === "AI_EXECUTE",
    d.requested_capability, "AI_EXECUTE");
  check("bad_input", "alias run_agent → AI_EXECUTE: GATE not BLOCK", d.decision !== "BLOCK",
    d.decision, "GATE");
}

// 3d. Empty requested_capability → no crash, returns a decision
{
  const d = evaluate({ service_id: "granthx", operation: "write", requested_capability: "", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "empty_capability: no crash, returns decision", typeof d.decision === "string",
    d.decision, "any-valid");
}

// 3e. Empty operation string → no crash
{
  const d = evaluate({ service_id: "granthx", operation: "", requested_capability: "WRITE", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "empty_operation: no crash, returns decision", typeof d.decision === "string",
    d.decision, "any-valid");
}

// 3f. Unknown service → shadow WARN, never BLOCK (AEG-E-002 / unregistered path)
{
  const d = evaluate({ service_id: "svc-does-not-exist", operation: "deploy", requested_capability: "DEPLOY", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "unknown_service: shadow WARN not BLOCK", d.decision === "WARN" && d.enforcement_phase === "shadow",
    `${d.decision}/${d.enforcement_phase}`, "WARN/shadow");
  check("bad_input", "unknown_service: not in canary phase", !d.in_canary,
    String(d.in_canary), "false");
}

// 3g. Non-canary TIER-A (carbonx) → soft mode but NOT in canary → shadow phase
{
  const d = evaluate({ service_id: "carbonx", operation: "deploy", requested_capability: "DEPLOY", caller_id: "b22-bad" });
  logDecision(d);
  check("bad_input", "non_canary_tier_a (carbonx): stays in shadow phase", d.enforcement_phase === "shadow",
    d.enforcement_phase, "shadow");
  check("bad_input", "non_canary_tier_a (carbonx): in_canary=false", !d.in_canary,
    String(d.in_canary), "false");
}

// 3h. Non-TIER-A service → monitor-only (WARN) regardless of mode
{
  const d = evaluate({ service_id: "freightbox", operation: "execute", requested_capability: "EXECUTE", caller_id: "b22-bad" });
  logDecision(d);
  // freightbox is TIER-B — should get WARN (monitor-only) or shadow
  check("bad_input", "non_tier_a (freightbox): no hard BLOCK", d.decision !== "BLOCK",
    `${d.decision}/${d.enforcement_phase}`, "WARN|ALLOW/shadow");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Approval lifecycle edge cases
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. Approval lifecycle edge cases ──");

// Issue a fresh GATE decision to get a live token
function issueGate(svc: string, op: string = "execute", cap: string = "EXECUTE"): string | null {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b22-lifecycle" });
  logDecision(d);
  return d.approval_token ?? null;
}

// 4a. Blank approval_reason rejected (AEG-E-014)
{
  const token = issueGate("granthx");
  if (token) {
    const r = approveToken(token, "", "capt.anil.sharma");
    check("approval_lifecycle", "blank_approval_reason: rejected (AEG-E-014)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    // Token still pending — clean up with a deny
    denyToken(token, "b22 test cleanup", "b22-script");
  }
}

// 4b. Blank approved_by rejected
{
  const token = issueGate("stackpilot");
  if (token) {
    const r = approveToken(token, "valid reason", "");
    check("approval_lifecycle", "blank_approved_by: rejected", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(token, "b22 test cleanup", "b22-script");
  }
}

// 4c. Token replay protection (AEG-E-015): approve same token twice
{
  const token = issueGate("ankrclaw");
  if (token) {
    const r1 = approveToken(token, "first approval", "capt.anil.sharma");
    const r2 = approveToken(token, "second attempt — replay", "capt.anil.sharma");
    check("approval_lifecycle", "token_replay: first approval succeeds", r1.ok,
      r1.ok ? "accepted" : "rejected", "accepted");
    check("approval_lifecycle", "token_replay: second attempt rejected (AEG-E-015)", !r2.ok,
      r2.ok ? "accepted" : "rejected", "rejected", r2.error);
  }
}

// 4d. Wrong service binding rejected (AEG-E-016)
{
  const token = issueGate("granthx");
  if (token) {
    const r = approveToken(token, "binding mismatch test", "capt.anil.sharma",
      { service_id: "stackpilot" }); // granthx token, claiming stackpilot
    check("approval_lifecycle", "wrong_binding: rejected (AEG-E-016)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(token, "b22 test cleanup", "b22-script");
  }
}

// 4e. Denied token cannot be re-approved (AEG-E-017)
{
  const token = issueGate("stackpilot");
  if (token) {
    const deny = denyToken(token, "risk too high", "capt.anil.sharma");
    const reApprove = approveToken(token, "trying after denial", "capt.anil.sharma");
    check("approval_lifecycle", "denied_then_approve: denied", deny.ok,
      deny.ok ? "denied" : "deny_failed", "denied");
    check("approval_lifecycle", "denied_then_approve: re-approve rejected", !reApprove.ok,
      reApprove.ok ? "accepted" : "rejected", "rejected", reApprove.error);
  }
}

// 4f. Revoked token cannot be re-approved (AEG-E-018)
{
  const token = issueGate("ankrclaw");
  if (token) {
    const rev = revokeToken(token, "capt.anil.sharma", "b22 revocation test");
    const reApprove = approveToken(token, "trying after revoke", "capt.anil.sharma");
    check("approval_lifecycle", "revoked_then_approve: revoked ok", rev.ok,
      rev.ok ? "revoked" : "revoke_failed", "revoked");
    check("approval_lifecycle", "revoked_then_approve: re-approve rejected", !reApprove.ok,
      reApprove.ok ? "accepted" : "rejected", "rejected", reApprove.error);
  }
}

// 4g. Blank revoke_reason rejected (AEG-E-018)
{
  const token = issueGate("granthx");
  if (token) {
    const r = revokeToken(token, "capt.anil.sharma", "");
    check("approval_lifecycle", "blank_revoke_reason: rejected (AEG-E-018)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(token, "b22 test cleanup", "b22-script");
  }
}

// 4h. Blank revoked_by rejected (AEG-E-018)
{
  const token = issueGate("stackpilot");
  if (token) {
    const r = revokeToken(token, "", "valid reason");
    check("approval_lifecycle", "blank_revoked_by: rejected (AEG-E-018)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(token, "b22 test cleanup", "b22-script");
  }
}

// 4i. Expired token cannot be approved
{
  const token = issueGate("ankrclaw");
  if (token) {
    // Simulate expiry by setting expires_at to past via the record reference
    const record = getApproval(token);
    if (record) {
      record.expires_at = new Date(Date.now() - 1000).toISOString(); // 1 second ago
      record.status = "pending"; // markExpiredLazily hasn't run yet — reset for next call
    }
    const r = approveToken(token, "late approval attempt", "capt.anil.sharma");
    // After approveToken calls markExpiredLazily, token should be expired
    check("approval_lifecycle", "expired_token: rejected (AEG-E-013)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
  }
}

// 4j. Non-canary token issues: approve a shadow decision's token (no token should be issued)
{
  // carbonx is TIER-A but not in canary — its GATE decisions should NOT issue tokens
  const d = evaluate({ service_id: "carbonx", operation: "deploy", requested_capability: "DEPLOY", caller_id: "b22-notoken" });
  logDecision(d);
  check("approval_lifecycle", "non_canary_gate: no approval_token in shadow", !d.approval_token,
    d.approval_token ? "token_issued" : "no_token", "no_token",
    `phase=${d.enforcement_phase} decision=${d.decision}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Rollback drill after all edge-case traffic
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Rollback drill ──");
const drillOps = [
  { operation: "execute", requested_capability: "EXECUTE" },
  { operation: "deploy",  requested_capability: "DEPLOY" },
  { operation: "delete",  requested_capability: "delete" },
];
const drill = runRollbackDrill(evaluate, CANARY, drillOps);
check("rollback", "drill_verdict: PASS", drill.verdict === "PASS",
  drill.verdict, "PASS");
for (const s of drill.services_checked) {
  check("rollback", `${s.service_id}: shadow after kill`, s.verdict === "ok",
    s.phase_after_kill, "shadow");
  check("rollback", `${s.service_id}: no tokens while killed`, !s.tokens_issued,
    String(s.tokens_issued), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Final canary status
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Final canary status ──");
const status = getCanaryStatus(CANARY);
const sc = status.success_criteria;

check("canary_status", "zero_read_gates", sc.no_read_gates, String(sc.no_read_gates), "true");
check("canary_status", "zero_unknown_blocks", sc.no_unknown_service_blocks, String(sc.no_unknown_service_blocks), "true");
check("canary_status", "zero_token_replay", sc.no_token_replay_successes, String(sc.no_token_replay_successes), "true");
check("canary_status", "no_approval_without_reason", sc.no_approval_without_reason, String(sc.no_approval_without_reason), "true");
check("canary_status", "no_revoke_without_reason", sc.no_revoke_without_reason, String(sc.no_revoke_without_reason), "true");
check("canary_status", "rollback_drill_passed", sc.rollback_drill_passed === true, String(sc.rollback_drill_passed), "true");
check("canary_status", "decision_log_has_canary_entries", sc.decision_log_has_canary_entries, String(sc.decision_log_has_canary_entries), "true");
check("canary_status", "all_criteria_met", sc.all_criteria_met, String(sc.all_criteria_met), "true");

// ═══════════════════════════════════════════════════════════════════════════════
// Results
// ═══════════════════════════════════════════════════════════════════════════════
const passed = checks.filter(c => c.passed);
const failed = checks.filter(c => !c.passed);

console.log(`\n══ Summary ══`);
console.log(`  Total checks:  ${checks.length}`);
console.log(`  PASS:          ${passed.length}`);
console.log(`  FAIL:          ${failed.length}`);
console.log(`  ready_to_expand: ${status.ready_to_expand}`);

if (failed.length > 0) {
  console.log(`\n  Failures:`);
  for (const f of failed) {
    console.log(`    ✗ [${f.category}] ${f.label}: expected=${f.expected} actual=${f.actual}${f.detail ? ` (${f.detail})` : ""}`);
  }
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
const decisionCounts: Record<string, number> = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 };
for (const k of Object.keys(status.decision_distribution) as Array<keyof typeof status.decision_distribution>) {
  decisionCounts[k] = status.decision_distribution[k];
}

writeFileSync(
  join(AEGIS_DIR, "batch22_edge_decision_counts.json"),
  JSON.stringify({
    generated_at: new Date().toISOString(),
    batch: "batch22",
    canary_services: CANARY,
    total_decisions_in_log: status.total_decisions,
    canary_decisions: status.canary_decisions,
    shadow_decisions: status.shadow_decisions,
    distribution: decisionCounts,
    per_service: status.service_stats.map(s => ({
      service_id: s.service_id,
      total: s.total_decisions,
      ALLOW: s.allow,
      WARN: s.warn,
      GATE: s.gate,
      BLOCK: s.block,
      read_gates: s.read_gates,
    })),
  }, null, 2),
);

writeFileSync(
  join(AEGIS_DIR, "batch22_edge_failures.json"),
  JSON.stringify({
    generated_at: new Date().toISOString(),
    batch: "batch22",
    total_checks: checks.length,
    passed: passed.length,
    failed: failed.length,
    ready_to_expand: status.ready_to_expand,
    failures: failed.map(f => ({
      category: f.category,
      label: f.label,
      expected: f.expected,
      actual: f.actual,
      detail: f.detail,
    })),
    success_criteria: sc,
    rollback_drill_verdict: drill.verdict,
  }, null, 2),
);

// ── Summary MD ────────────────────────────────────────────────────────────────
const by_category = checks.reduce((acc, c) => {
  if (!acc[c.category]) acc[c.category] = { pass: 0, fail: 0 };
  c.passed ? acc[c.category].pass++ : acc[c.category].fail++;
  return acc;
}, {} as Record<string, { pass: number; fail: number }>);

const mdLines = [
  `# AEGIS Batch 22 — Edge-Case Canary Observation`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Canary services:** ${CANARY.join(", ")}`,
  `**Purpose:** Final validation window before 3 → 6 expansion`,
  ``,
  `## Check Summary`,
  ``,
  `| Category | Checks | PASS | FAIL |`,
  `|---|---|---|---|`,
  ...Object.entries(by_category).map(([cat, r]) =>
    `| ${cat} | ${r.pass + r.fail} | ${r.pass} | ${r.fail} |`
  ),
  `| **TOTAL** | **${checks.length}** | **${passed.length}** | **${failed.length}** |`,
  ``,
  `## Decision Log Totals (cumulative across all batches)`,
  ``,
  `| Metric | Value |`,
  `|---|---|`,
  `| Total decisions in log | ${status.total_decisions} |`,
  `| Canary decisions (soft_canary) | ${status.canary_decisions} |`,
  `| Shadow decisions | ${status.shadow_decisions} |`,
  `| ALLOW | ${status.decision_distribution.ALLOW} |`,
  `| WARN | ${status.decision_distribution.WARN} |`,
  `| GATE | ${status.decision_distribution.GATE} |`,
  `| BLOCK | ${status.decision_distribution.BLOCK} |`,
  ``,
  `## Edge-Case Invariant Verification`,
  ``,
  `| Invariant | Result |`,
  `|---|---|`,
  `| Unknown capability: no hard BLOCK | ${checks.find(c => c.label.includes("unknown_capability"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Lowercase capability: normalised | ${checks.find(c => c.label.includes("lowercase_capability"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| run_agent alias → AI_EXECUTE | ${checks.filter(c => c.label.includes("alias run_agent")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Empty capability: no crash | ${checks.find(c => c.label.includes("empty_capability"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Empty operation: no crash | ${checks.find(c => c.label.includes("empty_operation"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown service: shadow WARN not BLOCK | ${checks.filter(c => c.label.includes("unknown_service")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-canary TIER-A: stays shadow | ${checks.filter(c => c.label.includes("non_canary_tier_a")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-TIER-A service: no hard BLOCK | ${checks.find(c => c.label.includes("non_tier_a"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Approval Lifecycle Edge-Case Verification`,
  ``,
  `| Edge Case | Rule | Result |`,
  `|---|---|---|`,
  `| Blank approval_reason rejected | AEG-E-014 | ${checks.find(c => c.label.includes("blank_approval_reason"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank approved_by rejected | AEG-E-014 | ${checks.find(c => c.label.includes("blank_approved_by"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Token replay rejected | AEG-E-015 | ${checks.filter(c => c.label.includes("token_replay")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Wrong service binding rejected | AEG-E-016 | ${checks.find(c => c.label.includes("wrong_binding"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Denied token re-approve rejected | AEG-E-017 | ${checks.filter(c => c.label.includes("denied_then_approve")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Revoked token re-approve rejected | AEG-E-018 | ${checks.filter(c => c.label.includes("revoked_then_approve")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoke_reason rejected | AEG-E-018 | ${checks.find(c => c.label.includes("blank_revoke_reason"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoked_by rejected | AEG-E-018 | ${checks.find(c => c.label.includes("blank_revoked_by"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Expired token rejected | AEG-E-013 | ${checks.find(c => c.label.includes("expired_token"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-canary GATE: no token issued | AEG-E-012 | ${checks.find(c => c.label.includes("non_canary_gate"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Rollback Drill`,
  ``,
  `| Service | Phase after kill | Tokens issued | Verdict |`,
  `|---|---|---|---|`,
  ...drill.services_checked.map(s =>
    `| ${s.service_id} | ${s.phase_after_kill} | ${s.tokens_issued} | ${s.verdict} |`
  ),
  ``,
  `**Overall drill verdict:** ${drill.verdict}`,
  ``,
  `## Canary Success Criteria`,
  ``,
  `| Criterion | Result |`,
  `|---|---|`,
  `| no_read_gates | ${sc.no_read_gates ? "✓ PASS" : "✗ FAIL"} |`,
  `| no_unknown_service_blocks | ${sc.no_unknown_service_blocks ? "✓ PASS" : "✗ FAIL"} |`,
  `| no_token_replay_successes | ${sc.no_token_replay_successes ? "✓ PASS" : "✗ FAIL"} |`,
  `| no_approval_without_reason | ${sc.no_approval_without_reason ? "✓ PASS" : "✗ FAIL"} |`,
  `| no_revoke_without_reason | ${sc.no_revoke_without_reason ? "✓ PASS" : "✗ FAIL"} |`,
  `| rollback_drill_passed | ${sc.rollback_drill_passed === true ? "✓ PASS" : sc.rollback_drill_passed === null ? "— not run" : "✗ FAIL"} |`,
  `| decision_log_has_canary_entries | ${sc.decision_log_has_canary_entries ? "✓ PASS" : "✗ FAIL"} |`,
  `| **all_criteria_met** | **${sc.all_criteria_met ? "✓ PASS" : "✗ FAIL"}** |`,
  ``,
  sc.blockers.length > 0 ? `## Blockers\n\n${sc.blockers.map(b => `- ${b}`).join("\n")}\n` : `## Blockers\n\nNone.\n`,
  `## Expansion Signal`,
  ``,
  `\`\`\``,
  `ready_to_expand: ${status.ready_to_expand}`,
  `edge_check_pass_rate: ${passed.length}/${checks.length}`,
  `rollback_verdict: ${drill.verdict}`,
  ``,
  status.ready_to_expand && failed.length === 0
    ? `All gates clear. Window 3 complete. Ready for 3 → 6 expansion.`
    : `${failed.length} check(s) failed. Resolve before expanding.`,
  `\`\`\``,
  ``,
  `## Window Protocol Status`,
  ``,
  `| Window | Purpose | Status |`,
  `|---|---|---|`,
  `| Window 1 | Synthetic replay (Batch 20 baseline) | complete |`,
  `| Window 2 | Real traffic (Batch 21) | complete |`,
  `| Window 3 | Mixed + edge cases (Batch 22) | ${failed.length === 0 ? "complete" : "FAILED"} |`,
  ``,
  `Expansion step: 3 → 6 services (not 3 → 12).`,
  ``,
  `---`,
  `*AEGIS soft-canary edge-case observation — Batch 22 — @rule:AEG-E-019*`,
];

writeFileSync(
  join(AEGIS_DIR, "batch22_edge_observation_summary.md"),
  mdLines.join("\n"),
);

console.log(`\n── Artifacts ──`);
console.log(`  ${join(AEGIS_DIR, "batch22_edge_observation_summary.md")}`);
console.log(`  ${join(AEGIS_DIR, "batch22_edge_decision_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch22_edge_failures.json")}`);
console.log(`\n  ready_to_expand: ${status.ready_to_expand}`);
console.log(`  edge checks: ${passed.length}/${checks.length} PASS`);
console.log(failed.length === 0
  ? `  Window 3 complete — 3 → 6 expansion gate is clear.`
  : `  ${failed.length} check(s) FAILED — resolve before expanding.`
);
