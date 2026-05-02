#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 25 — 6-service rough-weather canary window
// Final gate before 6 → 12 expansion.
// Same abuse categories as Batch 22, applied across all 6 canary services.
//
// Categories:
//   1. Normal regression (all 6)
//   2. High-risk ops (all 6)
//   3. Bad-input (all 6 + boundary)
//   4. Approval lifecycle edge cases (all 6, representative coverage)
//   5. Rollback drill (all 6)
//
// Produces:
//   .aegis/batch25_rough_weather_summary.md
//   .aegis/batch25_decision_counts.json
//   .aegis/batch25_approval_counts.json
//   .aegis/batch25_failures.json

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// ── Live canary flags: 6-service scope ───────────────────────────────────────
process.env.AEGIS_RUNTIME_ENABLED      = "true";
process.env.AEGIS_ENFORCEMENT_MODE     = "soft";
process.env.AEGIS_DRY_RUN              = "false";
process.env.AEGIS_SOFT_CANARY_SERVICES = "granthx,stackpilot,ankrclaw,carbonx,parali-central,pramana";

const HOME = process.env.HOME ?? "/root";
const AEGIS_DIR = join(HOME, ".aegis");
if (!existsSync(AEGIS_DIR)) mkdirSync(AEGIS_DIR, { recursive: true });
process.env.AEGIS_DECISION_LOG_PATH = join(AEGIS_DIR, "aegis_decisions.log");
process.env.AEGIS_APPROVAL_LOG_PATH = join(AEGIS_DIR, "aegis_approval.log");

// ── Import AFTER env ──────────────────────────────────────────────────────────
const { evaluate } = await import("../src/enforcement/gate");
const { logDecision } = await import("../src/enforcement/logger");
const { getCanaryStatus } = await import("../src/enforcement/canary-status");
const { approveToken, denyToken, revokeToken, getApproval, consumeToken, runRollbackDrill } =
  await import("../src/enforcement/approval");

// ── Types ─────────────────────────────────────────────────────────────────────
interface CheckResult {
  category: string; label: string; passed: boolean;
  actual: string; expected: string; detail?: string;
}
const checks: CheckResult[] = [];

function check(cat: string, label: string, passed: boolean, actual: string, expected: string, detail?: string) {
  checks.push({ category: cat, label, passed, actual, expected, detail });
  console.log(`  ${passed ? "✓" : "✗"} [${passed ? "PASS" : "FAIL"}] ${label.padEnd(65)} actual=${actual}`);
}

const ALL_6  = ["granthx", "stackpilot", "ankrclaw", "carbonx", "parali-central", "pramana"];
const ORIG_3 = ["granthx", "stackpilot", "ankrclaw"];
const NEW_3  = ["carbonx", "parali-central", "pramana"];

function gate(svc: string, op: string, cap: string, callerId = "b25") {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: callerId });
  logDecision(d);
  return d;
}

// Cycle through services for representative lifecycle coverage
function svcAt(i: number) { return ALL_6[i % ALL_6.length]; }

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Normal regression — all 6
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Normal regression (all 6 services) ──");

const normalOps = [
  { op: "read",    cap: "READ",    expectDecision: "ALLOW", expectPhase: "soft_canary" },
  { op: "write",   cap: "WRITE",   expectDecision: "ALLOW", expectPhase: "soft_canary" },
  { op: "approve", cap: "APPROVE", expectDecision: "GATE",  expectPhase: "soft_canary" },
];

for (const svc of ALL_6) {
  for (const { op, cap, expectDecision, expectPhase } of normalOps) {
    const d = gate(svc, op, cap, "b25-normal");
    check("normal", `${svc}/${op}`,
      d.decision === expectDecision && d.enforcement_phase === expectPhase,
      `${d.decision}/${d.enforcement_phase}`, `${expectDecision}/${expectPhase}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. High-risk — all 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. High-risk traffic (all 6 services) ──");

const highRiskOps = [
  { op: "execute",    cap: "EXECUTE",    label: "EXECUTE" },
  { op: "deploy",     cap: "DEPLOY",     label: "DEPLOY" },
  { op: "delete",     cap: "delete",     label: "DELETE" },
  { op: "ai-execute", cap: "ai_execute", label: "AI_EXECUTE" },
  { op: "tool_call",  cap: "tool_call",  label: "TOOL_CALL" },
  { op: "rollout",    cap: "rollout",    label: "ROLLOUT" },
];

for (const svc of ALL_6) {
  for (const { op, cap, label } of highRiskOps) {
    const d = gate(svc, op, cap, "b25-highrisk");
    const noHardBlock = d.decision !== "BLOCK";
    const inCanary    = d.enforcement_phase === "soft_canary";
    check("high_risk", `${svc}/${label}: GATE not BLOCK`,
      noHardBlock && inCanary,
      `${d.decision}/${d.enforcement_phase}`, `GATE/soft_canary`,
      `cap=${d.requested_capability}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Bad inputs — one representative per service + boundary cases
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. Bad inputs ──");

// 3a. Unknown capability — one per service, no BLOCK
for (const svc of ALL_6) {
  const d = gate(svc, "frob", "FROB_UNKNOWN", "b25-bad");
  check("bad_input", `${svc}: unknown_cap no BLOCK`, d.decision !== "BLOCK",
    d.decision, "ALLOW|WARN|GATE");
}

// 3b. Lowercase capability — normalises correctly (test on new 3 specifically)
for (const svc of NEW_3) {
  const d = gate(svc, "write", "write", "b25-bad");
  check("bad_input", `${svc}: lowercase_cap normalised`, d.requested_capability === "WRITE",
    d.requested_capability, "WRITE");
}

// 3c. Alias: run_agent → AI_EXECUTE on each service
for (const svc of ALL_6) {
  const d = gate(svc, "run_agent", "run_agent", "b25-bad");
  check("bad_input", `${svc}: run_agent→AI_EXECUTE normalised`, d.requested_capability === "AI_EXECUTE",
    d.requested_capability, "AI_EXECUTE");
  check("bad_input", `${svc}: run_agent→AI_EXECUTE no BLOCK`, d.decision !== "BLOCK",
    d.decision, "GATE");
}

// 3d. Empty capability — no crash, valid decision
for (const svc of NEW_3) {
  const d = gate(svc, "write", "", "b25-bad");
  check("bad_input", `${svc}: empty_cap no crash`, typeof d.decision === "string",
    d.decision, "any-valid");
}

// 3e. Empty operation — no crash
for (const svc of NEW_3) {
  const d = gate(svc, "", "WRITE", "b25-bad");
  check("bad_input", `${svc}: empty_op no crash`, typeof d.decision === "string",
    d.decision, "any-valid");
}

// 3f. Unknown service — shadow WARN, never BLOCK
{
  const d = gate("svc-does-not-exist-b25", "deploy", "DEPLOY", "b25-bad");
  check("bad_input", "unknown_service: WARN not BLOCK", d.decision === "WARN",
    `${d.decision}/${d.enforcement_phase}`, "WARN/shadow");
  check("bad_input", "unknown_service: not in canary", !d.in_canary,
    String(d.in_canary), "false");
}

// 3g. Non-canary TIER-A (ankr-doctor, ship-slm) → shadow
for (const svc of ["ankr-doctor", "ship-slm"]) {
  const d = gate(svc, "deploy", "DEPLOY", "b25-bad");
  check("bad_input", `${svc}: non-canary TIER-A stays shadow`, d.enforcement_phase === "shadow",
    `${d.enforcement_phase}/${d.in_canary}`, "shadow/false");
  check("bad_input", `${svc}: no token issued in shadow`, !d.approval_token,
    d.approval_token ? "token_issued" : "no_token", "no_token");
}

// 3h. Non-TIER-A (freightbox=TIER-B) — no BLOCK
{
  const d = gate("freightbox", "execute", "EXECUTE", "b25-bad");
  check("bad_input", "non_tier_a (freightbox): no hard BLOCK", d.decision !== "BLOCK",
    `${d.decision}/${d.enforcement_phase}`, "WARN|ALLOW/shadow");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Approval lifecycle edge cases — representative across all 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. Approval lifecycle edge cases ──");

function issueGate(svc: string, op = "execute", cap = "EXECUTE"): string | null {
  const d = gate(svc, op, cap, "b25-lifecycle");
  return d.approval_token ?? null;
}

// 4a. Blank approval_reason — rejected on all 6 (AEG-E-014)
console.log("  4a. Blank approval_reason — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    const r = approveToken(token, "", "capt.anil.sharma");
    check("lifecycle", `${svc}: blank_approval_reason rejected`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
    denyToken(token, "b25 cleanup", "b25-script");
  }
}

// 4b. Blank approved_by — rejected on 3 representative services
console.log("  4b. Blank approved_by — representative services");
for (const svc of ["granthx", "carbonx", "pramana"]) {
  const token = issueGate(svc);
  if (token) {
    const r = approveToken(token, "valid reason", "");
    check("lifecycle", `${svc}: blank_approved_by rejected`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
    denyToken(token, "b25 cleanup", "b25-script");
  }
}

// 4c. Token replay — rejected on all 6 (AEG-E-015)
console.log("  4c. Token replay — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    const r1 = approveToken(token, `Batch 25 replay test first approval — ${svc}`, "capt.anil.sharma");
    const r2 = approveToken(token, "replay attempt", "capt.anil.sharma");
    check("lifecycle", `${svc}: replay_first approved`, r1.ok,
      r1.ok ? "accepted" : "rejected", "accepted");
    check("lifecycle", `${svc}: replay_second rejected (AEG-E-015)`, !r2.ok,
      r2.ok ? "accepted" : "rejected", "rejected", r2.error?.slice(0, 60));
  }
}

// 4d. Wrong service binding — rejected on all 6 (AEG-E-016)
console.log("  4d. Wrong service binding — all 6 services");
for (let i = 0; i < ALL_6.length; i++) {
  const svc = ALL_6[i];
  const wrongSvc = ALL_6[(i + 1) % ALL_6.length]; // shift by one
  const token = issueGate(svc, "deploy", "DEPLOY");
  if (token) {
    const r = approveToken(token, "binding mismatch test", "capt.anil.sharma",
      { service_id: wrongSvc });
    check("lifecycle", `${svc}: wrong binding (→${wrongSvc}) rejected (AEG-E-016)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
    denyToken(token, "b25 cleanup", "b25-script");
  }
}

// 4e. Denied token → re-approve rejected on all 6 (AEG-E-017)
console.log("  4e. Denied token re-approve — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    denyToken(token, `risk assessment pending for ${svc}`, "capt.anil.sharma");
    const r = approveToken(token, "trying after denial", "capt.anil.sharma");
    check("lifecycle", `${svc}: denied→reapprove rejected (AEG-E-017)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
  }
}

// 4f. Revoked token → re-approve rejected on all 6 (AEG-E-018)
console.log("  4f. Revoked token re-approve — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    revokeToken(token, "capt.anil.sharma", `b25 revocation — ${svc} operation held`);
    const r = approveToken(token, "trying after revoke", "capt.anil.sharma");
    check("lifecycle", `${svc}: revoked→reapprove rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
  }
}

// 4g. Blank revoke_reason — rejected on all 6 (AEG-E-018)
console.log("  4g. Blank revoke_reason — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    const r = revokeToken(token, "capt.anil.sharma", "");
    check("lifecycle", `${svc}: blank_revoke_reason rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
    denyToken(token, "b25 cleanup", "b25-script");
  }
}

// 4h. Blank revoked_by — rejected on all 6 (AEG-E-018)
console.log("  4h. Blank revoked_by — all 6 services");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    const r = revokeToken(token, "", "valid reason");
    check("lifecycle", `${svc}: blank_revoked_by rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
    denyToken(token, "b25 cleanup", "b25-script");
  }
}

// 4i. Expired token — rejected (AEG-E-013), one per group (orig/new)
console.log("  4i. Expired token — orig 3 + new 3");
for (const svc of ALL_6) {
  const token = issueGate(svc);
  if (token) {
    const record = getApproval(token);
    if (record) {
      record.expires_at = new Date(Date.now() - 1000).toISOString();
      record.status = "pending"; // reset so markExpiredLazily can fire
    }
    const r = approveToken(token, "late approval attempt", "capt.anil.sharma");
    check("lifecycle", `${svc}: expired_token rejected (AEG-E-013)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 60));
  }
}

// 4j. Non-canary GATE: no token issued in shadow
console.log("  4j. Non-canary GATE: no token issued");
for (const svc of ["ankr-doctor", "domain-capture", "chirpee"]) {
  const d = gate(svc, "deploy", "DEPLOY", "b25-notoken");
  check("lifecycle", `${svc}: shadow GATE issues no token`, !d.approval_token,
    d.approval_token ? "token_issued" : "no_token", "no_token",
    `phase=${d.enforcement_phase}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Rollback drill — all 6
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Rollback drill — all 6 services ──");

const drill = runRollbackDrill(evaluate, ALL_6, [
  { operation: "execute",    requested_capability: "EXECUTE" },
  { operation: "deploy",     requested_capability: "DEPLOY" },
  { operation: "ai-execute", requested_capability: "ai_execute" },
]);
check("rollback", "drill_verdict: PASS", drill.verdict === "PASS", drill.verdict, "PASS");
for (const s of drill.services_checked) {
  check("rollback", `${s.service_id}: shadow after kill`, s.verdict === "ok",
    s.phase_after_kill, "shadow");
  check("rollback", `${s.service_id}: no tokens while killed`, !s.tokens_issued,
    String(s.tokens_issued), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Final canary status — 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Final canary status ──");
const status = getCanaryStatus(ALL_6);
const sc = status.success_criteria;

check("canary_status", "6/6 service stats", status.service_stats.length === 6,
  String(status.service_stats.length), "6");
check("canary_status", "no_read_gates", sc.no_read_gates, String(sc.no_read_gates), "true");
check("canary_status", "no_unknown_service_blocks", sc.no_unknown_service_blocks, String(sc.no_unknown_service_blocks), "true");
check("canary_status", "no_token_replay_successes", sc.no_token_replay_successes, String(sc.no_token_replay_successes), "true");
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

const by_category = checks.reduce((acc, c) => {
  if (!acc[c.category]) acc[c.category] = { pass: 0, fail: 0 };
  c.passed ? acc[c.category].pass++ : acc[c.category].fail++;
  return acc;
}, {} as Record<string, { pass: number; fail: number }>);

console.log(`\n══ Summary ══`);
console.log(`  Total checks:    ${checks.length}`);
console.log(`  PASS:            ${passed.length}`);
console.log(`  FAIL:            ${failed.length}`);
console.log(`  ready_to_expand: ${status.ready_to_expand}`);

if (failed.length > 0) {
  console.log(`\n  Failures:`);
  for (const f of failed) {
    console.log(`    ✗ [${f.category}] ${f.label}: expected=${f.expected} actual=${f.actual}${f.detail ? ` (${f.detail})` : ""}`);
  }
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
writeFileSync(join(AEGIS_DIR, "batch25_decision_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch25",
  scope: "6-service rough-weather window",
  canary_services: ALL_6,
  cumulative_log: {
    total: status.total_decisions,
    canary: status.canary_decisions,
    shadow: status.shadow_decisions,
    distribution: status.decision_distribution,
  },
  per_service: status.service_stats.map(s => ({
    service_id: s.service_id,
    group: NEW_3.includes(s.service_id) ? "new" : "orig",
    total: s.total_decisions,
    ALLOW: s.allow, WARN: s.warn, GATE: s.gate, BLOCK: s.block,
    read_gates: s.read_gates,
  })),
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch25_approval_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch25",
  checks_by_category: by_category,
  lifecycle_checks: checks.filter(c => c.category === "lifecycle").length,
  lifecycle_pass: checks.filter(c => c.category === "lifecycle" && c.passed).length,
  lifecycle_fail: checks.filter(c => c.category === "lifecycle" && !c.passed).length,
  store_snapshot: {
    pending: status.approval_pending,
    approved: status.approval_approved,
    consumed: status.approval_consumed,
    denied: status.approval_denied,
    expired: status.approval_expired,
    revoked: status.approval_revoked,
  },
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch25_failures.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch25",
  total_checks: checks.length,
  passed: passed.length,
  failed: failed.length,
  ready_to_expand: status.ready_to_expand,
  rollback_verdict: drill.verdict,
  by_category,
  failures: failed.map(f => ({ category: f.category, label: f.label, expected: f.expected, actual: f.actual, detail: f.detail })),
  success_criteria: sc,
  blockers: sc.blockers,
}, null, 2));

// ── Summary MD ────────────────────────────────────────────────────────────────
// Derive per-invariant results from check labels for the table
function allPass(labelFragment: string) {
  const relevant = checks.filter(c => c.label.includes(labelFragment));
  return relevant.length > 0 && relevant.every(c => c.passed);
}

const mdLines = [
  `# AEGIS Batch 25 — 6-Service Rough-Weather Canary Window`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Canary services:** ${ALL_6.join(", ")}`,
  `**Purpose:** Final gate before 6 → 12 expansion`,
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
  `## Decision Distribution (cumulative log)`,
  ``,
  `| Service | Group | Total | ALLOW | WARN | GATE | BLOCK | READ gates |`,
  `|---|---|---|---|---|---|---|---|`,
  ...status.service_stats.map(s =>
    `| ${s.service_id} | ${NEW_3.includes(s.service_id) ? "new" : "orig"} | ${s.total_decisions} | ${s.allow} | ${s.warn} | ${s.gate} | ${s.block} | ${s.read_gates} |`
  ),
  ``,
  `## Invariant Verification`,
  ``,
  `| Invariant | Scope | Result |`,
  `|---|---|---|`,
  `| READ always ALLOW (AEG-E-002) | all 6 | ${checks.filter(c => c.label.includes("/read") && c.category === "normal").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| High-risk: GATE not BLOCK | all 6 × 6 ops | ${checks.filter(c => c.category === "high_risk" && c.label.includes("GATE not BLOCK")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown capability: no BLOCK | all 6 | ${checks.filter(c => c.label.includes("unknown_cap no BLOCK")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Lowercase cap normalises | new 3 | ${checks.filter(c => c.label.includes("lowercase_cap")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| run_agent → AI_EXECUTE | all 6 | ${checks.filter(c => c.label.includes("run_agent→AI_EXECUTE")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Empty cap: no crash | new 3 | ${checks.filter(c => c.label.includes("empty_cap")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Empty op: no crash | new 3 | ${checks.filter(c => c.label.includes("empty_op")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown service: WARN/shadow | 1 check | ${checks.filter(c => c.label.includes("unknown_service")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-canary TIER-A: shadow, no token | ankr-doctor, ship-slm | ${checks.filter(c => c.label.includes("non-canary TIER-A") || c.label.includes("ankr-doctor") || c.label.includes("ship-slm")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Approval Lifecycle Verification`,
  ``,
  `| Edge Case | Rule | Scope | Result |`,
  `|---|---|---|---|`,
  `| Blank approval_reason rejected | AEG-E-014 | all 6 | ${checks.filter(c => c.label.includes("blank_approval_reason")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank approved_by rejected | AEG-E-014 | 3 svc | ${checks.filter(c => c.label.includes("blank_approved_by")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Token replay rejected | AEG-E-015 | all 6 | ${checks.filter(c => c.label.includes("replay_second rejected")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Wrong service binding rejected | AEG-E-016 | all 6 | ${checks.filter(c => c.label.includes("wrong binding")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Denied → re-approve rejected | AEG-E-017 | all 6 | ${checks.filter(c => c.label.includes("denied→reapprove rejected")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Revoked → re-approve rejected | AEG-E-018 | all 6 | ${checks.filter(c => c.label.includes("revoked→reapprove rejected")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoke_reason rejected | AEG-E-018 | all 6 | ${checks.filter(c => c.label.includes("blank_revoke_reason")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoked_by rejected | AEG-E-018 | all 6 | ${checks.filter(c => c.label.includes("blank_revoked_by")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Expired token rejected | AEG-E-013 | all 6 | ${checks.filter(c => c.label.includes("expired_token")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-canary GATE: no token | shadow svcs | ${checks.filter(c => c.label.includes("shadow GATE issues no token")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Rollback Drill — All 6 Services`,
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
  `## Rollout Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 17 | 3 svc | Synthetic replay | complete |`,
  `| Batch 21 | 3 svc | Real traffic | complete |`,
  `| Batch 22 | 3 svc | Rough weather | complete |`,
  `| Batch 23 | 6 svc | Expansion | complete |`,
  `| Batch 24 | 6 svc | Observation window | complete |`,
  `| **Batch 25** | **6 svc** | **Rough weather** | **${failed.length === 0 ? "complete" : "FAILED"}** |`,
  `| Batch 26 | 12 svc | Full TIER-A expansion | ${failed.length === 0 ? "gate clear" : "BLOCKED"} |`,
  ``,
  `---`,
  `*AEGIS soft-canary 6-service rough-weather — Batch 25 — @rule:AEG-E-019*`,
];

writeFileSync(join(AEGIS_DIR, "batch25_rough_weather_summary.md"), mdLines.join("\n"));

console.log(`\n── Artifacts ──`);
console.log(`  ${join(AEGIS_DIR, "batch25_rough_weather_summary.md")}`);
console.log(`  ${join(AEGIS_DIR, "batch25_decision_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch25_approval_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch25_failures.json")}`);
console.log(`\n  6-service rough-weather: ${failed.length === 0 ? "CLEAN — Batch 26 (6→12 expansion) gate is clear." : `${failed.length} FAILURE(S) — resolve before expanding.`}`);
