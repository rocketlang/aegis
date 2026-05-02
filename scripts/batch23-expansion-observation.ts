#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 23 — Soft-canary expansion: 3 → 6 services
// Adds carbonx, parali-central, pramana to the canary set.
// Runs observation + edge checks + rollback drill across all 6.
//
// Expansion criteria (all confirmed in batch23 preamble):
//   carbonx:       TIER-A, external_call, BR-3, no code scan
//   parali-central: TIER-A, external_call, BR-3, no code scan
//   pramana:        TIER-A, read_only, BR-5 — BLOCK→GATE in soft-canary (safe)
//
// Produces:
//   .aegis/batch23_expansion_summary.md
//   .aegis/batch23_decision_counts.json
//   .aegis/batch23_failures.json

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
const { approveToken, denyToken, revokeToken, runRollbackDrill } = await import("../src/enforcement/approval");

// ── Types ─────────────────────────────────────────────────────────────────────
interface CheckResult {
  category: string; label: string; passed: boolean;
  actual: string; expected: string; detail?: string;
}
const checks: CheckResult[] = [];

function check(cat: string, label: string, passed: boolean, actual: string, expected: string, detail?: string) {
  checks.push({ category: cat, label, passed, actual, expected, detail });
  console.log(`  ${passed ? "✓" : "✗"} [${passed ? "PASS" : "FAIL"}] ${label.padEnd(60)} actual=${actual}`);
}

const ALL_6  = ["granthx", "stackpilot", "ankrclaw", "carbonx", "parali-central", "pramana"];
const ORIG_3 = ["granthx", "stackpilot", "ankrclaw"];
const NEW_3  = ["carbonx", "parali-central", "pramana"];

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Expansion eligibility confirmation (live registry read)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Expansion eligibility — new 3 services ──");

const { loadRegistry, isInPilotScope } = await import("../src/enforcement/registry");
const reg = loadRegistry();

for (const svc of NEW_3) {
  const e = reg[svc];
  check("eligibility", `${svc}: in registry`, !!e, e ? "found" : "missing", "found");
  check("eligibility", `${svc}: TIER-A`, e?.runtime_readiness.tier === "TIER-A",
    e?.runtime_readiness.tier ?? "missing", "TIER-A");
  check("eligibility", `${svc}: in pilot scope`, isInPilotScope(svc),
    String(isInPilotScope(svc)), "true");
  const ac = e?.authority_class ?? "";
  const noFinancial = !["financial", "governance"].includes(ac);
  check("eligibility", `${svc}: non-financial authority (${ac})`, noFinancial,
    ac, "not financial/governance");
  check("eligibility", `${svc}: no code scan required`, !e?.needs_code_scan,
    String(e?.needs_code_scan), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Observation traffic — all 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. Observation traffic — all 6 canary services ──");

const observationOps = [
  { operation: "read",    requested_capability: "READ",    expectDecision: "ALLOW", expectPhase: "soft_canary" },
  { operation: "get",     requested_capability: "READ",    expectDecision: "ALLOW", expectPhase: "soft_canary" },
  { operation: "write",   requested_capability: "WRITE",   expectDecision: "ALLOW", expectPhase: "soft_canary" },
  { operation: "execute", requested_capability: "EXECUTE", expectDecision: "GATE",  expectPhase: "soft_canary" },
  { operation: "deploy",  requested_capability: "DEPLOY",  expectDecision: "GATE",  expectPhase: "soft_canary" },
  { operation: "approve", requested_capability: "APPROVE", expectDecision: "GATE",  expectPhase: "soft_canary" },
];

for (const svc of ALL_6) {
  for (const op of observationOps) {
    const d = evaluate({ service_id: svc, operation: op.operation, requested_capability: op.requested_capability, caller_id: "b23-obs" });
    logDecision(d);
    const phaseOk = d.enforcement_phase === op.expectPhase;
    const decOk   = d.decision === op.expectDecision;
    check("observation", `${svc}/${op.operation}`, phaseOk && decOk,
      `${d.decision}/${d.enforcement_phase}`, `${op.expectDecision}/${op.expectPhase}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. New services: BLOCK → GATE softening (pramana has aegis_gate_overall=BLOCK)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. BLOCK → GATE softening for high-blast services ──");

// pramana: read_only authority + BR-5 → critical ops should GATE not BLOCK in soft-canary
const softOps = [
  { operation: "delete",    requested_capability: "delete" },
  { operation: "ai-execute",requested_capability: "ai_execute" },
];
for (const svc of ["pramana", "carbonx", "parali-central"]) {
  for (const op of softOps) {
    const d = evaluate({ service_id: svc, operation: op.operation, requested_capability: op.requested_capability, caller_id: "b23-softening" });
    logDecision(d);
    check("softening", `${svc}/${op.operation}: no hard BLOCK in soft-canary`, d.decision !== "BLOCK",
      d.decision, "GATE|ALLOW|WARN",
      `phase=${d.enforcement_phase}`);
    check("softening", `${svc}/${op.operation}: in soft_canary phase`, d.enforcement_phase === "soft_canary",
      d.enforcement_phase, "soft_canary");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Edge cases for new 3 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. Edge cases — new 3 services ──");

// 4a. READ always ALLOW (AEG-E-002) — even pramana BR-5
for (const svc of NEW_3) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b23-edge" });
  logDecision(d);
  check("edge_new", `${svc}: READ always ALLOW (AEG-E-002)`, d.decision === "ALLOW",
    d.decision, "ALLOW");
}

// 4b. Unknown capability on new services — no BLOCK
for (const svc of NEW_3) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "FROB_UNKNOWN", caller_id: "b23-edge" });
  logDecision(d);
  check("edge_new", `${svc}: unknown_cap no BLOCK`, d.decision !== "BLOCK",
    d.decision, "ALLOW|WARN|GATE");
}

// 4c. Approval lifecycle on new services — GATE + approve with reason
const gateTokens: Array<{ token: string; svc: string; op: string }> = [];
for (const svc of NEW_3) {
  const d = evaluate({ service_id: svc, operation: "execute", requested_capability: "EXECUTE", caller_id: "b23-lifecycle" });
  logDecision(d);
  if (d.decision === "GATE" && d.approval_token) {
    gateTokens.push({ token: d.approval_token, svc, op: "execute" });
  }
  check("edge_new", `${svc}: EXECUTE produces GATE+token`, d.decision === "GATE" && !!d.approval_token,
    `${d.decision}/${d.approval_token ? "token_issued" : "no_token"}`, "GATE/token_issued");
}

// Approve all gate tokens with proper attribution
for (const g of gateTokens) {
  const r = approveToken(g.token, `Batch 23 expansion approval — ${g.op} on ${g.svc} reviewed`, "capt.anil.sharma",
    { service_id: g.svc });
  check("edge_new", `${g.svc}: GATE approval accepted`, r.ok,
    r.ok ? "approved" : r.error ?? "error", "approved");
}

// 4d. Blank approval still rejected on new services
{
  const d = evaluate({ service_id: "carbonx", operation: "deploy", requested_capability: "DEPLOY", caller_id: "b23-edge" });
  logDecision(d);
  if (d.approval_token) {
    const r = approveToken(d.approval_token, "", "capt.anil.sharma");
    check("edge_new", "carbonx: blank approval_reason rejected (AEG-E-014)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(d.approval_token, "b23 cleanup", "b23-script");
  }
}

// 4e. Token still bound to its service (AEG-E-016)
{
  const d = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b23-edge" });
  logDecision(d);
  if (d.approval_token) {
    const r = approveToken(d.approval_token, "binding mismatch test", "capt.anil.sharma",
      { service_id: "granthx" }); // wrong service
    check("edge_new", "pramana: wrong service binding rejected (AEG-E-016)", !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error);
    denyToken(d.approval_token, "b23 cleanup", "b23-script");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Original 3 still behave correctly after expansion
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Original 3 unchanged after expansion ──");

for (const svc of ORIG_3) {
  const read = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b23-regression" });
  logDecision(read);
  check("regression", `${svc}: READ still ALLOW`, read.decision === "ALLOW", read.decision, "ALLOW");

  const deploy = evaluate({ service_id: svc, operation: "deploy", requested_capability: "DEPLOY", caller_id: "b23-regression" });
  logDecision(deploy);
  check("regression", `${svc}: DEPLOY still GATE`, deploy.decision === "GATE", deploy.decision, "GATE");
  check("regression", `${svc}: still in soft_canary`, deploy.enforcement_phase === "soft_canary",
    deploy.enforcement_phase, "soft_canary");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Non-canary TIER-A still shadow after expansion
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Non-canary TIER-A still shadow ──");

const stillShadow = ["ankr-doctor", "domain-capture", "ship-slm", "chief-slm", "chirpee", "puranic-os"];
for (const svc of stillShadow) {
  const d = evaluate({ service_id: svc, operation: "deploy", requested_capability: "DEPLOY", caller_id: "b23-shadow" });
  logDecision(d);
  check("shadow_boundary", `${svc}: not in canary (shadow)`, d.enforcement_phase === "shadow",
    d.enforcement_phase, "shadow");
  check("shadow_boundary", `${svc}: in_canary=false`, !d.in_canary,
    String(d.in_canary), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Rollback drill across all 6
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 7. Rollback drill — all 6 services ──");

const drillOps = [
  { operation: "execute", requested_capability: "EXECUTE" },
  { operation: "deploy",  requested_capability: "DEPLOY" },
];
const drill = runRollbackDrill(evaluate, ALL_6, drillOps);
check("rollback", "drill_verdict: PASS", drill.verdict === "PASS", drill.verdict, "PASS");
for (const s of drill.services_checked) {
  check("rollback", `${s.service_id}: shadow after kill`, s.verdict === "ok",
    s.phase_after_kill, "shadow");
  check("rollback", `${s.service_id}: no tokens while killed`, !s.tokens_issued,
    String(s.tokens_issued), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Final canary status — 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 8. Final canary status — 6-service scope ──");
const status = getCanaryStatus(ALL_6);
const sc = status.success_criteria;

check("canary_status", "6/6 service stats present", status.service_stats.length === 6,
  String(status.service_stats.length), "6");
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
const by_category = checks.reduce((acc, c) => {
  if (!acc[c.category]) acc[c.category] = { pass: 0, fail: 0 };
  c.passed ? acc[c.category].pass++ : acc[c.category].fail++;
  return acc;
}, {} as Record<string, { pass: number; fail: number }>);

writeFileSync(join(AEGIS_DIR, "batch23_decision_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch23",
  canary_services: ALL_6,
  scope: "6-service expansion (3→6)",
  total_decisions_in_log: status.total_decisions,
  canary_decisions: status.canary_decisions,
  shadow_decisions: status.shadow_decisions,
  distribution: status.decision_distribution,
  per_service: status.service_stats.map(s => ({
    service_id: s.service_id,
    is_new: NEW_3.includes(s.service_id),
    total: s.total_decisions,
    ALLOW: s.allow, WARN: s.warn, GATE: s.gate, BLOCK: s.block,
    read_gates: s.read_gates,
  })),
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch23_failures.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch23",
  total_checks: checks.length,
  passed: passed.length,
  failed: failed.length,
  ready_to_expand: status.ready_to_expand,
  rollback_drill_verdict: drill.verdict,
  failures: failed.map(f => ({ category: f.category, label: f.label, expected: f.expected, actual: f.actual, detail: f.detail })),
  success_criteria: sc,
  by_category,
}, null, 2));

const mdLines = [
  `# AEGIS Batch 23 — Soft-Canary Expansion: 3 → 6 Services`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Previous canary:** granthx, stackpilot, ankrclaw`,
  `**New additions:** carbonx, parali-central, pramana`,
  `**Full canary:** ${ALL_6.join(", ")}`,
  ``,
  `## Expansion Eligibility`,
  ``,
  `| Service | Tier | Authority Class | Blast Radius | Code Scan | Gate | Approved |`,
  `|---|---|---|---|---|---|---|`,
  ...NEW_3.map(svc => {
    const e = reg[svc];
    return `| ${svc} | ${e?.runtime_readiness.tier} | ${e?.authority_class} | ${e?.governance_blast_radius} | ${e?.needs_code_scan ? "YES" : "no"} | ${e?.aegis_gate.overall} | ✓ |`;
  }),
  ``,
  `> **pramana note:** aegis_gate_overall=BLOCK reflects BR-5 governance blast radius.`,
  `> In soft-canary mode, BLOCK → GATE. Authority class is read_only — no write or deploy authority.`,
  `> Safe to include. GATE forces human review before any operation continues.`,
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
  `| Service | New? | Total | ALLOW | WARN | GATE | BLOCK | READ gates |`,
  `|---|---|---|---|---|---|---|---|`,
  ...status.service_stats.map(s =>
    `| ${s.service_id} | ${NEW_3.includes(s.service_id) ? "**NEW**" : ""} | ${s.total_decisions} | ${s.allow} | ${s.warn} | ${s.gate} | ${s.block} | ${s.read_gates} |`
  ),
  ``,
  `## Invariant Verification`,
  ``,
  `| Invariant | Result |`,
  `|---|---|`,
  `| READ always ALLOW on all 6 (AEG-E-002) | ${NEW_3.every(svc => checks.find(c => c.label.includes(svc) && c.label.includes("READ always"))?.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| BLOCK → GATE in soft-canary (all new) | ${checks.filter(c => c.category === "softening").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown capability: no BLOCK (all new) | ${NEW_3.every(svc => checks.find(c => c.label.includes(svc) && c.label.includes("unknown_cap"))?.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| GATE tokens issued to new services | ${NEW_3.every(svc => checks.find(c => c.label.includes(svc) && c.label.includes("EXECUTE"))?.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank approval still rejected (AEG-E-014) | ${checks.find(c => c.label.includes("blank approval_reason"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Wrong binding still rejected (AEG-E-016) | ${checks.find(c => c.label.includes("wrong service binding"))?.passed ? "✓ PASS" : "✗ FAIL"} |`,
  `| Original 3 unchanged after expansion | ${checks.filter(c => c.category === "regression").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-canary TIER-A still shadow | ${checks.filter(c => c.category === "shadow_boundary").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Rollback Drill — All 6 Services`,
  ``,
  `| Service | Phase after kill | Tokens issued | Verdict |`,
  `|---|---|---|---|`,
  ...drill.services_checked.map(s => `| ${s.service_id} | ${s.phase_after_kill} | ${s.tokens_issued} | ${s.verdict} |`),
  ``,
  `**Overall drill verdict:** ${drill.verdict}`,
  ``,
  `## Success Criteria`,
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
  `## Canary Rollout Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 17 | 3 services | Synthetic replay | complete |`,
  `| Batch 21 | 3 services | Real traffic | complete |`,
  `| Batch 22 | 3 services | Edge cases | complete |`,
  `| **Batch 23** | **6 services** | **Expansion** | **${failed.length === 0 ? "complete" : "FAILED"}** |`,
  `| Batch 24 | 6 services | Observation window | pending |`,
  `| Batch 25 | 6 services | Edge-case window | pending |`,
  `| Batch 26 | 12 services | Full TIER-A expansion | pending |`,
  ``,
  `---`,
  `*AEGIS soft-canary 3→6 expansion — Batch 23 — @rule:AEG-E-001 (shadow→soft→hard; never skip)*`,
];

writeFileSync(join(AEGIS_DIR, "batch23_expansion_summary.md"), mdLines.join("\n"));

console.log(`\n── Artifacts ──`);
console.log(`  ${join(AEGIS_DIR, "batch23_expansion_summary.md")}`);
console.log(`  ${join(AEGIS_DIR, "batch23_decision_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch23_failures.json")}`);
console.log(`\n  Canary scope: ${ALL_6.join(", ")}`);
console.log(`  ready_to_expand: ${status.ready_to_expand}`);
console.log(`  edge checks: ${passed.length}/${checks.length} PASS`);
console.log(failed.length === 0
  ? `  Expansion complete. Batch 24 (6-service observation window) is next.`
  : `  ${failed.length} check(s) FAILED — resolve before next step.`
);
