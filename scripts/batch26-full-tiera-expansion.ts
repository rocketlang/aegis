#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 26 — Full TIER-A soft-canary expansion: 6 → 12 services
// Adds ankr-doctor, domain-capture, ship-slm, chief-slm, chirpee, puranic-os.
// Runs eligibility check, observation, rough-weather, lifecycle, and rollback
// across all 12. Still soft only — hard mode is Batch 30+ territory.
//
// Expansion notes on new 6:
//   ankr-doctor:     governance class + BR-5; aegis_gate=GATE (already gated)
//   domain-capture:  read_only, BR-5; BLOCK→GATE in soft-canary
//   ship-slm:        read_only, BR-0; BLOCK→GATE in soft-canary
//   chief-slm:       read_only, BR-0; BLOCK→GATE in soft-canary
//   chirpee:         read_only, BR-0; BLOCK→GATE in soft-canary
//   puranic-os:      read_only, BR-1; BLOCK→GATE in soft-canary
//
// Produces:
//   .aegis/batch26_full_tiera_expansion_summary.md
//   .aegis/batch26_decision_counts.json
//   .aegis/batch26_approval_counts.json
//   .aegis/batch26_failures.json

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// ── Live canary flags: full 12-service TIER-A scope ──────────────────────────
process.env.AEGIS_RUNTIME_ENABLED      = "true";
process.env.AEGIS_ENFORCEMENT_MODE     = "soft";
process.env.AEGIS_DRY_RUN              = "false";
process.env.AEGIS_SOFT_CANARY_SERVICES = [
  "granthx", "stackpilot", "ankrclaw",
  "carbonx", "parali-central", "pramana",
  "ankr-doctor", "domain-capture", "ship-slm",
  "chief-slm", "chirpee", "puranic-os",
].join(",");

const HOME = process.env.HOME ?? "/root";
const AEGIS_DIR = join(HOME, ".aegis");
if (!existsSync(AEGIS_DIR)) mkdirSync(AEGIS_DIR, { recursive: true });
process.env.AEGIS_DECISION_LOG_PATH = join(AEGIS_DIR, "aegis_decisions.log");
process.env.AEGIS_APPROVAL_LOG_PATH = join(AEGIS_DIR, "aegis_approval.log");

// ── Import AFTER env ──────────────────────────────────────────────────────────
const { evaluate } = await import("../src/enforcement/gate");
const { logDecision } = await import("../src/enforcement/logger");
const { getCanaryStatus } = await import("../src/enforcement/canary-status");
const { approveToken, denyToken, revokeToken, getApproval, runRollbackDrill } =
  await import("../src/enforcement/approval");
const { loadRegistry, isInPilotScope } = await import("../src/enforcement/registry");

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

const ORIG_6 = ["granthx", "stackpilot", "ankrclaw", "carbonx", "parali-central", "pramana"];
const NEW_6  = ["ankr-doctor", "domain-capture", "ship-slm", "chief-slm", "chirpee", "puranic-os"];
const ALL_12 = [...ORIG_6, ...NEW_6];

function gate(svc: string, op: string, cap: string, callerId = "b26") {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: callerId });
  logDecision(d);
  return d;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Expansion eligibility — new 6 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 1. Expansion eligibility — new 6 services ──");

const reg = loadRegistry();

for (const svc of NEW_6) {
  const e = reg[svc];
  check("eligibility", `${svc}: in registry`, !!e, e ? "found" : "missing", "found");
  check("eligibility", `${svc}: TIER-A`, e?.runtime_readiness.tier === "TIER-A",
    e?.runtime_readiness.tier ?? "missing", "TIER-A");
  check("eligibility", `${svc}: in pilot scope`, isInPilotScope(svc),
    String(isInPilotScope(svc)), "true");

  const ac = e?.authority_class ?? "";
  // governance is allowed with a gate — it's the mechanism that makes governance-class safe
  const notFinancial = ac !== "financial";
  check("eligibility", `${svc}: not financial authority (${ac})`, notFinancial,
    ac, "not financial");
  if (ac === "governance") {
    check("eligibility", `${svc}: governance+GATE is safe (gate holds authority)`,
      e?.aegis_gate.overall === "GATE",
      e?.aegis_gate.overall ?? "missing", "GATE",
      "governance ops require human gate — soft-canary is the right place to prove this");
  }
  check("eligibility", `${svc}: no code scan required`, !e?.needs_code_scan,
    String(e?.needs_code_scan), "false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Observation traffic — all 12
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 2. Observation traffic — all 12 TIER-A services ──");

// Expected execute decision depends on authority class + blast radius:
// read_only + BR-0/BR-1 → ALLOW (no gate trigger: not high-authority, BR < 3)
// governance/deploy/financial OR BR≥3 OR human_gate_required → GATE
function expectedExecuteDecision(svc: string): string {
  const e = reg[svc];
  if (!e) return "WARN";
  const highAuthority = ["financial", "governance", "deploy"].includes(e.authority_class);
  const highBlast = parseInt(e.governance_blast_radius.replace("BR-", "") || "0", 10) >= 3;
  if (e.human_gate_required || highAuthority || highBlast) return "GATE";
  return "ALLOW"; // read_only + low blast → passes through
}

const observeReadWrite = [
  { op: "read",  cap: "READ",  expectDecision: "ALLOW" },
  { op: "get",   cap: "READ",  expectDecision: "ALLOW" },
  { op: "list",  cap: "READ",  expectDecision: "ALLOW" },
  { op: "write", cap: "WRITE", expectDecision: "ALLOW" },
  { op: "deploy",cap: "DEPLOY",expectDecision: "GATE"  },
];

for (const svc of ALL_12) {
  for (const { op, cap, expectDecision } of observeReadWrite) {
    const d = gate(svc, op, cap, "b26-obs");
    check("observation", `${svc}/${op}`,
      d.decision === expectDecision && d.enforcement_phase === "soft_canary",
      `${d.decision}/${d.enforcement_phase}`, `${expectDecision}/soft_canary`);
  }
  // execute: per-service expected decision
  const execExpect = expectedExecuteDecision(svc);
  const de = gate(svc, "execute", "EXECUTE", "b26-obs");
  check("observation", `${svc}/execute`,
    de.decision === execExpect && de.enforcement_phase === "soft_canary",
    `${de.decision}/${de.enforcement_phase}`, `${execExpect}/soft_canary`,
    `authority=${reg[svc]?.authority_class} blast=${reg[svc]?.governance_blast_radius}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. BLOCK → GATE softening — new 6 (5 have aegis_gate_overall=BLOCK)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 3. BLOCK → GATE softening — new 6 services ──");

const softenOps = [
  { op: "delete",    cap: "delete" },
  { op: "ai-execute",cap: "ai_execute" },
  { op: "rollout",   cap: "rollout" },
];
for (const svc of NEW_6) {
  for (const { op, cap } of softenOps) {
    const d = gate(svc, op, cap, "b26-soften");
    check("softening", `${svc}/${op}: no BLOCK in soft-canary`, d.decision !== "BLOCK",
      `${d.decision}/${d.enforcement_phase}`, "GATE/soft_canary",
      `aegis_gate=${reg[svc]?.aegis_gate.overall}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. READ always ALLOW — new 6 (AEG-E-002)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 4. READ always ALLOW — new 6 (AEG-E-002) ──");

for (const svc of NEW_6) {
  for (const { op, cap } of [
    { op: "read", cap: "READ" }, { op: "get", cap: "READ" }, { op: "list", cap: "READ" }
  ]) {
    const d = gate(svc, op, cap, "b26-read");
    check("read_always_allow", `${svc}/${op}: ALLOW`, d.decision === "ALLOW",
      d.decision, "ALLOW");
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Bad-input invariants — new 6
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 5. Bad inputs — new 6 services ──");

for (const svc of NEW_6) {
  const d = gate(svc, "frob", "FROB_UNKNOWN", "b26-bad");
  check("bad_input", `${svc}: unknown_cap no BLOCK`, d.decision !== "BLOCK",
    d.decision, "ALLOW|WARN|GATE");
}
for (const svc of NEW_6) {
  const d = gate(svc, "run_agent", "run_agent", "b26-bad");
  check("bad_input", `${svc}: run_agent→AI_EXECUTE normalised`, d.requested_capability === "AI_EXECUTE",
    d.requested_capability, "AI_EXECUTE");
  check("bad_input", `${svc}: run_agent no BLOCK`, d.decision !== "BLOCK",
    d.decision, "GATE");
}
for (const svc of NEW_6) {
  const d = gate(svc, "write", "", "b26-bad");
  check("bad_input", `${svc}: empty_cap no crash`, typeof d.decision === "string",
    d.decision, "any-valid");
}
// Unknown service still WARN/shadow
{
  const d = gate("svc-b26-unknown", "deploy", "DEPLOY", "b26-bad");
  check("bad_input", "unknown_service: WARN/shadow not BLOCK",
    d.decision === "WARN" && d.enforcement_phase === "shadow",
    `${d.decision}/${d.enforcement_phase}`, "WARN/shadow");
}
// Non-TIER-A service
{
  const d = gate("freightbox", "execute", "EXECUTE", "b26-bad");
  check("bad_input", "non_tier_a (freightbox): no BLOCK", d.decision !== "BLOCK",
    `${d.decision}/${d.enforcement_phase}`, "WARN|ALLOW/shadow");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Approval lifecycle — new 6 services (full rule set)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 6. Approval lifecycle — new 6 services ──");

function issueGate(svc: string, op = "execute", cap = "EXECUTE"): string | null {
  const d = gate(svc, op, cap, "b26-lifecycle");
  return d.approval_token ?? null;
}

// 6a. Blank approval_reason — all 6 new services (AEG-E-014)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    const r = approveToken(token, "", "capt.anil.sharma");
    check("lifecycle", `${svc}: blank_reason rejected (AEG-E-014)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
    denyToken(token, "b26 cleanup", "b26-script");
  }
}

// 6b. Token replay — all 6 new (AEG-E-015)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    const r1 = approveToken(token, `Batch 26 expansion approval — ${svc} execute reviewed`, "capt.anil.sharma");
    const r2 = approveToken(token, "replay attempt", "capt.anil.sharma");
    check("lifecycle", `${svc}: replay_first approved`, r1.ok, r1.ok ? "accepted" : "rejected", "accepted");
    check("lifecycle", `${svc}: replay_second rejected (AEG-E-015)`, !r2.ok,
      r2.ok ? "accepted" : "rejected", "rejected", r2.error?.slice(0, 55));
  }
}

// 6c. Wrong service binding — all 6 new, cycled shift (AEG-E-016)
for (let i = 0; i < NEW_6.length; i++) {
  const svc = NEW_6[i];
  const wrongSvc = NEW_6[(i + 1) % NEW_6.length];
  const token = issueGate(svc, "deploy", "DEPLOY");
  if (token) {
    const r = approveToken(token, "binding mismatch", "capt.anil.sharma", { service_id: wrongSvc });
    check("lifecycle", `${svc}: wrong_binding (→${wrongSvc}) rejected (AEG-E-016)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
    denyToken(token, "b26 cleanup", "b26-script");
  }
}

// 6d. Denied → re-approve rejected — all 6 new (AEG-E-017)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    denyToken(token, `b26 risk hold on ${svc}`, "capt.anil.sharma");
    const r = approveToken(token, "trying after denial", "capt.anil.sharma");
    check("lifecycle", `${svc}: denied→reapprove rejected (AEG-E-017)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
  }
}

// 6e. Revoked → re-approve rejected — all 6 new (AEG-E-018)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    revokeToken(token, "capt.anil.sharma", `b26 revoke hold on ${svc}`);
    const r = approveToken(token, "trying after revoke", "capt.anil.sharma");
    check("lifecycle", `${svc}: revoked→reapprove rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
  }
}

// 6f. Blank revoke_reason — all 6 new (AEG-E-018)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    const r = revokeToken(token, "capt.anil.sharma", "");
    check("lifecycle", `${svc}: blank_revoke_reason rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
    denyToken(token, "b26 cleanup", "b26-script");
  }
}

// 6g. Blank revoked_by — all 6 new (AEG-E-018)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    const r = revokeToken(token, "", "valid reason");
    check("lifecycle", `${svc}: blank_revoked_by rejected (AEG-E-018)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
    denyToken(token, "b26 cleanup", "b26-script");
  }
}

// 6h. Expired token — all 6 new (AEG-E-013)
for (const svc of NEW_6) {
  const token = issueGate(svc);
  if (token) {
    const record = getApproval(token);
    if (record) {
      record.expires_at = new Date(Date.now() - 1000).toISOString();
      record.status = "pending";
    }
    const r = approveToken(token, "late approval", "capt.anil.sharma");
    check("lifecycle", `${svc}: expired_token rejected (AEG-E-013)`, !r.ok,
      r.ok ? "accepted" : "rejected", "rejected", r.error?.slice(0, 55));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. Regression — original 6 unchanged after expansion to 12
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 7. Regression — original 6 unchanged ──");

for (const svc of ORIG_6) {
  const read   = gate(svc, "read",   "READ",    "b26-regression");
  const write  = gate(svc, "write",  "WRITE",   "b26-regression");
  const deploy = gate(svc, "deploy", "DEPLOY",  "b26-regression");
  check("regression", `${svc}: READ=ALLOW/soft_canary`,
    read.decision === "ALLOW" && read.enforcement_phase === "soft_canary",
    `${read.decision}/${read.enforcement_phase}`, "ALLOW/soft_canary");
  check("regression", `${svc}: WRITE=ALLOW/soft_canary`,
    write.decision === "ALLOW" && write.enforcement_phase === "soft_canary",
    `${write.decision}/${write.enforcement_phase}`, "ALLOW/soft_canary");
  check("regression", `${svc}: DEPLOY=GATE/soft_canary`,
    deploy.decision === "GATE" && deploy.enforcement_phase === "soft_canary",
    `${deploy.decision}/${deploy.enforcement_phase}`, "GATE/soft_canary");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Non-TIER-A services remain shadow (sample)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 8. Non-TIER-A services — still shadow ──");

const nonTierA = ["freightbox", "mari8x-community", "ankr-academy", "svc-b26-nonexist"];
for (const svc of nonTierA) {
  const d = gate(svc, "deploy", "DEPLOY", "b26-boundary");
  check("shadow_boundary", `${svc}: not in canary`,
    d.enforcement_phase === "shadow" && !d.in_canary,
    `${d.enforcement_phase}/${d.in_canary}`, "shadow/false");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Rollback drill — all 12
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 9. Rollback drill — all 12 TIER-A services ──");

const drill = runRollbackDrill(evaluate, ALL_12, [
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
// 10. Final canary status — 12 services
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── 10. Final canary status — 12-service scope ──");
const status = getCanaryStatus(ALL_12);
const sc = status.success_criteria;

check("canary_status", "12/12 service stats", status.service_stats.length === 12,
  String(status.service_stats.length), "12");
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
const by_cat = checks.reduce((acc, c) => {
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
  for (const f of failed)
    console.log(`    ✗ [${f.category}] ${f.label}: expected=${f.expected} actual=${f.actual}${f.detail ? ` (${f.detail})` : ""}`);
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
writeFileSync(join(AEGIS_DIR, "batch26_decision_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch26", scope: "12-service full TIER-A expansion",
  canary_services: ALL_12,
  cumulative_log: {
    total: status.total_decisions,
    canary: status.canary_decisions,
    shadow: status.shadow_decisions,
    distribution: status.decision_distribution,
  },
  per_service: status.service_stats.map(s => ({
    service_id: s.service_id,
    group: NEW_6.includes(s.service_id) ? "new" : "prev",
    total: s.total_decisions, ALLOW: s.allow, WARN: s.warn,
    GATE: s.gate, BLOCK: s.block, read_gates: s.read_gates,
  })),
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch26_approval_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(), batch: "batch26",
  by_category: by_cat,
  lifecycle_checks: checks.filter(c => c.category === "lifecycle").length,
  lifecycle_pass: checks.filter(c => c.category === "lifecycle" && c.passed).length,
  store_snapshot: {
    pending: status.approval_pending, approved: status.approval_approved,
    consumed: status.approval_consumed, denied: status.approval_denied,
    expired: status.approval_expired, revoked: status.approval_revoked,
  },
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch26_failures.json"), JSON.stringify({
  generated_at: new Date().toISOString(), batch: "batch26",
  total_checks: checks.length, passed: passed.length, failed: failed.length,
  ready_to_expand: status.ready_to_expand, rollback_verdict: drill.verdict,
  by_category: by_cat,
  failures: failed.map(f => ({ category: f.category, label: f.label, expected: f.expected, actual: f.actual, detail: f.detail })),
  success_criteria: sc, blockers: sc.blockers,
}, null, 2));

const elibRows = NEW_6.map(svc => {
  const e = reg[svc];
  const ac = e?.authority_class ?? "?";
  const note = ac === "governance" ? "gated — GATE is the protection" : ac === "read_only" ? "safest class" : ac;
  return `| ${svc} | ${e?.runtime_readiness.tier} | ${ac} | ${e?.governance_blast_radius} | ${e?.aegis_gate.overall} | ${note} |`;
});

const mdLines = [
  `# AEGIS Batch 26 — Full TIER-A Soft-Canary Expansion: 6 → 12`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Previous canary:** ${ORIG_6.join(", ")}`,
  `**New additions:** ${NEW_6.join(", ")}`,
  `**Full canary (12):** ${ALL_12.join(", ")}`,
  ``,
  `## Expansion Eligibility — New 6`,
  ``,
  `| Service | Tier | Authority Class | Blast Radius | Gate | Note |`,
  `|---|---|---|---|---|---|`,
  ...elibRows,
  ``,
  `> **ankr-doctor note:** authority_class=governance means governance-level operations.`,
  `> aegis_gate_overall=GATE means every non-read operation is already gated — the soft-canary`,
  `> GATE is exactly the mechanism that makes governance-class services safe to observe.`,
  `>`,
  `> **ship-slm, chief-slm, chirpee, puranic-os:** read_only, BR-0/1 — safest possible profile.`,
  `> aegis_gate_overall=BLOCK → GATE in soft-canary. No hard block ever reaches the caller.`,
  ``,
  `## Check Summary`,
  ``,
  `| Category | Checks | PASS | FAIL |`,
  `|---|---|---|---|`,
  ...Object.entries(by_cat).map(([cat, r]) =>
    `| ${cat} | ${r.pass + r.fail} | ${r.pass} | ${r.fail} |`
  ),
  `| **TOTAL** | **${checks.length}** | **${passed.length}** | **${failed.length}** |`,
  ``,
  `## Decision Distribution (cumulative log)`,
  ``,
  `| Service | Group | Total | ALLOW | WARN | GATE | BLOCK | READ gates |`,
  `|---|---|---|---|---|---|---|---|`,
  ...status.service_stats.map(s =>
    `| ${s.service_id} | ${NEW_6.includes(s.service_id) ? "**new**" : "prev"} | ${s.total_decisions} | ${s.allow} | ${s.warn} | ${s.gate} | ${s.block} | ${s.read_gates} |`
  ),
  ``,
  `## Key Invariants`,
  ``,
  `| Invariant | Scope | Result |`,
  `|---|---|---|`,
  `| READ always ALLOW (AEG-E-002) | all 12 | ${checks.filter(c => c.category === "read_always_allow").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| BLOCK → GATE in soft-canary | new 6 × 3 ops | ${checks.filter(c => c.category === "softening").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown cap: no BLOCK | new 6 | ${checks.filter(c => c.label.includes("unknown_cap no BLOCK")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| run_agent → AI_EXECUTE | new 6 | ${checks.filter(c => c.label.includes("run_agent→AI_EXECUTE")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Empty cap: no crash | new 6 | ${checks.filter(c => c.label.includes("empty_cap")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Unknown service: WARN/shadow | 1 | ${checks.filter(c => c.label.includes("unknown_service")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Original 6 unchanged | 6 × 3 | ${checks.filter(c => c.category === "regression").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Non-TIER-A: shadow | 4 | ${checks.filter(c => c.category === "shadow_boundary").every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Approval Lifecycle (new 6, all rules)`,
  ``,
  `| Edge Case | Rule | Scope | Result |`,
  `|---|---|---|---|`,
  `| Blank approval_reason | AEG-E-014 | all 6 new | ${checks.filter(c => c.label.includes("blank_reason rejected")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Token replay | AEG-E-015 | all 6 new | ${checks.filter(c => c.label.includes("replay_second rejected")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Wrong binding | AEG-E-016 | all 6 new cycled | ${checks.filter(c => c.label.includes("wrong_binding")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Denied → re-approve | AEG-E-017 | all 6 new | ${checks.filter(c => c.label.includes("denied→reapprove")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Revoked → re-approve | AEG-E-018 | all 6 new | ${checks.filter(c => c.label.includes("revoked→reapprove")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoke_reason | AEG-E-018 | all 6 new | ${checks.filter(c => c.label.includes("blank_revoke_reason")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Blank revoked_by | AEG-E-018 | all 6 new | ${checks.filter(c => c.label.includes("blank_revoked_by")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  `| Expired token | AEG-E-013 | all 6 new | ${checks.filter(c => c.label.includes("expired_token")).every(c => c.passed) ? "✓ PASS" : "✗ FAIL"} |`,
  ``,
  `## Rollback Drill — All 12`,
  ``,
  `| Service | Group | Phase after kill | Tokens issued | Verdict |`,
  `|---|---|---|---|---|`,
  ...drill.services_checked.map(s =>
    `| ${s.service_id} | ${NEW_6.includes(s.service_id) ? "new" : "prev"} | ${s.phase_after_kill} | ${s.tokens_issued} | ${s.verdict} |`
  ),
  ``,
  `**Overall verdict:** ${drill.verdict}`,
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
  `## Rollout Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 17 | 3 svc | Synthetic replay | complete |`,
  `| Batch 21 | 3 svc | Real traffic | complete |`,
  `| Batch 22 | 3 svc | Rough weather | complete |`,
  `| Batch 23 | 6 svc | Expansion | complete |`,
  `| Batch 24 | 6 svc | Observation | complete |`,
  `| Batch 25 | 6 svc | Rough weather | complete |`,
  `| **Batch 26** | **12 svc** | **Full TIER-A expansion** | **${failed.length === 0 ? "complete" : "FAILED"}** |`,
  `| Batch 27 | 12 svc | Observation window | pending |`,
  `| Batch 28 | 12 svc | Rough-weather window | pending |`,
  `| Batch 29 | 12 svc | Config-driven canary | pending |`,
  `| Batch 30 | 12 svc | Hard-mode readiness | pending |`,
  ``,
  `---`,
  `*AEGIS full TIER-A soft-canary — Batch 26 — @rule:AEG-E-001 (shadow→soft→hard; never skip)*`,
];

writeFileSync(join(AEGIS_DIR, "batch26_full_tiera_expansion_summary.md"), mdLines.join("\n"));

console.log(`\n── Artifacts ──`);
console.log(`  ${join(AEGIS_DIR, "batch26_full_tiera_expansion_summary.md")}`);
console.log(`  ${join(AEGIS_DIR, "batch26_decision_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch26_approval_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch26_failures.json")}`);
console.log(`\n  Full TIER-A canary (12 services): ${failed.length === 0 ? "CLEAN — Batch 27 observation window is next." : `${failed.length} FAILURE(S).`}`);
