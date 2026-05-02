#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 24 — 6-service soft-canary observation window
// Post-expansion normal traffic across granthx, stackpilot, ankrclaw,
// carbonx, parali-central, pramana.
// No expansion. No edge cases. Observation only.
//
// Produces:
//   .aegis/batch24_observation_summary.md
//   .aegis/batch24_decision_counts.json
//   .aegis/batch24_approval_counts.json
//   .aegis/batch24_blockers.json

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
const { approveToken, denyToken, consumeToken, runRollbackDrill } = await import("../src/enforcement/approval");

const ALL_6  = ["granthx", "stackpilot", "ankrclaw", "carbonx", "parali-central", "pramana"];
const ORIG_3 = ["granthx", "stackpilot", "ankrclaw"];
const NEW_3  = ["carbonx", "parali-central", "pramana"];

// ── Per-service decision counters (this batch only) ───────────────────────────
const batchCounts: Record<string, { ALLOW: number; WARN: number; GATE: number; BLOCK: number; read_gates: number }> = {};
for (const svc of ALL_6) batchCounts[svc] = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0, read_gates: 0 };

// Approval lifecycle counters (this batch)
const approvalCounts = { issued: 0, approved: 0, consumed: 0, denied: 0, revoked: 0 };

// Invariant violation log
const violations: string[] = [];

function gate(svc: string, op: string, cap: string, callerId: string) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: callerId });
  logDecision(d);

  if (batchCounts[svc]) {
    const c = batchCounts[svc];
    c[d.decision as keyof typeof c] = (c[d.decision as keyof typeof c] as number) + 1;

    const isRead = ["read", "get", "list", "query", "search", "fetch"].some(k =>
      op.toLowerCase().startsWith(k) || cap.toLowerCase().startsWith(k)
    );
    if (isRead && (d.decision === "GATE" || d.decision === "BLOCK")) {
      c.read_gates++;
      violations.push(`READ gated: ${svc}/${op} → ${d.decision}`);
    }
    if (d.decision === "BLOCK") {
      violations.push(`Hard BLOCK in soft-canary: ${svc}/${op} → BLOCK (should be GATE)`);
    }
  }
  return d;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 1 — Read-heavy operational traffic (simulate typical read workload)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 1: Read-heavy operational traffic ──");

const readOps = [
  { op: "read",   cap: "READ"  },
  { op: "get",    cap: "READ"  },
  { op: "list",   cap: "READ"  },
  { op: "query",  cap: "QUERY" },
  { op: "fetch",  cap: "READ"  },
  { op: "search", cap: "QUERY" },
];

for (const svc of ALL_6) {
  for (const { op, cap } of readOps) {
    const d = gate(svc, op, cap, `b24-wave1-${svc}`);
    console.log(`  ${svc.padEnd(16)} ${op.padEnd(10)} → ${d.decision}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 2 — Write and execute traffic with approval lifecycle
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 2: Write and execute traffic ──");

const writeExecOps = [
  { op: "write",   cap: "WRITE"   },
  { op: "update",  cap: "WRITE"   },
  { op: "create",  cap: "WRITE"   },
  { op: "execute", cap: "EXECUTE" },
  { op: "trigger", cap: "EXECUTE" },
];

const pendingGates: Array<{ token: string; svc: string; op: string }> = [];

for (const svc of ALL_6) {
  for (const { op, cap } of writeExecOps) {
    const d = gate(svc, op, cap, `b24-wave2-${svc}`);
    console.log(`  ${svc.padEnd(16)} ${op.padEnd(10)} → ${d.decision}${d.approval_token ? " (token_issued)" : ""}`);
    if (d.decision === "GATE" && d.approval_token) {
      approvalCounts.issued++;
      pendingGates.push({ token: d.approval_token, svc, op });
    }
  }
}

// Process approvals: approve all execute gates, deny one per service to show lifecycle
console.log("\n  Approval lifecycle:");
const denySet = new Set<string>();
for (const g of pendingGates) {
  if (g.op === "trigger" && !denySet.has(g.svc)) {
    // Deny one trigger per service — risk too ambiguous without context
    denySet.add(g.svc);
    const r = denyToken(g.token, `trigger op requires more context — denied for review`, "capt.anil.sharma");
    if (r.ok) {
      approvalCounts.denied++;
      console.log(`  DENIED    ${g.svc}/${g.op}`);
    }
  } else {
    // Approve execute gates
    const r = approveToken(g.token, `Wave 2 approved: ${g.op} on ${g.svc} reviewed`, "capt.anil.sharma",
      { service_id: g.svc });
    if (r.ok) {
      approvalCounts.approved++;
      consumeToken(g.token);
      approvalCounts.consumed++;
      console.log(`  APPROVED  ${g.svc}/${g.op} → consumed`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 3 — High-risk traffic (deploy/approve — always GATE in soft-canary)
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 3: High-risk traffic (DEPLOY / APPROVE) ──");

const highRiskOps = [
  { op: "deploy",  cap: "DEPLOY"  },
  { op: "approve", cap: "APPROVE" },
];

const wave3Gates: Array<{ token: string; svc: string; op: string }> = [];

for (const svc of ALL_6) {
  for (const { op, cap } of highRiskOps) {
    const d = gate(svc, op, cap, `b24-wave3-${svc}`);
    console.log(`  ${svc.padEnd(16)} ${op.padEnd(10)} → ${d.decision}${d.approval_token ? " (token_issued)" : ""}`);
    if (d.decision === "GATE" && d.approval_token) {
      approvalCounts.issued++;
      wave3Gates.push({ token: d.approval_token, svc, op });
    }
  }
}

// Approve deploy gates; deny approve gates (approve-as-operation is higher risk)
for (const g of wave3Gates) {
  if (g.op === "approve") {
    const r = denyToken(g.token, `approve operation requires explicit board-level sign-off`, "capt.anil.sharma");
    if (r.ok) { approvalCounts.denied++; console.log(`  DENIED    ${g.svc}/${g.op}`); }
  } else {
    const r = approveToken(g.token, `Batch 24 deploy window approved: ${g.svc} deploy reviewed by captain`, "capt.anil.sharma",
      { service_id: g.svc });
    if (r.ok) {
      approvalCounts.approved++;
      consumeToken(g.token);
      approvalCounts.consumed++;
      console.log(`  APPROVED  ${g.svc}/${g.op} → consumed`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 4 — Regression check: original 3 vs new 3 behave identically
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 4: Regression — orig 3 vs new 3 parity ──");

const regressionOps = [
  { op: "read",    cap: "READ",    expectDecision: "ALLOW" },
  { op: "write",   cap: "WRITE",   expectDecision: "ALLOW" },
  { op: "execute", cap: "EXECUTE", expectDecision: "GATE"  },
];

let regressionPass = 0, regressionFail = 0;
for (const { op, cap, expectDecision } of regressionOps) {
  const origResults = ORIG_3.map(svc => ({ svc, d: gate(svc, op, cap, "b24-regression") }));
  const newResults  = NEW_3.map(svc => ({ svc, d: gate(svc, op, cap, "b24-regression") }));

  for (const { svc, d } of [...origResults, ...newResults]) {
    const ok = d.decision === expectDecision && d.enforcement_phase === "soft_canary";
    ok ? regressionPass++ : regressionFail++;
    if (!ok) violations.push(`Regression: ${svc}/${op} expected ${expectDecision}/soft_canary got ${d.decision}/${d.enforcement_phase}`);
    console.log(`  ${ok ? "✓" : "✗"} ${svc.padEnd(16)} ${op.padEnd(10)} → ${d.decision}/${d.enforcement_phase}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Wave 5 — Non-canary services: confirm still shadow
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Wave 5: Non-canary boundary check ──");

const nonCanary = ["ankr-doctor", "domain-capture", "ship-slm", "chirpee", "puranic-os", "svc-unknown"];
let boundaryPass = 0;
for (const svc of nonCanary) {
  const d = gate(svc, "deploy", "DEPLOY", "b24-boundary");
  const inShadow = d.enforcement_phase === "shadow" && !d.in_canary;
  if (!inShadow) violations.push(`Boundary break: ${svc} not in shadow — got ${d.enforcement_phase}`);
  if (inShadow) boundaryPass++;
  console.log(`  ${inShadow ? "✓" : "✗"} ${svc.padEnd(20)} → ${d.decision}/${d.enforcement_phase} in_canary=${d.in_canary}`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Rollback drill
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Rollback drill ──");
const drill = runRollbackDrill(evaluate, ALL_6, [
  { operation: "execute", requested_capability: "EXECUTE" },
  { operation: "deploy",  requested_capability: "DEPLOY" },
]);
console.log(`  Verdict: ${drill.verdict}`);
for (const s of drill.services_checked) {
  console.log(`  ${s.service_id.padEnd(18)} phase_after_kill=${s.phase_after_kill} tokens=${s.tokens_issued} → ${s.verdict}`);
}
if (drill.verdict !== "PASS") violations.push("Rollback drill FAILED");

// ═══════════════════════════════════════════════════════════════════════════════
// Final canary status
// ═══════════════════════════════════════════════════════════════════════════════
console.log("\n── Canary status ──");
const status = getCanaryStatus(ALL_6);
const sc = status.success_criteria;

// ═══════════════════════════════════════════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════════════════════════════════════════
const totalBatchDecisions = ALL_6.reduce((acc, svc) => {
  const c = batchCounts[svc];
  return acc + c.ALLOW + c.WARN + c.GATE + c.BLOCK;
}, 0);

console.log(`\n══ Batch 24 Summary ══`);
console.log(`  Decisions this batch:  ${totalBatchDecisions}`);
console.log(`  Approval issued:       ${approvalCounts.issued}`);
console.log(`  Approval approved:     ${approvalCounts.approved}`);
console.log(`  Approval consumed:     ${approvalCounts.consumed}`);
console.log(`  Approval denied:       ${approvalCounts.denied}`);
console.log(`  Regression checks:     ${regressionPass + regressionFail} (${regressionPass} pass, ${regressionFail} fail)`);
console.log(`  Boundary checks:       ${nonCanary.length} (${boundaryPass} shadow)`);
console.log(`  Rollback drill:        ${drill.verdict}`);
console.log(`  Violations:            ${violations.length}`);
console.log(`  ready_to_expand:       ${status.ready_to_expand}`);

if (violations.length > 0) {
  console.log(`\n  Violations:`);
  for (const v of violations) console.log(`    - ${v}`);
}

// ── Artifacts ─────────────────────────────────────────────────────────────────
writeFileSync(join(AEGIS_DIR, "batch24_decision_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch24",
  scope: "6-service observation window",
  canary_services: ALL_6,
  this_batch: batchCounts,
  cumulative_log: {
    total: status.total_decisions,
    canary: status.canary_decisions,
    shadow: status.shadow_decisions,
    distribution: status.decision_distribution,
  },
  per_service_cumulative: status.service_stats,
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch24_approval_counts.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch24",
  this_batch: approvalCounts,
  store_snapshot: {
    pending: status.approval_pending,
    approved: status.approval_approved,
    consumed: status.approval_consumed,
    denied: status.approval_denied,
    expired: status.approval_expired,
    revoked: status.approval_revoked,
  },
  approval_log_path: join(AEGIS_DIR, "aegis_approval.log"),
}, null, 2));

writeFileSync(join(AEGIS_DIR, "batch24_blockers.json"), JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch24",
  violations: violations,
  violations_count: violations.length,
  rollback_verdict: drill.verdict,
  success_criteria: sc,
  ready_to_expand: status.ready_to_expand,
  observation_clean: violations.length === 0 && drill.verdict === "PASS",
}, null, 2));

const mdLines = [
  `# AEGIS Batch 24 — 6-Service Canary Observation Window`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Canary services:** ${ALL_6.join(", ")}`,
  `**Purpose:** Post-expansion observation — normal operational traffic, no edge cases`,
  ``,
  `## Traffic Waves`,
  ``,
  `| Wave | Type | Operations | Notes |`,
  `|---|---|---|---|`,
  `| Wave 1 | Read-heavy | read, get, list, query, fetch, search | All should ALLOW |`,
  `| Wave 2 | Write + execute | write, update, create, execute, trigger | GATE on execute; deny trigger |`,
  `| Wave 3 | High-risk | deploy, approve | GATE + selective approve/deny |`,
  `| Wave 4 | Regression | read, write, execute | Orig 3 vs New 3 parity |`,
  `| Wave 5 | Boundary | deploy on non-canary | Confirm shadow boundary holds |`,
  ``,
  `## Decision Counts — This Batch`,
  ``,
  `| Service | Group | ALLOW | WARN | GATE | BLOCK | READ gates |`,
  `|---|---|---|---|---|---|---|`,
  ...ALL_6.map(svc => {
    const c = batchCounts[svc];
    const group = NEW_3.includes(svc) ? "new" : "orig";
    return `| ${svc} | ${group} | ${c.ALLOW} | ${c.WARN} | ${c.GATE} | ${c.BLOCK} | ${c.read_gates} |`;
  }),
  ``,
  `## Approval Lifecycle — This Batch`,
  ``,
  `| Event | Count | Notes |`,
  `|---|---|---|`,
  `| Tokens issued | ${approvalCounts.issued} | All from GATE decisions in waves 2-3 |`,
  `| Approved + consumed | ${approvalCounts.approved} | execute/deploy gates reviewed and approved |`,
  `| Denied | ${approvalCounts.denied} | trigger + approve-as-op denied (require more context) |`,
  `| Revoked | 0 | None |`,
  `| Expired | 0 | None |`,
  ``,
  `## Regression Check (Wave 4)`,
  ``,
  `| Result | Count |`,
  `|---|---|`,
  `| PASS | ${regressionPass} |`,
  `| FAIL | ${regressionFail} |`,
  ``,
  regressionFail === 0
    ? `Original 3 and new 3 behave identically across read/write/execute.`
    : `**REGRESSION DETECTED** — original and new service behaviour differs.`,
  ``,
  `## Non-Canary Boundary (Wave 5)`,
  ``,
  `${nonCanary.map(svc => `- ${svc}: shadow=${boundaryPass === nonCanary.length}`).join("\n")}`,
  ``,
  `## Rollback Drill`,
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
  `| rollback_drill_passed | ${sc.rollback_drill_passed === true ? "✓ PASS" : sc.rollback_drill_passed === null ? "— pending" : "✗ FAIL"} |`,
  `| decision_log_has_canary_entries | ${sc.decision_log_has_canary_entries ? "✓ PASS" : "✗ FAIL"} |`,
  `| **all_criteria_met** | **${sc.all_criteria_met ? "✓ PASS" : "✗ FAIL"}** |`,
  ``,
  violations.length > 0 ? `## Violations\n\n${violations.map(v => `- ${v}`).join("\n")}\n` : `## Violations\n\nNone.\n`,
  `## Rollout Sequence`,
  ``,
  `| Batch | Scope | Window | Status |`,
  `|---|---|---|---|`,
  `| Batch 17 | 3 services | Synthetic replay | complete |`,
  `| Batch 21 | 3 services | Real traffic observation | complete |`,
  `| Batch 22 | 3 services | Edge-case rough weather | complete |`,
  `| Batch 23 | 6 services | Expansion | complete |`,
  `| **Batch 24** | **6 services** | **Observation window** | **${violations.length === 0 && drill.verdict === "PASS" ? "complete" : "ISSUES FOUND"}** |`,
  `| Batch 25 | 6 services | Edge-case window | pending |`,
  `| Batch 26 | 12 services | Full TIER-A expansion | pending |`,
  ``,
  `---`,
  `*AEGIS soft-canary 6-service observation — Batch 24 — @rule:AEG-E-019*`,
];

writeFileSync(join(AEGIS_DIR, "batch24_observation_summary.md"), mdLines.join("\n"));

console.log(`\n── Artifacts ──`);
console.log(`  ${join(AEGIS_DIR, "batch24_observation_summary.md")}`);
console.log(`  ${join(AEGIS_DIR, "batch24_decision_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch24_approval_counts.json")}`);
console.log(`  ${join(AEGIS_DIR, "batch24_blockers.json")}`);
console.log(`\n  Window: ${violations.length === 0 && drill.verdict === "PASS" ? "CLEAN — Batch 25 edge-case window is next." : `ISSUES FOUND — ${violations.length} violation(s).`}`);
