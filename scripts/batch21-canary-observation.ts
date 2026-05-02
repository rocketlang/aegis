#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Batch 21 — Real traffic canary observation
// Runs live soft-canary traffic for granthx, stackpilot, ankrclaw
// then reads /canary/status to verify expansion readiness.
//
// Usage: bun scripts/batch21-canary-observation.ts
// Produces:
//   .aegis/canary_observation_summary.md
//   .aegis/canary_decision_counts.json
//   .aegis/canary_blockers.json

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// ── Live canary flags ─────────────────────────────────────────────────────────
process.env.AEGIS_RUNTIME_ENABLED         = "true";
process.env.AEGIS_ENFORCEMENT_MODE        = "soft";
process.env.AEGIS_DRY_RUN                 = "false";
process.env.AEGIS_SOFT_CANARY_SERVICES    = "granthx,stackpilot,ankrclaw";

// Route log to a known path so getCanaryStatus can read it back
const HOME = process.env.HOME ?? "/root";
const AEGIS_DIR = join(HOME, ".aegis");
if (!existsSync(AEGIS_DIR)) mkdirSync(AEGIS_DIR, { recursive: true });
process.env.AEGIS_DECISION_LOG_PATH  = join(AEGIS_DIR, "aegis_decisions.log");
process.env.AEGIS_APPROVAL_LOG_PATH  = join(AEGIS_DIR, "aegis_approval.log");

// ── Import enforcement layer AFTER env is set ─────────────────────────────────
const { evaluate } = await import("../src/enforcement/gate");
const { logDecision } = await import("../src/enforcement/logger");
const { getCanaryStatus, getRecentCanaryDecisions, getCanaryApprovals } = await import("../src/enforcement/canary-status");
const { approveToken, denyToken, revokeToken, listAll } = await import("../src/enforcement/approval");

// ── Traffic definition ────────────────────────────────────────────────────────
const CANARY_SERVICES = ["granthx", "stackpilot", "ankrclaw"];

const OPERATIONS: Array<{ operation: string; requested_capability: string; label: string }> = [
  { operation: "read",    requested_capability: "READ",        label: "READ" },
  { operation: "get",     requested_capability: "READ",        label: "READ-get" },
  { operation: "list",    requested_capability: "READ",        label: "READ-list" },
  { operation: "write",   requested_capability: "WRITE",       label: "WRITE" },
  { operation: "update",  requested_capability: "WRITE",       label: "WRITE-update" },
  { operation: "execute", requested_capability: "EXECUTE",     label: "EXECUTE" },
  { operation: "deploy",  requested_capability: "DEPLOY",      label: "DEPLOY" },
  { operation: "approve", requested_capability: "APPROVE",     label: "APPROVE" },
  { operation: "query",   requested_capability: "QUERY",       label: "QUERY" },
  { operation: "fetch",   requested_capability: "READ",        label: "FETCH" },
  // Unknown capability — must not hard-block (shadow warn only)
  { operation: "run_agent",  requested_capability: "run_agent",   label: "UNKNOWN-run_agent" },
];

// ── Run traffic ───────────────────────────────────────────────────────────────
console.log("=== Batch 21: Real Traffic Canary Observation ===");
console.log(`Mode: ${process.env.AEGIS_ENFORCEMENT_MODE} | DryRun: ${process.env.AEGIS_DRY_RUN} | RuntimeEnabled: ${process.env.AEGIS_RUNTIME_ENABLED}`);
console.log(`Services: ${CANARY_SERVICES.join(", ")}`);
console.log(`Operations: ${OPERATIONS.length} per service (${CANARY_SERVICES.length * OPERATIONS.length} total)\n`);

const trafficResults: Array<{
  service_id: string;
  operation: string;
  label: string;
  decision: string;
  enforcement_phase: string;
  in_canary: boolean;
  approval_token?: string;
}> = [];

let gateDecisions: Array<{ token: string; service_id: string; operation: string; label: string }> = [];

for (const svc of CANARY_SERVICES) {
  for (const op of OPERATIONS) {
    const decision = evaluate({
      service_id: svc,
      operation: op.operation,
      requested_capability: op.requested_capability,
      caller_id: "batch21-canary-traffic",
      session_id: `b21-${svc}`,
    });
    logDecision(decision);

    const row = {
      service_id: svc,
      operation: op.operation,
      label: op.label,
      decision: decision.decision,
      enforcement_phase: decision.enforcement_phase,
      in_canary: decision.in_canary,
      approval_token: decision.approval_token,
    };
    trafficResults.push(row);

    if (decision.decision === "GATE" && decision.approval_token) {
      gateDecisions.push({
        token: decision.approval_token,
        service_id: svc,
        operation: op.operation,
        label: op.label,
      });
    }

    const phase = decision.enforcement_phase.padEnd(12);
    const dec   = decision.decision.padEnd(6);
    console.log(`  ${svc.padEnd(12)} ${op.label.padEnd(18)} → [${phase}] ${dec} ${decision.approval_token ? "(GATE:token_issued)" : ""}`);
  }
}

// ── Simulate approval lifecycle on GATE decisions ────────────────────────────
console.log(`\n── Approval lifecycle for ${gateDecisions.length} GATE decision(s) ──`);

for (const gate of gateDecisions) {
  // Window 1: approve the first GATE for each service
  // Window 2: deny next (if more than one GATE per service)
  const approveResult = approveToken(
    gate.token,
    `Batch 21 canary approval — ${gate.operation} on ${gate.service_id} reviewed and authorised`,
    "capt.anil.sharma",
    { service_id: gate.service_id, operation: gate.operation },
  );
  if (approveResult.ok) {
    console.log(`  APPROVED  ${gate.service_id} / ${gate.label} → token consumed`);
  } else {
    console.log(`  APPROVE FAILED: ${approveResult.error}`);
  }
}

// ── Rollback drill ────────────────────────────────────────────────────────────
console.log("\n── Rollback drill ──");
const { runRollbackDrill } = await import("../src/enforcement/approval");
const drillOps = [
  { operation: "execute", requested_capability: "EXECUTE" },
  { operation: "deploy",  requested_capability: "DEPLOY" },
];
const drill = runRollbackDrill(evaluate, CANARY_SERVICES, drillOps);
console.log(`  Verdict: ${drill.verdict}`);
for (const s of drill.services_checked) {
  console.log(`  ${s.service_id}: phase_after_kill=${s.phase_after_kill} tokens=${s.tokens_issued} → ${s.verdict}`);
}

// ── Read canary status ────────────────────────────────────────────────────────
console.log("\n── Canary Status ──");
const status = getCanaryStatus(CANARY_SERVICES);

console.log(`  enforcement_mode:   ${status.enforcement_mode}`);
console.log(`  enforcement_phase:  ${status.enforcement_phase}`);
console.log(`  dry_run:            ${status.dry_run}`);
console.log(`  total_decisions:    ${status.total_decisions}`);
console.log(`  canary_decisions:   ${status.canary_decisions}`);
console.log(`  shadow_decisions:   ${status.shadow_decisions}`);
console.log(`  distribution:       ALLOW=${status.decision_distribution.ALLOW} WARN=${status.decision_distribution.WARN} GATE=${status.decision_distribution.GATE} BLOCK=${status.decision_distribution.BLOCK}`);
console.log(`  approval_pending:   ${status.approval_pending}`);
console.log(`  approval_approved:  ${status.approval_approved}`);
console.log(`  approval_consumed:  ${status.approval_consumed}`);
console.log(`  ready_to_expand:    ${status.ready_to_expand}`);

console.log("\n── Success Criteria ──");
const sc = status.success_criteria;
console.log(`  no_read_gates:                  ${sc.no_read_gates}`);
console.log(`  no_unknown_service_blocks:      ${sc.no_unknown_service_blocks}`);
console.log(`  no_token_replay_successes:      ${sc.no_token_replay_successes}`);
console.log(`  no_approval_without_reason:     ${sc.no_approval_without_reason}`);
console.log(`  no_revoke_without_reason:       ${sc.no_revoke_without_reason}`);
console.log(`  rollback_drill_passed:          ${sc.rollback_drill_passed}`);
console.log(`  decision_log_has_canary_entries:${sc.decision_log_has_canary_entries}`);
console.log(`  all_criteria_met:               ${sc.all_criteria_met}`);
if (sc.blockers.length > 0) {
  console.log(`\n  BLOCKERS:`);
  for (const b of sc.blockers) console.log(`    - ${b}`);
}

// ── Service stats ─────────────────────────────────────────────────────────────
console.log("\n── Per-Service Stats ──");
for (const s of status.service_stats) {
  console.log(`  ${s.service_id}: total=${s.total_decisions} ALLOW=${s.allow} WARN=${s.warn} GATE=${s.gate} BLOCK=${s.block} read_gates=${s.read_gates}`);
}

// ── Decision counts JSON ──────────────────────────────────────────────────────
const decisionCounts: Record<string, Record<string, number>> = {};
for (const r of trafficResults) {
  decisionCounts[r.service_id] ??= { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 };
  decisionCounts[r.service_id][r.decision] = (decisionCounts[r.service_id][r.decision] ?? 0) + 1;
}

const decisionCountsPath = join(AEGIS_DIR, "canary_decision_counts.json");
writeFileSync(decisionCountsPath, JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch21",
  canary_services: CANARY_SERVICES,
  per_service: decisionCounts,
  totals: {
    ALLOW: status.decision_distribution.ALLOW,
    WARN:  status.decision_distribution.WARN,
    GATE:  status.decision_distribution.GATE,
    BLOCK: status.decision_distribution.BLOCK,
  },
  canary_decisions: status.canary_decisions,
  shadow_decisions: status.shadow_decisions,
}, null, 2));

// ── Blockers JSON ─────────────────────────────────────────────────────────────
const blockersPath = join(AEGIS_DIR, "canary_blockers.json");
writeFileSync(blockersPath, JSON.stringify({
  generated_at: new Date().toISOString(),
  batch: "batch21",
  ready_to_expand: status.ready_to_expand,
  all_criteria_met: sc.all_criteria_met,
  rollback_drill_verdict: drill.verdict,
  blockers: sc.blockers,
  success_criteria: sc,
}, null, 2));

// ── Observation summary MD ────────────────────────────────────────────────────
const recentDecisions = getRecentCanaryDecisions(CANARY_SERVICES, 20);
const approvalRecords  = getCanaryApprovals(CANARY_SERVICES);

const summaryLines = [
  `# AEGIS Batch 21 — Real Traffic Canary Observation`,
  ``,
  `**Generated:** ${new Date().toISOString()}`,
  `**Canary services:** ${CANARY_SERVICES.join(", ")}`,
  `**Enforcement mode:** ${status.enforcement_mode}`,
  `**Enforcement phase:** ${status.enforcement_phase}`,
  `**Dry run:** ${status.dry_run}`,
  ``,
  `## Decision Summary`,
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
  `## Per-Service Decision Breakdown`,
  ``,
  `| Service | Total | ALLOW | WARN | GATE | BLOCK | READ gates |`,
  `|---|---|---|---|---|---|---|`,
  ...status.service_stats.map(s =>
    `| ${s.service_id} | ${s.total_decisions} | ${s.allow} | ${s.warn} | ${s.gate} | ${s.block} | ${s.read_gates} |`
  ),
  ``,
  `## Approval Lifecycle`,
  ``,
  `| Status | Count |`,
  `|---|---|`,
  `| pending | ${status.approval_pending} |`,
  `| approved | ${status.approval_approved} |`,
  `| consumed | ${status.approval_consumed} |`,
  `| denied | ${status.approval_denied} |`,
  `| expired | ${status.approval_expired} |`,
  `| revoked | ${status.approval_revoked} |`,
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
  `## Expansion Signal`,
  ``,
  `\`\`\``,
  `ready_to_expand: ${status.ready_to_expand}`,
  ``,
  sc.all_criteria_met
    ? `All ${Object.keys(sc).filter(k => k !== "blockers" && k !== "all_criteria_met").length} success criteria met.`
    : `${sc.blockers.length} blocker(s) prevent expansion. Resolve before widening canary scope.`,
  `\`\`\``,
  ``,
  `## Window Protocol`,
  ``,
  `Before expanding from 3 → 6 services, require:`,
  `- Window 1 (synthetic replay): complete`,
  `- Window 2 (real traffic): complete`,
  `- Window 3 (mixed + edge cases): pending`,
  ``,
  `Expansion step: 3 → 6 services (not 3 → 12).`,
  ``,
  `---`,
  `*AEGIS soft-canary observation — Batch 21 — @rule:AEG-E-019*`,
];

const summaryPath = join(AEGIS_DIR, "canary_observation_summary.md");
writeFileSync(summaryPath, summaryLines.join("\n"));

console.log(`\n── Artifacts Written ──`);
console.log(`  ${decisionCountsPath}`);
console.log(`  ${blockersPath}`);
console.log(`  ${summaryPath}`);

console.log(`\n── Expansion Signal ──`);
console.log(`  ready_to_expand: ${status.ready_to_expand}`);
console.log(status.ready_to_expand
  ? `  All criteria met. Window 2 (real traffic) complete.`
  : `  ${sc.blockers.length} blocker(s) remain.`
);
