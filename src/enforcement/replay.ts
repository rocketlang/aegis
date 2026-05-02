// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Decision Log Replay + False-Positive/False-Negative Audit
//
// @rule:AEG-E-009 — no soft enforcement until FP audit passes (0 READ FPs, 0 DEPLOY FNs)
// @rule:AEG-E-010 — audit must cover all 12 TIER-A pilot services before promotion

import { readFileSync, existsSync, writeFileSync } from "fs";
import { join } from "path";
import { logPath } from "./logger";
import { pilotSet } from "./registry";
import type { GateDecision, EnforcementMode } from "./types";

export interface LogEntry {
  schema_version: string;
  service_id: string;
  operation: string;
  requested_capability: string;
  trust_mask: number;
  trust_mask_hex: string;
  authority_class: string;
  governance_blast_radius: string;
  runtime_readiness_tier: string;
  aegis_gate_result: string;
  enforcement_mode: EnforcementMode;
  decision: GateDecision;
  reason: string;
  pilot_scope: boolean;
  dry_run: boolean;
  timestamp: string;
  caller_id?: string;
  session_id?: string;
}

export interface FalsePositive {
  type: "fp";
  category: string;
  entry: LogEntry;
  description: string;
}

export interface FalseNegative {
  type: "fn";
  category: string;
  entry: LogEntry;
  description: string;
}

export interface ServiceDecisionRow {
  service_id: string;
  tier: string;
  in_pilot: boolean;
  total_decisions: number;
  allow: number;
  warn: number;
  gate: number;
  block: number;
  read_gated: number;   // false positives: reads should never gate
  deploy_allowed: number; // false negatives: deploys should never allow in production
  unique_operations: string[];
  unique_capabilities: string[];
}

export interface AuditSummary {
  generated_at: string;
  schema_version: string;
  log_path: string;
  total_log_entries: number;
  pilot_services_covered: number;
  pilot_services_total: number;
  pilot_coverage_complete: boolean;
  false_positives: FalsePositive[];
  false_negatives: FalseNegative[];
  fp_count: number;
  fn_count: number;
  service_matrix: ServiceDecisionRow[];
  decision_distribution: Record<GateDecision, number>;
  enforcement_mode_seen: EnforcementMode[];
  soft_gate_eligible: boolean;
  soft_gate_blockers: string[];
  audit_verdict: "PASS" | "CONDITIONAL_PASS" | "FAIL";
  audit_notes: string[];
}

// @rule:AEG-E-009 success gate — all conditions must be true for soft enforcement
function checkSoftGateEligibility(
  fps: FalsePositive[],
  fns: FalseNegative[],
  matrix: ServiceDecisionRow[],
  pilotTotal: number,
): { eligible: boolean; blockers: string[] } {
  const blockers: string[] = [];

  const readFPs = fps.filter(f => f.category === "read_gated");
  if (readFPs.length > 0) {
    blockers.push(`${readFPs.length} READ false positive(s) — reads must always ALLOW`);
  }

  const deployFNs = fns.filter(f => f.category === "deploy_allowed");
  if (deployFNs.length > 0) {
    blockers.push(`${deployFNs.length} DEPLOY false negative(s) — deploys must never ALLOW silently`);
  }

  const unknownHardBlocks = fps.filter(f => f.category === "unknown_service_blocked");
  if (unknownHardBlocks.length > 0) {
    blockers.push(`${unknownHardBlocks.length} unknown-service hard BLOCK(s) — unknown services must only WARN`);
  }

  const coveredServices = new Set(matrix.filter(r => r.total_decisions > 0).map(r => r.service_id));
  if (coveredServices.size < pilotTotal) {
    const missing = pilotSet().filter(s => !coveredServices.has(s));
    blockers.push(`Log coverage missing for ${missing.length} TIER-A service(s): ${missing.slice(0, 5).join(", ")}`);
  }

  return { eligible: blockers.length === 0, blockers };
}

export function runAudit(logFilePath?: string): AuditSummary {
  const path = logFilePath ?? logPath();
  const now = new Date().toISOString();
  const pilot = pilotSet();

  const entries: LogEntry[] = [];

  if (existsSync(path)) {
    const lines = readFileSync(path, "utf-8").split("\n").filter(l => l.trim());
    for (const line of lines) {
      try {
        entries.push(JSON.parse(line) as LogEntry);
      } catch { /* malformed line — skip */ }
    }
  }

  const fps: FalsePositive[] = [];
  const fns: FalseNegative[] = [];

  // Per-service aggregation
  const serviceMap = new Map<string, ServiceDecisionRow>();
  for (const svc of pilot) {
    serviceMap.set(svc, {
      service_id: svc, tier: "TIER-A", in_pilot: true,
      total_decisions: 0, allow: 0, warn: 0, gate: 0, block: 0,
      read_gated: 0, deploy_allowed: 0,
      unique_operations: [], unique_capabilities: [],
    });
  }

  const decisionDist: Record<GateDecision, number> = { ALLOW: 0, WARN: 0, GATE: 0, BLOCK: 0 };
  const modesSet = new Set<EnforcementMode>();

  for (const e of entries) {
    const op = (e.operation ?? "").toLowerCase();
    const cap = (e.requested_capability ?? "").toLowerCase();
    const decision = e.decision;

    decisionDist[decision] = (decisionDist[decision] ?? 0) + 1;
    modesSet.add(e.enforcement_mode);

    // Update service matrix row
    let row = serviceMap.get(e.service_id);
    if (!row) {
      row = {
        service_id: e.service_id,
        tier: e.runtime_readiness_tier,
        in_pilot: e.pilot_scope,
        total_decisions: 0, allow: 0, warn: 0, gate: 0, block: 0,
        read_gated: 0, deploy_allowed: 0,
        unique_operations: [], unique_capabilities: [],
      };
      serviceMap.set(e.service_id, row);
    }
    row.total_decisions++;
    if (decision === "ALLOW") row.allow++;
    if (decision === "WARN")  row.warn++;
    if (decision === "GATE")  row.gate++;
    if (decision === "BLOCK") row.block++;
    if (!row.unique_operations.includes(op)) row.unique_operations.push(op);
    if (!row.unique_capabilities.includes(cap)) row.unique_capabilities.push(cap);

    // ── False positive detection ──────────────────────────────────────────────

    // FP-1: READ that was gated or blocked
    const isRead = ["read", "get", "list", "query", "search", "fetch", "health", "state"].some(k => op.includes(k) || cap.includes(k));
    if (isRead && (decision === "GATE" || decision === "BLOCK")) {
      row.read_gated++;
      fps.push({ type: "fp", category: "read_gated", entry: e, description: `READ op '${e.operation}' returned ${decision} — reads must always ALLOW` });
    }

    // FP-2: low-risk WRITE that was GATE or BLOCK (only flag if not financial/governance authority)
    const isWrite = ["write", "create", "update", "patch"].some(k => op === k || cap === k);
    const isHighAuthority = ["financial", "governance", "deploy"].includes(e.authority_class);
    if (isWrite && decision === "BLOCK" && !isHighAuthority) {
      fps.push({ type: "fp", category: "low_risk_write_blocked", entry: e, description: `Low-risk WRITE '${e.operation}' was BLOCK on non-high-authority service ${e.service_id} (ac=${e.authority_class})` });
    }

    // FP-3: TIER-A service forced to monitor-only (should be in pilot scope)
    if (e.runtime_readiness_tier === "TIER-A" && !e.pilot_scope) {
      fps.push({ type: "fp", category: "tier_a_monitor_only", entry: e, description: `TIER-A service '${e.service_id}' not in pilot scope — check TIER_A_PILOT_SET` });
    }

    // FP-4: unknown service that received BLOCK (should only WARN)
    if (e.reason?.includes("not found in registry") && decision === "BLOCK") {
      fps.push({ type: "fp", category: "unknown_service_blocked", entry: e, description: `Unknown service '${e.service_id}' received BLOCK — unknown services must only WARN` });
    }

    // ── False negative detection ──────────────────────────────────────────────

    // FN-1: DEPLOY allowed (should always be GATE or BLOCK)
    const isDeploy = ["deploy", "rollout", "release", "ship", "push"].some(k => op === k || cap === k);
    if (isDeploy && decision === "ALLOW") {
      row.deploy_allowed++;
      fns.push({ type: "fn", category: "deploy_allowed", entry: e, description: `DEPLOY op '${e.operation}' returned ALLOW — deployments must always be GATE or BLOCK` });
    }

    // FN-2: DELETE allowed
    const isDelete = ["delete", "destroy", "drop", "remove"].some(k => op.includes(k) || cap.includes(k));
    if (isDelete && decision === "ALLOW") {
      fns.push({ type: "fn", category: "delete_allowed", entry: e, description: `DELETE op '${e.operation}' returned ALLOW — destructive ops must be GATE or BLOCK` });
    }

    // FN-3: EXECUTE allowed where governance BR >= BR-4
    const isExecute = ["execute", "trigger", "run", "invoke"].some(k => op === k || cap === k);
    const brNum = parseInt(e.governance_blast_radius?.replace("BR-", "") || "0", 10) || 0;
    if (isExecute && decision === "ALLOW" && brNum >= 4) {
      fns.push({ type: "fn", category: "execute_high_br_allowed", entry: e, description: `EXECUTE allowed on '${e.service_id}' with governance BR-${brNum} — should be GATE` });
    }

    // FN-4: financial/legal action allowed without human gate
    const isFinancial = ["bl_issue", "book", "rate_desk", "approve", "financial"].some(k => op.includes(k) || cap.includes(k));
    if (isFinancial && decision === "ALLOW" && !e.dry_run) {
      fns.push({ type: "fn", category: "financial_allowed_no_gate", entry: e, description: `Financial/legal op '${e.operation}' allowed without human gate (dry_run=false)` });
    }
  }

  const matrix = [...serviceMap.values()];
  const pilotCoverage = matrix.filter(r => pilot.includes(r.service_id) && r.total_decisions > 0).length;
  const { eligible, blockers } = checkSoftGateEligibility(fps, fns, matrix, pilot.length);

  const verdict: AuditSummary["audit_verdict"] =
    fps.length === 0 && fns.length === 0 && eligible ? "PASS" :
    fps.length === 0 && fns.length === 0 ? "CONDITIONAL_PASS" :
    "FAIL";

  const notes: string[] = [];
  if (entries.length === 0) notes.push("Log is empty — run synthetic traffic (POST /api/v2/enforcement/gate) before auditing");
  if (pilotCoverage < pilot.length) notes.push(`Coverage gap: ${pilot.length - pilotCoverage} TIER-A services have no log entries`);
  if (eligible) notes.push("Soft gate eligible — all success conditions met");

  return {
    generated_at: now,
    schema_version: "aegis.audit.v1",
    log_path: path,
    total_log_entries: entries.length,
    pilot_services_covered: pilotCoverage,
    pilot_services_total: pilot.length,
    pilot_coverage_complete: pilotCoverage >= pilot.length,
    false_positives: fps,
    false_negatives: fns,
    fp_count: fps.length,
    fn_count: fns.length,
    service_matrix: matrix.sort((a, b) => b.total_decisions - a.total_decisions),
    decision_distribution: decisionDist,
    enforcement_mode_seen: [...modesSet],
    soft_gate_eligible: eligible,
    soft_gate_blockers: blockers,
    audit_verdict: verdict,
    audit_notes: notes,
  };
}

// ── Markdown report generators ─────────────────────────────────────────────────

export function renderDecisionMatrix(summary: AuditSummary): string {
  const rows = summary.service_matrix
    .filter(r => r.in_pilot || r.total_decisions > 0)
    .map(r => `| ${r.service_id.padEnd(28)} | ${r.tier.padEnd(6)} | ${String(r.in_pilot).padEnd(5)} | ${r.total_decisions.toString().padStart(5)} | ${r.allow.toString().padStart(5)} | ${r.warn.toString().padStart(4)} | ${r.gate.toString().padStart(4)} | ${r.block.toString().padStart(5)} | ${r.read_gated.toString().padStart(9)} | ${r.deploy_allowed.toString().padStart(13)} |`)
    .join("\n");

  return `# AEGIS Service Decision Matrix
Generated: ${summary.generated_at}

| Service                       | Tier   | Pilot | Total | Allow |  Warn |  Gate | Block | ReadGated | DeployAllowed |
|-------------------------------|--------|-------|-------|-------|-------|-------|-------|-----------|---------------|
${rows}

## Verdict: ${summary.audit_verdict}
- False positives: ${summary.fp_count}
- False negatives: ${summary.fn_count}
- Soft gate eligible: ${summary.soft_gate_eligible}
${summary.soft_gate_blockers.map(b => `- BLOCKER: ${b}`).join("\n")}
`;
}

export function renderTopViolations(summary: AuditSummary): string {
  const fps = summary.false_positives.map(f =>
    `### FP: ${f.category}\n- Service: ${f.entry.service_id}\n- Decision: ${f.entry.decision}\n- ${f.description}`
  ).join("\n\n") || "_None_";

  const fns = summary.false_negatives.map(f =>
    `### FN: ${f.category}\n- Service: ${f.entry.service_id}\n- Decision: ${f.entry.decision}\n- ${f.description}`
  ).join("\n\n") || "_None_";

  return `# AEGIS Top Violations
Generated: ${summary.generated_at}
Verdict: **${summary.audit_verdict}**

## False Positives (${summary.fp_count})
${fps}

## False Negatives (${summary.fn_count})
${fns}

## Soft Gate Blockers
${summary.soft_gate_blockers.length === 0 ? "_None — eligible for soft enforcement_" : summary.soft_gate_blockers.map(b => `- ${b}`).join("\n")}
`;
}

// Write audit files to a directory
export function writeAuditFiles(summary: AuditSummary, outDir: string): void {
  writeFileSync(join(outDir, "enforcement_audit_summary.json"), JSON.stringify(summary, null, 2));
  writeFileSync(join(outDir, "service_decision_matrix.md"), renderDecisionMatrix(summary));
  writeFileSync(join(outDir, "top_violations.md"), renderTopViolations(summary));
}
