// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// [EE] AEGIS Shield — HanumanG Enterprise Edition
// Extends the 7-axis OSS check with domain registry validation,
// posture scoring across session history, and structured posture reports.
// @rule:KAV-015 HanumanG delegation chain validation
// @rule:KAV-YK-008 Domain registry check is EE — validates agent type against known registry

import type { SpawnContext, HanumanGResult } from "./hanumang";
import { checkHanumanG } from "./hanumang";

export interface AgentRegistryEntry {
  agent_type: string;       // e.g. "data-pipeline", "code-reviewer", "file-manager"
  allowed_tools: string[];  // canonical allowed tools for this type
  max_depth: number;
  max_budget_usd: number;
  domains: string[];        // which service domains this agent type may touch
}

export interface HanumanGPostureScore {
  session_id: string;
  total_spawns: number;
  passed: number;
  blocked: number;
  posture_level: "GREEN" | "AMBER" | "RED";
  score: number;             // 0–100
  dominant_failure: string | null;
  report_generated_at: string;
}

export interface HanumanGEEResult extends HanumanGResult {
  registry_check: {
    agent_type: string | null;
    registered: boolean;
    registry_violations: string[];
  };
  posture_score?: HanumanGPostureScore;
}

// In-memory registry — in EE deployment this is loaded from xShieldAI via ankr-agent-registry
const DEFAULT_REGISTRY: AgentRegistryEntry[] = [
  { agent_type: "code-reviewer",   allowed_tools: ["Read","Grep","Glob","Bash"], max_depth: 2, max_budget_usd: 0.5, domains: ["*"] },
  { agent_type: "data-pipeline",   allowed_tools: ["Read","Write","Bash"],       max_depth: 2, max_budget_usd: 1.0, domains: ["*"] },
  { agent_type: "file-manager",    allowed_tools: ["Read","Write","Edit"],        max_depth: 1, max_budget_usd: 0.2, domains: ["*"] },
  { agent_type: "frontend-dev",    allowed_tools: ["Read","Write","Edit","Bash"], max_depth: 3, max_budget_usd: 2.0, domains: ["frontend","ui"] },
  { agent_type: "backend-dev",     allowed_tools: ["Read","Write","Edit","Bash"], max_depth: 3, max_budget_usd: 2.0, domains: ["backend","api"] },
  { agent_type: "security-audit",  allowed_tools: ["Read","Grep","Glob","Bash"], max_depth: 2, max_budget_usd: 1.0, domains: ["security"] },
  { agent_type: "db-migration",    allowed_tools: ["Read","Bash"],               max_depth: 1, max_budget_usd: 0.3, domains: ["database"] },
];

// Session posture accumulator — keyed by session_id
const sessionHistory = new Map<string, { passed: number; blocked: number; failures: string[] }>();

function inferAgentType(ctx: SpawnContext): string | null {
  const desc = (ctx.agent_description || "").toLowerCase();
  if (desc.includes("review")) return "code-reviewer";
  if (desc.includes("pipeline") || desc.includes("data")) return "data-pipeline";
  if (desc.includes("frontend") || desc.includes("ui")) return "frontend-dev";
  if (desc.includes("backend") || desc.includes("api")) return "backend-dev";
  if (desc.includes("security") || desc.includes("audit")) return "security-audit";
  if (desc.includes("db") || desc.includes("database") || desc.includes("migration")) return "db-migration";
  if (desc.includes("file")) return "file-manager";
  return null;
}

function checkRegistry(ctx: SpawnContext): HanumanGEEResult["registry_check"] {
  const agent_type = inferAgentType(ctx);
  if (!agent_type) {
    return { agent_type: null, registered: false, registry_violations: ["Agent type unrecognised — description too vague to classify"] };
  }

  const entry = DEFAULT_REGISTRY.find(r => r.agent_type === agent_type);
  if (!entry) {
    return { agent_type, registered: false, registry_violations: [`Agent type '${agent_type}' not in EE registry`] };
  }

  const violations: string[] = [];

  // Budget check against registry cap
  if (ctx.child_budget_cap_usd !== undefined && ctx.child_budget_cap_usd > entry.max_budget_usd) {
    violations.push(`Budget $${ctx.child_budget_cap_usd} exceeds registry max $${entry.max_budget_usd} for type '${agent_type}'`);
  }

  // Depth check against registry
  const childDepth = (ctx.parent_depth ?? 0) + 1;
  if (childDepth > entry.max_depth) {
    violations.push(`Depth ${childDepth} exceeds registry max ${entry.max_depth} for type '${agent_type}'`);
  }

  // Tool scope check
  if (ctx.child_tools_requested && ctx.child_tools_requested.length > 0 && !entry.allowed_tools.includes("*")) {
    const excess = ctx.child_tools_requested.filter(t => !entry.allowed_tools.includes(t));
    if (excess.length > 0) {
      violations.push(`Tools not permitted for '${agent_type}': ${excess.join(", ")}`);
    }
  }

  return { agent_type, registered: true, registry_violations: violations };
}

export function checkHanumanGEE(
  ctx: SpawnContext,
  sessionId: string = "unknown",
  registry?: AgentRegistryEntry[],
): HanumanGEEResult {
  // Run base 7-axis check
  const base = checkHanumanG(ctx);

  // Registry check (EE)
  const registry_check = checkRegistry(ctx);

  // Accumulate posture history
  const hist = sessionHistory.get(sessionId) ?? { passed: 0, blocked: 0, failures: [] };
  const registryFailed = registry_check.registry_violations.length > 0;
  const blocked = !base.passed || registryFailed;

  if (blocked) {
    hist.blocked++;
    hist.failures.push(...base.failed_axes, ...registry_check.registry_violations.map(v => v.slice(0, 60)));
  } else {
    hist.passed++;
  }
  sessionHistory.set(sessionId, hist);

  // Posture score
  const total = hist.passed + hist.blocked;
  const score = total === 0 ? 100 : Math.round((hist.passed / total) * 100);
  const posture_level: HanumanGPostureScore["posture_level"] = score >= 80 ? "GREEN" : score >= 50 ? "AMBER" : "RED";

  // Dominant failure
  const failCounts = hist.failures.reduce((acc, f) => { acc[f] = (acc[f] ?? 0) + 1; return acc; }, {} as Record<string, number>);
  const dominant_failure = Object.keys(failCounts).sort((a, b) => failCounts[b] - failCounts[a])[0] ?? null;

  const posture_score: HanumanGPostureScore = {
    session_id: sessionId,
    total_spawns: total,
    passed: hist.passed,
    blocked: hist.blocked,
    posture_level,
    score,
    dominant_failure,
    report_generated_at: new Date().toISOString(),
  };

  // If registry fails, override passed to false and merge reason
  const finalPassed = base.passed && !registryFailed;
  const finalReason = finalPassed
    ? base.reason
    : [base.passed ? "" : base.reason, ...registry_check.registry_violations].filter(Boolean).join("; ");

  return {
    ...base,
    passed: finalPassed,
    reason: finalReason,
    registry_check,
    posture_score,
  };
}

export function getSessionPosture(sessionId: string): HanumanGPostureScore | null {
  const hist = sessionHistory.get(sessionId);
  if (!hist) return null;
  const total = hist.passed + hist.blocked;
  const score = total === 0 ? 100 : Math.round((hist.passed / total) * 100);
  const posture_level: HanumanGPostureScore["posture_level"] = score >= 80 ? "GREEN" : score >= 50 ? "AMBER" : "RED";
  const failCounts = hist.failures.reduce((acc, f) => { acc[f] = (acc[f] ?? 0) + 1; return acc; }, {} as Record<string, number>);
  const dominant_failure = Object.keys(failCounts).sort((a, b) => failCounts[b] - failCounts[a])[0] ?? null;
  return { session_id: sessionId, total_spawns: total, passed: hist.passed, blocked: hist.blocked, posture_level, score, dominant_failure, report_generated_at: new Date().toISOString() };
}
