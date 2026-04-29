// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Close — Check Out protocol (V2-032)
// Transitions agent to COMPLETED, writes final manifest, returns unused budget to parent.
// @rule:KAV-010 Agent check-out at session end
// @rule:KAV-YK-009 Check-in / check-out lifecycle

import { writeFileSync, existsSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";
import { loadAgent, transitionState } from "../../sandbox/quarantine";
import { resolveAgentId } from "../../sandbox/policy-loader";
import { rebalanceBudget } from "../../core/db";

export default function close(args: string[]): void {
  const idxId      = args.indexOf("--id");
  const idxSession = args.indexOf("--session");
  const idxReason  = args.indexOf("--reason");

  const agentId   = idxId >= 0      ? args[idxId + 1]      : resolveAgentId({ systemPromptText: process.env.SYSTEM_PROMPT ?? "" }).agent_id;
  const sessionId = idxSession >= 0  ? args[idxSession + 1] : (process.env.AEGIS_SESSION_ID ?? null);
  const reason    = idxReason >= 0   ? args[idxReason + 1]  : "completed normally";

  if (!agentId) {
    console.error("[AEGIS] close: agent_id required — use --id <id> or set AEGIS_AGENT_ID env var");
    process.exit(1);
  }

  const record = loadAgent(agentId);
  if (!record) {
    console.error(`[AEGIS] close: agent ${agentId} not found — was it registered?`);
    process.exit(1);
  }

  if (record.state === "COMPLETED") {
    console.log(`[AEGIS] Agent ${agentId} already COMPLETED`);
    process.exit(0);
  }

  // Write final manifest before transitioning
  const manifestPath = join(getAegisDir(), "agents", `${agentId}.manifest.json`);
  const closedAt = new Date().toISOString();
  const unusedBudget = Math.max(0, record.budget_cap_usd - record.budget_used_usd);

  const manifest = {
    agent_id: agentId,
    session_id: sessionId ?? record.session_id,
    closed_at: closedAt,
    spawn_timestamp: record.spawn_timestamp,
    duration_ms: Date.now() - new Date(record.spawn_timestamp).getTime(),
    state_at_close: record.state,
    tool_calls: record.tool_calls,
    violation_count: record.violation_count,
    budget_cap_usd: record.budget_cap_usd,
    budget_used_usd: record.budget_used_usd,
    unused_budget_usd: unusedBudget,
    parent_id: record.parent_id,
    depth: record.depth,
    close_reason: reason,
  };

  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  // V2-063 — Budget pool rebalancing (KAV-003)
  try { rebalanceBudget(agentId); } catch {}

  const result = transitionState(agentId, "COMPLETED", { reason });

  if (!result.success) {
    console.error(`[AEGIS] close: transition failed — ${result.error}`);
    process.exit(1);
  }

  console.log(`[AEGIS] Closed: ${agentId}`);
  console.log(`  State:         ${record.state} → COMPLETED`);
  console.log(`  Tool calls:    ${record.tool_calls}`);
  console.log(`  Violations:    ${record.violation_count}`);
  if (record.budget_cap_usd > 0) {
    console.log(`  Budget used:   $${record.budget_used_usd.toFixed(4)} / $${record.budget_cap_usd.toFixed(4)}`);
    if (unusedBudget > 0) {
      console.log(`  Unused budget: $${unusedBudget.toFixed(4)} returned to parent pool`);
    }
  }
  console.log(`  Manifest:      ${manifestPath}`);
}
