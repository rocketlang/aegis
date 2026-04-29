// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Register — Check In protocol (V2-031)
// Creates policy file from template, registers agent in session-agent registry.
// @rule:KAV-002 Agent check-in at session start
// @rule:KAV-YK-009 Check-in / check-out lifecycle

import { writeFileSync, readFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../core/config";
import { makeDefaultPolicy, POLICY_SCHEMA_VERSION, DEFAULT_POLICY, type AgentPolicy } from "../../sandbox/policy-schema";
import { createAgent } from "../../sandbox/quarantine";
import { resolveAgentId } from "../../sandbox/policy-loader";
import { initValve } from "../../kavach/gate-valve";
import { checkBudgetInheritance } from "../../core/db";

function getAgentsDir(): string {
  const dir = join(getAegisDir(), "agents");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

export default function register(args: string[]): void {
  // Parse flags
  const idxId    = args.indexOf("--id");
  const idxDepth = args.indexOf("--depth");
  const idxBudget = args.indexOf("--budget");
  const idxParent = args.indexOf("--parent");
  const idxSession = args.indexOf("--session");

  const agentId   = idxId >= 0     ? args[idxId + 1]     : resolveAgentId({ systemPromptText: process.env.SYSTEM_PROMPT ?? "" }).agent_id;
  const depth     = idxDepth >= 0  ? parseInt(args[idxDepth + 1]) : 0;
  const budgetCap = idxBudget >= 0 ? parseFloat(args[idxBudget + 1]) : 0;
  const parentId  = idxParent >= 0 ? args[idxParent + 1] : null;
  const sessionId = idxSession >= 0 ? args[idxSession + 1] : (process.env.AEGIS_SESSION_ID ?? `ses_${Date.now()}`);

  if (!agentId) {
    console.error("[AEGIS] register: agent_id required — use --id <id> or set AEGIS_AGENT_ID env var");
    process.exit(1);
  }

  const policyPath = join(getAgentsDir(), `${agentId}.json`);

  // Create default policy file if not present
  if (!existsSync(policyPath)) {
    const policy = makeDefaultPolicy(agentId, {
      budget_cap_usd: budgetCap,
      max_depth: Math.max(0, 3 - depth),
    });
    writeFileSync(policyPath, JSON.stringify(policy, null, 2));
    console.log(`[AEGIS] Policy created: ${policyPath}`);
  } else {
    console.log(`[AEGIS] Policy exists: ${policyPath}`);
  }

  // Resolve identity confidence
  const identity = resolveAgentId({ systemPromptText: process.env.SYSTEM_PROMPT ?? "", envAgentId: agentId });

  // V2-062 — Budget inheritance check (KAV-018)
  if (parentId && budgetCap > 0) {
    const budgetCheck = checkBudgetInheritance({ parent_id: parentId, child_cap_usd: budgetCap });
    if (!budgetCheck.allowed) {
      console.error(`[AEGIS] register: ${budgetCheck.error}`);
      process.exit(1);
    }
  }

  // Register in state machine
  const existing = existsSync(join(getAgentsDir(), `${agentId}.state.json`));
  if (existing) {
    console.log(`[AEGIS] Agent ${agentId} already registered — skipping state creation`);
  } else {
    let toolsDeclared = 0;
    try {
      const p = JSON.parse(readFileSync(policyPath, "utf-8")) as AgentPolicy;
      toolsDeclared = Array.isArray(p.tools_allowed) ? p.tools_allowed.length : 0;
    } catch {}
    createAgent({
      agent_id: agentId,
      identity_confidence: identity.confidence,
      parent_id: parentId,
      session_id: sessionId,
      depth,
      budget_cap_usd: budgetCap,
      policy_path: policyPath,
      tools_declared: toolsDeclared,
    });
    console.log(`[AEGIS] Registered: ${agentId} (depth=${depth}, confidence=${identity.confidence}, budget=$${budgetCap || "inherit"})`);
  }

  // @rule:NULL-KAV-001 — init gate valve from policy at registration, not on first violation
  const valvePath = join(getAgentsDir(), `${agentId}.valve.json`);
  if (!existsSync(valvePath)) {
    let permMask = DEFAULT_POLICY.perm_mask;
    let classMask = DEFAULT_POLICY.class_mask;
    try {
      const p = JSON.parse(readFileSync(policyPath, "utf-8")) as AgentPolicy;
      if (typeof p.perm_mask === "number") permMask = p.perm_mask;
      if (typeof p.class_mask === "number") classMask = p.class_mask;
    } catch {}
    initValve(agentId, permMask, classMask);
    console.log(`[AEGIS] Gate valve initialized: perm=0x${permMask.toString(16)}, class=0x${classMask.toString(16)}`);
  } else {
    console.log(`[AEGIS] Gate valve exists: ${agentId}`);
  }

  // Print policy template path for operator reference
  console.log(`[AEGIS] Edit policy: ${policyPath}`);
  console.log(`[AEGIS] Schema: ${POLICY_SCHEMA_VERSION}`);
}
