// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Scenario 10 — Loop Count Quarantine
// An agent with loop_count > 50 must be quarantined by check-spawn (INF-KAV-014).
// Also verifies that an agent with loop_count=5 passes through normally.

import { TestHarness, now } from "../harness.ts";

function seedAgent(h: TestHarness, agentId: string, sessionId: string, loopCount: number): void {
  const ts = now();

  // File-backed state (read by loadAgent in check-spawn depth + loop checks)
  h.writeFile(`agents/${agentId}.state.json`, JSON.stringify({
    agent_id: agentId,
    state: "RUNNING",
    identity_confidence: "declared",
    parent_id: null,
    session_id: sessionId,
    depth: 1,
    budget_cap_usd: 10.0,
    budget_used_usd: 0.0,
    tool_calls: loopCount,
    loop_count: loopCount,
    policy_path: null,
    tools_declared: 0,
    violation_count: 0,
    spawn_timestamp: ts,
    last_seen: ts,
    stop_requested: 0,
    quarantine_reason: null,
    quarantine_rule: null,
    release_reason: null,
    released_by: null,
    resume_manifest_path: null,
  }));

  // Valve record — PERM_STANDARD | SPAWN_AGENTS = 0x617F; CLASS_STANDARD = 0x183
  h.writeFile(`agents/${agentId}.valve.json`, JSON.stringify({
    agent_id: agentId,
    state: "OPEN",
    declared_perm_mask: 0x617F,
    effective_perm_mask: 0x617F,
    declared_class_mask: 0x183,
    effective_class_mask: 0x183,
    violation_count: 0,
    loop_count: loopCount,
    narrowed_at: null,
    narrowed_reason: null,
    locked_by: null,
    locked_at: null,
    quarantine_flag: false,
  }));

  // SQLite row (used by getSessionSpawnCount, isStopRequested)
  h.seedDb((db) => {
    db.run(`INSERT OR REPLACE INTO agents
      (agent_id, state, identity_confidence, session_id, depth, budget_cap_usd,
       budget_used_usd, tool_calls, loop_count, spawn_timestamp, last_seen, stop_requested)
      VALUES (?, 'RUNNING', 'declared', ?, 1, 10.0, 0.0, ?, ?, ?, ?, 0)`,
      [agentId, sessionId, loopCount, loopCount, ts, ts]);
  });
}

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("10-loop-quarantine");
  try {
    h.setup({
      enforcement: { mode: "enforce" },
      budget: { spawn_limit_per_session: 100, cost_estimate_threshold_usd: 0.001 },
    });

    // Agent with loop_count = 52 → must be quarantined
    const hotId = "hot-agent-10";
    seedAgent(h, hotId, "session-10a", 52);

    const hotResult = await h.callHook(
      "check-spawn",
      { tool_name: "Agent", session_id: "session-10a", tool_input: { subagent_type: "general-purpose", prompt: "go" } },
      { CLAUDE_SESSION_ID: "session-10a", CLAUDE_AGENT_ID: hotId },
    );

    if (hotResult.exitCode !== 2) {
      return {
        passed: false,
        details: `Expected exit 2 for loop_count=52, got ${hotResult.exitCode}. stderr: ${hotResult.stderr.slice(0, 300)}`,
      };
    }
    const stderrLower = hotResult.stderr.toLowerCase();
    if (!stderrLower.includes("quarantine") && !stderrLower.includes("loop")) {
      return {
        passed: false,
        details: `Exit 2 but missing quarantine/loop in stderr: ${hotResult.stderr.slice(0, 300)}`,
      };
    }

    // Agent with loop_count = 5 → must pass through
    const coolId = "cool-agent-10";
    seedAgent(h, coolId, "session-10b", 5);

    const coolResult = await h.callHook(
      "check-spawn",
      {
        tool_name: "Agent",
        session_id: "session-10b",
        tool_input: {
          subagent_type: "general-purpose",
          description: "File inventory agent",
          prompt: "List all TypeScript files in /root/aegis/src and return their paths as a JSON array.",
        },
      },
      { CLAUDE_SESSION_ID: "session-10b", CLAUDE_AGENT_ID: coolId },
    );

    if (coolResult.exitCode !== 0) {
      return {
        passed: false,
        details: `loop_count=52 quarantined correctly, but loop_count=5 exited ${coolResult.exitCode} — false positive`,
      };
    }

    return {
      passed: true,
      details: `loop_count=52 → QUARANTINE exit 2 (INF-KAV-014); loop_count=5 → exit 0 (no false positive)`,
    };
  } finally {
    h.cleanup();
  }
}
