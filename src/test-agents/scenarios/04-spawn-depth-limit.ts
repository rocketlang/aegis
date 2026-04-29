// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 04 — Spawn Depth Limit
// An agent at max_depth must be blocked from spawning children (check-spawn exits 2).
// Tests the delegation chain depth enforcement (V2-052, KAV-008, INF-KAV-004).

import { TestHarness, now } from "../harness.ts";

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("04-spawn-depth");
  try {
    const MAX_DEPTH = 3;
    h.setup({
      enforcement: { mode: "enforce" },
      budget: { max_depth: MAX_DEPTH, spawn_limit_per_session: 100, cost_estimate_threshold_usd: 0.001 },
    });

    // Register an agent already at max_depth
    const agentId = "deep-agent-04";
    const ts = now();
    h.seedDb((db) => {
      db.run(`
        INSERT INTO agents
          (agent_id, state, identity_confidence, session_id, depth, budget_cap_usd, budget_used_usd,
           spawn_timestamp, last_seen, loop_count, stop_requested)
        VALUES (?, 'RUNNING', 'declared', 'session-04', ?, 10.0, 0.0, ?, ?, 0, 0)
      `, [agentId, MAX_DEPTH, ts, ts]);
    });

    // Write the file-backed state record (used by check-spawn depth check via loadAgent)
    h.writeFile(`agents/${agentId}.state.json`, JSON.stringify({
      agent_id: agentId,
      state: "RUNNING",
      identity_confidence: "declared",
      parent_id: null,
      session_id: "session-04",
      depth: MAX_DEPTH,
      budget_cap_usd: 10.0,
      budget_used_usd: 0.0,
      tool_calls: 0,
      loop_count: 0,
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

    // Write a valve file granting SPAWN_AGENTS so the block comes from depth, not perm_mask
    // PERM_STANDARD (0x6177) | SPAWN_AGENTS (0x8) = 0x617F = 24959
    // CLASS_STANDARD = 0x183 = 387
    h.writeFile(`agents/${agentId}.valve.json`, JSON.stringify({
      agent_id: agentId,
      state: "OPEN",
      declared_perm_mask: 0x617F,
      effective_perm_mask: 0x617F,
      declared_class_mask: 0x183,
      effective_class_mask: 0x183,
      violation_count: 0,
      loop_count: 0,
      narrowed_at: null,
      narrowed_reason: null,
      locked_by: null,
      locked_at: null,
      quarantine_flag: false,
    }));

    const result = await h.callHook(
      "check-spawn",
      {
        tool_name: "Agent",
        session_id: "session-04",
        tool_input: { subagent_type: "general-purpose", prompt: "do something", description: "child agent" },
      },
      {
        CLAUDE_SESSION_ID: "session-04",
        CLAUDE_AGENT_ID: agentId,
      },
    );

    if (result.exitCode !== 2) {
      return {
        passed: false,
        details: `Expected exit 2 at depth=${MAX_DEPTH}/${MAX_DEPTH}, got ${result.exitCode}. stderr: ${result.stderr.slice(0, 300)}`,
      };
    }
    if (!result.stderr.toLowerCase().includes("depth")) {
      return {
        passed: false,
        details: `Exit 2 but stderr missing depth mention: ${result.stderr.slice(0, 300)}`,
      };
    }

    return {
      passed: true,
      details: `agent at depth ${MAX_DEPTH}/${MAX_DEPTH} blocked from spawning; exit 2 + depth in stderr`,
    };
  } finally {
    h.cleanup();
  }
}
