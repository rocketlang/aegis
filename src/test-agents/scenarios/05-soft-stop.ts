// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 05 — L1 Soft Stop
// An agent with stop_requested=1 must be blocked by check-shield (exit 2, enforce mode).
// This simulates AEGIS deciding mid-session that an agent should yield gracefully.

import { TestHarness, now } from "../harness.ts";

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("05-soft-stop");
  try {
    h.setup({ enforcement: { mode: "enforce" }, kavach: { enabled: true } });

    const agentId = "stop-agent-05";
    const ts = now();
    h.seedDb((db) => {
      db.run(`
        INSERT INTO agents
          (agent_id, state, identity_confidence, session_id, depth, budget_cap_usd, budget_used_usd,
           spawn_timestamp, last_seen, loop_count, stop_requested)
        VALUES (?, 'RUNNING', 'declared', 'session-05', 1, 10.0, 0.0, ?, ?, 0, 1)
      `, [agentId, ts, ts]);
    });

    // check-shield reads stop_requested via isStopRequested() before running any detection
    const result = await h.callHook(
      "check-shield",
      {
        tool_name: "Bash",
        session_id: "session-05",
        tool_input: { command: "ls /tmp" },
      },
      {
        CLAUDE_SESSION_ID: "session-05",
        CLAUDE_AGENT_ID: agentId,
      },
    );

    if (result.exitCode !== 2) {
      return {
        passed: false,
        details: `Expected exit 2 for stop_requested agent, got ${result.exitCode}. stderr: ${result.stderr.slice(0, 300)}`,
      };
    }
    if (!result.stderr.toLowerCase().includes("stop")) {
      return {
        passed: false,
        details: `Exit 2 but stderr missing "stop": ${result.stderr.slice(0, 300)}`,
      };
    }

    return {
      passed: true,
      details: "stop_requested=1 agent blocked by check-shield (exit 2, L1 Soft Stop in stderr)",
    };
  } finally {
    h.cleanup();
  }
}
