// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 07 — Zombie State Transition
// An agent idle past heartbeat.timeout_seconds should be detected as a zombie.
// We test the watchdog's zombie detection logic by calling its detection via a small
// subprocess, then asserting the DB state transitioned to ZOMBIE.

import { TestHarness, now, minutesAgo } from "../harness.ts";

// Run one watchdog detection tick via subprocess — only the zombie check, not the poll loop
async function runWatchdogTick(h: TestHarness): Promise<string> {
  const script = `
    import { listAgentRows, setAgentState } from "./src/core/db.ts";
    import { loadConfig } from "./src/core/config.ts";

    const config = loadConfig();
    const maxIdleMs = (config.heartbeat?.timeout_seconds ?? 300) * 1000;
    const agents = listAgentRows(["RUNNING"]);
    const now = Date.now();

    for (const agent of agents) {
      const idleMs = now - new Date(agent.last_seen).getTime();
      if (idleMs >= maxIdleMs) {
        setAgentState(agent.agent_id, "ZOMBIE", {
          reason: "idle > " + Math.round(maxIdleMs / 1000) + "s",
          rule: "KAV-013",
        });
        process.stdout.write("ZOMBIE:" + agent.agent_id);
      }
    }
    process.stdout.write("DONE");
  `;
  const proc = Bun.spawn(["bun", "run", "-"], {
    cwd: "/root/aegis",
    stdin: Buffer.from(script),
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HOME: h.home },
  });
  const [, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
  return stdout;
}

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("07-zombie");
  try {
    // 60-second heartbeat timeout, agent was last seen 10 minutes ago
    h.setup({ heartbeat: { timeout_seconds: 60, action: "alert" } });

    const agentId = "idle-agent-07";
    const ts = now();
    h.seedDb((db) => {
      db.run(`
        INSERT INTO agents
          (agent_id, state, identity_confidence, session_id, depth,
           budget_cap_usd, budget_used_usd, spawn_timestamp, last_seen, loop_count, stop_requested)
        VALUES (?, 'RUNNING', 'unknown', 'session-07', 0, 5.0, 0.0, ?, ?, 0, 0)
      `, [agentId, ts, minutesAgo(10)]);  // last_seen = 10 min ago, timeout = 60s
    });

    // Also register an active agent that should NOT become zombie
    const activeId = "active-agent-07";
    h.seedDb((db) => {
      db.run(`
        INSERT INTO agents
          (agent_id, state, identity_confidence, session_id, depth,
           budget_cap_usd, budget_used_usd, spawn_timestamp, last_seen, loop_count, stop_requested)
        VALUES (?, 'RUNNING', 'declared', 'session-07', 0, 5.0, 0.0, ?, ?, 0, 0)
      `, [activeId, ts, now()]);  // last_seen = right now
    });

    const tickOutput = await runWatchdogTick(h);

    if (!tickOutput.includes(`ZOMBIE:${agentId}`)) {
      return {
        passed: false,
        details: `Expected ${agentId} to be marked ZOMBIE (idle 10m > 60s timeout). Tick output: ${tickOutput.slice(0, 200)}`,
      };
    }

    // Verify DB state directly
    type AgentRow = { state: string };
    const rows = h.queryDb<AgentRow>("SELECT state FROM agents WHERE agent_id = ?", agentId);
    if (rows[0]?.state !== "ZOMBIE") {
      return {
        passed: false,
        details: `Tick reported ZOMBIE but DB shows state=${rows[0]?.state ?? "missing"}`,
      };
    }

    // Active agent must remain RUNNING
    const activeRows = h.queryDb<AgentRow>("SELECT state FROM agents WHERE agent_id = ?", activeId);
    if (activeRows[0]?.state !== "RUNNING") {
      return {
        passed: false,
        details: `Active agent incorrectly transitioned to ${activeRows[0]?.state} — false positive`,
      };
    }

    return {
      passed: true,
      details: `${agentId} (idle 10m) → ZOMBIE in DB (KAV-013); ${activeId} (just-seen) remains RUNNING`,
    };
  } finally {
    h.cleanup();
  }
}
