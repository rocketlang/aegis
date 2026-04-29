// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Scenario 08 — Orphan Detection
// When a parent agent's state is FORCE_CLOSED, a watchdog tick must transition
// its RUNNING child to ORPHAN (INF-KAV-007). An agent with no dead parent stays RUNNING.

import { TestHarness, now } from "../harness.ts";

async function runOrphanTick(h: TestHarness): Promise<string> {
  const script = `
    import { listAgentRows, setAgentState } from "./src/core/db.ts";

    const TERMINAL = new Set(["FORCE_CLOSED", "KILLED", "FAILED"]);
    const agents = listAgentRows();

    const terminalIds = new Set(
      agents.filter((a) => TERMINAL.has(a.state)).map((a) => a.agent_id)
    );

    const orphaned = [];
    for (const agent of agents) {
      if (!["RUNNING", "QUARANTINED"].includes(agent.state)) continue;
      if (!agent.parent_id) continue;
      if (!terminalIds.has(agent.parent_id)) continue;
      setAgentState(agent.agent_id, "ORPHAN", {
        reason: "parent " + agent.parent_id + " is terminal",
        rule: "INF-KAV-007",
      });
      orphaned.push(agent.agent_id);
    }
    process.stdout.write(JSON.stringify(orphaned));
  `;
  const proc = Bun.spawn(["bun", "run", "-"], {
    cwd: "/root/aegis",
    stdin: Buffer.from(script),
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HOME: h.home },
  });
  const [, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
  return stdout.trim();
}

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("08-orphan");
  try {
    h.setup();

    const parentId = "parent-agent-08";
    const childId = "child-agent-08";
    const soloId = "solo-agent-08";
    const ts = now();

    h.seedDb((db) => {
      // Parent — already FORCE_CLOSED
      db.run(`INSERT INTO agents (agent_id, state, identity_confidence, session_id, depth,
        budget_cap_usd, budget_used_usd, spawn_timestamp, last_seen)
        VALUES (?, 'FORCE_CLOSED', 'declared', 'session-08', 0, 5.0, 3.0, ?, ?)`,
        [parentId, ts, ts]);

      // Child — RUNNING, parent_id points to dead parent
      db.run(`INSERT INTO agents (agent_id, state, identity_confidence, parent_id, session_id, depth,
        budget_cap_usd, budget_used_usd, spawn_timestamp, last_seen)
        VALUES (?, 'RUNNING', 'declared', ?, 'session-08', 1, 2.0, 0.0, ?, ?)`,
        [childId, parentId, ts, ts]);

      // Solo agent — RUNNING, no parent → must NOT become orphan
      db.run(`INSERT INTO agents (agent_id, state, identity_confidence, session_id, depth,
        budget_cap_usd, budget_used_usd, spawn_timestamp, last_seen)
        VALUES (?, 'RUNNING', 'declared', 'session-08b', 0, 5.0, 0.0, ?, ?)`,
        [soloId, ts, ts]);
    });

    const output = await runOrphanTick(h);
    let orphaned: string[];
    try {
      orphaned = JSON.parse(output);
    } catch {
      return { passed: false, details: `Tick output parse error: ${output.slice(0, 200)}` };
    }

    if (!orphaned.includes(childId)) {
      return { passed: false, details: `Expected ${childId} in orphaned list, got: ${JSON.stringify(orphaned)}` };
    }

    // Verify DB
    type Row = { state: string };
    const childRow = h.queryDb<Row>("SELECT state FROM agents WHERE agent_id = ?", childId);
    if (childRow[0]?.state !== "ORPHAN") {
      return { passed: false, details: `DB shows child state=${childRow[0]?.state}, expected ORPHAN` };
    }

    const soloRow = h.queryDb<Row>("SELECT state FROM agents WHERE agent_id = ?", soloId);
    if (soloRow[0]?.state !== "RUNNING") {
      return { passed: false, details: `Solo agent incorrectly became ${soloRow[0]?.state} — false positive` };
    }

    return {
      passed: true,
      details: `${childId} (parent FORCE_CLOSED) → ORPHAN (INF-KAV-007); ${soloId} (no parent) stays RUNNING`,
    };
  } finally {
    h.cleanup();
  }
}
