// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 06 — Budget Inheritance Rejection
// checkBudgetInheritance must reject a child spawn when the child cap exceeds the parent's
// remaining budget (parentRemaining < childCap → allowed=false, KAV-018).
// Also verifies that a child cap within parent budget IS allowed.

import { TestHarness, now } from "../harness.ts";
// Import the pure computation logic from db.ts — needs isolated HOME to get isolated DB
// We test via a seed + direct query since checkBudgetInheritance imports via getDb() singleton.
// Strategy: spawn a small bun subprocess that imports and calls checkBudgetInheritance.

async function callInheritanceCheck(
  h: TestHarness,
  parentId: string,
  childCap: number,
): Promise<{ allowed: boolean; error?: string }> {
  const script = Buffer.from(`
    import { checkBudgetInheritance } from "./src/core/db.ts";
    const result = checkBudgetInheritance({ parent_id: ${JSON.stringify(parentId)}, child_cap_usd: ${childCap} });
    process.stdout.write(JSON.stringify(result));
  `);
  const proc = Bun.spawn(["bun", "run", "-"], {
    cwd: "/root/aegis",
    stdin: script,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HOME: h.home },
  });
  const [, stdout] = await Promise.all([proc.exited, new Response(proc.stdout).text()]);
  try {
    return JSON.parse(stdout.trim());
  } catch {
    return { allowed: false, error: `parse error: ${stdout.slice(0, 200)}` };
  }
}

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("06-budget-inherit");
  try {
    h.setup();

    const parentId = "parent-agent-06";
    const ts = now();
    // Parent has $5 cap, $4 used, $0 reserved → $1 remaining
    h.seedDb((db) => {
      db.run(`
        INSERT INTO agents
          (agent_id, state, identity_confidence, session_id, depth,
           budget_cap_usd, budget_used_usd, budget_pool_reserved,
           spawn_timestamp, last_seen)
        VALUES (?, 'RUNNING', 'declared', 'session-06', 0, 5.0, 4.0, 0.0, ?, ?)
      `, [parentId, ts, ts]);
    });

    // Child requesting $3 — parent has only $1 → must be rejected
    const rejected = await callInheritanceCheck(h, parentId, 3.0);
    if (rejected.allowed !== false) {
      return { passed: false, details: `Expected allowed=false (child $3 > parent remaining $1), got ${JSON.stringify(rejected)}` };
    }

    // Re-seed parent (inheritance check reserves budget on success — reload for clean state)
    h.seedDb((db) => {
      db.run("UPDATE agents SET budget_used_usd = 4.0, budget_pool_reserved = 0.0 WHERE agent_id = ?", [parentId]);
    });

    // Child requesting $0.50 — parent has $1 → must be allowed
    const allowed = await callInheritanceCheck(h, parentId, 0.5);
    if (allowed.allowed !== true) {
      return { passed: false, details: `Expected allowed=true (child $0.50 <= parent remaining $1), got ${JSON.stringify(allowed)}` };
    }

    return {
      passed: true,
      details: "child $3 > parent $1 remaining → rejected (KAV-018); child $0.50 → allowed",
    };
  } finally {
    h.cleanup();
  }
}
