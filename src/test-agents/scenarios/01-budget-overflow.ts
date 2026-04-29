// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 01 — Budget Overflow
// Daily spend > limit in enforce mode → check-budget must exit 2 and write "BLOCKED" to stderr.
// Also verifies that alert mode (the safe default) does NOT exit 2.

import { TestHarness, dailyPeriodKey, now } from "../harness.ts";

export async function run(): Promise<{ passed: boolean; details: string }> {
  const h = new TestHarness("01-budget-overflow");
  try {
    h.setup({ enforcement: { mode: "enforce" }, budget: { daily_limit_usd: 5 } });

    // Inject $6 spend against a $5 daily limit
    h.seedDb((db) => {
      db.run(
        "INSERT OR REPLACE INTO budget_state (period, spent_usd, limit_usd, last_updated) VALUES (?, ?, ?, ?)",
        [dailyPeriodKey(), 6.0, 5.0, now()],
      );
    });

    // check-budget reads no stdin payload — just checks DB state
    const result = await h.callHook("check-budget", {}, {
      CLAUDE_SESSION_ID: "test-agent-01",
    });

    if (result.exitCode !== 2) {
      return { passed: false, details: `Expected exit 2 but got ${result.exitCode}. stderr: ${result.stderr.trim()}` };
    }
    if (!result.stderr.includes("Daily budget") && !result.stderr.includes("budget")) {
      return { passed: false, details: `Exit 2 but stderr missing budget message: ${result.stderr.trim()}` };
    }

    // Sanity-check: alert mode should NOT block (exit 0)
    const h2 = new TestHarness("01-budget-overflow-alert");
    h2.setup({ enforcement: { mode: "alert" }, budget: { daily_limit_usd: 5 } });
    h2.seedDb((db) => {
      db.run(
        "INSERT OR REPLACE INTO budget_state (period, spent_usd, limit_usd, last_updated) VALUES (?, ?, ?, ?)",
        [dailyPeriodKey(), 6.0, 5.0, now()],
      );
    });
    const alertResult = await h2.callHook("check-budget", {}, { CLAUDE_SESSION_ID: "test-agent-01a" });
    h2.cleanup();

    if (alertResult.exitCode !== 0) {
      return { passed: false, details: `Alert mode must exit 0 (safe default), got ${alertResult.exitCode}` };
    }

    return { passed: true, details: "enforce mode exits 2 + stderr budget message; alert mode exits 0" };
  } finally {
    h.cleanup();
  }
}
