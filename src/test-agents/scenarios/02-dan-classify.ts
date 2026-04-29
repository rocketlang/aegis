// SPDX-License-Identifier: AGPL-3.0-only
// Scenario 02 — KAVACH DAN Classification
// Tests classifyCommand (pure function) for correct level assignment.
// Also tests that check-destructive blocks a HIGH severity rule without waiting for gate approval.

import { TestHarness } from "../harness.ts";
import { classifyCommand } from "../../kavach/gate.ts";

const DESTRUCTIVE_RULES = JSON.stringify({
  bash_block_patterns: [
    {
      pattern: "rm\\s+-rf\\s+/",
      flags: "i",
      reason: "Recursive delete from filesystem root",
      severity: "HIGH",
    },
    {
      pattern: "prisma\\s+migrate\\s+reset",
      flags: "i",
      reason: "Full database wipe",
      severity: "CRITICAL",
    },
  ],
  allowed_override_token: "AEGIS-DESTRUCTIVE-CONFIRMED",
});

export async function run(): Promise<{ passed: boolean; details: string }> {
  // --- Part A: pure function classification (no subprocess, no DB) ---
  const cases: Array<{ cmd: string; expectedLevel: 4 | 3 | 2 | 1 | null; label: string }> = [
    { cmd: "prisma migrate reset",         expectedLevel: 4, label: "L4 — full DB wipe" },
    { cmd: "docker compose down -v",        expectedLevel: 3, label: "L3 — volume destruction" },
    { cmd: "rm -rf /tmp/testdir",            expectedLevel: 2, label: "L2 — recursive delete (non-system path)" },
    { cmd: "DROP TABLE users",              expectedLevel: 2, label: "L2 — DROP TABLE" },
    { cmd: "DELETE FROM sessions",          expectedLevel: 1, label: "L1 — DELETE FROM" },
    { cmd: "bun install && bun run build",  expectedLevel: null, label: "clean — no match" },
  ];

  const failures: string[] = [];
  for (const { cmd, expectedLevel, label } of cases) {
    const result = classifyCommand(cmd);
    const actual = result?.level ?? null;
    if (actual !== expectedLevel) {
      failures.push(`${label}: expected L${expectedLevel} got L${actual} (cmd="${cmd}")`);
    }
  }
  if (failures.length > 0) {
    return { passed: false, details: `classifyCommand failures:\n  ${failures.join("\n  ")}` };
  }

  // --- Part B: hook blocks HIGH severity rule immediately (no gate) ---
  const h = new TestHarness("02-dan-high");
  try {
    h.setup({ enforcement: { mode: "enforce" } });
    h.writeFile("destructive-rules.json", DESTRUCTIVE_RULES);

    const result = await h.callHook("check-destructive", {
      tool_name: "Bash",
      session_id: "test-agent-02",
      tool_input: { command: "rm -rf /etc/production" },
    });

    if (result.exitCode !== 2) {
      return {
        passed: false,
        details: `Part A ok. Part B: expected exit 2 for HIGH rule, got ${result.exitCode}. stderr: ${result.stderr.slice(0, 200)}`,
      };
    }
    if (!result.stderr.includes("KAVACH BLOCK") && !result.stderr.includes("BLOCK")) {
      return {
        passed: false,
        details: `Part A ok. Part B: exit 2 but missing KAVACH BLOCK in stderr: ${result.stderr.slice(0, 200)}`,
      };
    }

    return {
      passed: true,
      details: `${cases.length} classifyCommand cases correct; HIGH rule exits 2 with KAVACH BLOCK`,
    };
  } finally {
    h.cleanup();
  }
}
