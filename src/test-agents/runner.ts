// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Test Runner — Aegis on Aegis
//
// This runner registers itself as a real AEGIS agent in the production DB.
// Scenarios run against isolated HOME directories (no contamination of prod state).
// The runner itself is subject to all AEGIS governance: watchdog can quarantine it,
// budget can stop it, and KAVACH can intercept it.
//
// Usage:
//   bun src/test-agents/runner.ts             # run all scenarios
//   bun src/test-agents/runner.ts 01 03       # run specific scenarios by number
//
// Exit code: 0 = all passed, 1 = one or more failed

import { upsertAgent, touchAgent, setAgentState } from "../core/db.ts";

const RUNNER_ID = `aegis-test-runner-${Date.now()}`;
const SESSION_ID = `test-session-${new Date().toISOString().slice(0, 10)}`;

// ── Self-registration — AEGIS on AEGIS ─────────────────────────────────────
function registerSelf(): void {
  const ts = new Date().toISOString();
  upsertAgent({
    agent_id: RUNNER_ID,
    state: "RUNNING",
    identity_confidence: "declared",
    parent_id: null,
    session_id: SESSION_ID,
    depth: 0,
    budget_cap_usd: 0.50,   // test runner should cost nothing — hard cap for early warning
    budget_used_usd: 0,
    budget_pool_reserved: 0,
    tool_calls: 0,
    loop_count: 0,
    tools_declared: 1,
    violation_count: 0,
    spawn_timestamp: ts,
    last_seen: ts,
    policy_path: null,
    stop_requested: 0,
    quarantine_reason: null,
    quarantine_rule: null,
    release_reason: null,
    released_by: null,
    resume_manifest_path: null,
  });
}

function closeSelf(passed: boolean): void {
  const finalState = passed ? "FORCE_CLOSED" : "FAILED";
  setAgentState(RUNNER_ID, finalState, {
    reason: passed ? "test run complete — all passed" : "test run complete — failures detected",
    rule: "KAV-002",
  });
}

// ── Scenario registry ────────────────────────────────────────────────────────

const SCENARIOS = [
  { id: "01", name: "Budget Overflow",         loader: () => import("./scenarios/01-budget-overflow.ts") },
  { id: "02", name: "KAVACH DAN Classify",     loader: () => import("./scenarios/02-dan-classify.ts") },
  { id: "03", name: "Injection Block",         loader: () => import("./scenarios/03-injection-block.ts") },
  { id: "04", name: "Spawn Depth Limit",       loader: () => import("./scenarios/04-spawn-depth-limit.ts") },
  { id: "05", name: "L1 Soft Stop",            loader: () => import("./scenarios/05-soft-stop.ts") },
  { id: "06", name: "Budget Inheritance",      loader: () => import("./scenarios/06-budget-inheritance.ts") },
  { id: "07", name: "Zombie State Transition", loader: () => import("./scenarios/07-zombie-state.ts") },
];

// ── Runner ───────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const filter = process.argv.slice(2);
  const scenarios = filter.length > 0
    ? SCENARIOS.filter((s) => filter.some((f) => s.id.startsWith(f)))
    : SCENARIOS;

  if (scenarios.length === 0) {
    console.error(`No scenarios matched: ${filter.join(", ")}`);
    process.exit(1);
  }

  console.log(`\n╔══════════════════════════════════════════════════════╗`);
  console.log(`║  AEGIS on AEGIS — Self-Governance Test Suite          ║`);
  console.log(`╚══════════════════════════════════════════════════════╝`);
  console.log(`  Runner agent: ${RUNNER_ID}`);
  console.log(`  Running ${scenarios.length} scenario${scenarios.length === 1 ? "" : "s"}\n`);

  registerSelf();

  const results: Array<{ id: string; name: string; passed: boolean; details: string; durationMs: number }> = [];

  for (const scenario of scenarios) {
    process.stdout.write(`  [${scenario.id}] ${scenario.name} ... `);
    const start = Date.now();
    try {
      touchAgent(RUNNER_ID);
      const mod = await scenario.loader();
      const result = await mod.run();
      const durationMs = Date.now() - start;
      results.push({ id: scenario.id, name: scenario.name, ...result, durationMs });
      const icon = result.passed ? "✓" : "✗";
      console.log(`${icon}  (${durationMs}ms)`);
      if (!result.passed) {
        console.log(`     ↳ ${result.details}`);
      }
    } catch (err: unknown) {
      const durationMs = Date.now() - start;
      const msg = err instanceof Error ? err.message : String(err);
      results.push({ id: scenario.id, name: scenario.name, passed: false, details: `THROW: ${msg}`, durationMs });
      console.log(`✗  (${durationMs}ms)`);
      console.log(`     ↳ THROW: ${msg}`);
    }
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  const total = results.length;
  const allPassed = failed === 0;

  console.log(`\n  ─────────────────────────────────────`);
  console.log(`  Results: ${passed}/${total} passed${failed > 0 ? `, ${failed} failed` : ""}`);

  if (!allPassed) {
    console.log(`\n  Failed scenarios:`);
    for (const r of results.filter((r) => !r.passed)) {
      console.log(`    [${r.id}] ${r.name}`);
      console.log(`         ${r.details}`);
    }
  }

  closeSelf(allPassed);
  console.log(`\n  Runner state: ${allPassed ? "FORCE_CLOSED (clean)" : "FAILED"}`);
  console.log(`  Agent ID recorded in ~/.aegis/aegis.db: ${RUNNER_ID}\n`);

  process.exit(allPassed ? 0 : 1);
}

main().catch((e) => {
  console.error("Runner crashed:", e);
  process.exit(1);
});
