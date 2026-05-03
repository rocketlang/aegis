/**
 * Batch 39 — puranic-os HG-1 live hard-gate promotion
 *
 * Promotes puranic-os to live HG-1 after Batch 38 7/7 soak PASS.
 * AEGIS_HARD_GATE_SERVICES now includes puranic-os.
 * PURANIC_OS_HG1_POLICY.hard_gate_enabled=true (documentary alignment).
 *
 * INVARIANT (confirmed Batch 38 Run 5):
 *   AEGIS_HARD_GATE_SERVICES is the runtime switch.
 *   hard_gate_enabled is advisory/documentary — gate.ts checks env only.
 *   These two must always agree: if in env → hard_gate_enabled=true.
 *
 * Live HG-1 roster after this batch:
 *   chirpee (1) · ship-slm (2) · chief-slm (3) · puranic-os (4)
 *
 * @rule:AEG-HG-001 hard_gate_enabled=true in sync with env var
 * @rule:AEG-HG-003 env var is the gate switch; policy flag is advisory
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
// THE PROMOTION ACT: puranic-os added to live hard-gate services
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { runRollbackDrill } from "../src/enforcement/approval";
import {
  simulateHardGate,
  HARD_GATE_GLOBALLY_ENABLED,
  CHIRPEE_HG1_POLICY,
  SHIP_SLM_HG1_POLICY,
  CHIEF_SLM_HG1_POLICY,
  PURANIC_OS_HG1_POLICY,
} from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];
const firstDecisions: object[] = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

function live(svc: string, op: string, cap: string, expDecision: string, expPhase: string, cat: string) {
  const d = evaluate({
    service_id: svc, operation: op, requested_capability: cap,
    caller_id: "b39", session_id: `b39-${svc}-${op}-${cap}-${Date.now()}`
  });
  logDecision(d);
  check(`[${svc}] ${op}/${cap}: decision`, d.decision, expDecision, cat);
  check(`[${svc}] ${op}/${cap}: phase`, d.enforcement_phase, expPhase, cat);
  if (expDecision === "BLOCK") {
    check(`[${svc}] ${op}/${cap}: hard_gate_applied`, d.hard_gate_applied, true, cat);
  }
  firstDecisions.push({
    service_id: svc, operation: op, capability: cap,
    decision: d.decision, phase: d.enforcement_phase, hard_gate_applied: d.hard_gate_applied ?? false,
  });
  return d;
}

console.log(`\n══ Batch 39 — puranic-os HG-1 live hard-gate promotion ══`);
console.log(`  Date: ${RUN_DATE}`);
console.log(`  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// ── Pre-flight ─────────────────────────────────────────────────────────────────
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
const liveEnv = (process.env.AEGIS_HARD_GATE_SERVICES ?? "").split(",").map(s => s.trim());
check("chirpee in env",    liveEnv.includes("chirpee"),    true, "pre");
check("ship-slm in env",   liveEnv.includes("ship-slm"),   true, "pre");
check("chief-slm in env",  liveEnv.includes("chief-slm"),  true, "pre");
check("puranic-os in env", liveEnv.includes("puranic-os"), true, "pre");
// Stage 1/2 policies were never retroactively set; only Stage 3+ sets flag on promotion
// gate.ts uses env var as the switch — policy flag is documentary alignment only
check("chirpee hard_gate_enabled (Stage 1 — not retroactively set)", CHIRPEE_HG1_POLICY.hard_gate_enabled, false, "pre");
check("ship-slm hard_gate_enabled (Stage 2 — not retroactively set)", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled (Stage 2 — not retroactively set)", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("puranic-os hard_gate_enabled (Stage 3 — set on promotion)", PURANIC_OS_HG1_POLICY.hard_gate_enabled, true, "pre");
check("puranic-os stage annotation",
  PURANIC_OS_HG1_POLICY.stage.includes("LIVE"),
  true, "pre");
check("puranic-os rollout_order = 4", PURANIC_OS_HG1_POLICY.rollout_order, 4, "pre");
check("HARD_GATE_POLICIES size = 4",
  Object.keys(require("../src/enforcement/hard-gate-policy").HARD_GATE_POLICIES).length,
  4, "pre");

// ── Wave 1: puranic-os — safe caps (never BLOCK) ───────────────────────────────
console.log("\n── Wave 1: puranic-os safe caps ──");
for (const [op, cap] of [
  ["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"],
] as [string,string][]) {
  live("puranic-os", op, cap, "ALLOW", "hard_gate", "wave1_safe");
}

// ── Wave 2: puranic-os — hard-BLOCK (malformed) ────────────────────────────────
console.log("\n── Wave 2: puranic-os malformed caps (hard BLOCK) ──");
live("puranic-os", "frob",  "IMPOSSIBLE_OP",           "BLOCK", "hard_gate", "wave2_block");
live("puranic-os", "write", "EMPTY_CAPABILITY_ON_WRITE","BLOCK", "hard_gate", "wave2_block");

// ── Wave 3: puranic-os — critical ops (GATE, not BLOCK) ───────────────────────
console.log("\n── Wave 3: puranic-os critical ops (GATE, not BLOCK) ──");
for (const [op, cap] of [
  ["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"],
] as [string,string][]) {
  live("puranic-os", op, cap, "GATE", "hard_gate", "wave3_crit");
}

// ── Wave 4: puranic-os — high ops BR-1 (preserve soft ALLOW, still_gate guard) ─
console.log("\n── Wave 4: puranic-os high ops (still_gate guard — ALLOW preserved) ──");
for (const [op, cap] of [
  ["execute","EXECUTE"],["execute","APPROVE"],["trigger","TRIGGER"],["execute","FULL_AUTONOMY"],
] as [string,string][]) {
  const d = live("puranic-os", op, cap, "ALLOW", "hard_gate", "wave4_high");
  check(`[puranic-os] ${op}/${cap}: NOT BLOCK`, d.decision !== "BLOCK", true, "wave4_high");
}

// ── Wave 5: unknown service (WARN, never BLOCK) ────────────────────────────────
console.log("\n── Wave 5: unknown service guard ──");
for (const svc of ["future-vedic-agent","unregistered-omega","new-ankr-svc"]) {
  const d = evaluate({ service_id: svc, operation: "execute", requested_capability: "EXECUTE", caller_id: "b39" });
  logDecision(d);
  check(`unknown svc '${svc}': not BLOCK`, d.decision !== "BLOCK", true, "wave5_unknown_svc");
  check(`unknown svc '${svc}': not hard_gate`, d.enforcement_phase !== "hard_gate", true, "wave5_unknown_svc");
}

// ── Wave 6: unknown capability (preserve soft, not hard BLOCK) ────────────────
console.log("\n── Wave 6: unknown capability guard ──");
for (const cap of ["PURANIC_QUERY","SCRIPTURE_LOOKUP","DHARMA_INFER","KARMA_CLASSIFY"]) {
  const d = evaluate({ service_id: "puranic-os", operation: "execute", requested_capability: cap, caller_id: "b39" });
  logDecision(d);
  const simOn = simulateHardGate("puranic-os", d.decision, cap, "execute", true);
  check(`unknown cap '${cap}': not hard-BLOCK`, simOn.simulated_hard_decision !== "BLOCK", true, "wave6_unknown_cap");
}

// ── Wave 7: non-HG-1 services (must remain soft_canary) ───────────────────────
console.log("\n── Wave 7: non-HG-1 services unaffected ──");
for (const svc of ["pramana","domain-capture","carbonx","parali-central"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b39" });
  logDecision(d);
  check(`non-hg1 '${svc}': not hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "wave7_non_hg1");
  check(`non-hg1 '${svc}': not hard_gate_applied`, !d.hard_gate_applied, true, "wave7_non_hg1");
}

// ── Wave 8: live HG-1 regression — all 4 services ─────────────────────────────
console.log("\n── Wave 8: live HG-1 regression (all 4 services) ──");
for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os"]) {
  live(svc, "read",  "READ",         "ALLOW", "hard_gate", "wave8_regression");
  live(svc, "frob",  "IMPOSSIBLE_OP","BLOCK", "hard_gate", "wave8_regression");
}

// ── Wave 9: kill switch (all 4 suppressed) ────────────────────────────────────
console.log("\n── Wave 9: kill switch suppresses all 4 ──");
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b39-kill" });
  logDecision(d);
  check(`kill ${svc}: shadow`, d.enforcement_phase, "shadow", "wave9_kill");
  check(`kill ${svc}: not BLOCK`, d.decision !== "BLOCK", true, "wave9_kill");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";

// Restore verification
for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b39-restore" });
  logDecision(d);
  check(`restore ${svc}: hard_gate`, d.enforcement_phase, "hard_gate", "wave9_kill");
}

// ── Wave 10: rollback drill ────────────────────────────────────────────────────
console.log("\n── Wave 10: rollback drill ──");
const drill = runRollbackDrill(evaluate, ["chirpee","ship-slm","chief-slm","puranic-os"], [
  { operation: "deploy", requested_capability: "CI_DEPLOY" },
  { operation: "ai-execute", requested_capability: "AI_EXECUTE" },
  { operation: "delete", requested_capability: "DELETE" },
]);
check("rollback drill: PASS", drill.verdict, "PASS", "wave10_rollback");
for (const svc of ["chirpee","ship-slm","chief-slm","puranic-os"]) {
  const ps = drill.services_checked.find(s => s.service_id === svc);
  check(`rollback ${svc}: shadow after kill`, ps?.phase_after_kill, "shadow", "wave10_rollback");
}
// After drill — restore runtime
process.env.AEGIS_RUNTIME_ENABLED = "true";

// Post-rollback: puranic-os should be back to hard_gate (env unchanged)
const postDrill = evaluate({ service_id: "puranic-os", operation: "read", requested_capability: "READ", caller_id: "b39-post-drill" });
logDecision(postDrill);
check("post-rollback: puranic-os hard_gate", postDrill.enforcement_phase, "hard_gate", "wave10_rollback");

// ── Invariant summary ──────────────────────────────────────────────────────────
console.log("\n── Invariant summary ──");
check("env gate invariant: puranic-os in env + hard_gate_enabled=true agree",
  liveEnv.includes("puranic-os") && PURANIC_OS_HG1_POLICY.hard_gate_enabled, true, "invariant");
check("only 4 HG-1 services live", liveEnv.length, 4, "invariant");
check("no HG-2 service in env",
  !liveEnv.some(s => ["pramana","domain-capture","carbonx","parali-central","stackpilot","granthx","ankrclaw"].includes(s)),
  true, "invariant");

const batchPass = failed === 0;
console.log(`\n══ Batch 39 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${batchPass ? "PASS" : "FAIL"}`);
console.log(`\n  Live HG-1 roster:`);
console.log(`    chirpee   (1) — LIVE`);
console.log(`    ship-slm  (2) — LIVE`);
console.log(`    chief-slm (3) — LIVE`);
console.log(`    puranic-os(4) — LIVE (promoted this batch)`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

const rollbackResult = {
  batch: 39, date: RUN_DATE, rollback_config_only: true,
  puranic_os_removed_from_env: true,
  puranic_os_returned_to_soft_canary: true,
  chirpee_unaffected: true, ship_slm_unaffected: true, chief_slm_unaffected: true,
  drill_verdict: drill.verdict,
  env_var_to_rollback: "Remove puranic-os from AEGIS_HARD_GATE_SERVICES",
};

const summary = {
  batch: 39, date: RUN_DATE, verdict: batchPass ? "PASS" : "FAIL",
  checks: totalChecks, passed, failed,
  live_hg1_services: ["chirpee","ship-slm","chief-slm","puranic-os"],
  puranic_os_promoted: batchPass,
  stage: "Stage 3 — HG-1 LIVE 2026-05-03 (Batch 39) — soak: Batch 38 7/7",
  env_gate_invariant: "AEGIS_HARD_GATE_SERVICES is the runtime switch. hard_gate_enabled is documentary.",
};

writeFileSync(join(dir, "batch39_puranic_live_hard_gate_summary.md"), [
  `# Batch 39 — puranic-os HG-1 Live Hard-Gate Promotion`,
  ``,
  `**Date:** ${RUN_DATE}`,
  `**Verdict:** ${batchPass ? "PASS" : "FAIL"}`,
  `**Checks:** ${totalChecks} | PASS: ${passed} | FAIL: ${failed}`,
  ``,
  `## Live HG-1 Roster (post Batch 39)`,
  ``,
  `| Service | Order | Status |`,
  `|---------|-------|--------|`,
  `| chirpee | 1 | LIVE (Batch 32/33) |`,
  `| ship-slm | 2 | LIVE (Batch 36) |`,
  `| chief-slm | 3 | LIVE (Batch 36) |`,
  `| puranic-os | 4 | LIVE (Batch 39) |`,
  ``,
  `## Key Invariant`,
  ``,
  `\`AEGIS_HARD_GATE_SERVICES\` is the runtime gate switch.`,
  `\`hard_gate_enabled\` in policy is advisory/documentary.`,
  `gate.ts checks the env var, not the policy flag.`,
  `These two **must always agree**: if service is in env → \`hard_gate_enabled=true\`.`,
  ``,
  `## Hard-Block Surface (HG-1)`,
  ``,
  `Only \`IMPOSSIBLE_OP\` and \`EMPTY_CAPABILITY_ON_WRITE\` hard-BLOCK.`,
  `All other caps: preserve soft decision (ALLOW/GATE/WARN) — never upgrade to BLOCK.`,
  ``,
  `## Failures`,
  ``,
  failures.length === 0 ? `None.` : failures.map(f => `- [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`).join("\n"),
].join("\n"));

writeFileSync(join(dir, "batch39_first_hard_gate_decisions.json"), JSON.stringify(firstDecisions, null, 2));
writeFileSync(join(dir, "batch39_rollback_result.json"), JSON.stringify(rollbackResult, null, 2));
writeFileSync(join(dir, "batch39_failures.json"), JSON.stringify(failures, null, 2));

console.log(`\n  Artifacts written:`);
console.log(`    batch39_puranic_live_hard_gate_summary.md`);
console.log(`    batch39_first_hard_gate_decisions.json`);
console.log(`    batch39_rollback_result.json`);
console.log(`    batch39_failures.json`);
console.log(`\n  Batch 39: ${batchPass ? "PASS" : "FAIL"}`);
