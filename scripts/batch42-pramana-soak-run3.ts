/**
 * Batch 42 Soak Run 3/7 — burst traffic + repeated malformed attempts
 *
 * Verifies stability under high-volume repeated calls:
 *   - 12× READ burst → all ALLOW, no drift
 *   - 10× VERIFY/ATTEST burst → all ALLOW
 *   - 8× EXECUTE burst → all GATE
 *   - 12× IMPOSSIBLE_OP → all soft=ALLOW, sim(on)=BLOCK (12 TPs)
 *   - 12× EMPTY_CAP     → all soft=ALLOW, sim(on)=BLOCK (12 TPs)
 *   - Total sim_TPs = 24, FP = 0, prod_fires = 0
 *
 * @rule:AEG-HG-001 pramana not live — policy off throughout
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED } from "../src/enforcement/hard-gate-policy";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const SOAK_RUN = 3;
const RUN_DATE = new Date().toISOString();
const dir = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

let totalChecks = 0, passed = 0, failed = 0;
const failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { passed++; console.log(`  ✓ [PASS] ${label.padEnd(76)} actual=${actual}`); }
  else { failed++; failures.push({ label, expected: String(expected), actual: String(actual), cat }); console.log(`  ✗ [FAIL] ${label.padEnd(76)} expected=${expected} actual=${actual}`); }
}

let simTPs = 0, prodFires = 0;

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — burst traffic + repeated malformed ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

console.log("\n── Pre-flight + HG-1 regression ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r3-reg" });
  check(`[${svc}] hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r3-reg" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ── Burst: READ × 12 ─────────────────────────────────────────────────────────
console.log("\n── Burst: READ × 12 ──");
for (let i = 0; i < 12; i++) {
  const d = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: `b42r3-burst-read-${i}` });
  check(`pramana READ burst[${i}]: ALLOW`, d.decision, "ALLOW", "burst_read");
  check(`pramana READ burst[${i}]: soft_canary`, d.enforcement_phase, "soft_canary", "burst_read");
  if (d.decision === "BLOCK") prodFires++;
}

// ── Burst: VERIFY + ATTEST × 10 each ─────────────────────────────────────────
console.log("\n── Burst: VERIFY × 10 + ATTEST × 10 ──");
for (let i = 0; i < 10; i++) {
  const dv = evaluate({ service_id: "pramana", operation: "verify", requested_capability: "VERIFY", caller_id: `b42r3-burst-verify-${i}` });
  logDecision(dv);
  check(`pramana VERIFY burst[${i}]: ALLOW`, dv.decision, "ALLOW", "burst_domain");
  const da = evaluate({ service_id: "pramana", operation: "attest", requested_capability: "ATTEST", caller_id: `b42r3-burst-attest-${i}` });
  logDecision(da);
  check(`pramana ATTEST burst[${i}]: ALLOW`, da.decision, "ALLOW", "burst_domain");
}

// ── Burst: EXECUTE × 8 (all GATE, BR-5 ≥ 3) ─────────────────────────────────
console.log("\n── Burst: EXECUTE × 8 ──");
for (let i = 0; i < 8; i++) {
  const d = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: `b42r3-burst-exec-${i}` });
  logDecision(d);
  check(`pramana EXECUTE burst[${i}]: GATE`, d.decision, "GATE", "burst_gate");
  check(`pramana EXECUTE burst[${i}]: soft_canary`, d.enforcement_phase, "soft_canary", "burst_gate");
}

// ── Burst: IMPOSSIBLE_OP × 12 ─────────────────────────────────────────────────
console.log("\n── Burst: IMPOSSIBLE_OP × 12 (TPs in simulation) ──");
for (let i = 0; i < 12; i++) {
  const d = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b42r3-burst-imp-${i}` });
  logDecision(d);
  check(`pramana IMPOSSIBLE_OP burst[${i}]: live ALLOW (not hard-gated)`, d.decision, "ALLOW", "burst_tp");
  check(`pramana IMPOSSIBLE_OP burst[${i}]: soft_canary (not hard_gate)`, d.enforcement_phase, "soft_canary", "burst_tp");
  const sim = simulateHardGate("pramana", d.decision, "IMPOSSIBLE_OP", "frob", true);
  check(`pramana IMPOSSIBLE_OP burst[${i}]: sim(on) BLOCK`, sim.simulated_hard_decision, "BLOCK", "burst_tp");
  if (sim.hard_gate_would_apply) simTPs++;
}

// ── Burst: EMPTY_CAPABILITY_ON_WRITE × 12 ────────────────────────────────────
console.log("\n── Burst: EMPTY_CAP_ON_WRITE × 12 (TPs in simulation) ──");
for (let i = 0; i < 12; i++) {
  const d = evaluate({ service_id: "pramana", operation: "write", requested_capability: "EMPTY_CAPABILITY_ON_WRITE", caller_id: `b42r3-burst-empty-${i}` });
  logDecision(d);
  check(`pramana EMPTY_CAP burst[${i}]: live ALLOW`, d.decision, "ALLOW", "burst_tp");
  const sim = simulateHardGate("pramana", d.decision, "EMPTY_CAPABILITY_ON_WRITE", "write", true);
  check(`pramana EMPTY_CAP burst[${i}]: sim(on) BLOCK`, sim.simulated_hard_decision, "BLOCK", "burst_tp");
  if (sim.hard_gate_would_apply) simTPs++;
}

// ── Mixed burst: varied caps across tiers × 5 ────────────────────────────────
console.log("\n── Mixed burst: 5 rounds across all tiers ──");
const MIXED_CAPS: Array<[string, string, string]> = [
  ["read",        "READ",          "ALLOW"],
  ["verify",      "VERIFY",        "ALLOW"],
  ["check-proof", "CHECK_PROOF",   "ALLOW"],
  ["execute",     "EXECUTE",       "GATE"],
  ["ai-execute",  "AI_EXECUTE",    "GATE"],
  ["deploy",      "CI_DEPLOY",     "GATE"],
];
for (let round = 0; round < 5; round++) {
  for (const [op, cap, expected] of MIXED_CAPS) {
    const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: `b42r3-mixed-${round}` });
    check(`mixed round[${round}] pramana [${cap}]: ${expected}`, d.decision, expected, "mixed_burst");
    check(`mixed round[${round}] pramana [${cap}]: soft_canary`, d.enforcement_phase, "soft_canary", "mixed_burst");
    if (d.decision === "BLOCK") prodFires++;
  }
}

console.log("\n── Count validation ──");
check(`simulation TPs = 24 (12× IMPOSSIBLE_OP + 12× EMPTY_CAP)`, simTPs, 24, "count");
check("production fires = 0", prodFires, 0, "count");

const soakPass = failed === 0 && prodFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch42_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({
  soak_run: SOAK_RUN, service: "pramana", hg_group: "HG-2A", date: RUN_DATE,
  verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed,
  simulation_true_positives: simTPs, production_gate_fires: prodFires, ready_to_promote: false,
}, null, 2));
console.log(`\n  Batch 42 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
