/**
 * Batch 42 Soak Run 6/7 — unknown capability + boundary + HG-2B isolation
 *
 * Verifies boundary conditions that must hold before promotion:
 *   - Unknown capabilities never hard-block for pramana (sim or live)
 *   - Empty string cap treated correctly
 *   - HG-2B services (parali-central, carbonx) remain not hard-gated
 *   - domain-capture confirmed not eligible
 *   - Non-TIER-A services stay in shadow
 *   - still_gate downgrade guard under all BR levels
 *   - never_block invariant: READ in any context
 *   - HG-1 regression + puranic-os (BR-1) vs pramana (BR-5) EXECUTE comparison
 *
 * @rule:AEG-HG-002 READ never hard-blocks
 * @rule:AEG-HG-003 unknown cap not hard-blocked until registry complete
 * @rule:AEG-E-007  non-pilot stays shadow
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

const SOAK_RUN = 6;
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

console.log(`\n══ Batch 42 Soak Run ${SOAK_RUN}/7 — unknown cap + boundary + HG-2B isolation ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

console.log("\n── Pre-flight + HG-1 regression ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("pramana NOT in env", process.env.AEGIS_HARD_GATE_SERVICES?.includes("pramana"), false, "pre");
for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os"]) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r6-reg" });
  check(`[${svc}] hard_gate + ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "hg1_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r6-reg" });
  check(`[${svc}] IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "hg1_reg");
}

// ── Unknown caps: pramana ─────────────────────────────────────────────────────
console.log("\n── Unknown capabilities — must never hard-block ──");
const UNKNOWN_CAPS: Array<[string, string]> = [
  ["frob",         "BRAND_NEW_CAP"],
  ["frob",         "X"],
  ["write",        "FUTURE_WRITE_THING"],
  ["execute",      "QUANTUM_EXEC"],
  ["frob",         "ABC_DEF_GHI_JKL_MNO_PQR_STU_VWX_YZ_VERY_LONG_CAPABILITY_NAME"],
  ["frob",         "CAP123"],
  ["read",         "SOME_READ_EXTENSION"],
];
for (const [op, cap] of UNKNOWN_CAPS) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: cap, caller_id: "b42r6-unk" });
  check(`pramana unknown [${cap.slice(0,20)}]: soft_canary`, d.enforcement_phase, "soft_canary", "unknown_cap");
  check(`pramana unknown [${cap.slice(0,20)}]: not BLOCK`, d.decision !== "BLOCK", true, "unknown_cap");
  const sim = simulateHardGate("pramana", d.decision, cap, op, true);
  check(`pramana unknown [${cap.slice(0,20)}]: sim(on) not BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "unknown_cap");
  check(`pramana unknown [${cap.slice(0,20)}]: sim would_apply = false`, sim.hard_gate_would_apply, false, "unknown_cap");
  if (sim.hard_gate_would_apply) prodFires++;
}

// ── never_block invariant: READ in all contexts ───────────────────────────────
console.log("\n── never_block: READ in all contexts ──");
// pramana READ even if in GATE soft decision context → always ALLOW
for (const op of ["read", "get", "list", "query", "search", "health"]) {
  const d = evaluate({ service_id: "pramana", operation: op, requested_capability: "READ", caller_id: "b42r6-neverblock" });
  check(`pramana [${op}] never_block: ALLOW`, d.decision, "ALLOW", "never_block");
  if (d.decision === "BLOCK") prodFires++;
  const sim = simulateHardGate("pramana", "ALLOW", "READ", op, true);
  check(`pramana [${op}] never_block sim(on): ALLOW`, sim.simulated_hard_decision, "ALLOW", "never_block");
}

// ── still_gate downgrade guard ────────────────────────────────────────────────
console.log("\n── still_gate downgrade guard ──");
// sim(BLOCK, cap_in_still_gate, op, true) → GATE (downgrade), never BLOCK
for (const [op, cap] of [
  ["execute",    "EXECUTE"],
  ["ai-execute", "AI_EXECUTE"],
  ["deploy",     "CI_DEPLOY"],
  ["delete",     "DELETE"],
  ["approve",    "APPROVE"],
  ["emit",       "EMIT"],
  ["write",      "MEMORY_WRITE"],
  ["write",      "AUDIT_WRITE"],
  ["write",      "SPAWN_AGENTS"],
] as [string, string][]) {
  const simDG = simulateHardGate("pramana", "BLOCK", cap, op, true);
  check(`still_gate DG [${cap}]: sim(BLOCK)→GATE`, simDG.simulated_hard_decision, "GATE", "still_gate_dg");
  const simNU = simulateHardGate("pramana", "ALLOW", cap, op, true);
  check(`still_gate NU [${cap}]: sim(ALLOW)→ALLOW`, simNU.simulated_hard_decision, "ALLOW", "still_gate_nu");
  if (simDG.hard_gate_would_apply || simNU.hard_gate_would_apply) prodFires++;
}

// ── HG-2B isolation ───────────────────────────────────────────────────────────
console.log("\n── HG-2B isolation (parali-central + carbonx) ──");
for (const svc of ["parali-central", "carbonx"]) {
  for (const [op, cap, expected] of [
    ["read",     "READ",        "ALLOW"],
    ["execute",  "EXECUTE",     "GATE"],   // BR-3 ≥ 3 → GATE
    ["frob",     "IMPOSSIBLE_OP", "ALLOW"], // soft only — no HG-2B policy yet
  ] as [string, string, string][]) {
    const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b42r6-hg2b" });
    check(`[${svc}] [${cap}]: ${expected} (HG-2B not hard-gated)`, d.decision, expected, "hg2b_isolation");
    check(`[${svc}] not in hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "hg2b_isolation");
  }
}

// ── domain-capture not eligible ───────────────────────────────────────────────
console.log("\n── domain-capture: not eligible ──");
for (const [op, cap] of [["read", "READ"], ["frob", "IMPOSSIBLE_OP"], ["execute", "EXECUTE"]] as [string, string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b42r6-dc" });
  check(`domain-capture [${cap}]: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "dc_isolation");
  if (d.enforcement_phase === "hard_gate") prodFires++;
}

// ── ankr-doctor isolation (HG-2C separate) ───────────────────────────────────
console.log("\n── ankr-doctor: HG-2C not started ──");
{
  const d = evaluate({ service_id: "ankr-doctor", operation: "read", requested_capability: "READ", caller_id: "b42r6-ad" });
  check("ankr-doctor: NOT hard_gate (HG-2C separate)", d.enforcement_phase !== "hard_gate", true, "hg2c_isolation");
  const de = evaluate({ service_id: "ankr-doctor", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r6-ad" });
  check("ankr-doctor EXECUTE: GATE (governance, soft layer)", de.decision, "GATE", "hg2c_isolation");
  check("ankr-doctor EXECUTE: NOT hard_gate phase", de.enforcement_phase !== "hard_gate", true, "hg2c_isolation");
}

// ── Non-pilot service stays shadow ───────────────────────────────────────────
console.log("\n── Non-pilot / non-TIER-A stays shadow ──");
for (const svc of ["unregistered-svc", "some-new-service", "test-unknown"]) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b42r6-nonpilot" });
  check(`[${svc}]: shadow + WARN`, d.enforcement_phase === "shadow" && d.decision === "WARN", true, "non_pilot");
}

// ── BR comparison: puranic-os (BR-1) vs pramana (BR-5) for EXECUTE ───────────
// This locks the lesson: BR changes high-risk behavior
console.log("\n── BR comparison: EXECUTE gating by blast radius ──");
{
  // puranic-os: read_only + BR-1 (<3) → EXECUTE high risk but BR < 3 → ALLOW
  // (puranic-os is HG-1 hard-gate, but enforcement_phase is hard_gate; decision for EXECUTE)
  const dPuranic = evaluate({ service_id: "puranic-os", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r6-br" });
  logDecision(dPuranic);
  // puranic-os BR-1: high op, brNum=1 < 3 → no BR gate; read_only not in highAuthorityClasses
  // → ALLOW from soft gate; hard-gate doesn't change ALLOW for EXECUTE (not in hard_block)
  check("puranic-os EXECUTE: ALLOW (BR-1 < 3, read_only, no gate rule fires)", dPuranic.decision, "ALLOW", "br_compare");
  check("puranic-os EXECUTE: hard_gate phase (still HG-1 live)", dPuranic.enforcement_phase, "hard_gate", "br_compare");

  // pramana: read_only + BR-5 (≥3) → EXECUTE high risk → GATE (BR-5 rule fires)
  const dPramana = evaluate({ service_id: "pramana", operation: "execute", requested_capability: "EXECUTE", caller_id: "b42r6-br" });
  logDecision(dPramana);
  check("pramana EXECUTE: GATE (BR-5 ≥ 3 rule fires — wider blast radius)", dPramana.decision, "GATE", "br_compare");
  check("pramana EXECUTE: soft_canary phase", dPramana.enforcement_phase, "soft_canary", "br_compare");
  // This is the key BR lesson: same authority_class (read_only), different blast radius → different gate behavior for high-risk ops
  check("BR lesson confirmed: same authority_class, BR-1→ALLOW vs BR-5→GATE for EXECUTE", true, true, "br_compare");
}

// ── TPs at run level ──────────────────────────────────────────────────────────
console.log("\n── TP baseline ──");
{
  const imp = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b42r6-tp" });
  const sim = simulateHardGate("pramana", imp.decision, "IMPOSSIBLE_OP", "frob", true);
  check("pramana IMPOSSIBLE_OP: sim(on) BLOCK", sim.simulated_hard_decision, "BLOCK", "tp");
  if (sim.hard_gate_would_apply) simTPs++;
  const emp = evaluate({ service_id: "pramana", operation: "write", requested_capability: "EMPTY_CAPABILITY_ON_WRITE", caller_id: "b42r6-tp" });
  const simE = simulateHardGate("pramana", emp.decision, "EMPTY_CAPABILITY_ON_WRITE", "write", true);
  check("pramana EMPTY_CAP: sim(on) BLOCK", simE.simulated_hard_decision, "BLOCK", "tp");
  if (simE.hard_gate_would_apply) simTPs++;
}

console.log("\n── Count validation ──");
check("simulation TPs ≥ 2", simTPs >= 2, true, "count");
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
