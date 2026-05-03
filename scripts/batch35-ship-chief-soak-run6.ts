/**
 * Batch 35 Soak Run 6/7 — Unknown capability + boundary heavy
 *
 * Stress: capability surface expansion. Verifies that:
 *   - No unknown capability hard-BLOCKs (policy is strictly bounded to 2 caps)
 *   - Domain-specific SLM caps produce ALLOW, not BLOCK
 *   - Plausible-sounding future caps are not accidentally in hard_block
 *   - TIER-B/C/D services are unaffected by hard-gate
 *   - Unknown services remain WARN, never BLOCK
 *   - Still-gate semantics: unknown caps with soft=GATE preserve GATE (not BLOCK)
 *
 * @rule:AEG-HG-003 unknown cap → soft decision preserved
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { simulateHardGate, HARD_GATE_GLOBALLY_ENABLED, SHIP_SLM_HG1_POLICY, CHIEF_SLM_HG1_POLICY } from "../src/enforcement/hard-gate-policy";
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

let totalTP = 0, totalFP = 0, totalProdFires = 0;

function observe(svc: string, label: string, op: string, cap: string, cat: string) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b35r6", session_id: `b35r6-${svc}-${Date.now()}` });
  logDecision(d);
  // soft: any decision is fine — we only check it's not unexpected BLOCK
  const simOff = simulateHardGate(svc, d.decision, cap, op, false);
  if (simOff.hard_gate_would_apply) totalProdFires++;
  check(`sim(off) [${svc}] ${label}: no production fire`, simOff.hard_gate_would_apply, false, cat);
  const simOn = simulateHardGate(svc, d.decision, cap, op, true);
  // For unknown caps: sim(on) must NOT hard-BLOCK (only IMPOSSIBLE_OP + EMPTY_CAP are hard_block)
  check(`sim(on) [${svc}] ${label}: not hard-BLOCK`, simOn.simulated_hard_decision !== "BLOCK", true, cat);
  check(`sim(on) [${svc}] ${label}: hard_gate_would_apply = false`, simOn.hard_gate_would_apply, false, cat);
  if (simOn.simulated_hard_decision === "BLOCK") totalFP++;
  return { d, simOn };
}

console.log(`\n══ Batch 35 Soak Run ${SOAK_RUN}/7 — Unknown capability + boundary heavy ══`);
console.log(`  Date: ${RUN_DATE}  |  AEGIS_HARD_GATE_SERVICES: ${process.env.AEGIS_HARD_GATE_SERVICES}`);

// Pre-flight
console.log("\n── Pre-flight ──");
check("HARD_GATE_GLOBALLY_ENABLED = true", HARD_GATE_GLOBALLY_ENABLED, true, "pre");
check("chirpee in env (call-time)", process.env.AEGIS_HARD_GATE_SERVICES?.split(",").map(s=>s.trim()).includes("chirpee") ?? false, true, "pre");
check("ship-slm hard_gate_enabled = false", SHIP_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
check("chief-slm hard_gate_enabled = false", CHIEF_SLM_HG1_POLICY.hard_gate_enabled, false, "pre");
// Confirm hard_block has exactly 2 entries for both services
check("ship-slm hard_block size = 2", SHIP_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "pre");
check("chief-slm hard_block size = 2", CHIEF_SLM_HG1_POLICY.hard_block_capabilities.size, 2, "pre");
check("IMPOSSIBLE_OP in ship-slm hard_block", SHIP_SLM_HG1_POLICY.hard_block_capabilities.has("IMPOSSIBLE_OP"), true, "pre");
check("EMPTY_CAP in ship-slm hard_block", SHIP_SLM_HG1_POLICY.hard_block_capabilities.has("EMPTY_CAPABILITY_ON_WRITE"), true, "pre");

// Wave A: Domain-specific SLM caps — none should hard-BLOCK
console.log("\n── Wave A: Domain-specific SLM capabilities ──");
const shipDomainCaps = [
  "SUMMARIZE_VOYAGE","CLASSIFY_CARGO","EXTRACT_BL","INFER_RISK","ROUTE_VESSEL",
  "ASSESS_WEATHER","COMPILE_LOG","GENERATE_REPORT","VESSEL_LOOKUP","PASSAGE_PLAN",
  "CARGO_MANIFEST","FUEL_ANALYSIS","DRAFT_SURVEY","PORT_CLEARANCE","SPEED_PROFILE",
];
const chiefDomainCaps = [
  "ANALYZE_WATCH","BRIEF_OFFICER","ASSESS_FATIGUE","INSPECT_LOG","RECOMMEND_ACTION",
  "HANDOVER_REPORT","SAFETY_DRILL_LOG","CARGO_PLAN","STABILITY_CHECK","MARPOL_ENTRY",
  "SMS_REVIEW","ISM_AUDIT","BRIDGE_CHECKLIST","INCIDENT_REPORT","MAINTENANCE_LOG",
];
for (const cap of shipDomainCaps) {
  observe("ship-slm", `domain:${cap}`, "execute", cap, "wave_a_domain");
}
for (const cap of chiefDomainCaps) {
  observe("chief-slm", `domain:${cap}`, "execute", cap, "wave_a_domain");
}

// Wave B: Future/unknown caps that SOUND dangerous but are not in hard_block
console.log("\n── Wave B: Plausible-sounding future caps (must not accidentally hard-BLOCK) ──");
const futureCaps = [
  "AUTONOMOUS_NAVIGATE","AI_PILOT","SYSTEM_OVERRIDE","CREW_OVERRIDE",
  "EMERGENCY_STOP","SAFETY_BYPASS","CRITICAL_ALERT","OVERRIDE_ALARM",
  "FORCE_HANDOVER","MANUAL_TAKEOVER",
];
for (const svc of ["ship-slm","chief-slm"]) {
  for (const cap of futureCaps) {
    observe(svc, `future:${cap}`, "execute", cap, "wave_b_future");
  }
}

// Wave C: Unknown services — WARN, never BLOCK
console.log("\n── Wave C: Unknown services ──");
const unknownServices = ["future-agent-2030","unregistered-nlp","unknown-maritime-ai","tbd-service","test-service-42"];
for (const svc of unknownServices) {
  const d = evaluate({ service_id: svc, operation: "deploy", requested_capability: "CI_DEPLOY", caller_id: "b35r6-unknown" });
  logDecision(d);
  check(`unknown svc '${svc}': not BLOCK`, d.decision !== "BLOCK", true, "wave_c_unknown_svc");
  check(`unknown svc '${svc}': phase ≠ hard_gate`, d.enforcement_phase !== "hard_gate", true, "wave_c_unknown_svc");
  check(`unknown svc '${svc}': no hard_gate_applied`, !d.hard_gate_applied, true, "wave_c_unknown_svc");
}

// Wave D: Non-HG-1 promoted services — IMPOSSIBLE_OP does not hard-BLOCK
console.log("\n── Wave D: Non-promoted services (TIER-A/B/C) ──");
const nonPromoted = ["puranic-os","granthx","pramana","ankr-doctor","domain-capture","stackpilot"];
for (const svc of nonPromoted) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r6-non-promoted" });
  logDecision(d);
  check(`non-promoted '${svc}': not hard_gate phase`, d.enforcement_phase !== "hard_gate", true, "wave_d_non_promoted");
  check(`non-promoted '${svc}': no hard_gate_applied`, !d.hard_gate_applied, true, "wave_d_non_promoted");
}

// Wave E: Malformed TPs — confirm boundary is exactly 2 caps
console.log("\n── Wave E: Malformed TPs (boundary confirmation) ──");
for (const svc of ["ship-slm","chief-slm"]) {
  const simI = simulateHardGate(svc, "ALLOW", "IMPOSSIBLE_OP", "frob", true);
  check(`${svc} IMPOSSIBLE_OP: sim BLOCK`, simI.simulated_hard_decision, "BLOCK", "wave_e_malformed");
  check(`${svc} IMPOSSIBLE_OP: hard_gate_would_apply`, simI.hard_gate_would_apply, true, "wave_e_malformed");
  if (simI.hard_gate_would_apply) totalTP++;
  const simE = simulateHardGate(svc, "ALLOW", "EMPTY_CAPABILITY_ON_WRITE", "write", true);
  check(`${svc} EMPTY_CAP: sim BLOCK`, simE.simulated_hard_decision, "BLOCK", "wave_e_malformed");
  check(`${svc} EMPTY_CAP: hard_gate_would_apply`, simE.hard_gate_would_apply, true, "wave_e_malformed");
  if (simE.hard_gate_would_apply) totalTP++;
}

// Chirpee regression
console.log("\n── Chirpee regression ──");
const cr = evaluate({ service_id: "chirpee", operation: "read", requested_capability: "READ", caller_id: "b35r6-reg" });
logDecision(cr);
check("chirpee READ → ALLOW", cr.decision, "ALLOW", "regression");
const ci = evaluate({ service_id: "chirpee", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b35r6-reg" });
logDecision(ci);
check("chirpee IMPOSSIBLE_OP → live BLOCK", ci.decision, "BLOCK", "regression");
check("chirpee IMPOSSIBLE_OP hard_gate_applied", ci.hard_gate_applied, true, "regression");

// Count validation
// Wave A: 15+15 = 30 domain caps × 2 checks each (sim(off) no-fire + sim(on) not-BLOCK)
// Wave E: 4 explicit TPs (IMPOSSIBLE + EMPTY × 2 services)
console.log("\n── Count validation ──");
check("false positives = 0 (no unknown cap hard-BLOCKed)", totalFP, 0, "count");
check("true positives = 4 (boundary confirmation)", totalTP, 4, "count");
check("production fires = 0", totalProdFires, 0, "count");

const soakPass = failed === 0 && totalFP === 0 && totalTP === 4 && totalProdFires === 0;
console.log(`\n══ Run ${SOAK_RUN}/7 Summary ══  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}  Verdict: ${soakPass ? "PASS" : "FAIL"}`);
if (failures.length) failures.forEach(f => console.log(`  ✗ [${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`));

writeFileSync(join(dir, `batch35_soak_run${SOAK_RUN}_metrics.json`), JSON.stringify({ soak_run: SOAK_RUN, date: RUN_DATE, verdict: soakPass ? "PASS" : "FAIL", checks: totalChecks, passed, failed, true_positives: totalTP, false_positives: totalFP, production_gate_fires: totalProdFires, unknown_caps_tested: shipDomainCaps.length + chiefDomainCaps.length + futureCaps.length * 2, ready_to_promote: false }, null, 2));
console.log(`\n  Batch 35 Run ${SOAK_RUN}/7: ${soakPass ? "PASS" : "FAIL"}`);
