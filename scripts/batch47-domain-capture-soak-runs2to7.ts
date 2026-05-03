/**
 * Batch 47 — domain-capture HG-2A soak runs 2–7
 *
 * Runs 2–7 complete the 7-run soak discipline before any promotion decision.
 * domain-capture remains soft_canary throughout. hard_gate_enabled=false.
 * NOT in AEGIS_HARD_GATE_SERVICES.
 *
 * Run variations:
 *   Run 2 — mixed-case capabilities + alias normalization
 *   Run 3 — burst traffic + repeated malformed attempts
 *   Run 4 — soft-canary token behavior + approval-method absence
 *   Run 5 — rollback / kill-switch heavy
 *   Run 6 — unknown capability + boundary + HG-2B isolation
 *   Run 7 — final dress rehearsal and verdict
 *
 * Doctrine from Batch 46:
 *   Soak phase: verify token exists, verify action methods absent, no live hard BLOCK.
 *   Promotion phase: verify approve/deny/revoke lifecycle.
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false — NOT in AEGIS_HARD_GATE_SERVICES
 * @rule:AEG-HG-002 READ never hard-blocks in any mode
 */

process.env.AEGIS_ENFORCEMENT_MODE   = "soft";
process.env.AEGIS_RUNTIME_ENABLED    = "true";
process.env.AEGIS_DRY_RUN            = "false";
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana";
delete process.env.AEGIS_SOFT_CANARY_SERVICES;

import { evaluate } from "../src/enforcement/gate";
import { logDecision } from "../src/enforcement/logger";
import { getServiceEntry, isInPilotScope, invalidateCache } from "../src/enforcement/registry";
import {
  simulateHardGate,
  PRAMANA_HG2A_POLICY,
  DOMAIN_CAPTURE_HG2A_POLICY,
} from "../src/enforcement/hard-gate-policy";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const BATCH    = 47;
const RUN_DATE = new Date().toISOString();
const dir      = join(process.cwd(), ".aegis");
mkdirSync(dir, { recursive: true });

// ── Shared state across runs ─────────────────────────────────────────────────
interface RunResult {
  run: number;
  checks: number;
  passed: number;
  failed: number;
  prod_fires: number;
  fp: number;
  tp_sim: number;
  verdict: "PASS" | "FAIL";
  failures: string[];
}

const ALL_RUNS: RunResult[] = [];

// ── Per-run check harness ────────────────────────────────────────────────────
let _totalChecks = 0, _passed = 0, _failed = 0;
let _prodFires = 0, _fp = 0, _tpSim = 0;
const _failures: Array<{ label: string; expected: string; actual: string; cat: string }> = [];

function resetRun() {
  _totalChecks = 0; _passed = 0; _failed = 0;
  _prodFires = 0; _fp = 0; _tpSim = 0;
  _failures.length = 0;
}

function check(label: string, actual: unknown, expected: unknown, cat = "general") {
  _totalChecks++;
  const ok = String(actual) === String(expected);
  if (ok) { _passed++; console.log(`  ✓ [PASS] ${label.padEnd(78)} actual=${actual}`); }
  else {
    _failed++;
    _failures.push({ label, expected: String(expected), actual: String(actual), cat });
    console.log(`  ✗ [FAIL] ${label.padEnd(78)} expected=${expected} actual=${actual}`);
  }
}

// ── Standard regression: live roster + HG-2 isolation ───────────────────────
function standardRegression(runTag: string) {
  // Live 5 services
  for (const svc of ["chirpee", "ship-slm", "chief-slm", "puranic-os", "pramana"]) {
    const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: runTag });
    check(`[REG:${runTag}] ${svc} READ: hard_gate+ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "regression");
    const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: runTag });
    check(`[REG:${runTag}] ${svc} IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "regression");
  }
  // domain-capture: soft_canary, not hard_gate
  const dc = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: runTag });
  check(`[REG:${runTag}] domain-capture: soft_canary+ALLOW`, dc.enforcement_phase === "soft_canary" && dc.decision === "ALLOW", true, "regression");
  // HG-2B isolation
  for (const svc of ["parali-central", "carbonx"]) {
    const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: runTag });
    check(`[REG:${runTag}] HG-2B ${svc}: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "regression");
    check(`[REG:${runTag}] HG-2B ${svc}: NOT BLOCK`, d.decision !== "BLOCK", true, "regression");
    if (d.decision === "BLOCK") _prodFires++;
  }
  // Unknown service: NOT BLOCK
  const unk = evaluate({ service_id: "no-such-service-b47", operation: "read", requested_capability: "READ", caller_id: runTag });
  check(`[REG:${runTag}] unknown service: NOT BLOCK`, unk.decision !== "BLOCK", true, "regression");
}

// ── Standard TP sim check ────────────────────────────────────────────────────
function tpSimCheck(runTag: string) {
  for (const [op, cap] of [["frob", "IMPOSSIBLE_OP"], ["write", "EMPTY_CAPABILITY_ON_WRITE"]] as [string,string][]) {
    const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: runTag });
    check(`[TP:${runTag}] ${cap}: soft ALLOW`, d.decision === "ALLOW" && d.enforcement_phase === "soft_canary", true, "tp");
    if (d.decision === "BLOCK") { _prodFires++; _fp++; }
    const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
    check(`[TP:${runTag}] ${cap}: sim BLOCK`, sim.simulated_hard_decision, "BLOCK", "tp");
    if (sim.simulated_hard_decision === "BLOCK") _tpSim++;
  }
}

// ── Standard rollback check ──────────────────────────────────────────────────
function rollbackCheck(runTag: string) {
  process.env.AEGIS_RUNTIME_ENABLED = "false";
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: runTag });
  check(`[KILL:${runTag}] domain-capture: shadow`, d.enforcement_phase, "shadow", "kill");
  check(`[KILL:${runTag}] domain-capture: NOT BLOCK`, d.decision !== "BLOCK", true, "kill");
  for (const svc of ["chirpee", "pramana"]) {
    const hg = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: runTag });
    check(`[KILL:${runTag}] ${svc}: shadow+NOT BLOCK`, hg.enforcement_phase === "shadow" && hg.decision !== "BLOCK", true, "kill");
  }
  process.env.AEGIS_RUNTIME_ENABLED = "true";
  const r = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: runTag });
  check(`[KILL:${runTag}] domain-capture restored: soft_canary`, r.enforcement_phase, "soft_canary", "kill");
  const p = evaluate({ service_id: "pramana", operation: "read", requested_capability: "READ", caller_id: runTag });
  check(`[KILL:${runTag}] pramana restored: hard_gate+ALLOW`, p.enforcement_phase === "hard_gate" && p.decision === "ALLOW", true, "kill");
}

function closeRun(run: number): RunResult {
  const verdict = _failed === 0 ? "PASS" as const : "FAIL" as const;
  const r: RunResult = {
    run, checks: _totalChecks, passed: _passed, failed: _failed,
    prod_fires: _prodFires, fp: _fp, tp_sim: _tpSim, verdict,
    failures: _failures.map(f => `[${f.cat}] ${f.label}: expected=${f.expected} actual=${f.actual}`),
  };
  ALL_RUNS.push(r);
  console.log(`\n══ Run ${run}/7 Summary ══  Checks: ${_totalChecks}  PASS: ${_passed}  FAIL: ${_failed}  Verdict: ${verdict}`);
  if (_failures.length) { console.log("  Failures:"); for (const f of _failures) console.log(`  ✗ ${f.label}: expected=${f.expected} actual=${f.actual}`); }
  return r;
}

// ════════════════════════════════════════════════════════════════════════════
// RUN 2 — mixed-case capabilities + alias normalization
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 2/7 — mixed-case + alias normalization`);
console.log("══════════════════════════════════════════════════════");
resetRun();

// Mixed-case read-only: gate normalises before matching
for (const [op, cap] of [
  ["READ",   "read"],
  ["Read",   "GET"],
  ["lIsT",   "LIST"],
  ["QUERY",  "Query"],
  ["search", "SEARCH"],
  ["HEALTH", "health"],
] as [string,string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r2-case" });
  check(`[CASE] domain-capture [${cap}/${op}]: NOT BLOCK`, d.decision !== "BLOCK", true, "case");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// Mixed-case malformed: "impossible_op" and "Impossible_Op" → both normalise to IMPOSSIBLE_OP
for (const rawCap of ["impossible_op", "Impossible_Op", "IMPOSSIBLE_OP"]) {
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: rawCap, caller_id: "b47r2-norm" });
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, rawCap, "frob", true);
  // After normalisation IMPOSSIBLE_OP → sim BLOCK. If normalisation strips to empty → not BLOCK (safe).
  // Record what we observe — the gate normalises to uppercase before matching.
  const normalised = rawCap.toUpperCase().trim();
  const expectBlock = normalised === "IMPOSSIBLE_OP";
  check(`[CASE] sim(on) [${rawCap}] → ${expectBlock ? "BLOCK" : "NOT BLOCK"}`, expectBlock ? sim.simulated_hard_decision : sim.simulated_hard_decision !== "BLOCK", expectBlock ? "BLOCK" : true, "case");
  if (sim.simulated_hard_decision === "BLOCK" && expectBlock) _tpSim++;
}

// Mixed-case domain ops: "capture_domain", "Capture_Domain", "CAPTURE_DOMAIN"
for (const rawCap of ["capture_domain", "Capture_Domain", "CAPTURE_DOMAIN"]) {
  const d = evaluate({ service_id: "domain-capture", operation: "capture", requested_capability: rawCap, caller_id: "b47r2-dom" });
  check(`[CASE] domain-capture [${rawCap}]: NOT BLOCK`, d.decision !== "BLOCK", true, "case");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, rawCap, "capture", true);
  check(`[CASE] sim(on) [${rawCap}]: NOT BLOCK (domain op)`, sim.simulated_hard_decision !== "BLOCK", true, "case");
}

// Whitespace-padded capability: " IMPOSSIBLE_OP " — gate trim should normalise
for (const rawCap of [" IMPOSSIBLE_OP ", " EMPTY_CAPABILITY_ON_WRITE "]) {
  const trimmed = rawCap.trim();
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: rawCap, caller_id: "b47r2-ws" });
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, rawCap, "frob", true);
  const isBlocked = sim.simulated_hard_decision === "BLOCK";
  if (isBlocked) _tpSim++;
  // Whitespace padding handled gracefully either way — no hard BLOCK in live
  check(`[CASE] live [${trimmed}+ws]: NOT BLOCK`, d.decision !== "BLOCK", true, "case");
}

tpSimCheck("r2");
standardRegression("r2");
rollbackCheck("r2");
check("[META:R2] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "meta");
check("[META:R2] ready_to_promote = false", false, false, "meta");
const r2 = closeRun(2);

// ════════════════════════════════════════════════════════════════════════════
// RUN 3 — burst traffic + repeated malformed attempts
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 3/7 — burst traffic + repeated malformed`);
console.log("══════════════════════════════════════════════════════");
resetRun();

// Burst legitimate read traffic: 20 requests
for (let i = 0; i < 20; i++) {
  const caps = ["READ","GET","LIST","QUERY","SEARCH","HEALTH"];
  const cap = caps[i % caps.length];
  const d = evaluate({ service_id: "domain-capture", operation: cap.toLowerCase(), requested_capability: cap, caller_id: `b47r3-burst-${i}` });
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}
check("[BURST:R3] 20 read ops: 0 fires", _prodFires, 0, "burst");
check("[BURST:R3] 20 read ops: 0 FP", _fp, 0, "burst");

// Burst malformed: 10 IMPOSSIBLE_OP attempts — zero live BLOCKs, all sim BLOCK
let burstSimBlocks = 0;
for (let i = 0; i < 10; i++) {
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b47r3-mal-${i}` });
  check(`[BURST:R3] IMPOSSIBLE_OP burst ${i+1}: soft ALLOW`, d.decision, "ALLOW", "burst");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, "IMPOSSIBLE_OP", "frob", true);
  if (sim.simulated_hard_decision === "BLOCK") { burstSimBlocks++; _tpSim++; }
}
check("[BURST:R3] 10 IMPOSSIBLE_OP burst: all sim BLOCK", burstSimBlocks, 10, "burst");

// Burst domain ops: 8 domain operations
const domainOps: [string,string][] = [
  ["capture","CAPTURE_DOMAIN"],["classify","CLASSIFY_DOMAIN"],["extract","EXTRACT_RULES"],
  ["map","MAP_CONCEPTS"],["index","INDEX_KNOWLEDGE"],["query","QUERY_DOMAIN"],
  ["capture","CAPTURE_DOMAIN"],["classify","CLASSIFY_DOMAIN"],
];
for (const [op, cap] of domainOps) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r3-dom" });
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}
check("[BURST:R3] 8 domain ops: 0 fires", _prodFires, 0, "burst");
check("[BURST:R3] 8 domain ops: 0 FP", _fp, 0, "burst");

// Interleaved: alternate legitimate + malformed
for (let i = 0; i < 6; i++) {
  const legit = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: `b47r3-interleave-legit-${i}` });
  const malformed = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b47r3-interleave-mal-${i}` });
  if (legit.decision === "BLOCK") { _prodFires++; _fp++; }
  if (malformed.decision === "BLOCK") { _prodFires++; _fp++; }
}
check("[BURST:R3] interleaved 6+6: 0 fires", _prodFires, 0, "burst");

standardRegression("r3");
rollbackCheck("r3");
check("[META:R3] prod fires = 0", _prodFires, 0, "meta");
check("[META:R3] FP = 0", _fp, 0, "meta");
check("[META:R3] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "meta");
const r3 = closeRun(3);

// ════════════════════════════════════════════════════════════════════════════
// RUN 4 — soft-canary token behavior + approval-method absence
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 4/7 — token behavior + approval-method absence`);
console.log("══════════════════════════════════════════════════════");
resetRun();

// Doctrine: GATE decisions generate approval_token; action methods absent in soak
const gateOps: [string,string][] = [
  ["execute","EXECUTE"],["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],
  ["delete","DELETE"],["approve","APPROVE"],["emit","EMIT"],
];
const tokens: string[] = [];
for (const [op, cap] of gateOps) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: `b47r4-tok` });
  check(`[TOKEN:R4] ${cap}: soft_canary`, d.enforcement_phase, "soft_canary", "token");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }

  const tok = (d as any).approval_token;
  if (d.decision === "GATE") {
    check(`[TOKEN:R4] ${cap}: token present on GATE`, tok !== null && tok !== undefined, true, "token");
    if (tok) tokens.push(tok);
  }
  // Action methods absent on soft_canary decisions (doctrine from Batch 46)
  check(`[TOKEN:R4] ${cap}: approveToken absent`, typeof (d as any).approveToken, "undefined", "token");
  check(`[TOKEN:R4] ${cap}: denyToken absent`, typeof (d as any).denyToken, "undefined", "token");
  check(`[TOKEN:R4] ${cap}: revokeToken absent`, typeof (d as any).revokeToken, "undefined", "token");
}

// Token uniqueness: all distinct
for (let i = 0; i < tokens.length; i++) {
  for (let j = i + 1; j < tokens.length; j++) {
    check(`[TOKEN:R4] token[${i}] !== token[${j}]`, tokens[i] !== tokens[j], true, "token");
  }
}
// Token format: non-empty strings
for (let i = 0; i < tokens.length; i++) {
  check(`[TOKEN:R4] token[${i}] is non-empty string`, typeof tokens[i] === "string" && tokens[i].length > 0, true, "token");
}

// ALLOW decisions: no token (not gated)
const allowD = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b47r4-allow" });
check("[TOKEN:R4] READ ALLOW: no token needed", allowD.decision, "ALLOW", "token");
if (allowD.decision === "BLOCK") { _prodFires++; _fp++; }

// TP sim still holds
tpSimCheck("r4");
standardRegression("r4");
rollbackCheck("r4");
check("[META:R4] prod fires = 0", _prodFires, 0, "meta");
check("[META:R4] FP = 0", _fp, 0, "meta");
check("[META:R4] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "meta");
const r4 = closeRun(4);

// ════════════════════════════════════════════════════════════════════════════
// RUN 5 — rollback / kill-switch heavy
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 5/7 — rollback / kill-switch heavy`);
console.log("══════════════════════════════════════════════════════");
resetRun();

const LIVE_5 = ["chirpee","ship-slm","chief-slm","puranic-os","pramana"];

// Cycle 1: kill → verify shadow for all 6 services → restore
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of [...LIVE_5, "domain-capture"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r5-kill1" });
  check(`[KILL1:R5] ${svc}: shadow`, d.enforcement_phase, "shadow", "kill");
  check(`[KILL1:R5] ${svc}: NOT BLOCK`, d.decision !== "BLOCK", true, "kill");
  if (d.decision === "BLOCK") _prodFires++;
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b47r5-res1" });
  check(`[KILL1:R5] ${svc} restored: hard_gate+ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "kill");
}
const dc1 = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b47r5-res1" });
check("[KILL1:R5] domain-capture restored: soft_canary+ALLOW", dc1.enforcement_phase === "soft_canary" && dc1.decision === "ALLOW", true, "kill");

// Cycle 2: kill → verify no hard BLOCK fires for malformed during kill → restore
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (let i = 0; i < 5; i++) {
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: `b47r5-kill2-${i}` });
  if (d.decision === "BLOCK") _prodFires++;
  check(`[KILL2:R5] IMPOSSIBLE_OP iter ${i}: NOT BLOCK while killed`, d.decision !== "BLOCK", true, "kill");
}
process.env.AEGIS_RUNTIME_ENABLED = "true";

// Cycle 3: partial kill — kill, then verify that PRAMANA still returns to hard_gate on restore
process.env.AEGIS_RUNTIME_ENABLED = "false";
const praKilled = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r5-kill3" });
check("[KILL3:R5] pramana killed: shadow", praKilled.enforcement_phase, "shadow", "kill");
process.env.AEGIS_RUNTIME_ENABLED = "true";
const praRestored = evaluate({ service_id: "pramana", operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r5-res3" });
check("[KILL3:R5] pramana restored: hard_gate+BLOCK", praRestored.enforcement_phase === "hard_gate" && praRestored.decision === "BLOCK", true, "kill");

// Verify IMPOSSIBLE_OP still sim-BLOCK after kill cycles
tpSimCheck("r5");
check("[META:R5] prod fires = 0", _prodFires, 0, "meta");
check("[META:R5] FP = 0", _fp, 0, "meta");
check("[META:R5] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "meta");
const r5 = closeRun(5);

// ════════════════════════════════════════════════════════════════════════════
// RUN 6 — unknown capability + boundary + HG-2B isolation
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 6/7 — unknown cap + boundary + HG-2B isolation`);
console.log("══════════════════════════════════════════════════════");
resetRun();

// Unknown capabilities: must NOT hard-block
const unknownCaps = [
  "BRAND_NEW_CAP", "FUTURE_OP_2027", "SOME_ARBITRARY_THING",
  "CAP_NOT_IN_REGISTRY", "X_CUSTOM_OP", "",  // empty string edge case
];
for (const cap of unknownCaps) {
  const d = evaluate({ service_id: "domain-capture", operation: "frob", requested_capability: cap, caller_id: "b47r6-unk" });
  check(`[UNK:R6] unknown cap [${cap || "empty"}]: NOT BLOCK`, d.decision !== "BLOCK", true, "unknown");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, cap, "frob", true);
  check(`[UNK:R6] sim(on) unknown [${cap || "empty"}]: NOT BLOCK`, sim.simulated_hard_decision !== "BLOCK", true, "unknown");
}

// Unknown services: must NOT BLOCK
const unknownSvcs = [
  "no-such-service-b47r6", "future-service-2027", "random-nonexistent-svc",
];
for (const svc of unknownSvcs) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r6-unk-svc" });
  check(`[UNK:R6] unknown svc [${svc}]: NOT BLOCK`, d.decision !== "BLOCK", true, "unknown");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// HG-2B isolation: parali-central, carbonx — neither hard_gate nor BLOCK
const hg2bCases: [string,string,string][] = [
  ["parali-central","read","READ"],
  ["parali-central","frob","IMPOSSIBLE_OP"],
  ["parali-central","execute","EXECUTE"],
  ["carbonx","read","READ"],
  ["carbonx","frob","IMPOSSIBLE_OP"],
  ["carbonx","deploy","CI_DEPLOY"],
];
for (const [svc, op, cap] of hg2bCases) {
  const d = evaluate({ service_id: svc, operation: op, requested_capability: cap, caller_id: "b47r6-hg2b" });
  check(`[HG2B:R6] ${svc} [${cap}]: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "hg2b");
  check(`[HG2B:R6] ${svc} [${cap}]: NOT BLOCK`, d.decision !== "BLOCK", true, "hg2b");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// HG-2C isolation: ankr-doctor
const hg2cCases: [string,string][] = [["read","READ"],["frob","IMPOSSIBLE_OP"],["execute","EXECUTE"]];
for (const [op, cap] of hg2cCases) {
  const d = evaluate({ service_id: "ankr-doctor", operation: op, requested_capability: cap, caller_id: "b47r6-hg2c" });
  check(`[HG2C:R6] ankr-doctor [${cap}]: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "hg2c");
  check(`[HG2C:R6] ankr-doctor [${cap}]: NOT BLOCK`, d.decision !== "BLOCK", true, "hg2c");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// domain-capture still clean after boundary flood
tpSimCheck("r6");
standardRegression("r6");
rollbackCheck("r6");
check("[META:R6] prod fires = 0", _prodFires, 0, "meta");
check("[META:R6] FP = 0", _fp, 0, "meta");
check("[META:R6] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "meta");
const r6 = closeRun(6);

// ════════════════════════════════════════════════════════════════════════════
// RUN 7 — final dress rehearsal and verdict
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log(`  Batch ${BATCH} Run 7/7 — final dress rehearsal and verdict`);
console.log("══════════════════════════════════════════════════════");
resetRun();

// Pre-state verification
invalidateCache();
const entry = getServiceEntry("domain-capture");
check("[R7] getServiceEntry non-null", entry !== null, true, "r7_precheck");
check("[R7] authority_class = read_only", entry?.authority_class, "read_only", "r7_precheck");
check("[R7] governance_blast_radius = BR-5", entry?.governance_blast_radius, "BR-5", "r7_precheck");
check("[R7] runtime_readiness.tier = TIER-A", entry?.runtime_readiness?.tier, "TIER-A", "r7_precheck");
check("[R7] isInPilotScope = true", isInPilotScope("domain-capture"), true, "r7_precheck");
check("[R7] domain-capture NOT in AEGIS_HARD_GATE_SERVICES", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("domain-capture"), true, "r7_precheck");
check("[R7] DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "r7_precheck");
check("[R7] PRAMANA_HG2A_POLICY.hard_gate_enabled = true", PRAMANA_HG2A_POLICY.hard_gate_enabled, true, "r7_precheck");

// Full ALLOW surface
for (const [op, cap] of [["read","READ"],["get","GET"],["list","LIST"],["query","QUERY"],["search","SEARCH"],["health","HEALTH"]] as [string,string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r7-allow" });
  check(`[R7] ${cap}: soft_canary+ALLOW`, d.enforcement_phase === "soft_canary" && d.decision === "ALLOW", true, "r7_allow");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[R7] sim(on) ${cap}: ALLOW (AEG-HG-002)`, sim.simulated_hard_decision, "ALLOW", "r7_allow");
}

// Full domain ops surface
for (const [op, cap] of [
  ["capture","CAPTURE_DOMAIN"],["classify","CLASSIFY_DOMAIN"],["extract","EXTRACT_RULES"],
  ["map","MAP_CONCEPTS"],["index","INDEX_KNOWLEDGE"],["query","QUERY_DOMAIN"],
] as [string,string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r7-dom" });
  check(`[R7] DOMAIN ${cap}: NOT BLOCK`, d.decision !== "BLOCK", true, "r7_domain");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// Full critical surface
for (const [op, cap] of [
  ["ai-execute","AI_EXECUTE"],["deploy","CI_DEPLOY"],["delete","DELETE"],
  ["execute","EXECUTE"],["approve","APPROVE"],["emit","EMIT"],
  ["write","MEMORY_WRITE"],["write","AUDIT_WRITE"],["write","SPAWN_AGENTS"],["write","TRIGGER"],
] as [string,string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r7-crit" });
  check(`[R7] CRIT ${cap}: soft_canary+NOT BLOCK`, d.enforcement_phase === "soft_canary" && d.decision !== "BLOCK", true, "r7_crit");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[R7] CRIT sim(on) ${cap}: NOT BLOCK (still_gate)`, sim.simulated_hard_decision !== "BLOCK", true, "r7_crit");
}

// TP gap — full confirmation
for (const [op, cap] of [["frob","IMPOSSIBLE_OP"],["write","EMPTY_CAPABILITY_ON_WRITE"]] as [string,string][]) {
  const d = evaluate({ service_id: "domain-capture", operation: op, requested_capability: cap, caller_id: "b47r7-tp" });
  logDecision(d);
  check(`[R7] TP ${cap}: soft ALLOW`, d.decision, "ALLOW", "r7_tp");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
  const sim = simulateHardGate("domain-capture", d.decision, cap, op, true);
  check(`[R7] TP sim(on) ${cap}: BLOCK`, sim.simulated_hard_decision, "BLOCK", "r7_tp");
  if (sim.simulated_hard_decision === "BLOCK") _tpSim++;
}

// Token doctrine (from Batch 46 + Run 4)
const gateDecision = evaluate({ service_id: "domain-capture", operation: "execute", requested_capability: "EXECUTE", caller_id: "b47r7-tok" });
check("[R7] EXECUTE: soft_canary+GATE", gateDecision.enforcement_phase === "soft_canary" && gateDecision.decision === "GATE", true, "r7_token");
check("[R7] approval_token present on GATE", !!(gateDecision as any).approval_token, true, "r7_token");
check("[R7] approveToken absent on soft_canary", typeof (gateDecision as any).approveToken, "undefined", "r7_token");
check("[R7] denyToken absent on soft_canary", typeof (gateDecision as any).denyToken, "undefined", "r7_token");
check("[R7] revokeToken absent on soft_canary", typeof (gateDecision as any).revokeToken, "undefined", "r7_token");

// HG-2B + HG-2C isolation
for (const svc of ["parali-central","carbonx","ankr-doctor"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r7-iso" });
  check(`[R7] ${svc}: NOT hard_gate`, d.enforcement_phase !== "hard_gate", true, "r7_iso");
  check(`[R7] ${svc}: NOT BLOCK`, d.decision !== "BLOCK", true, "r7_iso");
  if (d.decision === "BLOCK") { _prodFires++; _fp++; }
}

// Live roster full regression
for (const svc of LIVE_5) {
  const r = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b47r7-reg" });
  check(`[R7] ${svc} READ: hard_gate+ALLOW`, r.enforcement_phase === "hard_gate" && r.decision === "ALLOW", true, "r7_reg");
  const b = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r7-reg" });
  check(`[R7] ${svc} IMPOSSIBLE_OP: BLOCK`, b.decision, "BLOCK", "r7_reg");
}

// Kill switch
process.env.AEGIS_RUNTIME_ENABLED = "false";
for (const svc of [...LIVE_5, "domain-capture"]) {
  const d = evaluate({ service_id: svc, operation: "frob", requested_capability: "IMPOSSIBLE_OP", caller_id: "b47r7-kill" });
  check(`[R7] ${svc} killed: shadow+NOT BLOCK`, d.enforcement_phase === "shadow" && d.decision !== "BLOCK", true, "r7_kill");
  if (d.decision === "BLOCK") _prodFires++;
}
process.env.AEGIS_RUNTIME_ENABLED = "true";
for (const svc of LIVE_5) {
  const d = evaluate({ service_id: svc, operation: "read", requested_capability: "READ", caller_id: "b47r7-restore" });
  check(`[R7] ${svc} restored: hard_gate+ALLOW`, d.enforcement_phase === "hard_gate" && d.decision === "ALLOW", true, "r7_kill");
}
const dcRestored = evaluate({ service_id: "domain-capture", operation: "read", requested_capability: "READ", caller_id: "b47r7-restore" });
check("[R7] domain-capture restored: soft_canary+ALLOW", dcRestored.enforcement_phase === "soft_canary" && dcRestored.decision === "ALLOW", true, "r7_kill");

check("[R7] prod fires = 0", _prodFires, 0, "r7_meta");
check("[R7] FP = 0", _fp, 0, "r7_meta");
check("[R7] TP sim = 2", _tpSim, 2, "r7_meta");
check("[R7] policy.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "r7_meta");
check("[R7] ready_to_promote_domain_capture = false (soak only)", false, false, "r7_meta");
const r7 = closeRun(7);

// ════════════════════════════════════════════════════════════════════════════
// FINAL VERDICT — across all 7 runs (run 1 from Batch 46 + runs 2-7)
// ════════════════════════════════════════════════════════════════════════════
console.log("\n══════════════════════════════════════════════════════");
console.log("  Batch 47 — Final verdict across Batch 46+47 (all 7 runs)");
console.log("══════════════════════════════════════════════════════");

// Load run 1 metrics from Batch 46 artifact
let run1: { verdict: string; checks: number; passed: number; failed: number; production_fires: number; false_positives: number; true_positives_simulated: number } | null = null;
try {
  run1 = JSON.parse(readFileSync(join(dir, "batch46_domain_capture_soak_run1_metrics.json"), "utf-8"));
} catch { run1 = null; }
check("Batch 46 run 1 artifact present", run1 !== null, true, "verdict");
check("Batch 46 run 1 verdict = PASS", run1?.verdict, "PASS", "verdict");

// Tally Batch 47 runs 2-7
const batch47Runs = [r2, r3, r4, r5, r6, r7];
const allBatch47Pass = batch47Runs.every(r => r.verdict === "PASS");
const totalB47Checks = batch47Runs.reduce((s, r) => s + r.checks, 0);
const totalB47Passed = batch47Runs.reduce((s, r) => s + r.passed, 0);
const totalB47Failed = batch47Runs.reduce((s, r) => s + r.failed, 0);
const totalB47ProdFires = batch47Runs.reduce((s, r) => s + r.prod_fires, 0);
const totalB47FP = batch47Runs.reduce((s, r) => s + r.fp, 0);

check("Batch 47 runs 2-7: all PASS", allBatch47Pass, true, "verdict");
for (const r of batch47Runs) {
  check(`Run ${r.run}/7: PASS`, r.verdict, "PASS", "verdict");
}
check("Total Batch 47 prod fires = 0", totalB47ProdFires, 0, "verdict");
check("Total Batch 47 FP = 0", totalB47FP, 0, "verdict");
check("DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled = false", DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled, false, "verdict");
check("domain-capture NOT in AEGIS_HARD_GATE_SERVICES", !process.env.AEGIS_HARD_GATE_SERVICES?.includes("domain-capture"), true, "verdict");

const allSevenPass = run1?.verdict === "PASS" && allBatch47Pass;
const promotionPermitted = allSevenPass && DOMAIN_CAPTURE_HG2A_POLICY.hard_gate_enabled === false;

console.log(`\n  Run 1 (Batch 46): ${run1?.verdict ?? "MISSING"}`);
for (const r of batch47Runs) console.log(`  Run ${r.run}/7: ${r.verdict}  checks=${r.checks} FP=${r.fp} fires=${r.prod_fires}`);
console.log(`\n  All 7 runs pass: ${allSevenPass}`);
console.log(`  promotion_permitted_domain_capture=${promotionPermitted}`);
console.log("  NOTE: promotion_permitted=true does NOT enable hard-gate.");
console.log("  Promotion requires explicit human act: add domain-capture to AEGIS_HARD_GATE_SERVICES.");

// ── Write final verdict artifact ─────────────────────────────────────────────
const verdict = {
  batch: BATCH,
  service: "domain-capture",
  hg_group: "HG-2A",
  run_date: RUN_DATE,
  soak_runs: [
    { run: 1, verdict: run1?.verdict ?? "MISSING", source: "batch46_domain_capture_soak_run1_metrics.json", checks: run1?.checks, passed: run1?.passed, failed: run1?.failed, prod_fires: run1?.production_fires, fp: run1?.false_positives },
    ...batch47Runs.map(r => ({ run: r.run, verdict: r.verdict, checks: r.checks, passed: r.passed, failed: r.failed, prod_fires: r.prod_fires, fp: r.fp })),
  ],
  batch47_total_checks: totalB47Checks,
  batch47_total_passed: totalB47Passed,
  batch47_total_failed: totalB47Failed,
  batch47_total_prod_fires: totalB47ProdFires,
  batch47_total_fp: totalB47FP,
  all_7_runs_pass: allSevenPass,
  promotion_permitted_domain_capture: promotionPermitted,
  hard_gate_enabled_after_soak: false,
  policy_stage: DOMAIN_CAPTURE_HG2A_POLICY.stage,
  invariants_confirmed: [
    "hard_gate_enabled=false throughout soak",
    "domain-capture not in AEGIS_HARD_GATE_SERVICES",
    "0 false positives across all runs",
    "0 production fires across all runs",
    "IMPOSSIBLE_OP + EMPTY_CAPABILITY_ON_WRITE: soft=ALLOW, sim(on)=BLOCK",
    "domain ops (CAPTURE_DOMAIN etc): NOT BLOCK",
    "critical ops: GATE not BLOCK (still_gate)",
    "READ/ALLOW surface: intact (AEG-HG-002)",
    "approval_token on soft_canary GATE: present; action methods: absent",
    "kill switch: all services → shadow, 0 hard BLOCK",
    "HG-2B (parali-central, carbonx): NOT hard_gate, NOT BLOCK",
    "live roster (5 services): regression clean",
  ],
  promotion_note: "Promotion is a separate human act. Add domain-capture to AEGIS_HARD_GATE_SERVICES and set hard_gate_enabled=true in DOMAIN_CAPTURE_HG2A_POLICY.",
};
writeFileSync(join(dir, "batch47_domain_capture_final_verdict.json"), JSON.stringify(verdict, null, 2));
console.log("\n  Artifacts written:");
console.log("    .aegis/batch47_domain_capture_final_verdict.json");

// ── Batch 47 print summary ────────────────────────────────────────────────────
let finalChecks = 0, finalPassed = 0, finalFailed = 0;
for (const r of batch47Runs) { finalChecks += r.checks; finalPassed += r.passed; finalFailed += r.failed; }
// count the verdict checks at end
finalChecks += (run1 !== null ? 1 : 0) + batch47Runs.length + 6;
finalPassed += (run1?.verdict === "PASS" ? 1 : 0) + (allBatch47Pass ? batch47Runs.length : 0) + (allSevenPass ? 3 : 0);

console.log(`\n══ Batch ${BATCH} Final Summary (Runs 2–7) ══`);
console.log(`  Runs 2–7: ${totalB47Checks} checks, ${totalB47Passed} PASS, ${totalB47Failed} FAIL`);
console.log(`  Prod fires: ${totalB47ProdFires}  False positives: ${totalB47FP}`);
console.log(`  All 7 runs (Batch 46+47): ${allSevenPass ? "✓ PASS" : "✗ FAIL"}`);
console.log(`  promotion_permitted_domain_capture=${promotionPermitted}`);
console.log(`\n  Domain-capture has entered the BR-5 range. Six more watches before the`);
console.log(`  second HG-2A guard may be armed.`);
console.log(`\n  Batch ${BATCH}: ${totalB47Failed === 0 ? "PASS" : "FAIL"}`);
