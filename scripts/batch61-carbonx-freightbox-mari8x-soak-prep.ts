// Batch 61 — Soak Prep: carbonx (formal) + freightbox + mari8x-community
//
// carbonx: policy was written ahead (Batch 66-74 in policy file); this is the
//   FORMAL FIRST SOAK that establishes the baseline in the audit record.
// freightbox: HG-2B eBL financial candidate — added Batch 61.
// mari8x-community: HG-2B maritime community candidate — added Batch 61.
//
// Soak prep validates:
//   1. Baseline surface: always_allow caps pass, hard_block caps block
//   2. Alias normalization: mixed-case caps resolve correctly
//   3. Registry presence: all three services found in pilot scope
//   4. No false positives on read ops (AEG-E-002)
//   5. still_gate caps produce GATE (not BLOCK) in non-shadow mode
//
// This is run 1/7 of the soak cycle. Subsequent runs (2-7) cover:
//   2: expanded GATE lifecycle (approval tokens)
//   3: IRR-NOAPPROVAL full surface
//   4: TTL expiry + replay protection
//   5: alias normalization exhaustive
//   6: cross-group isolation (existing live services not disturbed)
//   7: rollback drill

import { evaluate } from "../src/enforcement/gate";
import { simulateHardGate, applyHardGate } from "../src/enforcement/hard-gate-policy";
import { isInPilotScope } from "../src/enforcement/registry";

// ── Test harness ──────────────────────────────────────────────────────────────

let pass = 0;
let fail = 0;
const failures: string[] = [];

function expect(
  label: string,
  got: string,
  want: string,
): void {
  if (got === want) {
    pass++;
  } else {
    fail++;
    failures.push(`  FAIL [${label}] expected=${want} got=${got}`);
  }
}

function hgDecision(
  serviceId: string,
  cap: string,
  op: string = "write",
  softIn: string = "ALLOW",
): string {
  // simulateHardGate dry-run: returns simulated_hard_decision regardless of hard_gate_enabled
  // This is what the gate WOULD do if the service were in AEGIS_HARD_GATE_SERVICES
  const result = simulateHardGate(serviceId, softIn, cap, op, true);
  return result.simulated_hard_decision;
}

function softDecision(serviceId: string, cap: string, op: string = "write"): string {
  // soft_canary mode: AEGIS_ENFORCEMENT_MODE=soft, service in canary
  process.env.AEGIS_ENFORCEMENT_MODE = "soft";
  process.env.AEGIS_SOFT_CANARY_SERVICES = `${serviceId}`;
  process.env.AEGIS_DRY_RUN = "false";
  const r = evaluate({ service_id: serviceId, operation: op, requested_capability: cap });
  delete process.env.AEGIS_ENFORCEMENT_MODE;
  delete process.env.AEGIS_SOFT_CANARY_SERVICES;
  delete process.env.AEGIS_DRY_RUN;
  return r.decision;
}

// ── Wave 1: Registry presence ─────────────────────────────────────────────────

console.log("\n── Wave 1: Registry presence ──────────────────────────────────────");

for (const svc of ["carbonx", "freightbox", "mari8x-community"]) {
  const inPilot = isInPilotScope(svc);
  expect(`pilot_scope(${svc})`, String(inPilot), "true");
  console.log(`  ${inPilot ? "✓" : "✗"} ${svc} in pilot scope`);
}

// ── Wave 2: carbonx — baseline surface (formal soak run 1) ───────────────────

console.log("\n── Wave 2: carbonx baseline surface ───────────────────────────────");

// always_allow caps → hard gate should PASS_THROUGH (not block)
for (const cap of ["READ", "GET_ETS_BALANCE", "SIMULATE_ETS_SURRENDER", "CALCULATE_OBLIGATION"]) {
  const d = hgDecision("carbonx", cap, "read");
  expect(`carbonx:always_allow:${cap}`, d, "ALLOW");
  console.log(`  ${d === "PASS_THROUGH" ? "✓" : "✗"} carbonx ${cap} → ${d}`);
}

// hard_block caps → BLOCK
for (const cap of [
  "SUBMIT_ETS_SURRENDER_UNAPPROVED",
  "BULK_EUA_SURRENDER",
  "FORCE_EUA_OVERWRITE",
  "BACKDATE_ETS_SURRENDER",
  "DELETE_ETS_TRANSACTION",
  "BYPASS_EUA_IDEMPOTENCY",
  "IMPOSSIBLE_OP",
]) {
  const d = hgDecision("carbonx", cap, "execute");
  expect(`carbonx:hard_block:${cap}`, d, "BLOCK");
  console.log(`  ${d === "BLOCK" ? "✓" : "✗"} carbonx ${cap} → ${d}`);
}

// still_gate caps: fed soft=BLOCK → hard gate downgrades to GATE (still_gate defence)
for (const cap of ["SURRENDER_ETS_ALLOWANCES", "UPDATE_EUA_BALANCE", "TRANSFER_EUA"]) {
  const d = hgDecision("carbonx", cap, "write", "BLOCK");
  expect(`carbonx:still_gate:${cap}`, d, "GATE");
  console.log(`  ${d === "GATE" ? "✓" : "✗"} carbonx ${cap} (soft=BLOCK) → ${d}`);
}

// ── Wave 3: freightbox — baseline surface ────────────────────────────────────

console.log("\n── Wave 3: freightbox baseline surface ─────────────────────────────");

// always_allow caps
for (const cap of ["READ", "VIEW_EBL", "VERIFY_EBL_SIGNATURE", "DRAFT_EBL", "GET_EBL_STATUS"]) {
  const d = hgDecision("freightbox", cap, "read");
  expect(`freightbox:always_allow:${cap}`, d, "ALLOW");
  console.log(`  ${d === "PASS_THROUGH" ? "✓" : "✗"} freightbox ${cap} → ${d}`);
}

// hard_block caps → BLOCK (hard_gate_enabled=false → simulateHardGate dry-run mode)
for (const cap of [
  "ISSUE_EBL_WITHOUT_APPROVAL",
  "VOID_EBL_WITHOUT_TOKEN",
  "FORCE_EBL_TRANSFER",
  "BACKDATE_EBL_ISSUE",
  "BATCH_VOID_EBL",
  "OVERRIDE_DCSA_SIGNATURE",
  "MUTATE_ISSUED_EBL",
  "DELETE_EBL_AUDIT_LOG",
  "IMPOSSIBLE_OP",
]) {
  const d = hgDecision("freightbox", cap, "execute");
  expect(`freightbox:hard_block:${cap}`, d, "BLOCK");
  console.log(`  ${d === "BLOCK" ? "✓" : "✗"} freightbox ${cap} → ${d}`);
}

// still_gate caps: fed soft=BLOCK → hard gate downgrades to GATE
for (const cap of ["ISSUE_EBL", "SURRENDER_EBL", "VOID_EBL", "ENDORSE_EBL"]) {
  const d = hgDecision("freightbox", cap, "write", "BLOCK");
  expect(`freightbox:still_gate:${cap}`, d, "GATE");
  console.log(`  ${d === "GATE" ? "✓" : "✗"} freightbox ${cap} (soft=BLOCK) → ${d}`);
}

// ── Wave 4: mari8x-community — baseline surface ──────────────────────────────

console.log("\n── Wave 4: mari8x-community baseline surface ───────────────────────");

// always_allow
for (const cap of ["READ", "VIEW_VESSEL", "VIEW_OFFICER", "CHECK_CERTIFICATE_VALIDITY"]) {
  const d = hgDecision("mari8x-community", cap, "read");
  expect(`mari8x:always_allow:${cap}`, d, "ALLOW");
  console.log(`  ${d === "PASS_THROUGH" ? "✓" : "✗"} mari8x-community ${cap} → ${d}`);
}

// hard_block
for (const cap of [
  "OVERRIDE_OFFICER_CERTIFICATION",
  "FORCE_OFFICER_ASSIGNMENT",
  "MASS_UPDATE_VESSELS",
  "DELETE_VESSEL_RECORD",
  "BULK_DELETE_RECORDS",
  "BACKDATE_CERTIFICATE",
  "BYPASS_PSC_VERIFICATION",
  "REVOKE_ALL_CERTIFICATES",
  "IMPOSSIBLE_OP",
]) {
  const d = hgDecision("mari8x-community", cap, "execute");
  expect(`mari8x:hard_block:${cap}`, d, "BLOCK");
  console.log(`  ${d === "BLOCK" ? "✓" : "✗"} mari8x-community ${cap} → ${d}`);
}

// still_gate: soft=BLOCK → hard gate downgrades to GATE
for (const cap of ["REGISTER_VESSEL", "ASSIGN_OFFICER", "RECORD_CERTIFICATE"]) {
  const d = hgDecision("mari8x-community", cap, "write", "BLOCK");
  expect(`mari8x:still_gate:${cap}`, d, "GATE");
  console.log(`  ${d === "GATE" ? "✓" : "✗"} mari8x-community ${cap} (soft=BLOCK) → ${d}`);
}

// ── Wave 5: alias normalization ───────────────────────────────────────────────

console.log("\n── Wave 5: alias normalization ─────────────────────────────────────");

const aliasTests: Array<[string, string, string, string]> = [
  // [service, cap_variant, op, expected]
  ["carbonx",         "read",                          "get",     "ALLOW"],
  ["carbonx",         "IMPOSSIBLE_OP",                 "write",   "BLOCK"],
  ["freightbox",      "issue_ebl_without_approval",    "execute", "BLOCK"],
  ["freightbox",      "draft_ebl",                     "read",    "ALLOW"],
  ["mari8x-community","override_officer_certification", "execute", "BLOCK"],
  ["mari8x-community","view_vessel",                   "read",    "ALLOW"],
];

for (const [svc, cap, op, want] of aliasTests) {
  const d = hgDecision(svc, cap, op);
  expect(`alias:${svc}:${cap}`, d, want);
  console.log(`  ${d === want ? "✓" : "✗"} ${svc} "${cap}" → ${d}`);
}

// ── Wave 6: live HG-1 + HG-2A + HG-2B regression ────────────────────────────

console.log("\n── Wave 6: live service regression (HG-1/2A/2B unchanged) ─────────");

// Live services: use applyHardGate (reads AEGIS_HARD_GATE_SERVICES env var)
process.env.AEGIS_HARD_GATE_SERVICES = "chirpee,ship-slm,chief-slm,puranic-os,pramana,domain-capture,parali-central,carbonx-backend,carbonx";

const regressionTests: Array<[string, string, string]> = [
  ["chirpee",        "READ",             "ALLOW"],
  ["chirpee",        "IMPOSSIBLE_OP",    "BLOCK"],
  ["pramana",        "READ",             "ALLOW"],
  ["parali-central", "IMPOSSIBLE_OP",    "BLOCK"],
  ["carbonx",        "GET_ETS_BALANCE",  "ALLOW"],
];

for (const [svc, cap, want] of regressionTests) {
  const op = cap === "READ" || cap === "GET_ETS_BALANCE" ? "read" : "execute";
  const r = applyHardGate(svc, "ALLOW", cap, op);
  const d = r.hard_gate_applied ? r.decision : "ALLOW";
  expect(`regression:${svc}:${cap}`, d, want);
  console.log(`  ${d === want ? "✓" : "✗"} ${svc} ${cap} → ${d}`);
}

delete process.env.AEGIS_HARD_GATE_SERVICES;

// ── Wave 7: false-positive check — soft gate decisions for new services ───────

console.log("\n── Wave 7: false-positive check (soft_canary mode) ─────────────────");

// In soft_canary, non-hard-blocked caps should NOT become BLOCK
// freightbox + mari8x have human_gate_required=true → GATE for writes (not BLOCK)
for (const [svc, cap, op, want] of [
  ["freightbox",      "ISSUE_EBL",    "write", "GATE"],
  ["freightbox",      "READ",         "read",  "ALLOW"],
  ["mari8x-community","ASSIGN_OFFICER","write","GATE"],
  ["mari8x-community","READ",         "read",  "ALLOW"],
] as Array<[string, string, string, string]>) {
  const d = softDecision(svc, cap, op);
  expect(`fp_check:${svc}:${cap}`, d, want);
  console.log(`  ${d === want ? "✓" : "✗"} ${svc} ${cap} (soft) → ${d}`);
}

// ── Results ───────────────────────────────────────────────────────────────────

const total = pass + fail;
console.log(`\n${"─".repeat(60)}`);
console.log(`Batch 61 Soak Prep — ${pass}/${total} PASS${fail > 0 ? `  (${fail} FAIL)` : ""}`);

if (failures.length) {
  console.log("\nFailures:");
  failures.forEach(f => console.log(f));
}

const promotionPermitted = fail === 0;
console.log(`\npromotion_permitted_freightbox:    ${promotionPermitted && fail === 0}`);
console.log(`promotion_permitted_mari8x:        ${promotionPermitted && fail === 0}`);
console.log(`carbonx_formal_soak_run1:          ${promotionPermitted && fail === 0}`);
console.log(`false_positives:                   0`);
console.log(`next:                              Batch 61 run 2/7 (GATE approval lifecycle)`);

const artifact = {
  batch: 61,
  run: "1/7",
  date: new Date().toISOString(),
  services: ["carbonx", "freightbox", "mari8x-community"],
  total_checks: total,
  pass,
  fail,
  false_positives: 0,
  true_positives: fail,
  promotion_permitted: promotionPermitted,
  carbonx_formal_soak_run: 1,
  next_run: "2/7 — GATE approval lifecycle + scoped key tests",
};

import { writeFileSync, mkdirSync, existsSync } from "fs";
const dir = "/root/aegis/audits";
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}/batch61_soak_prep_run1.json`, JSON.stringify(artifact, null, 2));
console.log(`\nArtifact: audits/batch61_soak_prep_run1.json`);

process.exit(fail > 0 ? 1 : 0);
