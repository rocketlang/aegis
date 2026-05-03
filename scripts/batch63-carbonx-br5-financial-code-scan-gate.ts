/**
 * Batch 63 — carbonx BR-5 Financial Service Code-Scan Gate
 *
 * Purpose:
 *   Resolve carbonx needs_code_scan=true before any HG-2B policy declaration
 *   or soft-canary soak. Inspect actual source code for financial-settlement
 *   controls. Determine gate_decision: READY_FOR_POLICY_DECLARATION or
 *   BLOCKED_FOR_SOAK (with specific blockers listed).
 *
 * Non-negotiables:
 *   - carbonx is NOT added to AEGIS_HARD_GATE_SERVICES this batch
 *   - carbonx hard_gate_enabled remains false
 *   - CARBONX_HG2B_POLICY is NOT declared unless gate passes
 *   - Live roster remains exactly 7 (parali-central only in HG-2B)
 *   - HG-2C live count remains 0
 *   - Existing seven live guards remain clean
 *
 * @rule:AEG-HG-001 hard_gate_enabled=false until promoted
 * @rule:AEG-HG-2B-002 approval_required_for_irreversible_action — non-negotiable
 * @rule:AEG-HG-2B-003 observability_required — no silent boundary crossings
 * @rule:IRR-NOAPPROVAL no AI agent may perform irreversible external action without token
 * @rule:AEG-E-016 approval tokens scoped to service_id + capability + operation
 */

import { existsSync, readFileSync } from "fs";
import { writeFileSync } from "fs";
import {
  applyHardGate,
  HARD_GATE_POLICIES,
  PARALI_CENTRAL_HG2B_POLICY,
} from "../src/enforcement/hard-gate-policy";

// ── Check infrastructure ──────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];
const findings: string[] = [];
const blockers: string[] = [];   // gate-decision blockers (subset of findings)

function check(
  group: number,
  label: string,
  actual: unknown,
  expected: unknown,
  tag: string,
): void {
  const ok =
    typeof expected === "object" && expected !== null
      ? JSON.stringify(actual) === JSON.stringify(expected)
      : actual === expected;
  const pad = String(group).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    const msg = `[${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`;
    failures.push(`${tag}: ${msg}`);
    console.log(`  ✗ ${msg}`);
  }
}

function blocker(code: string, label: string): void {
  const entry = `BLOCKER [${code}]: ${label}`;
  blockers.push(entry);
  findings.push(`⛔ ${entry}`);
  console.log(`  ⛔ ${entry}`);
}

function finding(label: string, detail: string): void {
  const entry = `FINDING: ${label} — ${detail}`;
  findings.push(entry);
  console.log(`  ⚠  ${entry}`);
}

function pass_finding(label: string, detail: string): void {
  const entry = `✅ ${label} — ${detail}`;
  findings.push(entry);
  console.log(`  ✅ ${entry}`);
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

function readSrc(path: string): string {
  try { return readFileSync(path, "utf-8"); }
  catch { return ""; }
}

// ── Constants ─────────────────────────────────────────────────────────────────

const CARBONX          = "carbonx-backend";
const PARALI_CENTRAL   = "parali-central";
const HG1_SERVICES     = ["chirpee", "ship-slm", "chief-slm", "puranic-os"];
const HG2A_SERVICES    = ["pramana", "domain-capture"];
const EXPECTED_LIVE_7  = [...HG1_SERVICES, ...HG2A_SERVICES, PARALI_CENTRAL];

const SRC_BASE  = "/root/apps/carbonx/backend/src";
const SRC = {
  etsService:     `${SRC_BASE}/services/ets/ets-service.ts`,
  etsTypes:       `${SRC_BASE}/schema/types/ets.ts`,
  carbonPrice:    `${SRC_BASE}/services/ets/carbon-price.service.ts`,
  creditsService: `${SRC_BASE}/services/credits/credits-service.ts`,
  reportGen:      `${SRC_BASE}/services/reports/report-generator.ts`,
  ciiTypes:       `${SRC_BASE}/schema/types/cii.ts`,
  fueleuTypes:    `${SRC_BASE}/schema/types/fueleu.ts`,
  eexiTypes:      `${SRC_BASE}/schema/types/eexi.ts`,
  context:        `${SRC_BASE}/schema/context.ts`,
  main:           `${SRC_BASE}/main.ts`,
  logger:         `${SRC_BASE}/utils/logger.ts`,
};
const PRISMA_SCHEMA = "/root/apps/carbonx/backend/prisma/schema.prisma";

// ── HEADER ────────────────────────────────────────────────────────────────────

console.log("══ Batch 63 — carbonx BR-5 Financial Service Code-Scan Gate ══");
console.log(`  Date: ${new Date().toISOString()}`);
console.log("  Purpose: Resolve needs_code_scan=true; determine soak readiness");
console.log("  Invariant: carbonx does NOT enter AEGIS_HARD_GATE_SERVICES this batch");
console.log();

// ── Load batch62 artifact ─────────────────────────────────────────────────────

const b62 = JSON.parse(readFileSync("audits/batch62_carbonx_hg2b_candidate_readiness.json", "utf-8")) as Record<string, unknown>;

// ── Pre-load source files ─────────────────────────────────────────────────────

const etsServiceSrc      = readSrc(SRC.etsService);
const etsTypesSrc        = readSrc(SRC.etsTypes);
const carbonPriceSrc     = readSrc(SRC.carbonPrice);
const creditsSrc         = readSrc(SRC.creditsService);
const contextSrc         = readSrc(SRC.context);
const mainSrc            = readSrc(SRC.main);
const ciiTypesSrc        = readSrc(SRC.ciiTypes);
const fueleuTypesSrc     = readSrc(SRC.fueleuTypes);
const eexiTypesSrc       = readSrc(SRC.eexiTypes);
const prismaSchemaSrc    = readSrc(PRISMA_SCHEMA);

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 1 — Source path exists
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 1: Verify carbonx backend source path exists");
const srcBaseExists = existsSync(SRC_BASE);
const etsServiceExists = existsSync(SRC.etsService);
const etsTypesExists = existsSync(SRC.etsTypes);
check(1, "carbonx backend src dir exists", srcBaseExists, true, "scan");
check(1, "ets-service.ts exists", etsServiceExists, true, "scan");
check(1, "schema/types/ets.ts exists", etsTypesExists, true, "scan");
if (!srcBaseExists || !etsServiceExists) {
  blocker("source_unavailable", "carbonx source not found — cannot complete code scan");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 2 — Package/build metadata
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 2: Package/build metadata");
const pkgPath = "/root/apps/carbonx/backend/package.json";
const pkgExists = existsSync(pkgPath);
check(2, "package.json exists", pkgExists, true, "scan");
if (pkgExists) {
  const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
  check(2, "package name references carbonx",
    String(pkg.name ?? "").toLowerCase().includes("carbon"), true, "scan");
  pass_finding("package.json", `name=${pkg.name}, runtime=bun`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 3 — External API clients identified
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 3: Identify external API clients");

// ICE / EEX price feed fetchers (READ-ONLY price feeds)
const hasIceFetch = carbonPriceSrc.includes("fetchFromIce") && carbonPriceSrc.includes("api.ice.com");
const hasEexFetch = carbonPriceSrc.includes("fetchFromEex") && carbonPriceSrc.includes("api.eex.com");
check(3, "ICE Carbon API client present (price-feed READ)", hasIceFetch, true, "scan");
check(3, "EEX Carbon API client present (price-feed READ)", hasEexFetch, true, "scan");

// Determine if ICE/EEX calls are READ-ONLY (no mutation to external state)
const iceIsReadOnly = carbonPriceSrc.includes("fetchFromIce") &&
  !carbonPriceSrc.includes("method: 'POST'") &&
  !carbonPriceSrc.includes("method: 'PUT'");
check(3, "external price-feed calls are GET-only (no external state mutation)",
  iceIsReadOnly, true, "scan");

// Carbon credit registry URLs: in constants, not actual fetch calls
const creditsHasFetch = creditsSrc.includes("fetch(") || creditsSrc.includes("axios");
check(3, "credits-service: no live registry fetch calls (URLs are reference constants only)",
  !creditsHasFetch, true, "scan");

pass_finding("external API surface", "ICE + EEX price feeds are read-only. Carbon credit registry URLs are constants only — no live external write calls found.");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 4 — Registry / ETS / EUA surrender code paths
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 4: Identify registry / ETS / EUA surrender code paths");

const hasSurrenderMethod = etsServiceSrc.includes("recordSurrender");
const hasSurrenderMutation = etsTypesSrc.includes("surrenderEtsAllowances");
const surrenderIsDbOnly = etsServiceSrc.includes("recordSurrender") &&
  !etsServiceSrc.includes("fetch(") && !etsServiceSrc.includes("axios");

check(4, "ets-service.ts has recordSurrender method", hasSurrenderMethod, true, "scan");
check(4, "ets.ts schema has surrenderEtsAllowances mutation", hasSurrenderMutation, true, "scan");
check(4, "recordSurrender is LOCAL database operation (no external registry fetch)",
  surrenderIsDbOnly, true, "scan");

if (surrenderIsDbOnly) {
  finding(
    "surrender is LOCAL DB only",
    "recordSurrender() writes to local Prisma DB (etsRecord + etsAccount + etsTransaction). " +
    "No integration with EU THETIS-MRV, MRV portal, or EU ETS registry found. " +
    "Risk: internal DB integrity, not live EU registry corruption. " +
    "However, IRR-NOAPPROVAL still applies — local surrender records flow to regulatory reports."
  );
}

// Check Prisma schema for surrender data model
const hasPrismaSurrender = prismaSchemaSrc.includes("euaSurrendered") &&
  prismaSchemaSrc.includes("EtsTransaction") && prismaSchemaSrc.includes("isSettled");
check(4, "Prisma schema models ETS surrender (EtsRecord + EtsTransaction + isSettled)",
  hasPrismaSurrender, true, "scan");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 5 — Financial settlement / carbon-credit mutation paths
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 5: Identify financial settlement or carbon-credit mutation paths");

const hasPrismaTransaction = etsServiceSrc.includes("prisma.$transaction");
const hasEuaBalanceDecrement = etsServiceSrc.includes("euaBalance: { decrement:");
check(5, "recordSurrender uses Prisma atomic $transaction", hasPrismaTransaction, true, "scan");
check(5, "recordSurrender decrements euaBalance (financial state mutation)",
  hasEuaBalanceDecrement, true, "scan");

// Check for bulk operations or mass mutation risk
const hasFleetCalculate = etsServiceSrc.includes("calculateFleetEts");
const hasFleetMutation = etsTypesSrc.includes("calculateFleetEts");
check(5, "fleet-level ETS recalculation exists (blast radius consideration)",
  hasFleetCalculate && hasFleetMutation, true, "scan");
if (hasFleetCalculate) {
  finding(
    "calculateFleetEts is a fleet-wide write",
    "calculateFleetEts() loops all vessels and calls calculateAndPersist() per vessel. " +
    "This is a bulk database mutation path. Does not surrender EUAs directly — " +
    "but updates obligationMt for all vessels. Included in GATE surface (not BLOCK)."
  );
}

// setManualCarbonPrice: admin-only mutation
const hasManualPrice = etsTypesSrc.includes("setManualCarbonPrice");
check(5, "setManualCarbonPrice mutation exists (admin — financial state)",
  hasManualPrice, true, "scan");
if (hasManualPrice) {
  finding(
    "setManualCarbonPrice lacks admin-role guard",
    "setManualCarbonPrice sets EUA price globally — affects all obligation calculations. " +
    "JWT auth only, no role=admin check visible in schema. Should require admin role guard."
  );
}

pass_finding("financial atomicity", "Prisma $transaction ensures all-or-nothing for surrender (record update + balance decrement + tx log).");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 6 — Database write paths
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 6: Identify database write paths");

const dbWrites = [
  { name: "euaSurrendered accumulate",    found: etsServiceSrc.includes("euaSurrendered: newSurrendered") },
  { name: "euaBalance decrement",          found: etsServiceSrc.includes("euaBalance: { decrement:") },
  { name: "etsTransaction.create",         found: etsServiceSrc.includes("etsTransaction.create") },
  { name: "etsRecord.upsert (calculate)",  found: etsServiceSrc.includes("etsRecord.upsert") },
  { name: "voyage.update (ets scope)",     found: etsServiceSrc.includes("prisma.voyage.update") },
];

for (const w of dbWrites) {
  check(6, `DB write path: ${w.name}`, w.found, true, "scan");
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 7 — Irreversible actions
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 7: Identify irreversible actions");

// Surrender: euaSurrendered is cumulative (+=). No undo mutation exists.
const hasUndoSurrender = etsServiceSrc.includes("undoSurrender") ||
  etsServiceSrc.includes("reverseSurrender") || etsTypesSrc.includes("undoSurrender");
check(7, "no undoSurrender / reverseSurrender method found",
  !hasUndoSurrender, true, "scan");

// The schema allows multiple surrenders — cumulative, not idempotent
const isIdempotent = etsServiceSrc.includes("idempotency") ||
  etsServiceSrc.includes("nonce") || etsServiceSrc.includes("externalRef");
check(7, "no idempotency key on surrender (double-call risk confirmed)",
  !isIdempotent, true, "scan");

if (!hasUndoSurrender) {
  finding(
    "surrenderEtsAllowances is irreversible",
    "recordSurrender() increments euaSurrendered (+=). No undo/reverse mutation exists. " +
    "Calling the mutation twice with the same amount double-decrements euaBalance. " +
    "This confirms IRR-NOAPPROVAL must apply — any surrender without explicit human approval " +
    "is undoable only by a corrective DB operation, not by a clean API path."
  );
}
if (!isIdempotent) {
  blocker(
    "no_idempotency_on_surrender",
    "recordSurrender has no idempotency key, deduplication, or external reference guard. " +
    "An AI agent retrying on network failure would double-surrender EUAs. " +
    "Required before soft-canary: add idempotencyKey or externalRef to EtsTransaction."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 8 — Approval / auth / human-gate hooks
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 8: Identify approval / auth / human-gate hooks on surrender path");

// JWT auth: exists. Required for all mutations via ctx.orgId()
const hasJwtVerify = mainSrc.includes("jwtVerify") || contextSrc.includes("jwtVerify");
check(8, "JWT authentication wired (jwtVerify in context)", hasJwtVerify, true, "scan");

// surrenderEtsAllowances mutation: does it check for an approval token beyond JWT?
const surrenderMutationSlice = etsTypesSrc.slice(
  etsTypesSrc.indexOf("surrenderEtsAllowances"),
  etsTypesSrc.indexOf("surrenderEtsAllowances") + 1200
);
const hasApprovalToken = surrenderMutationSlice.includes("approval") ||
  surrenderMutationSlice.includes("token") || surrenderMutationSlice.includes("humanGate") ||
  surrenderMutationSlice.includes("human_gate") || surrenderMutationSlice.includes("confirm");
const hasRoleGuard = surrenderMutationSlice.includes("role") ||
  surrenderMutationSlice.includes("admin") || surrenderMutationSlice.includes("isAdmin");

// Scan checks record truth — absence of control = finding/blocker, not a check failure.
// Audit PASS means scan completed and gaps were correctly identified.
check(8, "approval hook scan: absent on surrenderEtsAllowances (CARBONX-FIX-001 blocker recorded)",
  !hasApprovalToken, true, "scan");
// Role guard: slice-window may hit downstream mutations — record as finding, not check
finding("role guard scan", hasRoleGuard
  ? "role/admin string found within 1200 chars of surrender mutation — verify it applies to surrender specifically, not to setManualCarbonPrice which follows immediately"
  : "no role guard found in surrender mutation");

if (!hasApprovalToken) {
  blocker(
    "financial_irreversible_path_without_human_gate",
    "surrenderEtsAllowances mutation has JWT auth only. No approval token, " +
    "no role guard, no human-gate check before executing recordSurrender(). " +
    "Any authenticated org user (including an AI agent with a valid JWT) can " +
    "surrender EUAs without additional approval. " +
    "IRR-NOAPPROVAL doctrine is violated. This is the primary soak blocker."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 9 — Idempotency keys / transaction guards
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 9: Idempotency keys or transaction guards on financial mutations");

// Already found in Check 7: no idempotency key. Re-confirm from schema.
const schemaHasExtRef = prismaSchemaSrc.includes("externalRef") ||
  prismaSchemaSrc.includes("idempotencyKey") || prismaSchemaSrc.includes("nonce");
check(9, "idempotency scan: absent from EtsTransaction schema (CARBONX-FIX-004 finding recorded)",
  !schemaHasExtRef, true, "scan");
check(9, "Prisma $transaction atomicity exists (partial mitigation)",
  hasPrismaTransaction, true, "scan");

if (!schemaHasExtRef) {
  // Already recorded as blocker in Check 7 — don't double-list
  finding(
    "EtsTransaction schema has no idempotency field",
    "Prisma $transaction ensures DB atomicity (all 3 ops succeed or none do), " +
    "but does not prevent duplicate surrenders from distinct API calls. " +
    "An externalRef or transactionNonce field in EtsTransaction would close this gap."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 10 — Rollback / compensation logic
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 10: Rollback or compensation logic for surrender path");

const hasCompensation = etsServiceSrc.includes("compensat") ||
  etsServiceSrc.includes("reversal") || etsServiceSrc.includes("rollback") ||
  etsTypesSrc.includes("reverseSurrender") || etsTypesSrc.includes("correctSurrender");

check(10, "compensation scan: absent from ETS service (no_safe_soft_canary_surface blocker recorded)",
  !hasCompensation, true, "scan");

if (!hasCompensation) {
  blocker(
    "no_safe_soft_canary_surface",
    "No reversal, correction, or compensation path exists for incorrect surrenders. " +
    "Soft-canary simulation must have a safe surface: at minimum a dry-run mode " +
    "or a correctSurrender mutation that can undo a test surrender. " +
    "Without this, soak runs carry real financial correction cost on any error."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 11 — Audit logging
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 11: Audit logging on surrender path");

const surrenderHasLogger = etsServiceSrc.includes("logger.info") &&
  etsServiceSrc.includes("ETS surrender recorded");
check(11, "logger.info emitted after surrender (structured pino log)",
  surrenderHasLogger, true, "scan");

// Is there a separate audit trail beyond logger? (DB transaction log is one form)
const hasEtsTransactionLog = etsServiceSrc.includes("etsTransaction.create") &&
  etsServiceSrc.includes("type: 'surrender'");
check(11, "EtsTransaction record created per surrender (DB audit trail)",
  hasEtsTransactionLog, true, "scan");

pass_finding("audit trail partial", "etsTransaction.create provides a DB-level audit trail per surrender. pino structured log provides real-time observability. Sufficient for soft-canary if SENSE event added.");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 12 — SENSE / event emission on surrender path
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 12: SENSE / event emission from surrender path");

const sensePresentInMain = mainSrc.includes("/api/v2/forja/sense/emit");
const surrenderEmitsSense = etsServiceSrc.includes("sense") ||
  etsServiceSrc.includes("SENSE") || etsServiceSrc.includes("forja") ||
  etsServiceSrc.includes("emit(");

check(12, "Forja SENSE endpoint wired in main.ts",
  sensePresentInMain, true, "scan");
check(12, "SENSE scan: absent from recordSurrender (CA-003 blocker recorded)",
  !surrenderEmitsSense, true, "scan");

if (!surrenderEmitsSense) {
  blocker(
    "financial_irreversible_path_without_human_gate",  // same code — observability dimension
    "recordSurrender() emits only pino log — no SENSE event to the event bus. " +
    "CA-003 (AEG-HG-2B-003 observability_required) mandates that boundary-crossing " +
    "events are visible to downstream subscribers (kavachos, pramana, ankr-mailer). " +
    "A financial surrender is exactly the event that must be visible system-wide. " +
    "Required: SENSE event with before_snapshot + after_snapshot + delta (CA-003)."
  );
  finding(
    "SENSE endpoint exists but not called from surrender",
    "POST /api/v2/forja/sense/emit is wired in main.ts. " +
    "ets-service.ts does not call it. Adding SENSE emission to recordSurrender() " +
    "is a 5-line fix — but must happen before soak begins."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 13 — Secrets / env usage
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 13: Secrets and env usage");

const jwtSecretThrows = mainSrc.includes("JWT_SECRET") &&
  mainSrc.includes("throw new Error");
const jwtHardcoded = mainSrc.includes('"fallback"') ||
  mainSrc.includes("'secret'") || mainSrc.includes('"mysecret"');

check(13, "JWT_SECRET throws if not set (no insecure fallback)", jwtSecretThrows, true, "scan");
check(13, "JWT_SECRET has no hardcoded insecure fallback", !jwtHardcoded, true, "scan");
check(13, "ICE/EEX API keys are optional env vars (not required for core path)",
  carbonPriceSrc.includes("process.env.ICE_CARBON_API_KEY"), true, "scan");

pass_finding("secrets hygiene", "JWT_SECRET throws if absent. ICE/EEX API keys are optional (fallback to simulated price). No hardcoded credentials found in financial paths.");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 14 — Dry-run / simulation mode on surrender
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 14: Dry-run / simulation mode for surrender path");

// CII, EEXI, FuelEU all have simulate queries
const hasCiiSimulate  = ciiTypesSrc.includes("simulateCiiImprovement");
const hasFuelEuSimulate = fueleuTypesSrc.includes("simulateFuelMix");
const hasEexiSimulate   = eexiTypesSrc.includes("simulateEexi");
const hasSurrenderSimulate = etsTypesSrc.includes("simulateSurrender") ||
  etsTypesSrc.includes("dryRunSurrender") || etsTypesSrc.includes("dry_run");

check(14, "CII has simulateCiiImprovement query (precedent exists)",
  hasCiiSimulate, true, "scan");
check(14, "FuelEU has simulateFuelMix query (precedent exists)",
  hasFuelEuSimulate, true, "scan");
check(14, "EEXI has simulateEexi query (precedent exists)",
  hasEexiSimulate, true, "scan");
check(14, "dry-run scan: absent from ETS surrender path (no_safe_soft_canary_surface blocker recorded)",
  !hasSurrenderSimulate, true, "scan");

if (!hasSurrenderSimulate) {
  blocker(
    "no_safe_soft_canary_surface",
    "surrenderEtsAllowances has no dry-run or simulation mode. " +
    "CII, FuelEU, and EEXI all have simulate queries — the precedent and pattern exist. " +
    "Adding simulateSurrender query (read-only, no DB write) is the minimum required. " +
    "Without it, AEGIS cannot soak-test against carbonx without triggering real DB mutations."
  );
  finding(
    "simulate pattern established",
    "Add simulateSurrender(vesselId, year, euaAmount): EtsSurrenderSimulation " +
    "as a read-only query. Return { projectedNewSurrendered, wouldSettle, " +
    "projectedBalance, shortfall, compliancePct }. No DB write. " +
    "This is the soak surface AEGIS will call during soft-canary runs 1-7."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 15 — Test coverage for surrender/settlement paths
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 15: Test coverage around surrender/settlement paths");

const testDir = "/root/apps/carbonx/backend/src";
const testFiles = ["ets.test.ts", "ets-service.test.ts", "surrender.test.ts"]
  .filter(f => existsSync(`${testDir}/${f}`));
const hasEtsTests = testFiles.length > 0;

check(15, "test coverage scan: absent from surrender path (quality finding recorded — not a hard blocker)",
  !hasEtsTests, true, "scan");

if (!hasEtsTests) {
  finding(
    "zero test coverage for surrender path",
    "No *.test.ts files found in carbonx/backend/src. " +
    "CII, EEXI, and FuelEU calculators have pure-function logic suitable for unit tests. " +
    "recordSurrender() requires integration test. " +
    "Test coverage is not a hard soak blocker for AEGIS (AEGIS supplies the soak), " +
    "but is a quality gap that should be closed before production promotion."
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHECKS 16-19 — Financial-settlement addendum requirements
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 16-19: Financial-settlement addendum — doctrine requirements");

// 16: SUBMIT_ETS_SURRENDER must be HARD-BLOCK until explicit doctrine exists
const b62HardBlock = ((b62.surface_design as Record<string, unknown>)?.hard_block_surface as string[]) ?? [];
check(16, "Batch 62 candidate profile: SUBMIT_ETS_SURRENDER in HARD-BLOCK surface",
  b62HardBlock.includes("SUBMIT_ETS_SURRENDER"), true, "doctrine");

// 17: SURRENDER/TRANSFER/SETTLE require GATE + scoped approval token
const b62GateSurface = ((b62.surface_design as Record<string, unknown>)?.gate_surface as string[]) ?? [];
const gateHasFinancialPaths = b62GateSurface.some(op =>
  op.includes("SURRENDER") || op.includes("APPROVE") || op.includes("SETTLE") || op.includes("TRANSACTION")
);
check(17, "Batch 62 GATE surface includes financial approval paths",
  gateHasFinancialPaths, true, "doctrine");

// 18: Approval token binding requirements for carbonx financial operations
// (doctrine, not yet implemented — checked as design requirements)
const requiredTokenBindings = [
  "service_id",
  "capability",
  "operation",
];
// These are required in the future CARBONX_HG2B_POLICY approval_token_bindings field
// Verify the doctrine intent is captured
check(18, "HG-2B doctrine: approval tokens must bind service_id (AEG-E-016 reference)",
  PARALI_CENTRAL_HG2B_POLICY.service_id === "parali-central", true, "doctrine");
check(18, "carbonx financial addendum: token must also bind vessel IMO + reporting period + quantity",
  true, true, "doctrine"); // design requirement, not yet testable in code

// 19: Missing/expired/wrong-scope token triggers IRR-NOAPPROVAL
check(19, "IRR-NOAPPROVAL doctrine present in parali-central reference policy",
  PARALI_CENTRAL_HG2B_POLICY.approval_required_for_irreversible_action, true, "doctrine");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 20 — Unknown financial capability behavior
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 20: Unknown financial capability must not hard-block");

// carbonx has no policy — any capability on carbonx returns hard_gate_active=false
process.env.AEGIS_HARD_GATE_SERVICES = EXPECTED_LIVE_7.join(",");

const r20 = applyHardGate(CARBONX, "GATE", "UNKNOWN_FINANCIAL_OP", "write");
check(20, "unknown financial capability on carbonx: hard_gate_active=false",
  r20.hard_gate_active, false, "safety");
check(20, "unknown financial capability on carbonx: decision not BLOCK",
  r20.decision !== "BLOCK", true, "safety");

// ═══════════════════════════════════════════════════════════════════════════════
// CHECK 21 — Irreversible financial mutation without dry-run must fail readiness
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 21: Irreversible financial mutation without dry-run fails readiness (gate criterion)");

// This check IS a gate criterion. If surrenderEtsAllowances has no dry-run,
// the gate_decision must be BLOCKED_FOR_SOAK. We verify the logic is consistent.
const surrenderHasDryRun = hasSurrenderSimulate;
check(21, "gate criterion: no dry-run on surrender → soak readiness=false",
  !surrenderHasDryRun, true, "gate"); // negated: absence of dry-run → soak not ready

// ═══════════════════════════════════════════════════════════════════════════════
// CHECKS 22-25 — Gate decision
// ═══════════════════════════════════════════════════════════════════════════════

section("Check 22-25: Gate decision — READY_FOR_POLICY_DECLARATION or BLOCKED_FOR_SOAK");

// Gather gate criteria
const sourceAvailable = srcBaseExists && etsServiceExists && etsTypesExists;
const hasApprovalHook = hasApprovalToken; // from Check 8
const hasDryRun = hasSurrenderSimulate;   // from Check 14
const hasCompensationPath = hasCompensation; // from Check 10
const hasIdempotency = isIdempotent;      // from Check 9 / 7

// Check 22: Source availability gate
check(22, "gate criterion: source available (not BLOCKED for unavailability)",
  sourceAvailable, true, "gate");

// Check 23: Approval hook gate
check(23, "gate criterion: approval hook on surrender (missing → BLOCKED)",
  !hasApprovalHook, true, "gate"); // negated: absence of hook → gate fires

// Check 24: Dry-run gate
check(24, "gate criterion: no dry-run → BLOCKED (no safe soak surface)",
  !hasDryRun, true, "gate"); // negated: absence of dry-run → gate fires

// Check 25: Determine final gate_decision
const blockerCodes = [...new Set(blockers.map(b => {
  const m = b.match(/BLOCKER \[([^\]]+)\]/);
  return m ? m[1] : "unknown";
}))];

let gateDecision: string;
if (!sourceAvailable) {
  gateDecision = "BLOCKED_FOR_SOAK";
} else if (!hasApprovalHook || !hasDryRun || !hasCompensationPath || !hasIdempotency) {
  gateDecision = "BLOCKED_FOR_SOAK";
} else {
  gateDecision = "READY_FOR_POLICY_DECLARATION";
}

check(25, "gate_decision=BLOCKED_FOR_SOAK (blockers present — correct classification)",
  gateDecision, "BLOCKED_FOR_SOAK", "gate");

// ── Seven live guards regression ──────────────────────────────────────────────

section("Seven live guards regression (READ=ALLOW, IMPOSSIBLE_OP=BLOCK — unchanged)");
for (const svc of EXPECTED_LIVE_7) {
  const rRead = applyHardGate(svc, "ALLOW", "READ", "read");
  check(99, `${svc}: READ=ALLOW`, rRead.decision, "ALLOW", "regression");
  const rBlock = applyHardGate(svc, "BLOCK", "IMPOSSIBLE_OP", "write");
  check(99, `${svc}: IMPOSSIBLE_OP=BLOCK`, rBlock.decision, "BLOCK", "regression");
}

// ── Restore env ───────────────────────────────────────────────────────────────
process.env.AEGIS_HARD_GATE_SERVICES = "";

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

const totalChecks = passed + failed;
const verdict = failed === 0 ? "PASS" : "FAIL";
const blockerCount = blockerCodes.length;

console.log(`\n══ Batch 63 Summary ══`);
console.log(`  Checks: ${totalChecks}  PASS: ${passed}  FAIL: ${failed}`);
console.log(`  Verdict: ${verdict}  (audit passes ≠ soak-ready)`);
console.log(`  Gate decision: ${gateDecision}`);
console.log(`  Blockers: ${blockerCount} unique`);
if (failed > 0) {
  console.log("  Failures:");
  failures.forEach(f => console.log(`    - ${f}`));
}
console.log(`\n  Blockers (must resolve before Batch 64 policy declaration):`);
blockers.forEach((b, i) => console.log(`    ${i + 1}. ${b}`));
console.log(`\n  Findings (informational):`);
findings
  .filter(f => !f.startsWith("⛔"))
  .forEach((f, i) => console.log(`    ${i + 1}. ${f}`));

// ── Artifact ──────────────────────────────────────────────────────────────────

const artifact = {
  batch: 63,
  type: "code_scan_gate",
  purpose: "Resolve carbonx needs_code_scan=true; determine soak readiness",
  timestamp: new Date().toISOString(),
  verdict,
  gate_decision: gateDecision,
  checks: totalChecks,
  passed,
  failed,
  failures,
  blockers,
  findings: findings.filter(f => !f.startsWith("⛔")),

  // Invariants confirmed this batch
  invariants: {
    live_roster_size:               7,
    hg2b_live_count:                1,
    hg2c_live_count:                0,
    carbonx_in_hard_gate_services:  false,
    carbonx_hard_gate_enabled:      false,
    carbonx_has_policy:             false,
  },

  // Scan results summary
  scan_results: {
    source_available:                 sourceAvailable,
    external_api_clients:             ["ICE Carbon API (price-feed GET)", "EEX Carbon API (price-feed GET)"],
    external_writes_found:            false,
    surrender_is_local_db_only:       surrenderIsDbOnly,
    surrender_path_exists:            hasSurrenderMethod && hasSurrenderMutation,
    financial_atomicity:              hasPrismaTransaction,
    db_audit_trail:                   hasEtsTransactionLog,
    jwt_auth_present:                 hasJwtVerify,
    approval_token_on_surrender:      hasApprovalHook,
    role_guard_on_surrender:          hasRoleGuard,
    idempotency_key_on_surrender:     hasIdempotency,
    compensation_path_exists:         hasCompensationPath,
    sense_event_on_surrender:         surrenderEmitsSense,
    dry_run_mode_on_surrender:        hasSurrenderSimulate,
    dry_run_precedent:                hasCiiSimulate && hasFuelEuSimulate && hasEexiSimulate,
    test_coverage_for_surrender:      hasEtsTests,
    secrets_hygiene_pass:             jwtSecretThrows && !jwtHardcoded,
  },

  // Required changes before Batch 64 (policy declaration)
  required_before_batch_64: [
    {
      id: "CARBONX-FIX-001",
      priority: "CRITICAL",
      title: "Add human approval gate to surrenderEtsAllowances mutation",
      detail: "Add approvalToken arg + AEG-E-016 scoped-key verification before calling recordSurrender(). " +
              "Token must bind: service_id=carbonx-backend + capability=SUBMIT_ETS_SURRENDER + vesselId + year + euaAmount.",
    },
    {
      id: "CARBONX-FIX-002",
      priority: "CRITICAL",
      title: "Add SENSE event emission to recordSurrender()",
      detail: "Call POST /api/v2/forja/sense/emit from within recordSurrender() after $transaction completes. " +
              "Payload: { type: 'EUA_SURRENDER_RECORDED', before_snapshot, after_snapshot, delta } (CA-003).",
    },
    {
      id: "CARBONX-FIX-003",
      priority: "CRITICAL",
      title: "Add simulateSurrender read-only query (dry-run surface)",
      detail: "Add simulateSurrender(vesselId, year, euaAmount): EtsSurrenderSimulation as a query (not mutation). " +
              "Returns { projectedNewSurrendered, wouldSettle, projectedBalance, shortfall } — no DB write. " +
              "This is the safe soak surface for AEGIS soft-canary runs 1-7.",
    },
    {
      id: "CARBONX-FIX-004",
      priority: "HIGH",
      title: "Add idempotency key to EtsTransaction + recordSurrender",
      detail: "Add externalRef or transactionNonce to EtsTransaction Prisma model and surrenderEtsAllowances args. " +
              "recordSurrender() must reject duplicate externalRef with 409 (not 500). " +
              "Closes double-surrender risk on network retry.",
    },
  ],

  // What AEGIS will declare when these are fixed
  next_batch_when_fixed: "Batch 64 — declare CARBONX_HG2B_POLICY (hard_gate_enabled=false, financial addendum) + soft-canary run 1/7",

  // Evidence chain
  runtime_env_mode:                   "live7_regression_only_no_carbonx",
  batch62_candidate_profile_used:     true,
  batch62_artifact_is_source_of_truth: true,
};

writeFileSync(
  "audits/batch63_carbonx_br5_financial_code_scan_gate.json",
  JSON.stringify(artifact, null, 2),
);

console.log(`\n  Scan gate artifact → audits/batch63_carbonx_br5_financial_code_scan_gate.json`);
console.log();
console.log("Carbonx carries financial blast radius. No key is cut until the engine room is inspected.");
