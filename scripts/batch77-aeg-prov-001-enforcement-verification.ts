/**
 * AEGIS Batch 77 — AEG-PROV-001 Enforcement Verification
 * 2026-05-05
 *
 * Proves that the provenance enforcement module works under all three
 * conditions a promotion script will encounter:
 *
 *   Case A: clean repo      → promotion_permitted=true, no waiver needed
 *   Case B: dirty repo      → ProvenanceError thrown, promotion blocked
 *   Case C: dirty + waiver  → promotion_permitted=true, waiver recorded
 *
 * Also verifies that the retroactive carbonx case (Batch 75A) would have
 * been caught by this enforcement — and what the correct waiver text
 * would have been.
 *
 * This is not a promotion. It is enforcement verification.
 *
 * @rule:AEG-PROV-001 no hard-gate promotion without committed source
 */

import { execSync } from "child_process";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "fs";
import { join } from "path";
import {
  assertCleanSourceTree,
  checkSourceTree,
  validateProvenanceArtifact,
  ProvenanceError,
} from "../src/enforcement/provenance.js";

const AUDITS  = "/root/aegis/audits";
const TMP_DIR = "/tmp/aegis-prov-test";

// ── Harness ───────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function check(group: number, label: string, actual: unknown, expected: unknown, tag: string): void {
  const ok = actual === expected;
  const pad = String(group).padStart(2, " ");
  if (ok) {
    passed++;
    console.log(`  ✓ [${pad}] ${label.padEnd(72)} actual=${JSON.stringify(actual)}`);
  } else {
    failed++;
    failures.push(`${tag}: [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
    console.log(`  ✗ [${pad}] FAIL ${label} — expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
  }
}

function section(title: string): void {
  console.log(`\n── ${title} ──`);
}

function git(cmd: string, cwd: string): void {
  execSync(cmd, { cwd, stdio: "pipe" });
}

// ── Test fixture: isolated git repos ──────────────────────────────────────────

function makeCleanRepo(path: string): void {
  if (existsSync(path)) rmSync(path, { recursive: true });
  mkdirSync(path, { recursive: true });
  git("git init", path);
  git("git config user.email 'test@aegis'", path);
  git("git config user.name 'AEGIS Test'", path);
  writeFileSync(join(path, "service.ts"), "export const x = 1;\n");
  git("git add service.ts", path);
  git("git commit -m 'initial'", path);
}

function makeDirtyRepo(path: string): void {
  makeCleanRepo(path);
  writeFileSync(join(path, "service.ts"), "export const x = 2; // uncommitted change\n");
}

// ── §1  Case A: clean repo (checks 1–4) ───────────────────────────────────────

section("§1 Case A — clean repo: promotion_permitted=true");

const cleanRepoPath = join(TMP_DIR, "clean-repo");
makeCleanRepo(cleanRepoPath);

const cleanResult = checkSourceTree(cleanRepoPath);
check(1, "clean repo: source_tree_clean=true",      cleanResult.source_tree_clean, true, "caseA");
check(2, "clean repo: uncommitted_files=[]",         cleanResult.uncommitted_files.length, 0, "caseA");
check(3, "clean repo: promotion_permitted=true",     cleanResult.promotion_permitted, true, "caseA");

const cleanAsserted = assertCleanSourceTree(cleanRepoPath);
check(4, "assertCleanSourceTree(clean): returns without throwing", cleanAsserted.promotion_permitted, true, "caseA");

// ── §2  Case B: dirty repo, no waiver — must throw (checks 5–9) ───────────────

section("§2 Case B — dirty repo, no waiver: ProvenanceError thrown");

const dirtyRepoPath = join(TMP_DIR, "dirty-repo");
makeDirtyRepo(dirtyRepoPath);

const dirtyStatus = checkSourceTree(dirtyRepoPath);
check(5, "dirty repo: source_tree_clean=false",       dirtyStatus.source_tree_clean, false, "caseB");
check(6, "dirty repo: uncommitted_files non-empty",   dirtyStatus.uncommitted_files.length > 0, true, "caseB");
check(7, "dirty repo: promotion_permitted=false",      dirtyStatus.promotion_permitted, false, "caseB");

let threwProvenanceError = false;
let thrownMessage = "";
try {
  assertCleanSourceTree(dirtyRepoPath);
} catch (e: unknown) {
  if (e instanceof ProvenanceError) {
    threwProvenanceError = true;
    thrownMessage = e.message;
  }
}
check(8, "dirty + no waiver: throws ProvenanceError", threwProvenanceError, true, "caseB");
check(9, "ProvenanceError message cites AEG-PROV-001",
  thrownMessage.includes("AEG-PROV-001"), true, "caseB");

// ── §3  Case C: dirty repo + explicit waiver — permitted (checks 10–15) ────────

section("§3 Case C — dirty repo + explicit waiver: promotion_permitted=true, waiver recorded");

const waiver = {
  reason: "known hotfix applied in working tree; will be committed as separate post-promotion fix",
  authorized_by: "founder",
  waiver_id: "waiver-batch77-test-001",
  acknowledged_risk: "audited per AEG-PROV-001 Batch 75A pattern; repair artifact will follow",
};

const waivedResult = assertCleanSourceTree(dirtyRepoPath, waiver);
check(10, "dirty + waiver: promotion_permitted=true",   waivedResult.promotion_permitted, true, "caseC");
check(11, "dirty + waiver: waiver_applied=true",        waivedResult.waiver_applied, true, "caseC");
check(12, "dirty + waiver: source_tree_clean=false",    waivedResult.source_tree_clean, false, "caseC");
check(13, "dirty + waiver: waiver.waiver_id recorded",  waivedResult.waiver?.waiver_id, waiver.waiver_id, "caseC");
check(14, "dirty + waiver: waiver.authorized_by=founder", waivedResult.waiver?.authorized_by, "founder", "caseC");

// Blank waiver fields must not be accepted
let rejectedBlankWaiver = false;
try {
  assertCleanSourceTree(dirtyRepoPath, {
    reason: "",         // blank — invalid
    authorized_by: "founder",
    waiver_id: "waiver-blank",
    acknowledged_risk: "acknowledged",
  });
} catch {
  rejectedBlankWaiver = true;
}
check(15, "blank waiver.reason: throws (not accepted)", rejectedBlankWaiver, true, "caseC");

// ── §4  validateProvenanceArtifact: artifact validation (checks 16–20) ─────────

section("§4 Artifact validation: validateProvenanceArtifact");

// Clean promotion artifact
const cleanArtifact = {
  provenance: {
    rule: "AEG-PROV-001",
    source_tree_clean: true,
    uncommitted_files: [],
    waiver: null,
    waiver_applied: false,
    promotion_permitted: true,
    checked_at: new Date().toISOString(),
  },
};
const validClean = validateProvenanceArtifact(cleanArtifact);
check(16, "clean artifact: valid=true",                validClean.valid, true, "validate");

// Waived promotion artifact
const waivedArtifact = {
  provenance: {
    rule: "AEG-PROV-001",
    source_tree_clean: false,
    uncommitted_files: ["service.ts M"],
    waiver: waiver,
    waiver_applied: true,
    promotion_permitted: true,
    checked_at: new Date().toISOString(),
  },
};
const validWaived = validateProvenanceArtifact(waivedArtifact);
check(17, "waived artifact: valid=true",               validWaived.valid, true, "validate");

// No provenance field at all — invalid
const noProv = validateProvenanceArtifact({});
check(18, "missing provenance field: valid=false",     noProv.valid, false, "validate");

// Dirty tree, no waiver — invalid (this is the carbonx Batch 74 scenario)
const carbonxBatch74Scenario = {
  provenance: {
    rule: "AEG-PROV-001",
    source_tree_clean: false,
    uncommitted_files: ["backend/src/schema/types/ets.ts M"],
    waiver: null,
    waiver_applied: false,
    promotion_permitted: false,
    checked_at: new Date().toISOString(),
  },
};
const invalidCarbonx = validateProvenanceArtifact(carbonxBatch74Scenario);
check(19, "dirty + no waiver in artifact: valid=false (carbonx Batch 74 scenario)",
  invalidCarbonx.valid, false, "validate");

// Correctly repaired: dirty but waiver_applied=true
const repairedCarbonx = {
  provenance: {
    rule: "AEG-PROV-001",
    source_tree_clean: false,
    uncommitted_files: ["backend/src/schema/types/ets.ts M"],
    waiver: {
      reason: "Batch 71 fixes in working tree; will commit as post-promotion repair",
      authorized_by: "founder",
      waiver_id: "waiver-batch74-carbonx-001",
      acknowledged_risk: "repair committed as e13094b; provenance documented in Batch 75A",
    },
    waiver_applied: true,
    promotion_permitted: true,
    checked_at: new Date().toISOString(),
  },
};
const repairedOk = validateProvenanceArtifact(repairedCarbonx);
check(20, "repaired carbonx scenario (waiver + waiver_applied=true): valid=true",
  repairedOk.valid, true, "validate");

// ── §5  Retroactive carbonx assessment (checks 21–24) ─────────────────────────

section("§5 Retroactive Batch 74 assessment");

// What would have happened to carbonx Batch 74 if AEG-PROV-001 had been enforced?

// The ets.ts changes were in the working tree — dirty
// assertCleanSourceTree without waiver would have thrown
// Result: carbonx promotion would have been BLOCKED until e13094b was committed

check(21, "retroactive: dirty tree without waiver → ProvenanceError (promotion blocked)",
  (() => {
    try {
      // Simulate: dirty repo, no waiver
      assertCleanSourceTree(dirtyRepoPath);
      return false; // should not reach here
    } catch (e) {
      return e instanceof ProvenanceError;
    }
  })(), true, "retroactive");

check(22, "retroactive: with waiver → permitted (what Batch 74 would have recorded)",
  (() => {
    const carbonxWaiver = {
      reason: "Batch 71 gap closure (GAP-1, GAP-2) in working tree; commit will follow post-promotion",
      authorized_by: "founder",
      waiver_id: "waiver-batch74-carbonx-hypothetical",
      acknowledged_risk: "same pattern as Batch 75A; repair artifact required within one batch",
    };
    const r = assertCleanSourceTree(dirtyRepoPath, carbonxWaiver);
    return r.promotion_permitted && r.waiver_applied;
  })(), true, "retroactive");

check(23, "retrospective: e13094b commit represents the correct resolution to the waiver",
  (() => {
    const carbonxRepo = "/root/apps/carbonx";
    const log = execSync("git log --format='%H' | head -20", { cwd: carbonxRepo, encoding: "utf-8" });
    return log.includes("e13094b");
  })(), true, "retroactive");

check(24, "AEG-PROV-001 rule text is in hard-gate-policy.ts",
  (() => {
    const { readFileSync } = require("fs");
    const policy = readFileSync("/root/aegis/src/enforcement/hard-gate-policy.ts", "utf-8") as string;
    return policy.includes("AEG-PROV-001");
  })(), true, "retroactive");

// ── Cleanup ───────────────────────────────────────────────────────────────────

rmSync(TMP_DIR, { recursive: true });

// ── Summary + artifact ────────────────────────────────────────────────────────

console.log("\n" + "─".repeat(72));
console.log(`\n  Passed: ${passed}/${passed + failed}`);
if (failed > 0) {
  console.log(`\n  FAILURES (${failed}):`);
  for (const f of failures) console.log(`    ${f}`);
}
console.log("");

const verdict = failed === 0 ? "PASS" : "FAIL";

writeFileSync(
  join(AUDITS, "batch77_aeg_prov_001_enforcement_verification.json"),
  JSON.stringify({
    audit_id: "batch77-aeg-prov-001-enforcement-verification",
    batch: 77,
    type: "enforcement_verification",
    rule: "AEG-PROV-001",
    date: "2026-05-05",
    checks_total: passed + failed,
    checks_passed: passed,
    checks_failed: failed,
    verdict,
    cases_verified: [
      "Case A: clean repo → promotion_permitted=true",
      "Case B: dirty repo, no waiver → ProvenanceError (promotion blocked)",
      "Case C: dirty repo + explicit waiver → promotion_permitted=true, waiver recorded",
      "Case D: artifact validation (clean, waived, missing, blocked, repaired)",
      "Retroactive: carbonx Batch 74 would have been blocked without waiver",
    ],
    enforcement_status: "ACTIVE — provenance.ts in src/enforcement/",
    template_status: "ACTIVE — promotion-template.ts calls assertCleanSourceTree in §0",
    doctrine: "Behavioral truth is not enough. Source-control truth must agree. " +
      "Audit truth must say exactly when they diverged and how they were repaired.",
  }, null, 2) + "\n",
);

console.log(`  Audit artifact: audits/batch77_aeg_prov_001_enforcement_verification.json`);
console.log(`  Verdict: ${verdict}\n`);

if (verdict === "PASS") {
  console.log("  AEG-PROV-001 is now enforced in code, not only in doctrine.\n");
}

if (verdict === "FAIL") process.exit(1);
