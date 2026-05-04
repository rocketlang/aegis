/**
 * AEGIS Batch 78 — AEG-PROV-001 Promotion Template Enforcement
 * 2026-05-05
 *
 * Makes source-control provenance a mandatory pre-promotion gate for every
 * future hard-gate promotion. Verifies that assertSourceControlProvenance()
 * — the multi-repo extension of AEG-PROV-001 — behaves correctly under all
 * four conditions a promotion script will encounter, and that the promotion
 * template now embeds a `source_control_provenance` block in every artifact.
 *
 * Note on batch numbering: user's spec called this "Batch 76" but
 * Batch 76 = fleet classification scan (2026-05-05) and
 * Batch 77 = single-repo enforcement verification (2026-05-05).
 * This is Batch 78 to preserve the chain. Artifact filename reflects this.
 *
 * Checks:
 *   §1  Doctrine presence (1–3)
 *   §2  Multi-repo helper: clean path (4–7)
 *   §3  Multi-repo helper: fail-closed path (8–12)
 *   §4  Multi-repo helper: waiver path (13–17)
 *   §5  Artifact structure (18–20)
 *   §6  Back-test against real repos (21–24)
 *
 * @rule:AEG-PROV-001 no hard-gate promotion without committed source in all repos
 */

import { execSync } from "child_process";
import { existsSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "fs";
import { join } from "path";
import {
  assertSourceControlProvenance,
  validateProvenanceArtifact,
  ProvenanceError,
  type SourceControlProvenance,
} from "../src/enforcement/provenance.js";

const AUDITS   = "/root/aegis/audits";
const TMP_DIR  = "/tmp/aegis-prov-b78";
const AEGIS    = "/root/aegis";
const CARBONX  = "/root/apps/carbonx";

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

function makeCleanRepo(path: string): void {
  if (existsSync(path)) rmSync(path, { recursive: true });
  mkdirSync(path, { recursive: true });
  git("git init", path);
  git("git config user.email 'test@aegis'", path);
  git("git config user.name 'AEGIS Test'", path);
  writeFileSync(join(path, "svc.ts"), "export const v = 1;\n");
  git("git add svc.ts", path);
  git("git commit -m 'initial'", path);
}

function makeDirtyRepo(path: string): void {
  makeCleanRepo(path);
  writeFileSync(join(path, "svc.ts"), "export const v = 2; // dirty\n");
}

// ── §1  Doctrine presence (checks 1–3) ────────────────────────────────────────

section("§1 Doctrine presence");

check(1, "AEG-PROV-001 annotation in hard-gate-policy.ts",
  readFileSync(join(AEGIS, "src/enforcement/hard-gate-policy.ts"), "utf-8")
    .includes("AEG-PROV-001"), true, "doctrine");

check(2, "assertSourceControlProvenance exported from provenance.ts",
  readFileSync(join(AEGIS, "src/enforcement/provenance.ts"), "utf-8")
    .includes("export function assertSourceControlProvenance"), true, "doctrine");

check(3, "promotion-template.ts uses assertSourceControlProvenance (not old assertCleanSourceTree)",
  (() => {
    const tpl = readFileSync(join(AEGIS, "scripts/promotion-template.ts"), "utf-8");
    return tpl.includes("assertSourceControlProvenance") &&
           !tpl.includes("assertCleanSourceTree(");
  })(), true, "doctrine");

// ── §2  Multi-repo helper: clean path (checks 4–7) ────────────────────────────

section("§2 Clean path — both repos clean");

const cleanA = join(TMP_DIR, "clean-a");
const cleanB = join(TMP_DIR, "clean-b");
makeCleanRepo(cleanA);
makeCleanRepo(cleanB);

let cleanScp: SourceControlProvenance | undefined;
try {
  cleanScp = assertSourceControlProvenance({
    repos: [
      { name: "repo-a", path: cleanA },
      { name: "repo-b", path: cleanB },
    ],
    batch: 78,
    service_id: "test-svc",
  });
} catch { /* handled below */ }

check(4, "clean repos: assertSourceControlProvenance returns without throwing",
  cleanScp !== undefined, true, "clean");
check(5, "clean repos: promotion_permitted=true",
  cleanScp?.promotion_permitted, true, "clean");
check(6, "clean repos: both HEAD hashes captured (non-empty)",
  (cleanScp?.repos ?? []).every(r => r.head.length === 40), true, "clean");
check(7, "clean repos: dirty_tree_waiver_used=false",
  cleanScp?.dirty_tree_waiver_used, false, "clean");

// ── §3  Multi-repo helper: fail-closed path (checks 8–12) ─────────────────────

section("§3 Fail-closed path — one dirty repo, no waiver");

const dirtyRepo = join(TMP_DIR, "dirty-repo");
makeDirtyRepo(dirtyRepo);

let blockedError: ProvenanceError | undefined;
try {
  assertSourceControlProvenance({
    repos: [
      { name: "clean", path: cleanA },
      { name: "dirty", path: dirtyRepo },  // dirty, no waiver
    ],
    batch: 78,
    service_id: "test-svc",
  });
} catch (e) {
  if (e instanceof ProvenanceError) blockedError = e;
}

check(8,  "dirty + no waiver: throws ProvenanceError",
  blockedError instanceof ProvenanceError, true, "failclosed");
check(9,  "ProvenanceError message cites AEG-PROV-001",
  (blockedError?.message ?? "").includes("AEG-PROV-001"), true, "failclosed");
check(10, "ProvenanceError lists uncommitted files",
  (blockedError?.uncommitted_files?.length ?? 0) > 0, true, "failclosed");
check(11, "promotion_permitted is NOT true when ProvenanceError thrown",
  blockedError !== undefined, true, "failclosed"); // throw = no result = blocked

// Verify failed artifact pattern: source_control_provenance_failed=true
const failedArtifact = {
  source_control_provenance_failed: true,
  source_control_provenance: {
    rule: "AEG-PROV-001",
    verified: false,
    promotion_permitted: false,
    source_control_provenance_failed: true,
    dirty_tree_waiver_used: false,
    repos: [],
    checked_at: new Date().toISOString(),
  },
};
const failedValidation = validateProvenanceArtifact(failedArtifact);
check(12, "failed artifact: validateProvenanceArtifact returns valid=false",
  failedValidation.valid, false, "failclosed");

// ── §4  Multi-repo helper: waiver path (checks 13–17) ─────────────────────────

section("§4 Waiver path — dirty repo with explicit RepoWaiver");

const waiver = {
  reason: "known fix in working tree; repair commit to follow within one batch",
  approver: "founder",
  expiry: "2026-05-12",
  waiver_id: "waiver-batch78-test-001",
  acknowledged_risk: "audit per Batch 75A pattern; source_control_provenance_failed=false because waiver is explicit",
};

let waivedScp: SourceControlProvenance | undefined;
try {
  waivedScp = assertSourceControlProvenance({
    repos: [
      { name: "clean", path: cleanA },
      { name: "dirty", path: dirtyRepo, waiver },
    ],
    batch: 78,
    service_id: "test-svc",
  });
} catch { /* handled below */ }

check(13, "dirty + waiver: promotion_permitted=true",
  waivedScp?.promotion_permitted, true, "waiver");
check(14, "dirty + waiver: dirty_tree_waiver_used=true",
  waivedScp?.dirty_tree_waiver_used, true, "waiver");
check(15, "dirty repo result: waiver_applied=true",
  (waivedScp?.repos ?? []).find(r => r.name === "dirty")?.waiver_applied, true, "waiver");
check(16, "waiver.expiry captured in repo result",
  (waivedScp?.repos ?? []).find(r => r.name === "dirty")?.waiver?.expiry, waiver.expiry, "waiver");
check(17, "waiver.approver captured in repo result",
  (waivedScp?.repos ?? []).find(r => r.name === "dirty")?.waiver?.approver, "founder", "waiver");

// ── §5  Artifact structure (checks 18–20) ─────────────────────────────────────

section("§5 Artifact structure validation");

// Build a well-formed clean promotion artifact
const cleanArtifact = {
  source_control_provenance: {
    rule: "AEG-PROV-001",
    verified: true,
    repos: cleanScp?.repos ?? [],
    dirty_tree_waiver_used: false,
    promotion_permitted: true,
    source_control_provenance_failed: false,
    checked_at: new Date().toISOString(),
  },
};
const cleanValid = validateProvenanceArtifact(cleanArtifact);
check(18, "clean promotion artifact: validateProvenanceArtifact returns valid=true",
  cleanValid.valid, true, "artifact");

// Build a well-formed waived promotion artifact
const waivedArtifact = {
  source_control_provenance: {
    rule: "AEG-PROV-001",
    verified: true,
    repos: waivedScp?.repos ?? [],
    dirty_tree_waiver_used: true,
    promotion_permitted: true,
    source_control_provenance_failed: false,
    checked_at: new Date().toISOString(),
  },
};
const waivedValid = validateProvenanceArtifact(waivedArtifact);
check(19, "waived promotion artifact: validateProvenanceArtifact returns valid=true",
  waivedValid.valid, true, "artifact");

check(20, "source_control_provenance block: rule=AEG-PROV-001 in clean scp object",
  cleanScp?.rule, "AEG-PROV-001", "artifact");

// ── §6  Back-test against real repos (checks 21–24) ───────────────────────────

section("§6 Back-test: real aegis + carbonx repos");

// Real repos may carry in-progress work (carbonx has pre-existing uncommitted
// files; aegis may have untracked batch scripts). The back-test verifies the
// invariants that matter:
//   [21] e13094b (the gap-closure commit) IS in carbonx history
//   [22] Both repos are reachable and HEAD hashes are captured
//   [23] required_commits check correctly validates specific SHAs
//   [24] waiver path works on a real dirty repo (carbonx)

// Check 21: e13094b must be in carbonx history — this is the repair commit
const e13094bInHistory = (() => {
  try {
    const log = execSync("git log --format='%H'", {
      cwd: CARBONX, encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"],
    });
    return log.split("\n").some(h => h.trim().startsWith("e13094b"));
  } catch { return false; }
})();
check(21, "e13094b (Batch 71 gap closure) is in carbonx git history",
  e13094bInHistory, true, "realrepo");

// Check 22: Both repos are reachable — HEAD hashes non-empty
const aegisHead = (() => {
  try {
    return execSync("git rev-parse HEAD", { cwd: AEGIS, encoding: "utf-8", stdio: ["pipe","pipe","pipe"] }).trim();
  } catch { return ""; }
})();
const carbonxHead = (() => {
  try {
    return execSync("git rev-parse HEAD", { cwd: CARBONX, encoding: "utf-8", stdio: ["pipe","pipe","pipe"] }).trim();
  } catch { return ""; }
})();
check(22, "real repos: aegis HEAD hash captured (40 chars)",
  aegisHead.length, 40, "realrepo");
check(23, "real repos: carbonx HEAD hash captured (40 chars)",
  carbonxHead.length, 40, "realrepo");

// Check 24: assertSourceControlProvenance with required_commits validates e13094b
// Carbonx may be dirty — use waiver since this is a test, not a gate
let scpWithRequiredCommit: SourceControlProvenance | undefined;
try {
  scpWithRequiredCommit = assertSourceControlProvenance({
    repos: [
      {
        name: "carbonx",
        path: CARBONX,
        required_commits: ["e13094b"],
        // carbonx may have in-progress uncommitted work — waive for back-test
        waiver: {
          reason: "back-test only: carbonx has pre-existing uncommitted work unrelated to this enforcement check",
          approver: "batch78-test",
          expiry: "2026-05-06",
          waiver_id: "waiver-batch78-carbonx-backtest",
          acknowledged_risk: "this is a test execution, not a real promotion; e13094b in history is the invariant",
        },
      },
    ],
    batch: "78-backtest",
    service_id: "carbonx-backend",
  });
} catch { /* handled below */ }
check(24, "required_commits: e13094b verified in carbonx history via assertSourceControlProvenance",
  scpWithRequiredCommit?.repos.find(r => r.name === "carbonx")?.required_commits_present,
  true, "realrepo");

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
  join(AUDITS, "batch78_aeg_prov_001_promotion_template_enforcement.json"),
  JSON.stringify({
    audit_id: "batch78-aeg-prov-001-promotion-template-enforcement",
    batch: 78,
    type: "enforcement_verification",
    rule: "AEG-PROV-001",
    date: "2026-05-05",
    checks_total: passed + failed,
    checks_passed: passed,
    checks_failed: failed,
    verdict,
    note: "User spec called this Batch 76; renumbered to 78 to preserve chain after Batch 76 (fleet scan) and Batch 77 (single-repo verification).",
    cases_verified: [
      "§1 Doctrine: AEG-PROV-001 in policy + provenance.ts + promotion-template.ts",
      "§2 Clean path: two clean repos → promotion_permitted=true, HEAD captured",
      "§3 Fail-closed: one dirty repo no waiver → ProvenanceError, promotion blocked",
      "§4 Waiver path: dirty repo + RepoWaiver → permitted, expiry+approver recorded",
      "§5 Artifact structure: validateProvenanceArtifact handles multi-repo format",
      "§6 Real repos: e13094b in carbonx history; required_commits verification works",
    ],
    real_repo_heads: {
      aegis:   aegisHead,
      carbonx: carbonxHead,
    },
    doctrine: "No future key is turned unless the git ledger signs the order.",
  }, null, 2) + "\n",
);

console.log("  Artifact: audits/batch78_aeg_prov_001_promotion_template_enforcement.json");
console.log(`  Verdict: ${verdict}\n`);

if (verdict === "PASS") {
  console.log("  No future key is turned unless the git ledger signs the order.\n");
}

if (verdict === "FAIL") process.exit(1);
