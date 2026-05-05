/**
 * AEGIS Batch 87 — Fleet Codex v2 Enrichment Re-run
 * 2026-05-05
 *
 * Goal: Apply fleet-classifier-v2 vocabulary (from Batch 86) to all 61 codex
 *   files. Upgrades 19 services identified in the Batch 86 dry run; preserves
 *   Batch 85 human overrides; emits a confirmation queue for all v2-triggered
 *   side-effect upgrades.
 *
 * Non-negotiables:
 *   - No promotion (AEG-PROV-001 not triggered — classification ≠ promotion)
 *   - No downgrades (current hg_group is preserved if v2 gives a lower tier)
 *   - Batch 85 human overrides intact (human_override_applied=true → skip)
 *   - All v2-triggered upgrades marked requires_human_review=true
 *   - classification_source → "batch87_v2_machine_enrichment" on all machine blocks
 *   - machine_hg_group_before_v2 recorded on all upgraded blocks
 *   - carbonx-backend remains HG-2B-financial
 *
 * Idempotent: safe to re-run. postData pattern reads files after all mutations
 *   so checks are stable on first-run and re-run alike.
 *
 * Emits: audits/batch87_fleet_codex_v2_enrichment_queue.json
 *
 * Final line: The classifier learned more words. The human still decides consequence.
 *
 * @rule:AEG-PROV-001 not triggered — classification only, no promotion
 */

import { readFileSync, existsSync, writeFileSync } from "fs";
import { join } from "path";
import { glob } from "glob";

const AUDITS     = "/root/aegis/audits";
const VOCAB_FILE = "/root/aegis/vocabulary/fleet-classifier-v2.json";

// ── Load v2 vocabulary ────────────────────────────────────────────────────────

const vocab = JSON.parse(readFileSync(VOCAB_FILE, "utf-8")) as Record<string, unknown>;

const V2_FINANCIAL_VERBS        = vocab.financial_verbs       as string[];
const V2_IRREVERSIBLE_VERBS     = vocab.irreversible_verbs    as string[];
const V2_HG2B_GATE_VERBS        = vocab.hg2b_gate_verbs       as string[];
const V2_STATEFUL_EXTERNAL_VERBS= vocab.stateful_external_verbs as string[];
const V2_HG2A_PROOF_VERBS       = vocab.hg2a_proof_verbs      as string[];
const V2_READ_ONLY_VERBS        = vocab.read_only_verbs        as string[];

// ── Classifier functions (v2) ─────────────────────────────────────────────────

function verbMatchesV2(canDo: string[], verbList: string[]): boolean {
  return canDo.some(v => {
    const vUp = v.toUpperCase();
    return verbList.some(fv => vUp.includes(fv) || fv.includes(vUp));
  });
}

function isReadOnly(canDo: string[]): boolean {
  if (canDo.length === 0) return false;
  return canDo.every(v => V2_READ_ONLY_VERBS.some(rv => v.startsWith(rv)));
}

function classifyV2(canDo: string[]): {
  hg_group: string;
  confidence: string;
  authority_class: string;
  external_state_touch: boolean;
} {
  if (verbMatchesV2(canDo, V2_FINANCIAL_VERBS))
    return { hg_group: "HG-2B-financial", confidence: "high", authority_class: "financial", external_state_touch: true };
  if (verbMatchesV2(canDo, V2_IRREVERSIBLE_VERBS))
    return { hg_group: "HG-2B", confidence: "high", authority_class: "execution", external_state_touch: true };
  if (verbMatchesV2(canDo, V2_HG2B_GATE_VERBS))
    return { hg_group: "HG-2B", confidence: "medium", authority_class: "execution", external_state_touch: true };
  if (verbMatchesV2(canDo, V2_STATEFUL_EXTERNAL_VERBS))
    return { hg_group: "HG-2A", confidence: "medium", authority_class: "external_call", external_state_touch: true };
  if (!isReadOnly(canDo) && verbMatchesV2(canDo, V2_HG2A_PROOF_VERBS))
    return { hg_group: "HG-2A", confidence: "medium", authority_class: "external_call", external_state_touch: true };
  if (isReadOnly(canDo))
    return { hg_group: "HG-1", confidence: "medium", authority_class: "read_only", external_state_touch: false };
  return { hg_group: "HG-1", confidence: "low", authority_class: "execution", external_state_touch: false };
}

const HG_RANK: Record<string, number> = {
  "HG-1": 1, "HG-2A": 2, "HG-2B": 3, "HG-2B-financial": 4,
};

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

// ── §1  Vocabulary pre-flight (checks 1–4) ───────────────────────────────────

section("§1 Vocabulary pre-flight — v2 loaded from fleet-classifier-v2.json");

check(1, "Vocabulary schema = fleet-classifier-v2",
  vocab.schema, "fleet-classifier-v2", "vocab");

check(2, `HG2A_PROOF_VERBS: ${V2_HG2A_PROOF_VERBS.length} entries — RCA, VERIFY, ATTESTATION present`,
  V2_HG2A_PROOF_VERBS.includes("RCA") &&
  V2_HG2A_PROOF_VERBS.includes("VERIFICATION") &&
  V2_HG2A_PROOF_VERBS.includes("ATTESTATION"),
  true, "vocab");

check(3, `HG2B_GATE_VERBS: ${V2_HG2B_GATE_VERBS.length} entries — APPROVAL, APPROVE, SENSE, GATE present`,
  V2_HG2B_GATE_VERBS.includes("APPROVAL") &&
  V2_HG2B_GATE_VERBS.includes("APPROVE") &&
  V2_HG2B_GATE_VERBS.includes("SENSE") &&
  V2_HG2B_GATE_VERBS.includes("GATE"),
  true, "vocab");

// ── Load all codex files ──────────────────────────────────────────────────────

const codexPaths = [
  ...await (async () => { try { return await glob("/root/apps/*/codex.json"); } catch { return []; } })(),
  ...await (async () => { try { return await glob("/root/apps/*/*/codex.json"); } catch { return []; } })(),
  ...await (async () => { try { return await glob("/root/packages/*/codex.json"); } catch { return []; } })(),
];

check(4, "Fleet: 61 codex files discovered",
  codexPaths.length, 61, "vocab");

// ── §2  Batch 85 override preservation (checks 5–8) ──────────────────────────

section("§2 Batch 85 override preservation — skip human_override_applied=true");

// Read override state BEFORE any mutations
const OVERRIDE_PATHS = {
  pramana:        "/root/apps/pramana/codex.json",
  pramanaBackend: "/root/apps/pramana/backend/codex.json",
  paraliCentral:  "/root/apps/parali-central/backend/codex.json",
} as const;

function readCls(filePath: string): Record<string, unknown> {
  try {
    const d = JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>;
    return (d.aegis_classification as Record<string, unknown>) ?? {};
  } catch { return {}; }
}

const prePramana      = readCls(OVERRIDE_PATHS.pramana);
const prePramanaBack  = readCls(OVERRIDE_PATHS.pramanaBackend);
const preParali       = readCls(OVERRIDE_PATHS.paraliCentral);

check(5, "pramana/codex.json: human_override_applied=true (Batch 85 — must be skipped)",
  prePramana.human_override_applied, true, "overrides");

check(6, "pramana/backend/codex.json: human_override_applied=true (Batch 85 — must be skipped)",
  prePramanaBack.human_override_applied, true, "overrides");

check(7, "parali-central/backend/codex.json: human_override_applied=true (Batch 85 — must be skipped)",
  preParali.human_override_applied, true, "overrides");

check(8, "Batch 85 hg_group values preserved — pramana=HG-2A, pramana/backend=HG-2A, parali-central=HG-2B",
  prePramana.hg_group === "HG-2A" &&
  prePramanaBack.hg_group === "HG-2A" &&
  preParali.hg_group === "HG-2B",
  true, "overrides");

// ── Apply v2 enrichment ───────────────────────────────────────────────────────

interface Mutation {
  file:                        string;
  service:                     string;
  action:                      "preserved_human_override" | "upgraded" | "source_updated" | "skipped_no_block";
  before_hg:                   string;
  after_hg:                    string;
  v2_hg:                       string;
}

const mutations: Mutation[] = [];
const OVERRIDE_PATH_SET = new Set(Object.values(OVERRIDE_PATHS));

for (const filePath of codexPaths) {
  let data: Record<string, unknown>;
  try { data = JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>; }
  catch { continue; }

  const cls = data.aegis_classification as Record<string, unknown> | undefined;
  const serviceKey = (data.service as string) ||
    filePath.replace("/root/apps/", "").replace("/root/packages/", "").split("/codex.json")[0];

  if (!cls) {
    mutations.push({ file: filePath, service: serviceKey, action: "skipped_no_block",
      before_hg: "none", after_hg: "none", v2_hg: "unknown" });
    continue;
  }

  // Skip Batch 85 human overrides
  if (OVERRIDE_PATH_SET.has(filePath) || cls.human_override_applied === true) {
    mutations.push({ file: filePath, service: serviceKey, action: "preserved_human_override",
      before_hg: String(cls.hg_group), after_hg: String(cls.hg_group), v2_hg: String(cls.hg_group) });
    continue;
  }

  const canDo = Array.isArray(data.can_do) ? (data.can_do as string[]) : [];
  const v2    = classifyV2(canDo);
  const currentHg   = String(cls.hg_group ?? "HG-1");
  const currentRank = HG_RANK[currentHg] ?? 0;
  const v2Rank      = HG_RANK[v2.hg_group] ?? 0;

  if (v2Rank > currentRank) {
    // Upgrade: write new block preserving all existing fields
    const updatedCls: Record<string, unknown> = {
      ...cls,
      hg_group:                      v2.hg_group,
      authority_class:               v2.authority_class,
      external_state_touch:          v2.external_state_touch,
      classification_confidence:     v2.confidence,
      classification_source:         "batch87_v2_machine_enrichment",
      classification_batch:          87,
      classification_date:           "2026-05-05",
      requires_human_review:         true,
      machine_hg_group_before_v2:    currentHg,
      machine_confidence_before_v2:  cls.classification_confidence,
    };
    const updated = { ...data, aegis_classification: updatedCls };
    writeFileSync(filePath, JSON.stringify(updated, null, 2) + "\n");
    mutations.push({ file: filePath, service: serviceKey, action: "upgraded",
      before_hg: currentHg, after_hg: v2.hg_group, v2_hg: v2.hg_group });
  } else {
    // Same or higher (preserve current tier, just update source metadata)
    const updatedCls: Record<string, unknown> = {
      ...cls,
      classification_source: "batch87_v2_machine_enrichment",
      classification_batch:  87,
      classification_date:   "2026-05-05",
    };
    const updated = { ...data, aegis_classification: updatedCls };
    writeFileSync(filePath, JSON.stringify(updated, null, 2) + "\n");
    mutations.push({ file: filePath, service: serviceKey, action: "source_updated",
      before_hg: currentHg, after_hg: currentHg, v2_hg: v2.hg_group });
  }
}

// ── postData — re-read all files after mutations (idempotent check pattern) ───

interface PostRecord {
  file:                       string;
  service:                    string;
  hg_group:                   string;
  classification_source:      string;
  requires_human_review:      boolean;
  human_override_applied:     boolean;
  machine_hg_group_before_v2: string | null;
  classification_batch:       number;
}

const postData: PostRecord[] = [];
for (const filePath of codexPaths) {
  let data: Record<string, unknown>;
  try { data = JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>; }
  catch { continue; }

  const cls = (data.aegis_classification as Record<string, unknown>) ?? {};
  const serviceKey = (data.service as string) ||
    filePath.replace("/root/apps/", "").replace("/root/packages/", "").split("/codex.json")[0];

  postData.push({
    file:                       filePath,
    service:                    serviceKey,
    hg_group:                   String(cls.hg_group ?? "unknown"),
    classification_source:      String(cls.classification_source ?? ""),
    requires_human_review:      cls.requires_human_review === true,
    human_override_applied:     cls.human_override_applied === true,
    machine_hg_group_before_v2: cls.machine_hg_group_before_v2 as string | null ?? null,
    classification_batch:       Number(cls.classification_batch ?? 0),
  });
}

// Partition postData
const postByHgGroup: Record<string, number> = {};
for (const r of postData) {
  postByHgGroup[r.hg_group] = (postByHgGroup[r.hg_group] ?? 0) + 1;
}

const postUpgraded       = postData.filter(r => r.machine_hg_group_before_v2 !== null && !r.human_override_applied);
const postHumanOverrides = postData.filter(r => r.human_override_applied);
const postMachine        = postData.filter(r => !r.human_override_applied);
const postReviewReq      = postData.filter(r => r.requires_human_review && !r.human_override_applied);
const postBatch87        = postData.filter(r => r.classification_batch === 87);

// ── §3  v2 upgrades applied (checks 9–14) ────────────────────────────────────

section("§3 v2 upgrades committed — 19 side-effect services upgraded with human review flag");

console.log(`\n  Upgrades committed: ${postUpgraded.length}`);
if (postUpgraded.length > 0) {
  console.log(`  Upgraded services (with before→after):`);
  for (const r of postUpgraded) {
    const before = r.machine_hg_group_before_v2!;
    console.log(`    ${r.service.padEnd(45)} ${before} → ${r.hg_group}`);
  }
}

// powerpbox was identified as a side effect in batch86 dry run (v1=HG-1 from pure verb-match vs
// v2=HG-2B-financial). In practice, powerpbox was already HG-2B-financial via batch76 elevation
// before batch87 ran — so it appears as source_updated (no-op upgrade), not in postUpgraded.
// Actual upgrades = 18 (19 dry-run side effects − 1 already-elevated).
check(9, "18 v2 machine upgrades committed (19 dry-run side effects − 1 already-elevated via batch76)",
  postUpgraded.length, 18, "upgrades");

check(10, "All 18 upgraded services have requires_human_review=true",
  postUpgraded.every(r => r.requires_human_review), true, "upgrades");

check(11, "All 18 upgraded services have machine_hg_group_before_v2 recorded",
  postUpgraded.every(r => r.machine_hg_group_before_v2 !== null), true, "upgrades");

check(12, "All 18 upgraded services have classification_source=batch87_v2_machine_enrichment",
  postUpgraded.every(r => r.classification_source === "batch87_v2_machine_enrichment"),
  true, "upgrades");

// No downgrade check: compare v2 result vs current codex hg_group at time of processing
const postDowngrades = mutations.filter(m => {
  const beforeRank = HG_RANK[m.before_hg] ?? 0;
  const afterRank  = HG_RANK[m.after_hg] ?? 0;
  return afterRank < beforeRank;
});
check(13, "0 downgrades — no service's hg_group was decreased by v2 enrichment",
  postDowngrades.length, 0, "upgrades");

const carbonxPost = postData.find(r => r.file.includes("/carbonx/backend/"));
check(14, "carbonx-backend remains HG-2B-financial (unchanged by v2 enrichment)",
  carbonxPost?.hg_group, "HG-2B-financial", "upgrades");

// ── §4  Source metadata completeness (checks 15–17) ──────────────────────────

section("§4 Source metadata — all machine blocks updated to batch87");

check(15, `All ${postMachine.length} machine-written blocks have classification_source=batch87_v2_machine_enrichment`,
  postMachine.every(r => r.classification_source === "batch87_v2_machine_enrichment"),
  true, "source");

check(16, `All ${postMachine.length} machine-written blocks have classification_batch=87`,
  postMachine.every(r => r.classification_batch === 87),
  true, "source");

// Human overrides retain batch83/85 source (they were not touched)
const humanOverrideSourceOk = postHumanOverrides.every(
  r => r.classification_source === "batch83_machine_enrichment" && r.classification_batch === 83);
check(17, "Human override blocks retain original classification_source=batch83 (not overwritten)",
  humanOverrideSourceOk, true, "source");

// ── §5  Fleet distribution (checks 18–20) ────────────────────────────────────

section("§5 Fleet distribution — v2 upgrades shift the tier map");

console.log(`\n  Post-v2 HG distribution:`);
for (const [tier, count] of Object.entries(postByHgGroup).sort()) {
  console.log(`    ${tier.padEnd(18)} ${count}`);
}

// HG-2B-financial can only grow (v2 may add powerpbox; existing services never removed)
check(18, "HG-2B-financial count ≥ 15 (pre-batch87 count — financial tier only grows)",
  (postByHgGroup["HG-2B-financial"] ?? 0) >= 15, true, "distribution");

// HG-1 must shrink (19 services upgraded away from HG-1)
check(19, "HG-1 count decreased from pre-batch87 baseline of 40",
  (postByHgGroup["HG-1"] ?? 0) < 40, true, "distribution");

// Total fleet unchanged (61 files)
const postTotal = Object.values(postByHgGroup).reduce((a, b) => a + b, 0);
check(20, "Total fleet count = 61 (no files added or removed)",
  postTotal, 61, "distribution");

// ── §6  Confirmation queue (checks 21–24) ────────────────────────────────────

section("§6 Confirmation queue — upgraded services queued for human confirmation");

// Build queue entries for all upgraded services
const queueEntries = postUpgraded.map(r => ({
  service:                    r.service,
  file:                       r.file,
  v2_hg_group:                r.hg_group,
  machine_hg_before_v2:       r.machine_hg_group_before_v2,
  requires_human_review:      r.requires_human_review,
  classification_source:      r.classification_source,
  review_reason:              "v2_vocabulary_upgrade",
  review_note:                `v2 classifier upgraded from ${r.machine_hg_group_before_v2} → ${r.hg_group}. Confirm or override before next promotion gate.`,
}));

check(21, "Confirmation queue has 18 entries (19 dry-run side effects − powerpbox already-elevated)",
  queueEntries.length, 18, "queue");

check(22, "All queue entries have requires_human_review=true",
  queueEntries.every(e => e.requires_human_review), true, "queue");

check(23, "Preserved human overrides count = 3 (pramana, pramana/backend, parali-central)",
  postHumanOverrides.length, 3, "queue");

// Total review queue after batch87: 19 new upgrades + the 40 that batch83 flagged as low-conf
// but not yet reviewed (minus the 3 batch85 fixed). We now have batch87 upgrades marked review.
const totalReviewQueue = postReviewReq.length;
check(24, "Total requires_human_review in fleet reflects v2 upgrades (≥ 19)",
  totalReviewQueue >= 19, true, "queue");

// ── Summary + emit artifact ───────────────────────────────────────────────────

console.log("\n" + "─".repeat(72));
console.log(`\n  Passed: ${passed}/${passed + failed}`);
if (failed > 0) {
  console.log(`\n  FAILURES (${failed}):`);
  for (const f of failures) console.log(`    ${f}`);
}
console.log("");

const verdict = failed === 0 ? "PASS" : "FAIL";

writeFileSync(
  join(AUDITS, "batch87_fleet_codex_v2_enrichment_queue.json"),
  JSON.stringify({
    audit_id:      "batch87-fleet-codex-v2-enrichment",
    batch:         87,
    type:          "v2_enrichment_confirmation_queue",
    date:          "2026-05-05",
    checks_total:  passed + failed,
    checks_passed: passed,
    checks_failed: failed,
    verdict,
    vocabulary:    "fleet-classifier-v2 (batch86)",
    summary: {
      total_files:                       codexPaths.length,
      human_overrides_preserved:         postHumanOverrides.length,
      machine_upgrades_applied:          postUpgraded.length,
      source_updates_only:               postMachine.length - postUpgraded.length,
      downgrades:                        0,
      total_requires_review:             totalReviewQueue,
      batch86_dry_run_side_effects:      19,
      already_elevated_via_batch76:      1,
      already_elevated_service:          "powerpbox",
      already_elevated_note:             "powerpbox was HG-2B-financial in codex before batch87 ran (batch76 elevation). v2 dry run showed HG-1→HG-2B-financial but current codex was already at correct tier.",
    },
    hg_distribution_post_v2:   postByHgGroup,
    human_overrides_preserved: postHumanOverrides.map(r => ({
      service: r.service,
      file:    r.file,
      hg_group: r.hg_group,
      preserved_from_batch: 85,
    })),
    confirmation_queue:   queueEntries,
    invariants: [
      "No service promoted — classification does not constitute promotion",
      "No service downgraded — current hg_group preserved if v2 result is lower tier",
      "Batch 85 human overrides intact on pramana, pramana/backend, parali-central",
      "All v2-triggered upgrades marked requires_human_review=true",
      "machine_hg_group_before_v2 recorded for full traceability to batch83 state",
      "carbonx-backend remains HG-2B-financial",
      "classification_source updated to batch87_v2_machine_enrichment on all machine blocks",
    ],
    doctrine:
      "The classifier learned more words. The human still decides consequence.",
  }, null, 2) + "\n",
);

console.log(`  Artifact: audits/batch87_fleet_codex_v2_enrichment_queue.json`);
console.log(`  Verdict: ${verdict}\n`);

if (verdict === "PASS") {
  console.log(`  v2 enrichment applied: ${postUpgraded.length} upgrades committed, 0 downgrades.`);
  console.log(`  ${postHumanOverrides.length} Batch 85 human overrides preserved.`);
  console.log(`  Confirmation queue: ${queueEntries.length} services await human review.\n`);
  console.log("  The classifier learned more words. The human still decides consequence.\n");
}

if (verdict === "FAIL") process.exit(1);
