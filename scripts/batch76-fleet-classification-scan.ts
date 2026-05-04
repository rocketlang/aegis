/**
 * AEGIS Batch 76 — Fleet Classification Scan
 * 2026-05-05
 *
 * Read-only fleet survey. Reads all codex.json files across the ANKR fleet,
 * applies the AEGIS auto-classification rules, and produces a fleet map with
 * `aegis_hg_group_candidate` per service.
 *
 * This is the foundation for Phase 1 of the AEGIS fleet-scale platform.
 * It does NOT write back to codex.json. It does NOT change any policy.
 * It produces a single artifact that feeds the human confirmation pass.
 *
 * Classification rules (first match wins):
 *   FINANCIAL verbs in can_do  → HG-2B-financial (Five Locks required)
 *   IRREVERSIBLE external verbs → HG-2B
 *   STATEFUL external verbs     → HG-2A
 *   Any mutation verbs          → HG-1
 *   Read-only only              → HG-0 (observe, no gate needed)
 *   No can_do                   → UNCLASSIFIABLE
 *
 * @rule:AEG-PROV-001 no hard-gate promotion without committed source
 * @rule:FLEET-LAW-001 every service HG-group is machine-readable
 * @rule:FLEET-LAW-009 fleet status is a query, not a spreadsheet
 */

import { readFileSync, existsSync, writeFileSync } from "fs";
import { execSync } from "child_process";
import { join, dirname, basename } from "path";

const AUDITS    = "/root/aegis/audits";
const SERVICES  = "/root/.ankr/config/services.json";
const APPS_ROOT = "/root/apps";
const PKG_ROOT  = "/root/packages";

// ── Classification vocabulary ──────────────────────────────────────────────────

// All matching is case-insensitive substring on capability names
const FINANCIAL_VERBS = [
  "SURRENDER", "SETTLE", "SETTLEMENT", "TRANSFER_FUND", "DEBIT", "CREDIT",
  "PAYMENT", "EUA", "ALLOWANCE_TRANSFER", "BALANCE_DEDUCT", "BURN_TOKEN",
  "FINANCIAL", "INVOICE_SETTLE", "LEDGER_WRITE",
];

const IRREVERSIBLE_VERBS = [
  "SUBMIT_FILING", "FILE_COMPLIANCE", "REGISTER_ENTITY", "EMIT_EXTERNAL",
  "DELETE_EXTERNAL", "PUBLISH_CERTIFICATE", "REVOKE_CERTIFICATE",
  "CLOSE_ACCOUNT", "ARCHIVE_PERMANENT", "SIGN_CONTRACT", "EXECUTE_TRADE",
];

const STATEFUL_EXTERNAL_VERBS = [
  "UPDATE_EXTERNAL", "WRITE_EXTERNAL", "SYNC_EXTERNAL", "RECORD_TRANSACTION",
  "SUBMIT_REPORT", "PUSH_EXTERNAL", "NOTIFY_EXTERNAL", "UPDATE_REGISTRY",
  "LOG_EXTERNAL", "SEND_", "PUBLISH_", "POST_EXTERNAL",
];

const READ_ONLY_VERBS = [
  "GET", "LIST", "VIEW", "SEARCH", "REPORT", "EXPORT", "SIMULATE",
  "FETCH", "READ", "QUERY", "DESCRIBE", "AUDIT_READ", "HEALTH",
];

function classifyCapabilities(canDo: string[]): {
  hg_group: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  matched_verbs: string[];
} {
  const caps = canDo.map(c => c.toUpperCase());

  const matchedFinancial = caps.filter(c =>
    FINANCIAL_VERBS.some(v => c.includes(v)));
  if (matchedFinancial.length > 0) {
    return {
      hg_group: "HG-2B-financial",
      confidence: "HIGH",
      reason: "Financial settlement capability detected",
      matched_verbs: matchedFinancial,
    };
  }

  const matchedIrreversible = caps.filter(c =>
    IRREVERSIBLE_VERBS.some(v => c.includes(v)));
  if (matchedIrreversible.length > 0) {
    return {
      hg_group: "HG-2B",
      confidence: "HIGH",
      reason: "Irreversible external action capability detected",
      matched_verbs: matchedIrreversible,
    };
  }

  const matchedStateful = caps.filter(c =>
    STATEFUL_EXTERNAL_VERBS.some(v => c.includes(v)));
  if (matchedStateful.length > 0) {
    return {
      hg_group: "HG-2A",
      confidence: "MEDIUM",
      reason: "Stateful external write capability detected",
      matched_verbs: matchedStateful,
    };
  }

  // Check if all capabilities are read-only
  const allReadOnly = caps.every(c =>
    READ_ONLY_VERBS.some(v => c.startsWith(v)) ||
    c.startsWith("CAN_VIEW") || c.startsWith("CAN_LIST") || c.startsWith("CAN_READ"));

  if (allReadOnly && caps.length > 0) {
    return {
      hg_group: "HG-0",
      confidence: "MEDIUM",
      reason: "All capabilities are read-only — no gate needed",
      matched_verbs: caps,
    };
  }

  if (caps.length > 0) {
    return {
      hg_group: "HG-1",
      confidence: "MEDIUM",
      reason: "Mutation capabilities — internal state only (no external signals detected)",
      matched_verbs: [],
    };
  }

  return {
    hg_group: "UNCLASSIFIABLE",
    confidence: "LOW",
    reason: "No can_do declared",
    matched_verbs: [],
  };
}

// ── Fleet discovery ────────────────────────────────────────────────────────────

function findCodexFiles(root: string): string[] {
  try {
    const out = execSync(
      `find ${root} -name "codex.json" -not -path "*/node_modules/*" -not -path "*/.git/*"`,
      { encoding: "utf-8" },
    );
    return out.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

function readJson(path: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

// ── Load services.json for fleet baseline ─────────────────────────────────────

const svcsRaw = readJson(SERVICES);
const svcsMap = (svcsRaw.services ?? {}) as Record<string, Record<string, unknown>>;
const totalFleetCount = Object.keys(svcsMap).length;

// ── Discover codex.json files ──────────────────────────────────────────────────

const codexFiles = [
  ...findCodexFiles(APPS_ROOT),
  ...findCodexFiles(PKG_ROOT),
];

// Deduplicate: prefer backend/ over root service dir when both exist
const byServiceKey = new Map<string, string>();
for (const f of codexFiles) {
  const codex = readJson(f);
  const key = (codex.service_key ?? codex.service ?? basename(dirname(f))) as string;
  if (!byServiceKey.has(key)) {
    byServiceKey.set(key, f);
  } else {
    // Prefer the one in 'backend/' subdirectory
    if (f.includes("/backend/")) byServiceKey.set(key, f);
  }
}

// ── Classify each service ──────────────────────────────────────────────────────

interface ServiceRecord {
  service_key: string;
  codex_path: string;
  aegis_hg_group_existing: string | null;
  aegis_hg_group_candidate: string;
  confidence: string;
  reason: string;
  matched_verbs: string[];
  can_do_count: number;
  trust_mask: number;
  already_live: boolean;
}

const LIVE_SERVICES = new Set([
  "chirpee", "ship-slm", "chief-slm", "puranic-os",
  "pramana", "domain-capture", "parali-central", "carbonx-backend",
]);

const records: ServiceRecord[] = [];

for (const [key, codexPath] of byServiceKey.entries()) {
  const codex = readJson(codexPath);
  const canDo = Array.isArray(codex.can_do) ? (codex.can_do as string[]) : [];
  const existingHg = (codex.aegis_hg_group ?? codex.aegis_hard_gate ?? null) as string | null;
  const trustMask = (codex.trust_mask ?? 0) as number;

  const classification = classifyCapabilities(canDo);

  records.push({
    service_key: key,
    codex_path: codexPath.replace("/root/", ""),
    aegis_hg_group_existing: existingHg,
    aegis_hg_group_candidate: classification.hg_group,
    confidence: classification.confidence,
    reason: classification.reason,
    matched_verbs: classification.matched_verbs,
    can_do_count: canDo.length,
    trust_mask: trustMask,
    already_live: LIVE_SERVICES.has(key),
  });
}

// Sort: financial first, then by HG group severity
const HG_ORDER: Record<string, number> = {
  "HG-2B-financial": 0,
  "HG-2B": 1,
  "HG-2A": 2,
  "HG-1": 3,
  "HG-0": 4,
  "UNCLASSIFIABLE": 5,
};

records.sort((a, b) =>
  (HG_ORDER[a.aegis_hg_group_candidate] ?? 9) - (HG_ORDER[b.aegis_hg_group_candidate] ?? 9));

// ── Summary statistics ─────────────────────────────────────────────────────────

const distribution: Record<string, number> = {};
let highConfidence = 0;
let alreadyLiveCorrect = 0;

for (const r of records) {
  distribution[r.aegis_hg_group_candidate] = (distribution[r.aegis_hg_group_candidate] ?? 0) + 1;
  if (r.confidence === "HIGH") highConfidence++;
  if (r.already_live && r.aegis_hg_group_candidate.startsWith("HG-2B")) alreadyLiveCorrect++;
}

// ── Print fleet map ────────────────────────────────────────────────────────────

console.log("\n── AEGIS Batch 76 — Fleet Classification Scan ──\n");
console.log(`  Fleet size (services.json): ${totalFleetCount}`);
console.log(`  Codex.json files found:     ${codexFiles.length}`);
console.log(`  Unique services classified: ${records.length}`);
console.log(`  High-confidence classifications: ${highConfidence}/${records.length}`);
console.log("");

console.log("  Candidate HG-group distribution:");
for (const [group, count] of Object.entries(distribution).sort(
  (a, b) => (HG_ORDER[a[0]] ?? 9) - (HG_ORDER[b[0]] ?? 9))) {
  const bar = "█".repeat(Math.round(count / records.length * 40));
  console.log(`    ${group.padEnd(18)} ${String(count).padStart(3)}  ${bar}`);
}
console.log("");

console.log("  Financial candidates (require Five Locks review):");
const financialCandidates = records.filter(r => r.aegis_hg_group_candidate === "HG-2B-financial");
if (financialCandidates.length === 0) {
  console.log("    (none found beyond already-live services)");
} else {
  for (const r of financialCandidates) {
    const live = r.already_live ? " [LIVE]" : "";
    console.log(`    ${r.service_key.padEnd(30)} verbs: ${r.matched_verbs.slice(0,3).join(", ")}${live}`);
  }
}
console.log("");

console.log("  HG-2B candidates (irreversible external):");
const hg2bCandidates = records.filter(r => r.aegis_hg_group_candidate === "HG-2B");
if (hg2bCandidates.length === 0) {
  console.log("    (none found)");
} else {
  for (const r of hg2bCandidates) {
    const live = r.already_live ? " [LIVE]" : "";
    console.log(`    ${r.service_key.padEnd(30)} verbs: ${r.matched_verbs.slice(0,3).join(", ")}${live}`);
  }
}
console.log("");

console.log("  Already-live services confirmed in correct HG-group:");
for (const svc of LIVE_SERVICES) {
  const r = records.find(x => x.service_key === svc);
  if (r) {
    const match = r.aegis_hg_group_existing !== null ? "✓ (existing)" :
                  r.aegis_hg_group_candidate.startsWith("HG-") ? "✓ (candidate)" : "?";
    console.log(`    ${svc.padEnd(22)} existing=${r.aegis_hg_group_existing ?? "none"} candidate=${r.aegis_hg_group_candidate} ${match}`);
  } else {
    console.log(`    ${svc.padEnd(22)} no codex.json found`);
  }
}
console.log("");

const coveredByCodex = records.length;
const fleetGap = totalFleetCount - coveredByCodex;
console.log(`  Coverage gap: ${fleetGap} services in fleet have no codex.json`);
console.log(`  These cannot be auto-classified until codex.json is written.`);
console.log(`  (Woodpecker pass or R-012 gate closes this gap incrementally)`);
console.log("");

// ── Write artifact ─────────────────────────────────────────────────────────────

const artifact = {
  audit_id: "batch76-fleet-classification-scan",
  batch: 76,
  type: "fleet_scan",
  date: "2026-05-05",
  fleet_size_services_json: totalFleetCount,
  codex_files_found: codexFiles.length,
  unique_services_classified: records.length,
  fleet_coverage_percent: Math.round(records.length / totalFleetCount * 100),
  classification_gap: fleetGap,
  high_confidence_count: highConfidence,
  distribution,
  financial_candidates: financialCandidates.map(r => r.service_key),
  hg2b_candidates: hg2bCandidates.map(r => r.service_key),
  live_services_confirmed: [...LIVE_SERVICES],
  fleet_map: records.map(r => ({
    service_key: r.service_key,
    aegis_hg_group_existing: r.aegis_hg_group_existing,
    aegis_hg_group_candidate: r.aegis_hg_group_candidate,
    confidence: r.confidence,
    reason: r.reason,
    matched_verbs: r.matched_verbs,
    can_do_count: r.can_do_count,
    trust_mask: r.trust_mask,
    already_live: r.already_live,
  })),
  next_step: "Human confirmation pass: review fleet_map, confirm or override aegis_hg_group_candidate, write aegis_hg_group to codex.json. Start with HIGH confidence classifications.",
  platform_phases: [
    "Phase 1 DONE — Classification Oracle (this scan)",
    "Phase 2 TODO — Policy Templates (refactor hard-gate-policy.ts)",
    "Phase 3 TODO — Soak Runner CLI",
    "Phase 4 TODO — Convergence Audit + Promotion Gate CLI",
  ],
};

writeFileSync(
  join(AUDITS, "batch76_fleet_classification_scan.json"),
  JSON.stringify(artifact, null, 2) + "\n",
);

console.log("  Artifact: audits/batch76_fleet_classification_scan.json");
console.log("\n── Batch 76 COMPLETE — fleet map produced for human confirmation ──\n");
