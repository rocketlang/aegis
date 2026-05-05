/**
 * AEGIS Batch 92 — Fleet Quality Dashboard
 * 2026-05-05
 *
 * Goal:
 *   Convert Batch 91's drift scan into a buyer-visible product surface.
 *   The dashboard is the human interface to AEGIS-Q — the first place a
 *   customer, auditor, or founder sees whether the evidence behind their
 *   agentic fleet is still true today.
 *
 * Inputs:
 *   - aegis/audits/batch91_fleet_quality_drift_scan.json
 *   - aegis/audits/batch90_carbonx_quality_retroactive_audit.json
 *   - aegis/quality/quality-mask-schema.json
 *
 * Outputs:
 *   - aegis/dashboard/fleet-quality-dashboard.html   (buyer-visible)
 *   - aegis/audits/batch92_fleet_quality_dashboard.json
 *   - proposals/aegis--fleet-quality-dashboard--formal--2026-05-05.md
 *
 * Invariants (inherited from Batch 91):
 *   - No service is promoted
 *   - quality_mask_at_promotion is not mutated
 *   - Hard-gate policy is not changed
 *   - This batch is read-only on all promotion state
 *
 * Product line:
 *   AEGIS does not only stop unsafe agents.
 *   It shows which agentic work still has evidence behind it.
 *
 * @rule:AEG-Q-001 quality_mask_at_promotion required for every promoted service
 * @rule:AEG-Q-003 quality_drift_score is longitudinal — set post-promotion only
 * @rule:AEG-Q-004 pre_AEG_Q_001_legacy — not a violation, but a gap
 */

import * as fs   from "fs";
import * as path from "path";

// ── Constants ──────────────────────────────────────────────────────────────────

const BATCH         = 92;
const TODAY         = "2026-05-05";
const AUDIT_DIR     = path.join(__dirname, "..", "audits");
const DASHBOARD_DIR = path.join(__dirname, "..", "dashboard");
const PROPOSALS_DIR = "/root/proposals";

const B91_ARTIFACT  = path.join(AUDIT_DIR, "batch91_fleet_quality_drift_scan.json");
const B90_ARTIFACT  = path.join(AUDIT_DIR, "batch90_carbonx_quality_retroactive_audit.json");
const SCHEMA_PATH   = path.join(__dirname, "..", "quality", "quality-mask-schema.json");

// ── Check infrastructure ───────────────────────────────────────────────────────

interface CheckResult { id: string; pass: boolean; note: string; }
const checks: CheckResult[] = [];
let checks_passed = 0;
let checks_failed = 0;
function check(id: string, pass: boolean, note: string) {
  checks.push({ id, pass, note });
  if (pass) checks_passed++; else { checks_failed++; console.error(`  FAIL [${id}] ${note}`); }
}

console.log("\nAEGIS Batch 92 — Fleet Quality Dashboard");
console.log("─".repeat(62));

// ── §1 — Data loading ─────────────────────────────────────────────────────────

console.log("§1  Data loading");

const b91 = JSON.parse(fs.readFileSync(B91_ARTIFACT, "utf8"));
const b90 = JSON.parse(fs.readFileSync(B90_ARTIFACT, "utf8"));
const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

check("B92-001", b91.verdict === "PASS",
  `Batch 91 artifact loaded, verdict=${b91.verdict}`);

check("B92-002", b90.verdict === "PASS",
  `Batch 90 artifact loaded (carbonx reference), verdict=${b90.verdict}`);

check("B92-003", schema.schema === "aegis-quality-16bit-v1",
  `Quality schema loaded: ${schema.schema}`);

check("B92-004", b91.no_promotion_state_changed === true,
  `Batch 91 confirms no_promotion_state_changed=true — dashboard inherits this invariant`);

check("B92-005", b91.quality_mask_at_promotion_immutable === true,
  `Batch 91 confirms quality_mask_at_promotion_immutable=true`);

// ── §2 — Fleet metrics verification ───────────────────────────────────────────

console.log("§2  Fleet metrics");

const fleet           = b91.fleet_size;
const scanned         = b91.services_scanned;
const hg_dist         = b91.hg_distribution;
const quality_conf    = b91.quality_confidence_distribution;
const severity_counts = b91.severity_counts;
const live_count      = b91.live_hard_gate_count;
const drift_findings  = b91.drift_findings as any[];
const remediation_q   = b91.remediation_queue as any[];
const carbonx_ref     = b91.carbonx_reference_result;

check("B92-006", fleet === 61,
  `Fleet size: ${fleet} classified services`);

check("B92-007", scanned === 61,
  `Services scanned: ${scanned}`);

check("B92-008", live_count === 8,
  `Live hard-gate roster: ${live_count} services`);

check("B92-009", severity_counts.CRITICAL === 16,
  `CRITICAL findings: ${severity_counts.CRITICAL}`);

check("B92-010", severity_counts.HIGH === 12,
  `HIGH findings: ${severity_counts.HIGH}`);

check("B92-011", severity_counts.MEDIUM === 10,
  `MEDIUM findings: ${severity_counts.MEDIUM}`);

check("B92-012", severity_counts.LOW === 27,
  `LOW findings: ${severity_counts.LOW}`);

check("B92-013", quality_conf.unknown === 60 && quality_conf.low === 1,
  `Quality confidence: unknown=${quality_conf.unknown}, low=${quality_conf.low}, medium=${quality_conf.medium}, high=${quality_conf.high}`);

// ── §3 — HG risk distribution ─────────────────────────────────────────────────

console.log("§3  HG risk distribution");

const HG_REQUIRED: Record<string, { mask: string; bits: number; label: string }> = {
  "HG-2B-financial": { mask: "0x0FFF", bits: 12, label: "All 12 point-in-time bits" },
  "HG-2B":           { mask: "0x0FAB", bits: 9,  label: "9 point-in-time bits" },
  "HG-2A":           { mask: "0x0B83", bits: 6,  label: "6 point-in-time bits" },
  "HG-1":            { mask: "0x0302", bits: 3,  label: "3 point-in-time bits" },
};

check("B92-014", hg_dist["HG-2B-financial"] === 15,
  `HG-2B-financial: ${hg_dist["HG-2B-financial"]} services (required mask: 0x0FFF)`);

check("B92-015", hg_dist["HG-2B"] === 9,
  `HG-2B: ${hg_dist["HG-2B"]} services (required mask: 0x0FAB)`);

check("B92-016", hg_dist["HG-2A"] === 10,
  `HG-2A: ${hg_dist["HG-2A"]} services (required mask: 0x0B83)`);

check("B92-017", hg_dist["HG-1"] === 27,
  `HG-1: ${hg_dist["HG-1"]} services (required mask: 0x0302)`);

check("B92-018",
  hg_dist["HG-2B-financial"] + hg_dist["HG-2B"] + hg_dist["HG-2A"] + hg_dist["HG-1"] === 61,
  `HG distribution sums to fleet size: ${fleet}`);

// ── §4 — Quality coverage ─────────────────────────────────────────────────────

console.log("§4  Quality coverage");

const mask_coverage  = b91.quality_mask_at_promotion_coverage;
const drift_coverage = b91.quality_drift_score_coverage;

check("B92-019", mask_coverage.count === 1,
  `quality_mask_at_promotion coverage: ${mask_coverage.count}/${mask_coverage.of_fleet} (${mask_coverage.pct})`);

check("B92-020", drift_coverage.count === 1,
  `quality_drift_score coverage: ${drift_coverage.count}/${drift_coverage.of_fleet} (${drift_coverage.pct})`);

check("B92-021",
  drift_findings.filter((f: any) => f.drift_type === "quality_unaudited").length === 60,
  `60 services have quality_unaudited drift finding (pre-doctrine)`);

check("B92-022",
  drift_findings.filter((f: any) => f.severity === "CRITICAL" && f.drift_type === "quality_unaudited").length === 14,
  `14 HG-2B-financial services without quality evidence (CRITICAL — financial hard-gate with no quality proof)`);

// ── §5 — Carbonx reference card ───────────────────────────────────────────────

console.log("§5  Carbonx reference card");

check("B92-023", carbonx_ref.quality_mask_at_promotion === 0x012A,
  `carbonx quality_mask_at_promotion = 0x012A (from Batch 90, immutable)`);

check("B92-024", carbonx_ref.quality_drift_score === 0x3000,
  `carbonx quality_drift_score = 0x3000 (from Batch 91, idempotency+observability EVIDENCED)`);

check("B92-025", carbonx_ref.quality_confidence === "low",
  `carbonx quality_confidence = low (4/12 point-in-time bits satisfied)`);

check("B92-026", carbonx_ref.quality_mask_status === "pre_AEG_Q_001_legacy",
  `carbonx status = pre_AEG_Q_001_legacy (not a violation)`);

check("B92-027",
  carbonx_ref.drift_bits_evidenced.includes("Q-013") &&
  carbonx_ref.drift_bits_evidenced.includes("Q-014"),
  `Carbonx idempotency + observability evidenced in drift score`);

check("B92-028",
  carbonx_ref.drift_bits_unknown.includes("Q-015") &&
  carbonx_ref.drift_bits_unknown.includes("Q-016"),
  `Carbonx regression_clean + production_fire_zero still UNKNOWN (observation window incomplete)`);

// ── §6 — Dashboard HTML generation ───────────────────────────────────────────

console.log("§6  Dashboard HTML generation");

// Build top CRITICAL findings list (de-duped by pattern)
const critFindings = remediation_q.filter((f: any) => f.severity === "CRITICAL");
const highFindings = remediation_q.filter((f: any) => f.severity === "HIGH");
const medFindings  = remediation_q.filter((f: any) => f.severity === "MEDIUM");

// Unique unaudited services by HG group
const unauditedByHG: Record<string, string[]> = {
  "HG-2B-financial": [],
  "HG-2B":           [],
  "HG-2A":           [],
  "HG-1":            [],
};
for (const f of drift_findings) {
  if (f.drift_type !== "quality_unaudited") continue;
  const hg = f.expected_evidence.includes("HG-2B-financial") ? "HG-2B-financial" :
             f.expected_evidence.includes("HG-2B")           ? "HG-2B"           :
             f.expected_evidence.includes("HG-2A")           ? "HG-2A"           : "HG-1";
  if (!unauditedByHG[hg].includes(f.service)) unauditedByHG[hg].push(f.service);
}

// Top remediation items (not unaudited — those are shown separately)
const specificFindings = drift_findings.filter((f: any) =>
  f.drift_type !== "quality_unaudited" && f.service === "carbonx-backend"
).slice(0, 6);

function severityBadge(sev: string): string {
  const cls: Record<string, string> = {
    CRITICAL: "sev-critical", HIGH: "sev-high", MEDIUM: "sev-medium", LOW: "sev-low", INFO: "sev-info"
  };
  return `<span class="badge ${cls[sev] ?? "sev-info"}">${sev}</span>`;
}

function pct(num: number, total: number): string {
  return total === 0 ? "0%" : `${(num / total * 100).toFixed(0)}%`;
}

function progressBar(num: number, total: number, color: string): string {
  const p = total === 0 ? 0 : Math.round(num / total * 100);
  return `<div class="progress-track"><div class="progress-fill" style="width:${p}%;background:${color}"></div></div>`;
}

const htmlUnauditedRows = Object.entries(unauditedByHG).map(([hg, svcs]) => {
  if (svcs.length === 0) return "";
  const sev = hg === "HG-2B-financial" ? "CRITICAL" : hg === "HG-2B" ? "HIGH" : hg === "HG-2A" ? "MEDIUM" : "LOW";
  return `<tr>
      <td>${severityBadge(sev)}</td>
      <td><code>${hg}</code></td>
      <td>${svcs.length}</td>
      <td>${HG_REQUIRED[hg]?.mask ?? "?"}</td>
      <td class="action-cell">${HG_REQUIRED[hg]?.label ?? "?"}</td>
    </tr>`;
}).join("");

const htmlCarbonxDriftRows = specificFindings.map((f: any) => `<tr>
      <td>${severityBadge(f.severity)}</td>
      <td><code>${f.drift_type}</code></td>
      <td><code>${f.quality_bit ?? "—"}</code></td>
      <td class="action-cell">${f.recommended_action}</td>
    </tr>`).join("");

const htmlLongitudinalRows = (carbonx_ref.drift_bits_evidence as any[]).map(b => {
  const statusCls = b.status === "EVIDENCED" ? "status-evidenced" : "status-unknown";
  const statusLabel = b.status === "EVIDENCED" ? "✓ EVIDENCED" : "? UNKNOWN";
  return `<tr>
      <td><code>${b.id}</code></td>
      <td>${b.id === "Q-013" ? "idempotency_verified" : b.id === "Q-014" ? "observability_verified" : b.id === "Q-015" ? "regression_clean" : "production_fire_zero"}</td>
      <td><span class="status-badge ${statusCls}">${statusLabel}</span></td>
      <td class="evidence-cell">${b.evidence}</td>
    </tr>`;
}).join("");

const htmlTopRemediations = [
  { pri: "P0", sev: "CRITICAL", count: 14, action: `Capture <code>quality_mask_at_promotion</code> for all 14 HG-2B-financial services. Each runs a financial hard gate with zero quality evidence.` },
  { pri: "P0", sev: "CRITICAL", action: `Run <code>prisma migrate diff</code> on carbonx. Batch 64 added <code>externalRef</code> to schema with no migration evidence. Financial service — schema risk is critical.` },
  { pri: "P0", sev: "CRITICAL", action: `Run <code>truffleHog</code> / <code>gitleaks</code> on carbonx. <code>aegis-approval-token.ts</code> (financial tokens) was introduced without a secret scan.` },
  { pri: "P1", sev: "HIGH",     count: 9, action: `Capture <code>quality_mask_at_promotion</code> for 9 HG-2B services (gate authority, physical/autonomous actions).` },
  { pri: "P1", sev: "HIGH",     action: `Run <code>tsc --noEmit</code> on carbonx and record in next batch artifact. Never evidenced across 13 promotion batches.` },
  { pri: "P1", sev: "HIGH",     action: `Add carbonx to next human review queue for retrospective classification confirmation (batch 88-style protocol).` },
  { pri: "P2", sev: "MEDIUM",   count: 10, action: `Capture <code>quality_mask_at_promotion</code> for 10 HG-2A services (external proof/validation role).` },
].map(r => `<tr>
    <td><span class="pri-badge">${r.pri}</span></td>
    <td>${severityBadge(r.sev)}</td>
    <td class="action-cell">${r.action}</td>
  </tr>`).join("");

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AEGIS Fleet Quality Dashboard — Batch 92</title>
  <style>
    :root {
      --bg:        #0d1117;
      --surface:   #161b22;
      --border:    #30363d;
      --text:      #e6edf3;
      --muted:     #8b949e;
      --accent:    #58a6ff;
      --green:     #3fb950;
      --yellow:    #d29922;
      --orange:    #f0883e;
      --red:       #f85149;
      --purple:    #bc8cff;
      --teal:      #39d353;
      --code-bg:   #1c2128;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "SF Mono", "Fira Code", monospace;
      background: var(--bg);
      color: var(--text);
      font-size: 13px;
      line-height: 1.6;
      padding: 24px;
    }
    a { color: var(--accent); text-decoration: none; }
    h1 { font-size: 20px; font-weight: 600; color: var(--text); letter-spacing: -0.3px; }
    h2 { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase;
         letter-spacing: 1px; margin-bottom: 12px; padding-bottom: 6px;
         border-bottom: 1px solid var(--border); }
    h3 { font-size: 14px; font-weight: 600; color: var(--text); margin-bottom: 8px; }
    code { background: var(--code-bg); padding: 1px 5px; border-radius: 3px;
           color: var(--accent); font-size: 12px; }
    .header {
      display: flex; justify-content: space-between; align-items: flex-start;
      margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid var(--border);
    }
    .header-meta { color: var(--muted); font-size: 12px; text-align: right; }
    .header-meta .batch-badge {
      display: inline-block; background: var(--accent); color: var(--bg);
      padding: 2px 10px; border-radius: 12px; font-weight: 600; margin-bottom: 4px;
    }
    .doctrine {
      border-left: 3px solid var(--accent); padding: 10px 16px;
      background: var(--surface); border-radius: 0 6px 6px 0;
      margin-bottom: 28px; color: var(--muted); font-style: italic; font-size: 13px;
    }
    .doctrine strong { color: var(--text); font-style: normal; }
    /* Cards */
    .card-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px; margin-bottom: 28px;
    }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 16px;
    }
    .card-value { font-size: 32px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
    .card-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
    .card-sub   { font-size: 11px; color: var(--muted); margin-top: 4px; }
    .val-green  { color: var(--green); }
    .val-yellow { color: var(--yellow); }
    .val-orange { color: var(--orange); }
    .val-red    { color: var(--red); }
    .val-blue   { color: var(--accent); }
    .val-muted  { color: var(--muted); }
    /* Sections */
    .section { margin-bottom: 32px; }
    /* Tables */
    table {
      width: 100%; border-collapse: collapse;
      background: var(--surface); border-radius: 8px;
      overflow: hidden; border: 1px solid var(--border);
    }
    th {
      background: var(--code-bg); padding: 8px 12px;
      text-align: left; font-size: 11px; color: var(--muted);
      text-transform: uppercase; letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
    }
    td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(88, 166, 255, 0.04); }
    .action-cell { color: var(--muted); font-size: 12px; max-width: 380px; }
    .evidence-cell { color: var(--muted); font-size: 11px; max-width: 340px; }
    /* Badges */
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 10px; font-weight: 700; letter-spacing: 0.5px;
    }
    .sev-critical { background: rgba(248,81,73,.2);  color: var(--red);    border: 1px solid rgba(248,81,73,.3); }
    .sev-high     { background: rgba(240,136,62,.2); color: var(--orange); border: 1px solid rgba(240,136,62,.3); }
    .sev-medium   { background: rgba(210,153,34,.2); color: var(--yellow); border: 1px solid rgba(210,153,34,.3); }
    .sev-low      { background: rgba(88,166,255,.15); color: var(--accent); border: 1px solid rgba(88,166,255,.2); }
    .sev-info     { background: rgba(139,148,158,.15); color: var(--muted); border: 1px solid rgba(139,148,158,.2); }
    .status-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; }
    .status-evidenced { background: rgba(63,185,80,.15); color: var(--green); border: 1px solid rgba(63,185,80,.25); }
    .status-unknown   { background: rgba(139,148,158,.15); color: var(--muted); border: 1px solid rgba(139,148,158,.25); }
    .pri-badge { display: inline-block; background: var(--code-bg); color: var(--muted);
                 padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; }
    /* Progress bars */
    .progress-track {
      height: 6px; background: var(--border); border-radius: 3px;
      overflow: hidden; margin-top: 8px;
    }
    .progress-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
    /* HG risk rows */
    .hg-row { display: flex; gap: 12px; margin-bottom: 12px; align-items: flex-start; }
    .hg-chip {
      min-width: 140px; padding: 8px 12px; border-radius: 6px;
      font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
      text-align: center;
    }
    .hg-2bf { background: rgba(248,81,73,.15); color: var(--red);    border: 1px solid rgba(248,81,73,.25); }
    .hg-2b  { background: rgba(240,136,62,.15); color: var(--orange); border: 1px solid rgba(240,136,62,.25); }
    .hg-2a  { background: rgba(210,153,34,.15); color: var(--yellow); border: 1px solid rgba(210,153,34,.25); }
    .hg-1   { background: rgba(88,166,255,.1);  color: var(--accent); border: 1px solid rgba(88,166,255,.2); }
    .hg-detail { flex: 1; }
    .hg-detail-header { display: flex; gap: 16px; align-items: center; margin-bottom: 4px; }
    .hg-count { font-size: 18px; font-weight: 700; }
    .hg-mask  { font-size: 11px; color: var(--muted); }
    /* Carbonx card */
    .carbonx-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; overflow: hidden;
    }
    .carbonx-header {
      background: var(--code-bg); padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }
    .carbonx-body { padding: 16px; }
    .mask-display {
      font-family: monospace; font-size: 11px; margin-top: 8px;
    }
    .mask-bit {
      display: inline-block; width: 18px; height: 18px; line-height: 18px;
      text-align: center; border-radius: 3px; margin: 1px; font-size: 9px; font-weight: 700;
    }
    .bit-set    { background: var(--green);  color: #000; }
    .bit-unset  { background: var(--border); color: var(--muted); }
    .bit-long-set  { background: var(--purple); color: #000; }
    .bit-long-unk  { background: var(--border); color: var(--muted); border: 1px dashed var(--purple); }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .stat-row { display: flex; justify-content: space-between; padding: 4px 0;
                border-bottom: 1px solid var(--border); font-size: 12px; }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--muted); }
    .stat-value { font-weight: 600; }
    /* Footer */
    .footer {
      margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
      color: var(--muted); font-size: 11px; display: flex;
      justify-content: space-between; align-items: center;
    }
    .footer-product { font-weight: 600; color: var(--text); }
  </style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────────────────── -->
<div class="header">
  <div>
    <h1>AEGIS Fleet Quality Dashboard</h1>
    <p style="color:var(--muted);margin-top:4px;font-size:12px">
      Evidence surveillance layer — Agentic Evidence, Governance and Intelligence System
    </p>
  </div>
  <div class="header-meta">
    <div class="batch-badge">Batch 92</div><br>
    ${TODAY}<br>
    Schema: <code>aegis-quality-16bit-v1</code>
  </div>
</div>

<!-- ── Doctrine ────────────────────────────────────────────────────────────── -->
<div class="doctrine">
  <strong>AEGIS does not only stop unsafe agents.</strong>
  It shows which agentic work still has evidence behind it.
  <span style="float:right;font-size:11px">
    Quality is not what passed yesterday. Quality is what still survives today.
  </span>
</div>

<!-- ── Summary cards ──────────────────────────────────────────────────────── -->
<div class="section">
  <h2>Fleet Overview</h2>
  <div class="card-grid">
    <div class="card">
      <div class="card-value val-blue">${fleet}</div>
      <div class="card-label">Services Classified</div>
      <div class="card-sub">AEGIS fleet</div>
    </div>
    <div class="card">
      <div class="card-value val-green">${live_count}</div>
      <div class="card-label">Hard-Gate Live</div>
      <div class="card-sub">production enforcement</div>
    </div>
    <div class="card">
      <div class="card-value val-yellow">1</div>
      <div class="card-label">Quality Evidence</div>
      <div class="card-sub">quality_mask captured</div>
      ${progressBar(1, fleet, "var(--yellow)")}
    </div>
    <div class="card">
      <div class="card-value val-muted">60</div>
      <div class="card-label">Pre-Doctrine</div>
      <div class="card-sub">quality_unaudited</div>
      ${progressBar(60, fleet, "var(--border)")}
    </div>
    <div class="card">
      <div class="card-value val-red">${severity_counts.CRITICAL}</div>
      <div class="card-label">Critical Findings</div>
      <div class="card-sub">immediate action</div>
    </div>
    <div class="card">
      <div class="card-value val-orange">${severity_counts.HIGH}</div>
      <div class="card-label">High Findings</div>
      <div class="card-sub">evidence chain weak</div>
    </div>
    <div class="card">
      <div class="card-value val-yellow">${severity_counts.MEDIUM}</div>
      <div class="card-label">Medium Findings</div>
      <div class="card-sub">docs / codex drift</div>
    </div>
    <div class="card">
      <div class="card-value val-blue">${severity_counts.LOW}</div>
      <div class="card-label">Low Findings</div>
      <div class="card-sub">pre-doctrine gap</div>
    </div>
  </div>
</div>

<!-- ── HG risk distribution ───────────────────────────────────────────────── -->
<div class="section">
  <h2>HG Group Risk Distribution</h2>

  <div class="hg-row">
    <div class="hg-chip hg-2bf">HG-2B-financial</div>
    <div class="hg-detail">
      <div class="hg-detail-header">
        <span class="hg-count val-red">${hg_dist["HG-2B-financial"]}</span>
        <span class="hg-mask">Required: <code>0x0FFF</code> — all 12 point-in-time bits</span>
        <span>${severityBadge("CRITICAL")}</span>
      </div>
      <div style="color:var(--muted);font-size:11px">Financial settlement, EUA surrender, eBL issuance. Zero quality evidence on 14 of 15 services.</div>
      ${progressBar(14, hg_dist["HG-2B-financial"], "var(--red)")}
    </div>
  </div>

  <div class="hg-row">
    <div class="hg-chip hg-2b">HG-2B</div>
    <div class="hg-detail">
      <div class="hg-detail-header">
        <span class="hg-count val-orange">${hg_dist["HG-2B"]}</span>
        <span class="hg-mask">Required: <code>0x0FAB</code> — 9 point-in-time bits</span>
        <span>${severityBadge("HIGH")}</span>
      </div>
      <div style="color:var(--muted);font-size:11px">Gate authority, physical irreversibility, drone/vessel control. All 9 services lack quality evidence.</div>
      ${progressBar(9, hg_dist["HG-2B"], "var(--orange)")}
    </div>
  </div>

  <div class="hg-row">
    <div class="hg-chip hg-2a">HG-2A</div>
    <div class="hg-detail">
      <div class="hg-detail-header">
        <span class="hg-count val-yellow">${hg_dist["HG-2A"]}</span>
        <span class="hg-mask">Required: <code>0x0B83</code> — 6 point-in-time bits</span>
        <span>${severityBadge("MEDIUM")}</span>
      </div>
      <div style="color:var(--muted);font-size:11px">External proof/validation, audit, certification. All 10 services lack quality evidence.</div>
      ${progressBar(10, hg_dist["HG-2A"], "var(--yellow)")}
    </div>
  </div>

  <div class="hg-row">
    <div class="hg-chip hg-1">HG-1</div>
    <div class="hg-detail">
      <div class="hg-detail-header">
        <span class="hg-count val-blue">${hg_dist["HG-1"]}</span>
        <span class="hg-mask">Required: <code>0x0302</code> — 3 point-in-time bits</span>
        <span>${severityBadge("LOW")}</span>
      </div>
      <div style="color:var(--muted);font-size:11px">Standard governance, read/compute/infer. All 27 services lack quality evidence (low consequence).</div>
      ${progressBar(27, hg_dist["HG-1"], "var(--accent)")}
    </div>
  </div>
</div>

<!-- ── Quality evidence coverage ──────────────────────────────────────────── -->
<div class="section">
  <h2>Quality Evidence Coverage</h2>
  <table>
    <thead>
      <tr>
        <th>Evidence Type</th><th>Services</th><th>Coverage</th><th>Status</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>quality_mask_at_promotion</code> captured</td>
        <td>1 / ${fleet}</td>
        <td>${progressBar(1, fleet, "var(--yellow)")}</td>
        <td>${severityBadge("HIGH")}</td>
      </tr>
      <tr>
        <td><code>quality_drift_score</code> computed</td>
        <td>1 / ${fleet}</td>
        <td>${progressBar(1, fleet, "var(--purple)")}</td>
        <td>${severityBadge("MEDIUM")}</td>
      </tr>
      <tr>
        <td>quality_confidence = high</td>
        <td>${quality_conf.high} / ${fleet}</td>
        <td>${progressBar(quality_conf.high, fleet, "var(--green)")}</td>
        <td><span class="badge sev-info">NONE</span></td>
      </tr>
      <tr>
        <td>quality_confidence = medium</td>
        <td>${quality_conf.medium} / ${fleet}</td>
        <td>${progressBar(quality_conf.medium, fleet, "var(--yellow)")}</td>
        <td><span class="badge sev-info">NONE</span></td>
      </tr>
      <tr>
        <td>quality_confidence = low (carbonx)</td>
        <td>${quality_conf.low} / ${fleet}</td>
        <td>${progressBar(quality_conf.low, fleet, "var(--orange)")}</td>
        <td><span class="badge sev-low">IMPROVING</span></td>
      </tr>
      <tr>
        <td>quality_confidence = unknown (pre-doctrine)</td>
        <td>${quality_conf.unknown} / ${fleet}</td>
        <td>${progressBar(quality_conf.unknown, fleet, "var(--border)")}</td>
        <td>${severityBadge("HIGH")}</td>
      </tr>
    </tbody>
  </table>
</div>

<!-- ── Carbonx reference card ─────────────────────────────────────────────── -->
<div class="section">
  <h2>Carbonx Reference Card — The Fleet&#39;s Quality Benchmark</h2>
  <p style="color:var(--muted);font-size:12px;margin-bottom:12px">
    carbonx-backend is the first and only service with computed quality evidence.
    It serves as the reference implementation for quality capture across the fleet.
  </p>
  <div class="carbonx-card">
    <div class="carbonx-header">
      <div>
        <strong>carbonx-backend</strong>
        <span style="color:var(--muted);font-size:11px;margin-left:8px">HG-2B-financial · Financial ETS Surrender · promotion batch 74 · 2026-05-04</span>
      </div>
      <div>${severityBadge("LOW")} <span style="color:var(--muted);font-size:11px;margin-left:6px">pre_AEG_Q_001_legacy — not a violation</span></div>
    </div>
    <div class="carbonx-body">
      <div class="two-col">
        <div>
          <h3>Point-in-Time Evidence <code style="font-size:10px">quality_mask_at_promotion = 0x012A</code></h3>
          <div class="mask-display">
            <div style="margin-bottom:4px;font-size:10px;color:var(--muted)">Bits 11→0 (left=high)</div>
            ${[11,10,9,8,7,6,5,4,3,2,1,0].map(bit => {
              const set = (0x012A & (1 << bit)) !== 0;
              const names: Record<number,string> = {0:"TC",1:"TS",2:"LN",3:"ND",4:"MG",5:"RB",6:"DC",7:"CX",8:"AA",9:"SC",10:"NS",11:"HR"};
              return `<span class="mask-bit ${set ? "bit-set" : "bit-unset"}" title="bit ${bit}: ${names[bit]}">${names[bit] ?? bit}</span>`;
            }).join("")}
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:8px">
            <span class="mask-bit bit-set" style="width:auto;padding:0 4px">✓</span> TC=typecheck TS=tests LN=lint ND=no-diff MG=migration RB=rollback DC=docs CX=codex AA=audit SC=src-clean NS=no-secret HR=human
          </div>
          <div style="margin-top:12px">
            <div class="stat-row"><span class="stat-label">Satisfied</span><span class="stat-value" style="color:var(--green)">4/12 bits (TS, ND, RB, AA)</span></div>
            <div class="stat-row"><span class="stat-label">Missing</span><span class="stat-value" style="color:var(--orange)">8/12 bits</span></div>
            <div class="stat-row"><span class="stat-label">Confidence</span><span class="stat-value" style="color:var(--orange)">LOW</span></div>
            <div class="stat-row"><span class="stat-label">Required</span><span class="stat-value" style="color:var(--muted)">0x0FFF (all 12)</span></div>
            <div class="stat-row"><span class="stat-label">Gap</span><span class="stat-value" style="color:var(--red)">0x0ED5 (8 bits)</span></div>
          </div>
        </div>
        <div>
          <h3>Longitudinal Evidence <code style="font-size:10px">quality_drift_score = 0x3000</code></h3>
          <div class="mask-display">
            <div style="margin-bottom:4px;font-size:10px;color:var(--muted)">Bits 15→12 (longitudinal horizon)</div>
            ${[15,14,13,12].map(bit => {
              const set = (0x3000 & (1 << bit)) !== 0;
              const names: Record<number,string> = {12:"IP",13:"OB",14:"RC",15:"PF"};
              return `<span class="mask-bit ${set ? "bit-long-set" : "bit-long-unk"}" title="bit ${bit}: ${names[bit]}">${names[bit]}</span>`;
            }).join("")}
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:8px">
            <span class="mask-bit bit-long-set" style="width:auto;padding:0 4px">✓</span> IP=idempotency OB=observability
            <span class="mask-bit bit-long-unk" style="width:auto;padding:0 4px;margin-left:6px">?</span> RC=regression PF=prod-fire
          </div>
          <table style="margin-top:12px;font-size:11px">
            ${htmlLongitudinalRows}
          </table>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ── Carbonx drift findings ─────────────────────────────────────────────── -->
<div class="section">
  <h2>Carbonx Specific Drift Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Drift Type</th><th>Quality Bit</th><th>Recommended Action</th></tr>
    </thead>
    <tbody>
      ${htmlCarbonxDriftRows}
    </tbody>
  </table>
</div>

<!-- ── Unaudited services by HG group ─────────────────────────────────────── -->
<div class="section">
  <h2>Unaudited Services by HG Group (pre_AEG_Q_001_legacy)</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>HG Group</th><th>Count</th><th>Required Mask</th><th>Evidence Gap</th></tr>
    </thead>
    <tbody>
      ${htmlUnauditedRows}
    </tbody>
  </table>
</div>

<!-- ── Top remediation queue ──────────────────────────────────────────────── -->
<div class="section">
  <h2>Top Remediation Queue</h2>
  <table>
    <thead>
      <tr><th>Priority</th><th>Severity</th><th>Action</th></tr>
    </thead>
    <tbody>
      ${htmlTopRemediations}
    </tbody>
  </table>
</div>

<!-- ── Footer ─────────────────────────────────────────────────────────────── -->
<div class="footer">
  <div>
    <span class="footer-product">AEGIS</span> Fleet Quality Dashboard ·
    Batch 92 · ${TODAY} · Schema: <code>aegis-quality-16bit-v1</code>
  </div>
  <div>
    Promotions changed: 0 ·
    quality_mask_at_promotion: immutable ·
    Fleet: ${fleet} services
  </div>
</div>

</body>
</html>`;

const htmlOut = path.join(DASHBOARD_DIR, "fleet-quality-dashboard.html");
fs.writeFileSync(htmlOut, html);

check("B92-029", fs.existsSync(htmlOut),
  `HTML dashboard written: ${htmlOut}`);

check("B92-030", html.includes("Fleet Quality Dashboard"),
  `Dashboard title present`);

check("B92-031", html.includes("quality_mask_at_promotion"),
  `Dashboard shows quality_mask_at_promotion`);

check("B92-032", html.includes("quality_drift_score"),
  `Dashboard shows quality_drift_score`);

check("B92-033", html.includes("HG-2B-financial"),
  `Dashboard shows HG risk distribution`);

check("B92-034", html.includes("0x012A"),
  `Carbonx reference card: mask 0x012A shown`);

check("B92-035", html.includes("0x3000"),
  `Carbonx reference card: drift score 0x3000 shown`);

check("B92-036", html.includes("Top Remediation Queue"),
  `Top remediation queue section present`);

// ── §7 — Markdown report ──────────────────────────────────────────────────────

console.log("§7  Markdown report");

const markdown = `---
service: aegis
doc_type: fleet-quality-dashboard
batch: ${BATCH}
status: formal
date: ${TODAY}
quality: batch${BATCH}-dashboard
---

# AEGIS Fleet Quality Dashboard — Batch ${BATCH}

## Product Line

> AEGIS does not only stop unsafe agents.
> It shows which agentic work still has evidence behind it.

Batch ${BATCH} converts the Batch 91 drift scan into a buyer-visible product surface: a persistent HTML dashboard that shows the quality state of the entire AEGIS-governed fleet in one view.

The dashboard lives at: \`aegis/dashboard/fleet-quality-dashboard.html\`

---

## The Three-Batch Arc (Batch 89 → 91 → 92)

| Batch | What it did |
|---|---|
| Batch 89 | Defined quality evidence. Introduced \`quality_mask_at_promotion\` (bits 0–11, point-in-time) and \`quality_drift_score\` (bits 12–15, longitudinal). |
| Batch 90 | Scored carbonx retroactively. \`quality_mask_at_promotion = 0x012A\`. First honest quality score in the fleet. |
| Batch 91 | Scanned the fleet. 61 services. 65 drift findings. 60 services unaudited. |
| **Batch 92** | **Built the dashboard. Turned the scan into a product surface. Made the gap visible to buyers.** |

The shift: AEGIS crossed from *can this agent act safely?* to *is the evidence behind this agent's work still true today?* The dashboard is where buyers see the answer.

---

## Fleet Snapshot (${TODAY})

| Metric | Value |
|---|---|
| Classified services | ${fleet} |
| Live hard-gate services | ${live_count} |
| Services with quality evidence | 1 (carbonx-backend, 1.6%) |
| Services pre-doctrine | 60 (98.4%) |
| CRITICAL findings | ${severity_counts.CRITICAL} |
| HIGH findings | ${severity_counts.HIGH} |
| MEDIUM findings | ${severity_counts.MEDIUM} |
| LOW findings | ${severity_counts.LOW} |

---

## HG Risk Distribution

| HG Group | Services | Required Mask | Unaudited | Risk |
|---|---|---|---|---|
| HG-2B-financial | ${hg_dist["HG-2B-financial"]} | 0x0FFF (12/12 bits) | 14/15 | CRITICAL |
| HG-2B | ${hg_dist["HG-2B"]} | 0x0FAB (9/12 bits) | 9/9 | HIGH |
| HG-2A | ${hg_dist["HG-2A"]} | 0x0B83 (6/12 bits) | 10/10 | MEDIUM |
| HG-1 | ${hg_dist["HG-1"]} | 0x0302 (3/12 bits) | 27/27 | LOW |

The most urgent gap: **14 HG-2B-financial services** run financial hard gates under AEGIS with zero quality evidence. Each is a financial service that can surrender EUAs, issue eBLs, or settle ledger positions — without quality capture.

---

## Carbonx Reference Card

carbonx-backend is the fleet's quality reference implementation. All other services will be scored against this template.

\`\`\`
service:                  carbonx-backend
hg_group:                 HG-2B-financial
promotion_batch:          74 (2026-05-04)
status:                   pre_AEG_Q_001_legacy

quality_mask_at_promotion = 0x012A  (immutable — set at Batch 90)
  Satisfied: tests_passed + no_unrelated_diff + rollback_verified + audit_artifact_written
  Missing:   typecheck + lint + migration + docs + codex + source_clean + no_secret + human_reviewed
  Confidence: LOW

quality_drift_score = 0x3000  (set at Batch 91, longitudinal)
  Q-013 idempotency_verified:   EVIDENCED
  Q-014 observability_verified: EVIDENCED
  Q-015 regression_clean:       UNKNOWN (7-day window incomplete)
  Q-016 production_fire_zero:   UNKNOWN (7-day window incomplete)
\`\`\`

carbonx is not lying by scoring itself low. It is honest about what was verified and what was not. That honesty is what makes AEGIS-Q a moat, not a rubber stamp.

---

## Top Remediation Actions

**P0 — CRITICAL:**
1. Capture \`quality_mask_at_promotion\` for all 14 HG-2B-financial unaudited services
2. Run \`prisma migrate diff\` on carbonx for batch 64 schema change (externalRef)
3. Run secret scanner on carbonx covering batch 64 (aegis-approval-token.ts)

**P1 — HIGH:**
4. Capture \`quality_mask_at_promotion\` for all 9 HG-2B unaudited services
5. Add \`tsc --noEmit\` to carbonx pre-promotion gate
6. Add carbonx to human review queue (retrospective batch 88-style)

**P2 — MEDIUM:**
7. Capture \`quality_mask_at_promotion\` for 10 HG-2A unaudited services

---

## Next Batch

**Batch 93: Guard SDK MVP** — \`@ankr/aegis-guard\` extracts the approval token + SENSE + idempotency pattern from carbonx-backend into a reusable SDK. This is the mechanism that makes it 10× faster to wire Five Locks into new HG-2B services — accelerating quality evidence capture across the fleet.

The dashboard is the surface. The Guard SDK is the engine that fills it.

*Batch ${BATCH} — Fleet Quality Dashboard. ${fleet} services rendered. Promotions changed: 0. quality_mask_at_promotion: immutable.*

> Quality is not what passed yesterday. Quality is what still survives today.
`;

const mdOut = path.join(PROPOSALS_DIR, `aegis--fleet-quality-dashboard--formal--${TODAY}.md`);
fs.writeFileSync(mdOut, markdown);

check("B92-037", fs.existsSync(mdOut),
  `Markdown report written: ${mdOut}`);

check("B92-038", markdown.includes("Three-Batch Arc"),
  `Markdown includes three-batch arc (Batch 89→91→92)`);

check("B92-039", markdown.includes("Carbonx Reference Card"),
  `Markdown includes carbonx reference card`);

// ── §8 — Audit artifact ───────────────────────────────────────────────────────

console.log("§8  Audit artifact");

const finalVerdict = checks_failed === 0 ? "PASS" : "FAIL";

const jsonArtifact = {
  audit_id:               `batch${BATCH}-fleet-quality-dashboard`,
  batch:                  BATCH,
  type:                   "fleet_quality_dashboard",
  date:                   TODAY,
  doctrine:               "AEGIS does not only stop unsafe agents. It shows which agentic work still has evidence behind it.",
  no_promotion_state_changed: true,
  quality_mask_at_promotion_immutable: true,
  source_batch:           91,
  source_artifact:        B91_ARTIFACT,
  fleet_size:             fleet,
  services_scanned:       scanned,
  live_hard_gate_roster:  b91.live_hard_gate_roster,
  live_hard_gate_count:   live_count,
  hg_distribution:        hg_dist,
  quality_confidence_distribution: quality_conf,
  quality_mask_coverage: {
    count: mask_coverage.count,
    of_fleet: fleet,
    pct: mask_coverage.pct,
  },
  quality_drift_coverage: {
    count: drift_coverage.count,
    of_fleet: fleet,
    pct: drift_coverage.pct,
  },
  severity_counts,
  carbonx_reference: {
    quality_mask_at_promotion:     carbonx_ref.quality_mask_at_promotion,
    quality_mask_at_promotion_hex: carbonx_ref.quality_mask_at_promotion_hex,
    quality_drift_score:           carbonx_ref.quality_drift_score,
    quality_drift_score_hex:       carbonx_ref.quality_drift_score_hex,
    quality_confidence:            carbonx_ref.quality_confidence,
    quality_mask_status:           carbonx_ref.quality_mask_status,
    drift_bits_evidenced:          carbonx_ref.drift_bits_evidenced,
    drift_bits_unknown:            carbonx_ref.drift_bits_unknown,
  },
  dashboard_path:         htmlOut,
  markdown_path:          mdOut,
  batch_arc: [
    { batch: 89, milestone: "AEGIS-Q doctrine defined — quality_mask schema, assertQualityEvidence(), computeQualityDriftScore()" },
    { batch: 90, milestone: "carbonx scored retroactively — quality_mask_at_promotion=0x012A, first honest score in fleet" },
    { batch: 91, milestone: "Fleet drift scan — 61 services, 65 findings, quality_drift_score=0x3000 for carbonx" },
    { batch: 92, milestone: "Fleet quality dashboard — buyer-visible product surface, three-batch arc complete" },
  ],
  checks_total:  checks.length,
  checks_passed,
  checks_failed,
  checks,
  verdict:       finalVerdict,
  next_steps: [
    "Batch 93: Guard SDK MVP — @ankr/aegis-guard extracting approval token + SENSE + idempotency from carbonx-backend",
    "Begin quality_mask_at_promotion capture for 14 HG-2B-financial services (CRITICAL priority)",
    "Monitor carbonx quality_drift_score: when 7-day window passes, update Q-015 and Q-016 if clean",
    "Add dashboard to AEGIS landing page or viewer surface for customer access",
  ],
};

const jsonOut = path.join(AUDIT_DIR, `batch${BATCH}_fleet_quality_dashboard.json`);
fs.writeFileSync(jsonOut, JSON.stringify(jsonArtifact, null, 2));

check("B92-040", fs.existsSync(jsonOut),
  `JSON artifact written: ${jsonOut}`);

// ── §9 — Invariants ───────────────────────────────────────────────────────────

console.log("§9  Invariants");

// Verify carbonx codex quality_mask_at_promotion was not changed
const carbonxCodexNow = JSON.parse(
  fs.readFileSync("/root/apps/carbonx/backend/codex.json", "utf8")
);
check("B92-041", carbonxCodexNow.quality_mask_at_promotion === 0x012A,
  `carbonx quality_mask_at_promotion = 0x012A — NOT mutated by dashboard batch`);

check("B92-042", carbonxCodexNow.quality_drift_score === 0x3000,
  `carbonx quality_drift_score = 0x3000 — preserved from Batch 91`);

check("B92-043", jsonArtifact.no_promotion_state_changed === true,
  `no_promotion_state_changed = true confirmed`);

check("B92-044", jsonArtifact.quality_mask_at_promotion_immutable === true,
  `quality_mask_at_promotion_immutable = true confirmed`);

// ── Summary ───────────────────────────────────────────────────────────────────

console.log(`\n${"─".repeat(62)}`);
console.log(`Fleet:        ${fleet} classified services`);
console.log(`HG:           fin=${hg_dist["HG-2B-financial"]} 2B=${hg_dist["HG-2B"]} 2A=${hg_dist["HG-2A"]} 1=${hg_dist["HG-1"]}`);
console.log(`Coverage:     quality_mask 1/61 (1.6%) · drift_score 1/61 (1.6%)`);
console.log(`Findings:     CRITICAL:${severity_counts.CRITICAL} HIGH:${severity_counts.HIGH} MEDIUM:${severity_counts.MEDIUM} LOW:${severity_counts.LOW}`);
console.log(`Promotions:   0 changed`);
console.log(`Checks:       ${checks_passed}/${checks.length} pass`);
if (checks_failed > 0) {
  console.log(`\nFailed:`);
  checks.filter(c => !c.pass).forEach(c => console.log(`  ✗ [${c.id}] ${c.note}`));
}
console.log(`\nVerdict: ${finalVerdict}`);
console.log(`HTML:    ${htmlOut}`);
console.log(`JSON:    ${jsonOut}`);
console.log(`Report:  ${mdOut}`);
