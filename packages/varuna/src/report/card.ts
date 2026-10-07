/**
 * Posture Report Card assembler.
 * @rule:P2-003 Report Card = captain's leverage back at shore
 * @rule:P2-005 Checkpoint score history before overwrite
 * @rule:CA-001 Large output escape: > 50KB → overflow_granthx_ref
 * @rule:CA-005 human_modified: false on AI-generated executive summary
 */

import { buildTriggeredEvidencePack } from '../evidence/pack.js';
import { runIACSScorer } from '../iacs/scorer.js';
import { notifyShip8xCapabilityActive } from '../integrations/ship8x.js';
import { computePostureScore } from '../posture/scorer.js';
import { runProtocolScorer } from '../protocol/scorer.js';
import { appendScoreHistory, getVessel } from '../store/vessel.js';

const AI_PROXY_URL = process.env['AI_PROXY_URL'] ?? 'http://localhost:4444';
const ANKRCLAW_URL = process.env['ANKRCLAW_URL'] ?? 'http://localhost:4150';
const GRANTHX_URL = process.env['GRANTHX_URL'] ?? 'http://localhost:4130';

// @rule:CA-001 Overflow threshold: 50 KB
const OVERFLOW_THRESHOLD_BYTES = 50 * 1024;

export interface ReportCard {
  vessel_id: string;
  generated_at: string;
  posture_score: number;
  posture_band: 'GREEN' | 'AMBER' | 'RED';
  iacs_summary: {
    pass: number;
    partial: number;
    fail: number;
    unknown: number;
    compliance_pct: number;
  };
  protocol_summary: { pass: number; partial: number; fail: number; unknown: number };
  top_findings: Array<{ cap_id?: string; rule_id: string; severity: string; description: string }>;
  evidence_triggered: number;
  executive_summary: string;
  human_modified: boolean;
  score_history_entries: number;
  overflow_granthx_ref?: string;
}

export async function assembleReportCard(
  vessel_id: string
): Promise<ReportCard | { overflow_granthx_ref: string; vessel_id: string }> {
  const vessel = getVessel(vessel_id);
  const now = Date.now();

  // @rule:P2-005 Checkpoint before overwrite
  if (vessel.postureScore !== null) {
    const prevIACS = vessel.iacs_audit;
    const prevPass = prevIACS.filter((r) => r.status === 'PASS').length;
    const prevFail = prevIACS.filter((r) => r.status === 'FAIL').length;
    appendScoreHistory(vessel, {
      posture_score: vessel.postureScore,
      posture_band:
        vessel.postureScore >= 80 ? 'GREEN' : vessel.postureScore >= 50 ? 'AMBER' : 'RED',
      iacs_pass: prevPass,
      iacs_fail: prevFail,
      checkpoint_at: now,
      trigger: 'report_card_generation',
    });
  }

  // Run all scorers
  const iacs = runIACSScorer(vessel);
  const protocol = runProtocolScorer(vessel);
  const evidence = buildTriggeredEvidencePack(vessel);

  // Compute posture score from shared scorer
  const { score: postureScore, band: posture_band } = computePostureScore(vessel);
  vessel.postureScore = postureScore;

  // Top findings: FAIL first, then PARTIAL, limited to 10
  const top_findings = [
    ...iacs.results
      .filter((r) => r.status === 'FAIL')
      .map((r) => ({
        cap_id: r.cap_id,
        rule_id: r.rule_id,
        severity: 'CRITICAL',
        description: r.evidence,
      })),
    ...iacs.results
      .filter((r) => r.status === 'PARTIAL')
      .map((r) => ({
        cap_id: r.cap_id,
        rule_id: r.rule_id,
        severity: 'WARN',
        description: r.evidence,
      })),
    ...protocol.results
      .filter((r) => r.status === 'FAIL')
      .map((r) => ({ rule_id: r.rule_id, severity: 'CRITICAL', description: r.detail })),
  ].slice(0, 10);

  // Executive summary via AI proxy
  const executive_summary = await generateExecutiveSummary(
    vessel_id,
    postureScore,
    posture_band,
    iacs,
    top_findings
  );

  const card: ReportCard = {
    vessel_id,
    generated_at: new Date(now).toISOString(),
    posture_score: postureScore,
    posture_band,
    iacs_summary: {
      pass: iacs.pass,
      partial: iacs.partial,
      fail: iacs.fail,
      unknown: iacs.unknown,
      compliance_pct: iacs.compliance_pct,
    },
    protocol_summary: {
      pass: protocol.pass,
      partial: protocol.partial,
      fail: protocol.fail,
      unknown: protocol.unknown,
    },
    top_findings,
    evidence_triggered: evidence.length,
    executive_summary,
    human_modified: false,
    score_history_entries: vessel.score_history.length,
  };

  // @rule:CA-001 Large output escape
  const approxBytes = JSON.stringify(card).length;
  if (approxBytes > OVERFLOW_THRESHOLD_BYTES) {
    const ref = `${GRANTHX_URL}/api/docs/ref/varuna-report-${vessel_id}-${now}`;
    return { overflow_granthx_ref: ref, vessel_id };
  }

  // @rule:P3-004 Notify Ship8x capability bit (fire-and-forget)
  const _logStub = {
    debug: (_ctx: object, _msg: string) => {},
    warn: (_ctx: object, _msg: string) => {},
  };
  notifyShip8xCapabilityActive(vessel_id, postureScore, _logStub).catch(() => {});

  return card;
}

async function generateExecutiveSummary(
  vessel_id: string,
  score: number,
  band: string,
  iacs: { pass: number; fail: number; compliance_pct: number },
  top_findings: Array<{ severity: string; description: string }>
): Promise<string> {
  const failCount = top_findings.filter((f) => f.severity === 'CRITICAL').length;
  const prompt = `You are a maritime cyber security expert writing for a ship captain. Summarize in 3 sentences:
Vessel: ${vessel_id}
Posture: ${score}/100 (${band})
IACS compliance: ${iacs.pass} pass, ${iacs.fail} fail, ${iacs.compliance_pct}% compliant
Top critical findings: ${
    failCount === 0
      ? 'None'
      : top_findings
          .filter((f) => f.severity === 'CRITICAL')
          .map((f) => f.description)
          .slice(0, 3)
          .join('; ')
  }
Write only the summary. No bullet points. Tone: clear, actionable, no jargon.`;

  try {
    const res = await fetch(`${AI_PROXY_URL}/api/ai/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt, strategy: 'free_first', maxTokens: 200 }),
    });
    if (!res.ok) throw new Error(`AI proxy ${res.status}`);
    const data = (await res.json()) as { content?: string };
    return data.content?.trim() ?? fallbackSummary(vessel_id, score, band);
  } catch {
    return fallbackSummary(vessel_id, score, band);
  }
}

function fallbackSummary(vessel_id: string, score: number, band: string): string {
  return `Vessel ${vessel_id} posture: ${score}/100 (${band}). Review top findings for immediate action. Consult DPA.`;
}

// ─── HTML Report for PDF generation ──────────────────────────────────────────
export function buildReportHTML(card: ReportCard): string {
  const bandColor =
    card.posture_band === 'GREEN'
      ? '#22c55e'
      : card.posture_band === 'AMBER'
        ? '#f59e0b'
        : '#ef4444';
  const findings = card.top_findings
    .map(
      (f) => `
    <tr>
      <td style="color:${f.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'};font-weight:bold">${f.severity}</td>
      <td>${f.rule_id}</td>
      <td>${f.description}</td>
    </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Varuna OT Posture Report — ${card.vessel_id}</title>
<style>
  body { font-family: Arial, sans-serif; padding: 32px; max-width: 800px; margin: 0 auto; color: #1a1a1a; }
  h1 { color: #1e3a5f; font-size: 22px; }
  .band { display: inline-block; padding: 4px 12px; border-radius: 4px; color: #fff; background: ${bandColor}; font-weight: bold; font-size: 18px; }
  .score { font-size: 48px; font-weight: bold; color: ${bandColor}; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th { background: #1e3a5f; color: #fff; padding: 8px; text-align: left; font-size: 13px; }
  td { padding: 6px 8px; border-bottom: 1px solid #e5e7eb; font-size: 12px; }
  .summary-box { background: #f0f7ff; border-left: 4px solid #1e3a5f; padding: 12px 16px; margin: 16px 0; font-style: italic; }
  .meta { color: #6b7280; font-size: 11px; margin-top: 24px; }
</style>
</head>
<body>
  <h1>Varuna Maritime OT Posture Report</h1>
  <p><strong>Vessel:</strong> ${card.vessel_id} &nbsp;&nbsp; <strong>Generated:</strong> ${card.generated_at}</p>
  <div class="score">${card.posture_score}<small style="font-size:24px;color:#6b7280">/100</small></div>
  <div class="band">${card.posture_band}</div>

  <div class="summary-box">${card.executive_summary}</div>

  <h2 style="font-size:16px;margin-top:24px">IACS UR E26/E27 Compliance</h2>
  <p>Pass: <strong>${card.iacs_summary.pass}</strong> &nbsp; Partial: <strong>${card.iacs_summary.partial}</strong> &nbsp; Fail: <strong>${card.iacs_summary.fail}</strong> &nbsp; Unknown: <strong>${card.iacs_summary.unknown}</strong> &nbsp; Compliance: <strong>${card.iacs_summary.compliance_pct}%</strong></p>

  <h2 style="font-size:16px;margin-top:16px">Top Findings</h2>
  ${
    card.top_findings.length === 0
      ? '<p>No findings.</p>'
      : `
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th></tr></thead>
    <tbody>${findings}</tbody>
  </table>`
  }

  <p class="meta">Generated by Varuna xShieldAI &bull; Evidence pack: ${card.evidence_triggered} triggered entries &bull; History checkpoints: ${card.score_history_entries}</p>
</body>
</html>`;
}

// ─── WhatsApp summary text ────────────────────────────────────────────────────
export function buildWhatsAppSummary(card: ReportCard): string {
  const emoji = card.posture_band === 'GREEN' ? '🟢' : card.posture_band === 'AMBER' ? '🟡' : '🔴';
  const fails = card.top_findings.filter((f) => f.severity === 'CRITICAL').length;
  return `${emoji} *Varuna OT Report — ${card.vessel_id}*
Score: ${card.posture_score}/100 (${card.posture_band})
IACS: ${card.iacs_summary.compliance_pct}% compliant
Critical findings: ${fails}
${card.executive_summary}
_Generated ${card.generated_at}_`;
}

export async function sendWhatsApp(to: string, text: string): Promise<boolean> {
  try {
    const res = await fetch(`${ANKRCLAW_URL}/api/notify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to, message: text, service: 'xshieldai-varuna', channel: 'whatsapp' }),
    });
    return res.ok;
  } catch {
    return false;
  }
}
