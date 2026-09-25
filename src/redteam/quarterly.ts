// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AF-T-404 — the quarterly answerability report (AF-R-012: answerability LEADS).
//
// The recurring deliverable of the story "can you answer what your agents touched?".
// One artifact per period composing what already exists — nothing new is measured here:
//   answerability — the touched aggregation over the period (the LEAD, per AF-R-012)
//   rehearsal     — the incident chain walked against the live gates (AF-T-711)
//   posture       — destructive-gate score (AF-T-202: ASR/FPR blend, ceiling separate)
//   shield/exfil  — the detector faces (AF-T-301/706)
//   ci            — pipeline publish declarations (AF-T-710)
// Plus a DIFF against the previous period's report: what improved, what regressed, what
// is new. The diff is the sentence a subscriber actually reads.
//
// Same honesty spine as everything else: stage labels ride through, ceilings ride through,
// the digest is tamper-evidence via re-hash (not a signature — Ed25519 signing is the
// hosted EE leg, AF-T-403), and an empty answerability section means nothing LEDGERED.

import { createHash } from "crypto";
import { stable } from "./report";
import type { RedteamReport, PostureScore } from "./runner";
import type { ShieldFaceReport } from "./shield-face";
import type { ExfilFaceReport } from "./exfil-face";
import type { ChainRehearsalReport } from "./chain-rehearsal";
import type { CiAuditReport } from "../kavach/ci-audit";
import type { TouchedReport } from "../kavach/touched";

export const QUARTERLY_SCHEMA = "ankr-agent-firewall-quarterly-v1";

export interface QuarterlyReport {
  schema: string;
  ts: string;
  period: { since: string; until: string };
  /** the LEAD (AF-R-012): what our agents touched, aggregated */
  answerability: {
    principals: number;
    enforced_refusals: number;
    observations_by_invariant: Record<string, number>;
    provenance_rows: number;
    tripwire_tells: number;
    unparseable_lines: number;
  };
  rehearsal: { all_pass: boolean; steps: number; failed: string[]; digest: string };
  posture: { score: number; grade: string; catchableAsr: number; fpr: number; catchableGaps: number; ceilingGaps: number };
  shield: { injectionMisses: number; robustnessGaps: number; persistenceMisses: number; variantGaps: number; falsePositives: number };
  exfil: { credentialMisses: number; variantGaps: number; scenarioMismatches: number; falsePositives: number };
  ci: { workflows: number; undeclaredPublishes: number; thirdPartyActions: number };
  note: string;
  digest: string;
}

export interface QuarterlyParts {
  touched: TouchedReport;
  rehearsal: ChainRehearsalReport;
  redteam: RedteamReport;
  posture: PostureScore;
  shield: ShieldFaceReport;
  exfil: ExfilFaceReport;
  ci: CiAuditReport;
}

export function composeQuarterly(p: QuarterlyParts, ts = new Date().toISOString()): QuarterlyReport {
  const obs: Record<string, number> = {};
  let refusals = 0, provenance = 0, tells = 0;
  for (const pr of p.touched.principals) {
    refusals += pr.anumati.enforced_refusals;
    provenance += pr.anumati.provenance.length;
    tells += pr.tripwire.hits;
    for (const [k, v] of Object.entries(pr.anumati.observations)) obs[k] = (obs[k] ?? 0) + v;
  }

  const body: Omit<QuarterlyReport, "digest"> = {
    schema: QUARTERLY_SCHEMA,
    ts,
    period: { since: p.touched.since, until: p.touched.until },
    answerability: {
      principals: p.touched.principals.length,
      enforced_refusals: refusals,
      observations_by_invariant: obs,
      provenance_rows: provenance,
      tripwire_tells: tells,
      unparseable_lines: p.touched.totals.unparseable,
    },
    rehearsal: {
      all_pass: p.rehearsal.all_pass,
      steps: p.rehearsal.steps.length,
      failed: p.rehearsal.steps.filter((s) => !s.pass).map((s) => s.id),
      digest: p.rehearsal.digest,
    },
    posture: {
      score: p.posture.score, grade: p.posture.grade,
      catchableAsr: p.redteam.catchableAsr, fpr: p.redteam.fpr,
      catchableGaps: p.redteam.catchableGaps.length, ceilingGaps: p.redteam.ceilingGaps.length,
    },
    shield: {
      injectionMisses: p.shield.injection.misses.length,
      robustnessGaps: p.shield.injection.robustnessGaps.length,
      persistenceMisses: p.shield.persistence.misses.length,
      variantGaps: p.shield.persistence.variantGaps.length,
      falsePositives: p.shield.injection.falsePositives.length + p.shield.persistence.falsePositives.length,
    },
    exfil: {
      credentialMisses: p.exfil.credential.misses.length,
      variantGaps: p.exfil.credential.variantGaps.length,
      scenarioMismatches: p.exfil.exfil.mismatches.length,
      falsePositives: p.exfil.credential.falsePositives.length,
    },
    ci: {
      workflows: p.ci.audits.length,
      undeclaredPublishes: p.ci.undeclaredPublishes,
      thirdPartyActions: p.ci.audits.reduce((s, a) => s + a.thirdPartyActions.length, 0),
    },
    note:
      "Answerability leads (AF-R-012): the period section says what was ledgered, and an empty section " +
      "means nothing LEDGERED, never 'nothing happened' (tool-route + tripwire visibility; PRA-004 same-host " +
      "ceiling). Stage labels ride through from the rehearsal pack — 'alerted in shadow' is not 'blocked'. " +
      "Digest is tamper-evidence via re-hash; cryptographic signing is the hosted tier.",
  };
  return { ...body, digest: createHash("sha256").update(stable(body)).digest("hex") };
}

export interface QuarterlyDiff {
  score_delta: number;
  new_catchable_gaps: number;
  rehearsal_regressions: string[];
  rehearsal_recoveries: string[];
  undeclared_publish_delta: number;
  observations_delta: number;
  headline: string[];
}

/** The sentence a subscriber reads: prev vs current, regressions first. Pure. */
export function diffQuarterly(prev: QuarterlyReport, cur: QuarterlyReport): QuarterlyDiff {
  const prevFailed = new Set(prev.rehearsal.failed);
  const curFailed = new Set(cur.rehearsal.failed);
  const obsTotal = (r: QuarterlyReport) => Object.values(r.answerability.observations_by_invariant).reduce((s, n) => s + n, 0);

  const d: QuarterlyDiff = {
    score_delta: cur.posture.score - prev.posture.score,
    new_catchable_gaps: Math.max(0, cur.posture.catchableGaps - prev.posture.catchableGaps),
    rehearsal_regressions: [...curFailed].filter((s) => !prevFailed.has(s)),
    rehearsal_recoveries: [...prevFailed].filter((s) => !curFailed.has(s)),
    undeclared_publish_delta: cur.ci.undeclaredPublishes - prev.ci.undeclaredPublishes,
    observations_delta: obsTotal(cur) - obsTotal(prev),
    headline: [],
  };

  if (d.rehearsal_regressions.length) d.headline.push(`REGRESSION: rehearsal step(s) now failing: ${d.rehearsal_regressions.join(", ")}`);
  if (d.new_catchable_gaps > 0) d.headline.push(`REGRESSION: ${d.new_catchable_gaps} new catchable gap(s) in the destructive gate`);
  if (d.undeclared_publish_delta > 0) d.headline.push(`REGRESSION: ${d.undeclared_publish_delta} new undeclared CI publish step(s)`);
  if (d.score_delta !== 0) d.headline.push(`posture ${d.score_delta > 0 ? "+" : ""}${d.score_delta} (${prev.posture.score} → ${cur.posture.score})`);
  if (d.rehearsal_recoveries.length) d.headline.push(`recovered: ${d.rehearsal_recoveries.join(", ")}`);
  if (d.observations_delta !== 0) d.headline.push(`shadow observations ${d.observations_delta > 0 ? "+" : ""}${d.observations_delta} — promotion evidence ${d.observations_delta > 0 ? "accumulating" : "declining"}`);
  if (!d.headline.length) d.headline.push("no change against the previous period");
  return d;
}

export function renderQuarterly(r: QuarterlyReport, diff?: QuarterlyDiff): string {
  const a = r.answerability;
  let out = `# Agent Firewall — answerability report, ${r.period.since.slice(0, 10)} → ${r.period.until.slice(0, 10)}\n\n`;
  if (diff) {
    out += `## Against the previous period\n${diff.headline.map((h) => `- ${h}`).join("\n")}\n\n`;
  }
  out += `## What our agents touched (the lead)\n`;
  out += `- ${a.principals} principal(s) left ledger evidence · ${a.enforced_refusals} enforced refusal(s) · ${a.tripwire_tells} tripwire tell(s)\n`;
  out += `- shadow observations by invariant: ${Object.entries(a.observations_by_invariant).map(([k, v]) => `${k}×${v}`).join(", ") || "none"}\n`;
  out += `- outward-write provenance rows: ${a.provenance_rows}\n\n`;
  out += `## The incident chain, rehearsed\n- ${r.rehearsal.all_pass ? `ALL ${r.rehearsal.steps} steps refused or alerted` : `FAILED: ${r.rehearsal.failed.join(", ")}`} (pack digest ${r.rehearsal.digest.slice(0, 16)}…)\n\n`;
  out += `## Gate posture\n- destructive gate: ${r.posture.score}/100 (${r.posture.grade}) — catchable-ASR ${(r.posture.catchableAsr * 100).toFixed(1)}%, FPR ${(r.posture.fpr * 100).toFixed(1)}%; ceiling exposure ${r.posture.ceilingGaps} (reported separately, never folded in)\n`;
  out += `- shield: ${r.shield.injectionMisses + r.shield.persistenceMisses} miss(es), ${r.shield.robustnessGaps + r.shield.variantGaps} variant gap(s), ${r.shield.falsePositives} over-flag(s)\n`;
  out += `- exfil: ${r.exfil.credentialMisses} credential miss(es), ${r.exfil.scenarioMismatches} scenario mismatch(es), ${r.exfil.falsePositives} over-flag(s) (surfaced, not hidden)\n`;
  out += `- CI: ${r.ci.undeclaredPublishes} undeclared publish(es) across ${r.ci.workflows} workflow(s); ${r.ci.thirdPartyActions} third-party action(s) = scoped null\n\n`;
  out += `${r.note}\n\ndigest ${r.digest.slice(0, 16)}…\n`;
  return out;
}
