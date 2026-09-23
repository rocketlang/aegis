// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AF-R-002 — reads the Anumati shadow ledger and answers ONE question: is there enough real
// evidence to decide whether the ANU-I-006 UNKNOWN branch (unresolvable SQL targets) can be
// promoted from observe to enforce? It does NOT decide for you — it cannot, because an
// UNKNOWN target's true class is by definition unknown. It gathers the real UNKNOWN-branch
// observations (excluding this project's own synthetic test sessions), dedupes them, and
// hands back the distinct commands that WOULD be blocked if you enforced — so a human can
// judge whether they are legitimate dev writes (a false positive) or things that should carry
// an explicit -d / the override token. Pure; the caller supplies the ledger lines.

export interface DistinctCmd { cmd: string; count: number; sessions: number }
export interface LedgerReview {
  realCount: number;                 // real (non-synthetic) ANU-I-006 UNKNOWN observations
  excludedSynthetic: number;         // observations dropped as this project's own test sessions
  distinct: DistinctCmd[];           // deduped commands, most frequent first
  firstTs: string | null;
  lastTs: string | null;
  spanDays: number;                  // days between first and last real observation
  minDays: number;
  recommendation: "KEEP_OBSERVING" | "READY_FOR_REVIEW";
  reason: string;
}

// Sessions this project created while building/verifying ANU-I-006 — never real usage.
const DEFAULT_SYNTHETIC = /^(sem-verify|multic|promo-verify|pv|s|test|test-staging|smoke)(-|$)/i;

export function reviewAnumatiLedger(
  lines: string[],
  opts: { now?: Date; minDays?: number; exclude?: RegExp } = {},
): LedgerReview {
  const minDays = opts.minDays ?? 7;
  const exclude = opts.exclude ?? DEFAULT_SYNTHETIC;

  const byCmd = new Map<string, { count: number; sessions: Set<string> }>();
  let realCount = 0;
  let excludedSynthetic = 0;
  let firstTs: string | null = null;
  let lastTs: string | null = null;

  for (const line of lines) {
    if (!line.trim()) continue;
    let rec: any;
    try { rec = JSON.parse(line); } catch { continue; }
    const hit = (rec.observations || []).some(
      (o: any) => o.id === "ANU-I-006" && o.verdict === "UNKNOWN",
    );
    if (!hit) continue;

    const session = String(rec.session ?? "");
    if (exclude.test(session)) { excludedSynthetic++; continue; }

    realCount++;
    const cmd = String(rec.target ?? "");
    const e = byCmd.get(cmd) ?? { count: 0, sessions: new Set<string>() };
    e.count++; e.sessions.add(session); byCmd.set(cmd, e);

    const ts = String(rec.ts ?? "");
    if (ts) { if (!firstTs || ts < firstTs) firstTs = ts; if (!lastTs || ts > lastTs) lastTs = ts; }
  }

  const distinct = [...byCmd.entries()]
    .map(([cmd, v]) => ({ cmd, count: v.count, sessions: v.sessions.size }))
    .sort((a, b) => b.count - a.count);

  const spanDays = firstTs && lastTs
    ? (new Date(lastTs).getTime() - new Date(firstTs).getTime()) / 86_400_000
    : 0;

  let recommendation: LedgerReview["recommendation"];
  let reason: string;
  if (realCount === 0) {
    recommendation = "KEEP_OBSERVING";
    reason = "no real UNKNOWN-branch observations yet (only synthetic test sessions) — cannot tell 'nobody hits it' from 'just started'";
  } else if (spanDays < minDays) {
    recommendation = "KEEP_OBSERVING";
    reason = `only ${spanDays.toFixed(1)} days of real observations (< ${minDays}) — too early to judge the false-positive rate`;
  } else {
    recommendation = "READY_FOR_REVIEW";
    reason = `${realCount} real observations across ${distinct.length} distinct command(s) over ${spanDays.toFixed(1)} days — review the list: any that is a legitimate dev write is a false positive that enforcing would block`;
  }

  return { realCount, excludedSynthetic, distinct, firstTs, lastTs, spanDays, minDays, recommendation, reason };
}

export function renderLedgerReview(r: LedgerReview): string {
  let out = "# ANU-I-006 UNKNOWN-branch — shadow-ledger review (AF-R-002)\n\n";
  out += `Real UNKNOWN observations: ${r.realCount} (excluded ${r.excludedSynthetic} synthetic test-session entries)\n`;
  out += `Window: ${r.firstTs ?? "—"} … ${r.lastTs ?? "—"} (${r.spanDays.toFixed(1)} days; need ≥ ${r.minDays})\n`;
  out += `**${r.recommendation}** — ${r.reason}\n\n`;
  if (r.distinct.length) {
    out += "## Distinct commands that WOULD be blocked if the UNKNOWN branch enforced\n";
    out += "(a legitimate dev write here = a false positive; one that should carry -d or the override = correctly gated)\n\n";
    out += "| count | sessions | command |\n|--:|--:|---|\n";
    for (const d of r.distinct) out += `| ${d.count} | ${d.sessions} | \`${d.cmd.slice(0, 100)}\` |\n`;
  } else {
    out += "No real commands hit the UNKNOWN branch in this window.\n";
  }
  return out;
}
