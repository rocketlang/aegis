// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The red-team runner. It evaluates every applicable (exemplar × variant) and every control
// through the SAME pure decision function the live hook uses (destructiveVerdict), and sorts
// the misses into two piles that mean different things:
//
//   catchableGaps — a dangerous variant a regex denylist COULD catch, but this gate did not.
//                   A regression to fix by widening a rule (or by the shared normalizer).
//   ceilingGaps   — a dangerous variant no regex denylist can catch, because the dangerous
//                   text is split across shell tokens or supplied at runtime and is simply
//                   not in the command string. Not a bug in the rules; the ceiling of
//                   denylisting, and the reason the semantic gate (Anumati, which resolves
//                   the real target database) is the control that actually closes them.
//   falsePositives — a benign control the gate refused. Over-blocking is a real failure too.
//
// Ground truth is the human label on the exemplar, never the gate (RT-001). Nothing is ever
// executed (RT-002). CI gates on catchableGaps and falsePositives; ceilingGaps are reported.

import { destructiveVerdict, type DestructiveRules } from "../kavach/destructive-verdict";
import { isSqlCapableInvocation, isProvablyReadOnly } from "../kavach/sql-capability";
import { EXEMPLARS, CONTROLS, VARIANTS } from "./corpus";

export interface Gap {
  ruleId: string;
  harm: string;
  family: string;
  variant: string;
  preserves: string;
  regexCeiling: boolean;
  command: string;
  /** for a ceiling gap: does the SEMANTIC layer's trigger reach it (arbitrary-SQL invocation,
   *  not provably read-only)? If so, ANU-I-006 catches it on a non-dev/unresolved target. */
  semanticTrigger?: boolean;
}

export interface FalsePositive {
  control: string;
  matchedRulePattern: string;
}

export interface RedteamReport {
  dangerousTried: number;
  catchableGaps: Gap[];
  ceilingGaps: Gap[];
  controlsTried: number;
  falsePositives: FalsePositive[];
  /** catchable misses ÷ catchable variants tried, 0..1 — the number CI gates on */
  catchableAsr: number;
  /** false positives ÷ controls tried, 0..1 */
  fpr: number;
  /** AF-T-204 — precision against the broader benign corpus, when one was supplied. */
  precision?: PrecisionResult;
}

export interface PostureScore {
  /** 0–100, a defensible blend — NOT a vanity number. Each component cites what it measured. */
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  /** 1 − catchable-ASR: fraction of catchable lexical evasions the ruleset refused. */
  evasionResistance: number;
  /** 1 − FPR: fraction of benign controls the ruleset correctly permitted. */
  precision: number;
  /** ceiling variants a denylist CANNOT catch — reported as architectural exposure, NOT folded
   *  into the ruleset score (they are not the ruleset's fault; they need a semantic layer). */
  ceilingExposure: number;
  /** of that exposure, how many ANKR's semantic layer (ANU-I-006) would reach. */
  ceilingCoveredBySemantic: number;
}

// Weights: a MISS (evasion slips past) is worse for a security gate than an over-block, so
// evasion resistance dominates precision. Documented and fixed, so the score is reproducible.
const W_EVASION = 0.7;
const W_PRECISION = 0.3;

/**
 * Score a ruleset's posture from a red-team report. The score measures the RULESET
 * (evasion resistance + precision). Ceiling exposure is reported alongside, never blended in:
 * a pure denylist cannot close a quote-split or env-hidden write, so penalising the ruleset for
 * it would be measuring the wrong thing — the honest read is "this many holes need a semantic
 * layer". @rule:AFW-YK-005
 */
export function scorePosture(r: RedteamReport): PostureScore {
  const evasionResistance = 1 - r.catchableAsr;
  const precision = 1 - r.fpr;
  const score = Math.round(100 * (W_EVASION * evasionResistance + W_PRECISION * precision));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return {
    score,
    grade,
    evasionResistance,
    precision,
    ceilingExposure: r.ceilingGaps.length,
    ceilingCoveredBySemantic: r.ceilingGaps.filter((g) => g.semanticTrigger).length,
  };
}

export interface PrecisionFinding { cmd: string; category: string; matchedPattern: string }
export interface PrecisionResult {
  tried: number;
  falsePositives: PrecisionFinding[];
  fpr: number;
  byCategory: Record<string, { tried: number; falsePositives: number }>;
  /** "representative" (the built-in corpus) or "observed" (a buyer's real command log). */
  source: "representative" | "observed";
}

/**
 * Measure precision against a benign corpus: every command MUST be permitted, so any the gate
 * refuses is a false positive (an over-block). Broader than the in-code controls, so the FPR
 * reflects a realistic population. @rule:AFW-YK-005 @rule:one-sample-is-not-a-survey
 */
export function measurePrecision(
  rules: DestructiveRules,
  corpus: { cmd: string; category: string }[],
  source: "representative" | "observed" = "representative",
): PrecisionResult {
  const falsePositives: PrecisionFinding[] = [];
  const byCategory: Record<string, { tried: number; falsePositives: number }> = {};
  for (const { cmd, category } of corpus) {
    byCategory[category] ??= { tried: 0, falsePositives: 0 };
    byCategory[category].tried++;
    const v = destructiveVerdict(cmd, rules);
    if (v.kind === "match") {
      falsePositives.push({ cmd, category, matchedPattern: v.rule.pattern });
      byCategory[category].falsePositives++;
    }
  }
  return {
    tried: corpus.length,
    falsePositives,
    fpr: corpus.length === 0 ? 0 : falsePositives.length / corpus.length,
    byCategory,
    source,
  };
}

/** A dangerous command is "refused" iff the gate would block it (a match). Inert display and
 *  clear both mean "allowed". The corpus never contains the override token, so it can't mask a gap. */
function refuses(command: string, rules: DestructiveRules): boolean {
  return destructiveVerdict(command, rules).kind === "match";
}

export function runRedteam(
  rules: DestructiveRules,
  opts: { precisionCorpus?: { cmd: string; category: string }[]; precisionSource?: "representative" | "observed" } = {},
): RedteamReport {
  const catchableGaps: Gap[] = [];
  const ceilingGaps: Gap[] = [];
  let dangerousTried = 0;
  let catchableTried = 0;

  for (const ex of EXEMPLARS) {
    for (const v of VARIANTS) {
      if (!v.appliesTo.includes(ex.kind)) continue;
      const command = v.apply(ex.plain);
      dangerousTried++;
      if (!v.regexCeiling) catchableTried++;
      if (!refuses(command, rules)) {
        const gap: Gap = {
          ruleId: ex.ruleId, harm: ex.harm, family: v.family, variant: v.name,
          preserves: v.preserves, regexCeiling: v.regexCeiling, command,
        };
        if (v.regexCeiling) {
          gap.semanticTrigger = isSqlCapableInvocation(command) && !isProvablyReadOnly(command);
          ceilingGaps.push(gap);
        } else {
          catchableGaps.push(gap);
        }
      }
    }
  }

  const falsePositives: FalsePositive[] = [];
  for (const control of CONTROLS) {
    const verdict = destructiveVerdict(control, rules);
    if (verdict.kind === "match") falsePositives.push({ control, matchedRulePattern: verdict.rule.pattern });
  }

  return {
    dangerousTried,
    catchableGaps,
    ceilingGaps,
    controlsTried: CONTROLS.length,
    falsePositives,
    catchableAsr: catchableTried === 0 ? 0 : catchableGaps.length / catchableTried,
    fpr: CONTROLS.length === 0 ? 0 : falsePositives.length / CONTROLS.length,
    precision: opts.precisionCorpus
      ? measurePrecision(rules, opts.precisionCorpus, opts.precisionSource ?? "representative")
      : undefined,
  };
}

/** CI is red iff a catchable gap or a false positive exists. Ceiling gaps never fail CI. */
export function isClean(r: RedteamReport): boolean {
  return r.catchableGaps.length === 0 && r.falsePositives.length === 0;
}

export function renderReport(r: RedteamReport): string {
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  const p = scorePosture(r);
  let out = "# AEGIS red-team — destructive-gate robustness\n\n";
  out += `## Posture: **${p.score}/100 (grade ${p.grade})**\n`;
  out += `- evasion resistance ${pct(p.evasionResistance)} (weight ${W_EVASION}) · precision ${pct(p.precision)} (weight ${W_PRECISION})\n`;
  out += `- ceiling exposure: **${p.ceilingExposure}** variant(s) no denylist can catch — a semantic layer is required; ANKR's reaches ${p.ceilingCoveredBySemantic}/${p.ceilingExposure}\n`;
  out += `- formula: round(100 × (${W_EVASION}·evasionResistance + ${W_PRECISION}·precision)); ceiling exposure reported separately, never folded in\n\n`;
  out += `Dangerous variants tried: ${r.dangerousTried} · **catchable-ASR ${pct(r.catchableAsr)}** `;
  out += `(${r.catchableGaps.length} catchable gap(s)) · ${r.ceilingGaps.length} regex-ceiling gap(s)\n`;
  out += `Benign controls tried: ${r.controlsTried} · **FPR ${pct(r.fpr)}** (${r.falsePositives.length} false positive(s))\n\n`;

  if (r.catchableGaps.length === 0) out += "✓ No catchable evasion slipped past the gate.\n";
  else {
    out += "## Catchable gaps — WIDEN the rule (a regex could catch these)\n\n| rule | family | variant | command |\n|---|---|---|---|\n";
    for (const g of r.catchableGaps) out += `| ${g.ruleId} | ${g.family} | ${g.variant} | \`${g.command}\` |\n`;
  }
  out += "\n";
  if (r.falsePositives.length === 0) out += "✓ No benign control was refused.\n";
  else {
    out += "## False positives — the rule is over-broad\n\n| control | matched pattern |\n|---|---|\n";
    for (const fp of r.falsePositives) out += `| \`${fp.control}\` | \`${fp.matchedRulePattern}\` |\n`;
  }
  out += "\n";
  if (r.precision) {
    const p = r.precision;
    out += `## Precision — benign corpus (${p.source}: ${p.tried} commands)\n`;
    out += `False positives (over-blocks): **${p.falsePositives.length}** · FPR ${pct(p.fpr)}\n`;
    if (p.falsePositives.length) {
      out += "\n| category | command | matched pattern |\n|---|---|---|\n";
      for (const fp of p.falsePositives) out += `| ${fp.category} | \`${fp.cmd.slice(0, 70)}\` | \`${fp.matchedPattern}\` |\n`;
    } else out += "✓ no benign command in the corpus was refused.\n";
    out += "\n";
  }
  if (r.ceilingGaps.length > 0) {
    const covered = r.ceilingGaps.filter(g => g.semanticTrigger).length;
    out += "## Regex-ceiling gaps — a denylist cannot catch these (the semantic gate does)\n\n";
    out += "The dangerous text is split across shell tokens or supplied at runtime, so it is not\n";
    out += "in the command string at all. No regex closes these. The control that does is the\n";
    out += "semantic layer (ANU-I-006): it triggers on an arbitrary-SQL invocation that is not\n";
    out += "provably read-only, then refuses on a non-dev or unresolved target — without reading\n";
    out += "the SQL at all.\n\n";
    out += `**Within the semantic layer's reach: ${covered}/${r.ceilingGaps.length}** (its trigger fires).\n\n`;
    out += "| rule | variant | semantic trigger | command |\n|---|---|---|---|\n";
    for (const g of r.ceilingGaps) out += `| ${g.ruleId} | ${g.variant} | ${g.semanticTrigger ? "✓ caught" : "—"} | \`${g.command}\` |\n`;
  }
  return out;
}
