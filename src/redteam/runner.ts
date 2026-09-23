// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// The red-team runner. It evaluates every (exemplar × variant) and every control through
// the SAME pure decision function the live hook uses (destructiveVerdict), and reports:
//
//   gaps  — a dangerous variant the gate did NOT refuse. Ground truth is the human-authored
//           label on the exemplar (RT-001); the gate's own opinion is never the oracle.
//   false positives — a benign control the gate refused. Over-blocking is a real failure.
//
// The "attack success rate" (ASR) is gaps ÷ dangerous-variants: the fraction of
// meaning-preserving rewrites of a known-dangerous command that slipped past. ASR=0 with a
// clean control sheet is the goal; any gap names a rule whose regex should be widened.
//
// This module never executes a command. @rule:RT-002

import { destructiveVerdict, type DestructiveRules } from "../kavach/destructive-verdict";
import { EXEMPLARS, CONTROLS, VARIANTS } from "./corpus";

export interface Gap {
  ruleId: string;
  harm: string;
  variant: string;
  preserves: string;
  command: string;
}

export interface FalsePositive {
  control: string;
  matchedRulePattern: string;
}

export interface RedteamReport {
  dangerousTried: number;
  gaps: Gap[];
  controlsTried: number;
  falsePositives: FalsePositive[];
  /** gaps ÷ dangerousTried, 0..1 */
  asr: number;
  /** falsePositives ÷ controlsTried, 0..1 */
  fpr: number;
}

/**
 * A dangerous command is "refused" iff the gate matched a rule against it. The override
 * token is NOT a refusal — but the corpus never contains the token, so it cannot mask a gap.
 */
function refuses(command: string, rules: DestructiveRules): boolean {
  return destructiveVerdict(command, rules).kind === "match";
}

export function runRedteam(rules: DestructiveRules): RedteamReport {
  const gaps: Gap[] = [];
  let dangerousTried = 0;

  for (const ex of EXEMPLARS) {
    for (const v of VARIANTS) {
      const command = v.apply(ex.plain);
      dangerousTried++;
      if (!refuses(command, rules)) {
        gaps.push({ ruleId: ex.ruleId, harm: ex.harm, variant: v.name, preserves: v.preserves, command });
      }
    }
  }

  const falsePositives: FalsePositive[] = [];
  for (const control of CONTROLS) {
    const verdict = destructiveVerdict(control, rules);
    if (verdict.kind === "match") {
      falsePositives.push({ control, matchedRulePattern: verdict.rule.pattern });
    }
  }

  return {
    dangerousTried,
    gaps,
    controlsTried: CONTROLS.length,
    falsePositives,
    asr: dangerousTried === 0 ? 0 : gaps.length / dangerousTried,
    fpr: CONTROLS.length === 0 ? 0 : falsePositives.length / CONTROLS.length,
  };
}

export function renderReport(r: RedteamReport): string {
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  let out = "# AEGIS red-team — destructive-gate robustness\n\n";
  out += `Dangerous variants tried: ${r.dangerousTried} · gaps: ${r.gaps.length} · **ASR ${pct(r.asr)}**\n`;
  out += `Benign controls tried: ${r.controlsTried} · false positives: ${r.falsePositives.length} · **FPR ${pct(r.fpr)}**\n\n`;

  if (r.gaps.length === 0) out += "✓ No meaning-preserving rewrite of any exemplar slipped past the gate.\n";
  else {
    out += "## Gaps — a dangerous variant the gate did NOT refuse (widen the rule's regex)\n\n";
    out += "| rule | harm | variant | command |\n|---|---|---|---|\n";
    for (const g of r.gaps) out += `| ${g.ruleId} | ${g.harm} | ${g.variant} | \`${g.command}\` |\n`;
  }
  out += "\n";
  if (r.falsePositives.length === 0) out += "✓ No benign control was refused.\n";
  else {
    out += "## False positives — a benign command the gate refused (rule is over-broad)\n\n";
    out += "| control | matched pattern |\n|---|---|\n";
    for (const fp of r.falsePositives) out += `| \`${fp.control}\` | \`${fp.matchedRulePattern}\` |\n`;
  }
  return out;
}
