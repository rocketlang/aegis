// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AF-T-301 — the shield face of the red-team: scores the injection + persistence detectors the
// way the destructive face scores the destructive gate, using the SAME pure detectors the live
// hook runs (detectInjection, detectPersistenceWrite). Coverage + lexical/path robustness +
// precision. It does NOT cover credential-read (its detector records shared state — a pure
// classifier extraction is the noted remainder) or the stateful exfil-sequence detector (that
// needs a driven read→network sequence — AF-T-302). Nothing is executed. @rule:RT-002

import { detectInjection, detectPersistenceWrite, type ShieldRules } from "../shield/injection-detector";
import {
  INJECTION_MALICIOUS, INJECTION_BENIGN, PERSISTENCE_MALICIOUS, PERSISTENCE_BENIGN,
  lexicalVariants, pathVariants,
} from "./shield-corpus";

export interface ShieldFaceReport {
  injection: {
    triggersTried: number;
    misses: string[];                                  // a malicious string the shield did NOT flag
    robustnessTried: number;
    robustnessGaps: { base: string; variant: string; value: string }[];
    benignTried: number;
    falsePositives: { text: string; ruleId: string }[]; // benign text the shield flagged
  };
  persistence: {
    seedsTried: number;
    misses: string[];                                  // a persistence-target write NOT quarantined
    variantsTried: number;
    variantGaps: { base: string; variant: string; value: string }[];
    benignTried: number;
    falsePositives: { path: string; ruleId: string }[];
  };
}

const flagged = (v: { verdict: string }) => v.verdict !== "PASS";

export function runShieldFace(rules: ShieldRules): ShieldFaceReport {
  // — injection —
  const injMisses: string[] = [];
  const robustnessGaps: ShieldFaceReport["injection"]["robustnessGaps"] = [];
  let robustnessTried = 0;
  for (const text of INJECTION_MALICIOUS) {
    if (!flagged(detectInjection(text, rules))) injMisses.push(text);
    for (const v of lexicalVariants(text)) {
      robustnessTried++;
      if (!flagged(detectInjection(v.value, rules))) robustnessGaps.push({ base: text, variant: v.name, value: v.value });
    }
  }
  const injFps: ShieldFaceReport["injection"]["falsePositives"] = [];
  for (const text of INJECTION_BENIGN) {
    const r = detectInjection(text, rules);
    if (flagged(r)) injFps.push({ text, ruleId: r.rule_id });
  }

  // — persistence —
  const persMisses: string[] = [];
  const variantGaps: ShieldFaceReport["persistence"]["variantGaps"] = [];
  let variantsTried = 0;
  for (const path of PERSISTENCE_MALICIOUS) {
    if (detectPersistenceWrite(path, rules).verdict !== "QUARANTINE") persMisses.push(path);
    for (const v of pathVariants(path)) {
      variantsTried++;
      if (detectPersistenceWrite(v.value, rules).verdict !== "QUARANTINE") variantGaps.push({ base: path, variant: v.name, value: v.value });
    }
  }
  const persFps: ShieldFaceReport["persistence"]["falsePositives"] = [];
  for (const path of PERSISTENCE_BENIGN) {
    const r = detectPersistenceWrite(path, rules);
    if (r.verdict !== "PASS") persFps.push({ path, ruleId: r.rule_id });
  }

  return {
    injection: {
      triggersTried: INJECTION_MALICIOUS.length, misses: injMisses,
      robustnessTried, robustnessGaps, benignTried: INJECTION_BENIGN.length, falsePositives: injFps,
    },
    persistence: {
      seedsTried: PERSISTENCE_MALICIOUS.length, misses: persMisses,
      variantsTried, variantGaps, benignTried: PERSISTENCE_BENIGN.length, falsePositives: persFps,
    },
  };
}

/** Clean = every malicious seed caught, every robustness/path variant caught. Benign false
 *  positives are REPORTED (injection rules are inherently fuzzy) but do not fail — a miss is the
 *  real regression, an over-flag is a tuning finding. */
export function shieldFaceClean(r: ShieldFaceReport): boolean {
  return r.injection.misses.length === 0 && r.injection.robustnessGaps.length === 0 &&
    r.persistence.misses.length === 0 && r.persistence.variantGaps.length === 0;
}

export function renderShieldFace(r: ShieldFaceReport): string {
  const i = r.injection, p = r.persistence;
  let out = "# AEGIS red-team — shield face (injection + persistence)\n\n";
  out += "> Injection is natural language, so this measures coverage + lexical robustness +\n";
  out += "> precision, NOT provable semantic evasion. Persistence is path-based (RT-001-clean).\n\n";
  out += `## Injection\n`;
  out += `- coverage: ${i.triggersTried - i.misses.length}/${i.triggersTried} representative strings flagged`;
  out += i.misses.length ? ` — MISSED: ${i.misses.map((m) => `\`${m.slice(0, 40)}\``).join(", ")}\n` : "\n";
  out += `- lexical robustness: ${i.robustnessTried - i.robustnessGaps.length}/${i.robustnessTried} case/whitespace variants still flagged`;
  out += i.robustnessGaps.length ? ` — GAPS: ${i.robustnessGaps.map((g) => g.variant).join(", ")}\n` : "\n";
  out += `- precision: ${i.falsePositives.length} benign text(s) over-flagged`;
  out += i.falsePositives.length ? `:\n${i.falsePositives.map((f) => `  - ${f.ruleId}: \`${f.text}\``).join("\n")}\n` : " (none)\n";
  out += `\n## Persistence\n`;
  out += `- coverage: ${p.seedsTried - p.misses.length}/${p.seedsTried} persistence-target writes quarantined`;
  out += p.misses.length ? ` — MISSED: ${p.misses.join(", ")}\n` : "\n";
  out += `- path robustness: ${p.variantsTried - p.variantGaps.length}/${p.variantsTried} spelling variants still caught`;
  out += p.variantGaps.length ? ` — GAPS: ${p.variantGaps.map((g) => g.value).join(", ")}\n` : "\n";
  out += `- precision: ${p.falsePositives.length} benign write(s) over-flagged\n`;
  return out;
}
