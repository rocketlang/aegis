// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-003 — imperative language directed at agent role is suspect
// @rule:CG-YK-001 — agent-directed retrieval chunk → INJECT_SUSPECT

import { variants } from './normalize.js';

export interface ImperativeScanResult {
  confidence: number;
  categories: string[];
  matched_patterns: string[];
}

const PATTERN_GROUPS: { category: string; patterns: RegExp[]; weight: number }[] = [
  {
    category: 'constraint_override',
    patterns: [
      /\bignore\s+(all\s+)?(previous|prior|earlier|above)\b/i,
      /\bdisregard\s+(all\s+)?(previous|prior|earlier|above|your)\b/i,
      /\boverride\s+(your|all|previous|prior)?\s*(instructions?|rules?|constraints?|guidelines?)/i,
      /\bforget\s+(everything|all|your)\s*(you|about|previous)?\s*(know|instructions?)?/i,
      /\byou\s+(must|should|shall)\s+ignore\b/i,
    ],
    weight: 0.90,
  },
  {
    category: 'identity_claim',
    patterns: [
      /\byou\s+are\s+now\b/i,
      /\byour\s+(new\s+)?(name|role|identity|purpose|function|task)\s+is\b/i,
      /\byou\s+(have\s+been\s+)?(assigned|given|changed\s+to|switched\s+to)\b/i,
      /\boperating\s+as\b/i,
      /\bnew\s+operating\s+(mode|parameters|instructions?)\b/i,
      /\bmaintenance\s+mode\b/i,
      /\bsystem\s+override\b/i,
      /\byour\s+role\s+has\s+(changed|been\s+updated)\b/i,
    ],
    weight: 0.85,
  },
  {
    category: 'capability_expansion',
    patterns: [
      /\byou\s+(now\s+)?(have\s+)?(access\s+to|permission\s+to|authority\s+to)\b/i,
      /\byou\s+are\s+(now\s+)?(authoris[ez]d|permitted|allowed)\s+to\b/i,
      /\byour\s+(new\s+)?capabilities?\s+(include|are|now)\b/i,
      /\byou\s+may\s+now\b/i,
      /\byou\s+(can|could)\s+now\b/i,
    ],
    weight: 0.80,
  },
  {
    category: 'role_instruction',
    patterns: [
      /\bwhen\s+(asked|told|prompted|requested|instructed)\s+(to|about|for)\b/i,
      /\balways\s+(include|respond|reply|add|say|output)\b/i,
      /\bnever\s+(mention|reveal|say|tell|show|include)\b/i,
      /\byou\s+must\s+(always|never|only|not)\b/i,
      /\byou\s+should\s+(always|never|only|not)\b/i,
      /\bdo\s+not\s+(tell|mention|reveal|say|include)\s+(anyone|the\s+user|users?)\b/i,
      /\brespond\s+only\s+in\b/i,
      /\bact\s+as\s+(if|though|a|an)\b/i,
    ],
    weight: 0.60,
  },
];

// A phrase is AMBIGUOUS when ordinary text uses it as often as an attack does: "you can
// now download the invoice", "you are now listed as Senior Engineer", "always include
// your order number". On its own such a phrase is worth a flag, not a quarantine. The
// orchestrator (scan.evaluate) applies that; this scanner reports the raw weight as before.
const AMBIGUOUS_CATEGORIES = new Set(['capability_expansion', 'role_instruction']);
const AMBIGUOUS_PATTERNS = new Set([
  String(/\byou\s+are\s+now\b/i),
  String(/\byou\s+(have\s+been\s+)?(assigned|given|changed\s+to|switched\s+to)\b/i),
  String(/\byour\s+role\s+has\s+(changed|been\s+updated)\b/i),
]);

export interface ImperativeHit {
  category: string;
  weight: number;
  ambiguous: boolean;
  /** Identifies the pattern, so the same hit can be recognised in another view of the text. */
  key: string;
  text: string;
  start: number;
  end: number;
}

/** Every pattern hit in `text` as given — no normalisation. Used by the orchestrator. */
export function scanText(text: string): ImperativeHit[] {
  const hits: ImperativeHit[] = [];
  for (const group of PATTERN_GROUPS) {
    for (const pattern of group.patterns) {
      const m = text.match(pattern);
      if (m && m.index !== undefined) {
        hits.push({
          category: group.category,
          weight: group.weight,
          ambiguous: AMBIGUOUS_CATEGORIES.has(group.category) || AMBIGUOUS_PATTERNS.has(String(pattern)),
          key: 'imp:' + String(pattern),
          text: m[0].trim(),
          start: m.index,
          end: m.index + m[0].length,
        });
      }
    }
  }
  return hits;
}

/** The scanner's own confidence for a set of hits: the heaviest category plus a small boost per extra hit. */
export function confidenceOf(hits: ImperativeHit[]): number {
  if (hits.length === 0) return 0;
  const maxWeight = hits.reduce((m, h) => Math.max(m, h.weight), 0);
  const multiMatchBoost = Math.min((hits.length - 1) * 0.05, 0.09);
  return Math.round(Math.min(maxWeight + multiMatchBoost, 0.99) * 100) / 100;
}

export function scan(content: string): ImperativeScanResult {
  // The strongest result over the views of the text (see normalize.ts).
  let best: ImperativeHit[] = [];
  let bestConfidence = 0;
  for (const view of variants(content)) {
    const hits = scanText(view);
    const c = confidenceOf(hits);
    if (c > bestConfidence) {
      best = hits;
      bestConfidence = c;
    }
  }
  if (best.length === 0) return { confidence: 0, categories: [], matched_patterns: [] };
  return {
    confidence: bestConfidence,
    categories: [...new Set(best.map((h) => h.category))],
    matched_patterns: [...new Set(best.map((h) => h.text))].slice(0, 10),
  };
}
