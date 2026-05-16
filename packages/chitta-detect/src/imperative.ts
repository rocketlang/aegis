// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-003 — imperative language directed at agent role is suspect
// @rule:CG-YK-001 — agent-directed retrieval chunk → INJECT_SUSPECT

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

export function scan(content: string): ImperativeScanResult {
  const matched_patterns: string[] = [];
  const categories = new Set<string>();
  let maxWeight = 0;
  let matchCount = 0;

  for (const group of PATTERN_GROUPS) {
    for (const pattern of group.patterns) {
      const m = content.match(pattern);
      if (m) {
        matched_patterns.push(m[0].trim());
        categories.add(group.category);
        if (group.weight > maxWeight) maxWeight = group.weight;
        matchCount++;
      }
    }
  }

  if (matchCount === 0) return { confidence: 0, categories: [], matched_patterns: [] };

  const multiMatchBoost = Math.min((matchCount - 1) * 0.05, 0.09);
  const confidence = Math.min(maxWeight + multiMatchBoost, 0.99);

  return {
    confidence: Math.round(confidence * 100) / 100,
    categories: [...categories],
    matched_patterns: [...new Set(matched_patterns)].slice(0, 10),
  };
}
