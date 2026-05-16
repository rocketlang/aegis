// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:INF-CG-004 — memory delta capability claim → QUARANTINE pending review
// @rule:CG-YK-003 — cross-session capability expansion → QUARANTINE
// CG-T-023: capability expansion pattern library, separate namespace from injection fingerprints

export interface CapabilityExpansionMatch {
  pattern_id: string;
  matched_text: string;
  confidence: number;
}

const CAPABILITY_EXPANSION_PATTERNS: { id: string; pattern: RegExp; confidence: number }[] = [
  { id: 'CEP-001', pattern: /you\s+(now\s+)?have\s+access\s+to\b/i, confidence: 0.90 },
  { id: 'CEP-002', pattern: /you\s+are\s+(now\s+)?(authoris[ez]d|permitted|allowed)\s+to\b/i, confidence: 0.90 },
  { id: 'CEP-003', pattern: /your\s+(new\s+)?capabilities?\s+(include|now\s+include|are)\b/i, confidence: 0.92 },
  { id: 'CEP-004', pattern: /you\s+may\s+now\b/i, confidence: 0.85 },
  { id: 'CEP-005', pattern: /you\s+can\s+now\b/i, confidence: 0.80 },
  { id: 'CEP-006', pattern: /your\s+(permissions?|access\s+level|privileges?)\s+have\s+(been\s+)?(upgraded|expanded|increased|elevated)\b/i, confidence: 0.93 },
  { id: 'CEP-007', pattern: /you\s+(have\s+been\s+)?(granted|given)\s+(access|permission|authority)\b/i, confidence: 0.88 },
  { id: 'CEP-008', pattern: /admin\s+(access|mode|rights?|privileges?)\s+(granted|enabled|activated)\b/i, confidence: 0.95 },
  { id: 'CEP-009', pattern: /your\s+(role|function|purpose)\s+has\s+(expanded|been\s+updated|changed)\b/i, confidence: 0.85 },
  { id: 'CEP-010', pattern: /unrestricted\s+(access|mode|operation)\b/i, confidence: 0.93 },
];

export function scan(content: string): CapabilityExpansionMatch[] {
  const matches: CapabilityExpansionMatch[] = [];
  for (const { id, pattern, confidence } of CAPABILITY_EXPANSION_PATTERNS) {
    const m = content.match(pattern);
    if (m) {
      matches.push({ pattern_id: id, matched_text: m[0].trim(), confidence });
    }
  }
  return matches;
}

export function maxConfidence(matches: CapabilityExpansionMatch[]): number {
  return matches.reduce((max, m) => Math.max(max, m.confidence), 0);
}
