// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-YK-002 — tool output with identity/role claims → POISONING_SUSPECTED
// @rule:CG-012 — tool output provenance preserved separately from tool trust
// @rule:INF-CG-006 — tool output contradicts declared agent role → POISONING_SUSPECTED

import type { SourceMetadata } from './trust.js';
import { resolve as resolveTrust } from './trust.js';

export interface ToolOutputClassifyResult {
  classification: 'CLEAR' | 'POISONING_SUSPECTED';
  confidence: number;
  matched_patterns: string[];
  reason: string;
}

const IDENTITY_OVERRIDE_PATTERNS: { pattern: RegExp; label: string; confidence: number }[] = [
  { pattern: /SYSTEM\s+OVERRIDE\s*[:—]/i, label: 'SYSTEM_OVERRIDE', confidence: 0.97 },
  { pattern: /you\s+are\s+now\s+operating\s+in/i, label: 'OPERATING_MODE_CHANGE', confidence: 0.93 },
  { pattern: /maintenance\s+mode\s+(activated|enabled|on)/i, label: 'MAINTENANCE_MODE', confidence: 0.91 },
  { pattern: /disregard\s+(all\s+)?(previous|prior)\s+(instructions?|rules?)/i, label: 'DISREGARD_PREVIOUS', confidence: 0.93 },
  { pattern: /your\s+role\s+has\s+(changed|been\s+updated)/i, label: 'ROLE_CHANGED', confidence: 0.92 },
  { pattern: /new\s+operating\s+parameters?\s*:/i, label: 'NEW_OPERATING_PARAMS', confidence: 0.90 },
  { pattern: /\[SYSTEM\].*you\s+are\s+now/i, label: 'SYSTEM_IDENTITY_CLAIM', confidence: 0.95 },
  { pattern: /you\s+are\s+now\s+(a|an|the)\s+\w+\s+(AI|assistant|agent|system|bot)/i, label: 'IDENTITY_CLAIM', confidence: 0.88 },
];

export function classify(
  toolOutput: string,
  agentRole: string,
  provenanceRecord: { source: SourceMetadata; toolId: string }
): ToolOutputClassifyResult {
  const sourceTrust = resolveTrust(toolOutput, provenanceRecord.source);
  const matched: string[] = [];
  let maxConfidence = 0;

  for (const { pattern, label, confidence } of IDENTITY_OVERRIDE_PATTERNS) {
    if (pattern.test(toolOutput)) {
      matched.push(label);
      if (confidence > maxConfidence) maxConfidence = confidence;
    }
  }

  if (matched.length === 0) {
    return { classification: 'CLEAR', confidence: 0, matched_patterns: [], reason: 'no_identity_patterns' };
  }

  if (sourceTrust.classification === 'TRUSTED' && maxConfidence < 0.92) {
    return {
      classification: 'CLEAR',
      confidence: maxConfidence * 0.5,
      matched_patterns: matched,
      reason: 'trusted_source_low_confidence',
    };
  }

  return {
    classification: 'POISONING_SUSPECTED',
    confidence: maxConfidence,
    matched_patterns: matched,
    reason: `identity_claim_from_${sourceTrust.classification.toLowerCase()}_source`,
  };
}
