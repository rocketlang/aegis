// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-006 — injection fingerprint database is append-only
// @rule:INF-CG-001 — agent role instruction in memory content → INJECT_FINGERPRINT_HIT
//
// Pure in-memory fingerprint matcher. Ships with 16 bootstrap patterns
// (FP-001..FP-016). Consumers can register additional patterns at runtime
// via register(); persistence (if any) is the consumer's responsibility.
// The DB-backed version lives in the internal chitta-guard service.

export type FingerprintCategory =
  | 'agent_role_instruction'
  | 'capability_expansion'
  | 'identity_override'
  | 'constraint_bypass';

export interface FingerprintPattern {
  id: string;
  category: FingerprintCategory;
  pattern: RegExp;
  confidence: number;
  detected_date: string;
  source: 'bootstrap' | 'analyst' | 'automated';
  description?: string;
  hit_count: number;
}

export interface FingerprintScanResult {
  matched: boolean;
  patterns_hit: string[];
  max_confidence: number;
  categories: string[];
}

const BOOTSTRAP_PATTERNS: FingerprintPattern[] = [
  // AGENT_ROLE_INSTRUCTION
  { id: 'FP-001', category: 'agent_role_instruction', pattern: /\bsystem\s*:\s*(override|admin|root)\b/i, confidence: 0.95, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-002', category: 'agent_role_instruction', pattern: /\[INST\].*ignore.*(previous|prior|above)/i, confidence: 0.95, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-003', category: 'agent_role_instruction', pattern: /<\/?system>/i, confidence: 0.90, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-004', category: 'agent_role_instruction', pattern: /###\s*SYSTEM\s*(PROMPT|INSTRUCTION|MESSAGE)/i, confidence: 0.90, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-005', category: 'agent_role_instruction', pattern: /```system\b/i, confidence: 0.88, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },

  // CAPABILITY_EXPANSION
  { id: 'FP-006', category: 'capability_expansion', pattern: /you\s+(now\s+)?have\s+(unrestricted|full|complete)\s+access/i, confidence: 0.93, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-007', category: 'capability_expansion', pattern: /your\s+new\s+(capabilities|permissions?|access\s+level)\s+include/i, confidence: 0.92, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-008', category: 'capability_expansion', pattern: /you\s+are\s+now\s+(able|allowed|permitted|authoris[ez]d)\s+to/i, confidence: 0.88, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },

  // IDENTITY_OVERRIDE
  { id: 'FP-009', category: 'identity_override', pattern: /SYSTEM\s+OVERRIDE\s*:/i, confidence: 0.97, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-010', category: 'identity_override', pattern: /you\s+are\s+now\s+operating\s+in/i, confidence: 0.93, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-011', category: 'identity_override', pattern: /\[ROLE\s+CHANGE\]/i, confidence: 0.95, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-012', category: 'identity_override', pattern: /your\s+role\s+has\s+(changed|been\s+(updated|reassigned))/i, confidence: 0.92, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },

  // CONSTRAINT_BYPASS
  { id: 'FP-013', category: 'constraint_bypass', pattern: /DAN\s+(mode|prompt|jailbreak)/i, confidence: 0.97, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-014', category: 'constraint_bypass', pattern: /jailbreak\s+(mode|activated|enabled)/i, confidence: 0.97, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-015', category: 'constraint_bypass', pattern: /do\s+anything\s+now/i, confidence: 0.95, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
  { id: 'FP-016', category: 'constraint_bypass', pattern: /\bno\s+restrictions?\b.*\bmode\b/i, confidence: 0.90, detected_date: '2026-05-09', source: 'bootstrap', hit_count: 0 },
];

let _db: FingerprintPattern[] = BOOTSTRAP_PATTERNS.map(p => ({ ...p }));

// CG-T-032 — append-only insert; no update or delete
export function register(pattern: Omit<FingerprintPattern, 'hit_count'>): void {
  if (_db.find(p => p.id === pattern.id)) {
    throw new Error(`Fingerprint pattern ${pattern.id} already exists — append-only, cannot replace`);
  }
  _db.push({ ...pattern, hit_count: 0 });
}

export function getAll(): FingerprintPattern[] {
  return [..._db];
}

export function getCount(): number {
  return _db.length;
}

export function scan(content: string): FingerprintScanResult {
  const patterns_hit: string[] = [];
  const categories = new Set<string>();
  let maxConfidence = 0;

  for (const fp of _db) {
    if (fp.pattern.test(content)) {
      patterns_hit.push(fp.id);
      categories.add(fp.category);
      if (fp.confidence > maxConfidence) maxConfidence = fp.confidence;
      fp.hit_count++;
    }
  }

  return {
    matched: patterns_hit.length > 0,
    patterns_hit,
    max_confidence: maxConfidence,
    categories: [...categories],
  };
}

// Reset to bootstrap-only — useful in tests
export function reset(): void {
  _db = BOOTSTRAP_PATTERNS.map(p => ({ ...p }));
}
