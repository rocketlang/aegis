// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-002 — trust inherits from source, not from carrier
// @rule:INF-CG-002 — RAG chunk source trust below threshold → mark as UNTRUSTED context

export type TrustClassification = 'TRUSTED' | 'UNTRUSTED' | 'UNKNOWN';

export interface SourceMetadata {
  url?: string;
  db_name?: string;
  api_endpoint?: string;
  source_type?: 'internal' | 'external' | 'user_input' | 'tool_output';
  declared_trust?: TrustClassification;
}

export interface TrustClassifyResult {
  classification: TrustClassification;
  source_trust_score: number;
  reason: string;
  trust_inherited_from_source: boolean;
}

const TRUSTED_INTERNAL_PATTERNS: RegExp[] = [
  /^localhost:\d+/,
  /^127\.0\.0\.1:\d+/,
  /^http:\/\/localhost/,
  /^granthx:/,
  /^ankr-internal:/,
  /^postgresql:\/\/.*@localhost/,
  /^\/root\//,
];

const KNOWN_UNTRUSTED_PATTERNS: RegExp[] = [
  /^https?:\/\/(?!localhost|127\.0\.0\.1)/,
  /web_search|browser_tool|fetch_url/i,
];

export function resolve(content: string, sourceMetadata?: SourceMetadata): TrustClassifyResult {
  if (!sourceMetadata) {
    return {
      classification: 'UNKNOWN',
      source_trust_score: 0.3,
      reason: 'no_source_metadata',
      trust_inherited_from_source: false,
    };
  }

  if (sourceMetadata.declared_trust) {
    return {
      classification: sourceMetadata.declared_trust,
      source_trust_score: sourceMetadata.declared_trust === 'TRUSTED' ? 1.0 : 0.0,
      reason: 'declared_trust',
      trust_inherited_from_source: true,
    };
  }

  const sourceStr = [
    sourceMetadata.url,
    sourceMetadata.db_name,
    sourceMetadata.api_endpoint,
  ].filter(Boolean).join(' ');

  if (sourceMetadata.source_type === 'internal') {
    return { classification: 'TRUSTED', source_trust_score: 0.9, reason: 'source_type_internal', trust_inherited_from_source: true };
  }
  if (sourceMetadata.source_type === 'user_input') {
    return { classification: 'UNTRUSTED', source_trust_score: 0.1, reason: 'source_type_user_input', trust_inherited_from_source: true };
  }

  if (sourceStr) {
    for (const pattern of TRUSTED_INTERNAL_PATTERNS) {
      if (pattern.test(sourceStr)) {
        return { classification: 'TRUSTED', source_trust_score: 0.9, reason: 'trusted_internal_pattern', trust_inherited_from_source: true };
      }
    }
    for (const pattern of KNOWN_UNTRUSTED_PATTERNS) {
      if (pattern.test(sourceStr)) {
        return { classification: 'UNTRUSTED', source_trust_score: 0.0, reason: 'known_untrusted_pattern', trust_inherited_from_source: true };
      }
    }
  }

  if (sourceMetadata.source_type === 'tool_output') {
    return { classification: 'UNTRUSTED', source_trust_score: 0.2, reason: 'tool_output_default_untrusted', trust_inherited_from_source: true };
  }

  return { classification: 'UNKNOWN', source_trust_score: 0.3, reason: 'no_pattern_match', trust_inherited_from_source: false };
}

export const TRUSTED_THRESHOLD = 0.7;
