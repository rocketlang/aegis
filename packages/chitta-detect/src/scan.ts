// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-010 — scan confidence threshold is tuneable above a floor
// @rule:CG-YK-001 — combines imperative scanner + trust classifier + fingerprint scanner
//
// Orchestrator that combines all four primitive detectors into a single
// PASS / ADVISORY / INJECT_SUSPECT / BLOCK verdict. Pure — no service deps.

import { scan as imperativeScan } from './imperative.js';
import { resolve as resolveTrust } from './trust.js';
import { scan as fingerprintScan } from './fingerprint.js';
import { classify as classifyToolOutput } from './tool-output.js';
import type { SourceMetadata } from './trust.js';

export type ScanVerdict = 'PASS' | 'ADVISORY' | 'INJECT_SUSPECT' | 'BLOCK';

export interface AgentContext {
  agent_id: string;
  session_id?: string;
  declared_role?: string;
  posture?: 'NORMAL' | 'ELEVATED_SCRUTINY' | 'UNVALIDATED_MEMORY' | 'NO_BASELINE';
  tool_id?: string;
  source_metadata?: SourceMetadata;
  scan_type?: 'memory_write' | 'tool_output' | 'rag_chunk';
}

export interface ThresholdConfig {
  inject_suspect_threshold?: number;
  block_threshold?: number;
  advisory_floor?: number;
}

export interface ScanResult {
  scan_id: string;
  verdict: ScanVerdict;
  confidence: number;
  rules_fired: string[];
  details: {
    imperative_confidence: number;
    fingerprint_matched: boolean;
    fingerprint_patterns: string[];
    trust_classification: string;
    tool_output_classification?: string;
  };
  action: string;
  scanned_at: string;
}

const DEFAULT_THRESHOLDS: Required<ThresholdConfig> = {
  inject_suspect_threshold: 0.75,
  block_threshold: 0.95,
  advisory_floor: 0.60,
};

// CG-010: floor = 0.6, ceiling = 0.9 for inject_suspect_threshold
function clampThresholds(config: ThresholdConfig, posture: string): Required<ThresholdConfig> {
  let injectThreshold = Math.max(0.60, Math.min(0.90, config.inject_suspect_threshold ?? DEFAULT_THRESHOLDS.inject_suspect_threshold));
  let blockThreshold = config.block_threshold ?? DEFAULT_THRESHOLDS.block_threshold;
  const advisoryFloor = config.advisory_floor ?? DEFAULT_THRESHOLDS.advisory_floor;

  // CG-YK-006: ELEVATED_SCRUTINY lowers threshold by 0.15 (floor: 0.45)
  if (posture === 'ELEVATED_SCRUTINY') {
    injectThreshold = Math.max(0.45, injectThreshold - 0.15);
    blockThreshold = Math.max(0.80, blockThreshold - 0.05);
  }

  return { inject_suspect_threshold: injectThreshold, block_threshold: blockThreshold, advisory_floor: advisoryFloor };
}

let _scanCounter = 0;

function generateScanId(): string {
  _scanCounter++;
  return `cg-scan-${Date.now()}-${_scanCounter.toString().padStart(4, '0')}`;
}

export function evaluate(
  content: string,
  agentContext: AgentContext,
  thresholdConfig: ThresholdConfig = {}
): ScanResult {
  const scan_id = generateScanId();
  const scanned_at = new Date().toISOString();
  const posture = agentContext.posture ?? 'NORMAL';
  const thresholds = clampThresholds(thresholdConfig, posture);
  const rules_fired: string[] = [];

  const fp = fingerprintScan(content);
  if (fp.matched) {
    rules_fired.push('CG-006', 'INF-CG-001');
  }

  const imp = imperativeScan(content);
  if (imp.confidence > 0) {
    rules_fired.push('CG-003', 'CG-YK-001');
  }

  const trust = resolveTrust(content, agentContext.source_metadata);
  if (trust.classification !== 'TRUSTED') {
    rules_fired.push('CG-002');
    if (trust.source_trust_score < 0.7) rules_fired.push('INF-CG-002');
  }

  let toolOutputClassification: string | undefined;
  if (agentContext.scan_type === 'tool_output' && agentContext.tool_id && agentContext.declared_role) {
    const toc = classifyToolOutput(
      content,
      agentContext.declared_role,
      { source: agentContext.source_metadata ?? {}, toolId: agentContext.tool_id }
    );
    toolOutputClassification = toc.classification;
    if (toc.classification === 'POISONING_SUSPECTED') {
      rules_fired.push('CG-YK-002', 'INF-CG-006', 'CG-012');
      const result = buildResult(scan_id, 'INJECT_SUSPECT', toc.confidence, rules_fired, imp, fp, trust, toolOutputClassification, scanned_at);
      if (result.confidence >= thresholds.block_threshold) result.verdict = 'BLOCK';
      return result;
    }
  }

  let combinedConfidence = 0;
  if (fp.matched) {
    combinedConfidence = Math.max(combinedConfidence, fp.max_confidence);
  }
  if (imp.confidence > 0) {
    const trustMultiplier = trust.classification === 'UNTRUSTED' ? 1.15 : 1.0;
    combinedConfidence = Math.max(combinedConfidence, Math.min(0.99, imp.confidence * trustMultiplier));
  }

  let verdict: ScanVerdict;
  if (combinedConfidence >= thresholds.block_threshold) {
    verdict = 'BLOCK';
  } else if (combinedConfidence >= thresholds.inject_suspect_threshold) {
    verdict = 'INJECT_SUSPECT';
  } else if (combinedConfidence >= thresholds.advisory_floor) {
    verdict = posture === 'ELEVATED_SCRUTINY' ? 'INJECT_SUSPECT' : 'ADVISORY';
    if (posture === 'ELEVATED_SCRUTINY') rules_fired.push('CG-YK-006');
  } else {
    verdict = 'PASS';
  }

  return buildResult(scan_id, verdict, combinedConfidence, rules_fired, imp, fp, trust, toolOutputClassification, scanned_at);
}

function buildResult(
  scan_id: string,
  verdict: ScanVerdict,
  confidence: number,
  rules_fired: string[],
  imp: ReturnType<typeof imperativeScan>,
  fp: ReturnType<typeof fingerprintScan>,
  trust: ReturnType<typeof resolveTrust>,
  toolOutputClassification: string | undefined,
  scanned_at: string
): ScanResult {
  const actionMap: Record<ScanVerdict, string> = {
    PASS: 'allow_persist',
    ADVISORY: 'allow_persist_with_flag',
    INJECT_SUSPECT: 'quarantine',
    BLOCK: 'discard',
  };

  return {
    scan_id,
    verdict,
    confidence: Math.round(confidence * 100) / 100,
    rules_fired: [...new Set(rules_fired)],
    details: {
      imperative_confidence: imp.confidence,
      fingerprint_matched: fp.matched,
      fingerprint_patterns: fp.patterns_hit,
      trust_classification: trust.classification,
      tool_output_classification: toolOutputClassification,
    },
    action: actionMap[verdict],
    scanned_at,
  };
}
