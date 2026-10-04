// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-010 — scan confidence threshold is tuneable above a floor
// @rule:CG-YK-001 — combines imperative scanner + trust classifier + fingerprint scanner
//
// Orchestrator that combines all four primitive detectors into a single
// PASS / ADVISORY / INJECT_SUSPECT / BLOCK verdict. Pure — no service deps.

import { scan as imperativeScan, scanText as imperativeHits, confidenceOf as imperativeConfidence } from './imperative.js';
import { resolve as resolveTrust } from './trust.js';
import { scan as fingerprintScan, scanText as fingerprintHits } from './fingerprint.js';
import { views } from './normalize.js';
import { classify as classifyToolOutput } from './tool-output.js';
import type { SourceMetadata } from './trust.js';
import { emitAccReceipt } from './acc-bus.js';

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

// @rule:CG-015 — an ambiguous phrase alone is flagged; it is quarantined only when corroborated
//
// "You can now download the invoice" and "you are now listed as Senior Engineer" match the
// same patterns as an attack. Quarantining them makes the guard unusable on ordinary text,
// and a guard that is switched off protects nothing. So:
//   - any UNAMBIGUOUS hit decides as before (the heaviest signal wins);
//   - ambiguous hits only: AMBIGUOUS_ALONE (an ADVISORY at default thresholds), unless two
//     of them sit in different places AND are about different things, which is
//     AMBIGUOUS_CORROBORATED (an INJECT_SUSPECT at default thresholds).
// An untrusted source still multiplies the result, and ELEVATED_SCRUTINY still turns an
// ADVISORY into an INJECT_SUSPECT, so a caller who wants the strict behaviour has it.
const AMBIGUOUS_ALONE = 0.70;
const AMBIGUOUS_CORROBORATED = 0.80;

const FAMILY: Record<string, string> = {
  identity_claim: 'identity', identity_override: 'identity',
  capability_expansion: 'capability',
  constraint_override: 'constraint', constraint_bypass: 'constraint',
  role_instruction: 'role', agent_role_instruction: 'role',
};

interface Signal { family: string; start: number; end: number }

// Two ambiguous signals corroborate each other when they do not overlap in the text and
// have no family in common. "You are now allowed to" matches an identity pattern and a
// capability pattern on the same words: that is one signal, not two.
function corroborated(signals: Signal[]): boolean {
  const groups: { start: number; end: number; families: Set<string> }[] = [];
  for (const s of [...signals].sort((a, b) => a.start - b.start)) {
    const last = groups[groups.length - 1];
    if (last && s.start < last.end) {
      last.end = Math.max(last.end, s.end);
      last.families.add(s.family);
    } else {
      groups.push({ start: s.start, end: s.end, families: new Set([s.family]) });
    }
  }
  for (let i = 0; i < groups.length; i++) {
    for (let j = i + 1; j < groups.length; j++) {
      if (![...groups[i].families].some((f) => groups[j].families.has(f))) return true;
    }
  }
  return false;
}

// The combined confidence for one view of the text.
//
// `onlyBecauseCollapsed` holds the keys of hits that exist in this view and not in the
// view it was collapsed from — matches made by turning `ignore_previous` or
// `system-override` into two words. Code, flags and manuals write those every day, so
// such a hit is ambiguous whatever its pattern says (CG-014).
function combineView(view: string, trustMultiplier: number, parentView?: string): number {
  let fps = fingerprintHits(view);
  let imps = imperativeHits(view);
  if (parentView !== undefined) {
    const inParent = new Set<string>([...fingerprintHits(parentView), ...imperativeHits(parentView)].map((h) => h.key));
    fps = fps.map((h) => (inParent.has(h.key) ? h : { ...h, ambiguous: true }));
    imps = imps.map((h) => (inParent.has(h.key) ? h : { ...h, ambiguous: true }));
  }
  const clearFp = fps.filter((h) => !h.ambiguous);
  const clearImp = imps.filter((h) => !h.ambiguous);
  if (clearFp.length > 0 || clearImp.length > 0) {
    let c = clearFp.reduce((m, h) => Math.max(m, h.confidence), 0);
    if (clearImp.length > 0) c = Math.max(c, Math.min(0.99, imperativeConfidence(imps) * trustMultiplier));
    return c;
  }
  if (fps.length === 0 && imps.length === 0) return 0;
  const signals: Signal[] = [
    ...fps.map((h) => ({ family: FAMILY[h.category] ?? h.category, start: h.start, end: h.end })),
    ...imps.map((h) => ({ family: FAMILY[h.category] ?? h.category, start: h.start, end: h.end })),
  ];
  const base = corroborated(signals)
    ? AMBIGUOUS_CORROBORATED
    : Math.min(AMBIGUOUS_ALONE, Math.max(imperativeConfidence(imps), fps.length > 0 ? AMBIGUOUS_ALONE : 0));
  return Math.min(0.99, base * trustMultiplier);
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

  // The strongest result over the views of the text (normalize.ts), each combined under CG-015.
  const trustMultiplier = trust.classification === 'UNTRUSTED' ? 1.15 : 1.0;
  let combinedConfidence = 0;
  const all = views(content);
  for (const view of all) {
    const parent = view.parent === undefined ? undefined : all[view.parent].text;
    combinedConfidence = Math.max(combinedConfidence, combineView(view.text, trustMultiplier, parent));
  }

  let verdict: ScanVerdict;
  if (combinedConfidence >= thresholds.block_threshold) {
    verdict = 'BLOCK';
  } else if (combinedConfidence >= thresholds.inject_suspect_threshold) {
    verdict = 'INJECT_SUSPECT';
    // CG-YK-006: the verdict is INJECT_SUSPECT only because ELEVATED_SCRUTINY lowered the
    // threshold. The rule id used to be pushed in the branch below, which the lowered
    // threshold made unreachable (CD-049b); it is recorded here, where the promotion happens.
    if (posture === 'ELEVATED_SCRUTINY' && combinedConfidence < clampThresholds(thresholdConfig, 'NORMAL').inject_suspect_threshold) {
      rules_fired.push('CG-YK-006');
    }
  } else if (combinedConfidence >= thresholds.advisory_floor) {
    verdict = posture === 'ELEVATED_SCRUTINY' ? 'INJECT_SUSPECT' : 'ADVISORY';
    if (posture === 'ELEVATED_SCRUTINY') rules_fired.push('CG-YK-006');
  } else {
    verdict = 'PASS';
  }

  const result = buildResult(scan_id, verdict, combinedConfidence, rules_fired, imp, fp, trust, toolOutputClassification, scanned_at);

  // @rule:ACC-003 @rule:ACC-004 — emit cockpit receipt (no-op when bus unset)
  emitAccReceipt({
    receipt_id: scan_id,
    event_type: 'scan.evaluated',
    agent_id: agentContext.agent_id,
    verdict: result.verdict,
    rules_fired: result.rules_fired,
    summary: `${agentContext.scan_type ?? 'memory_write'} → ${result.verdict} (confidence=${result.confidence}, action=${result.action})`,
    payload: {
      scan_type: agentContext.scan_type,
      posture: agentContext.posture,
      confidence: result.confidence,
      fingerprint_matched: result.details.fingerprint_matched,
      tool_output_classification: result.details.tool_output_classification,
    },
  });

  return result;
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
