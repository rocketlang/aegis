// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Enforcement Layer — Type definitions
//
// @rule:AEG-E-001 — enforcement mode progresses shadow → soft → hard; never skip stages
// @rule:AEG-E-002 — READ operations must flow freely unless structurally blocked
// @rule:AEG-E-003 — TIER-C and TIER-D services remain monitor-only; never enforce
// @rule:AEG-E-004 — TIER-E blocks from runtime authority regardless of other fields
// @rule:AEG-E-005 — every gate decision is logged; log failure never blocks the decision
// @rule:AEG-E-006 — kill switch AEGIS_RUNTIME_ENABLED=false bypasses all enforcement
// @rule:AEG-E-007 — pilot scope is TIER-A services only until logs prove no false positives

export type EnforcementMode = "shadow" | "soft" | "hard";

export type OperationRisk = "low" | "medium" | "high" | "critical";

export type GateDecision = "ALLOW" | "WARN" | "GATE" | "BLOCK";

export type RuntimeReadinessTier = "TIER-A" | "TIER-B" | "TIER-C" | "TIER-D" | "TIER-E";

export type AuthorityClass =
  | "read_only"
  | "internal_write"
  | "execution"
  | "external_call"
  | "governance"
  | "deploy"
  | "financial";

export interface ServiceRegistryEntry {
  trust_mask: number;
  authority_class: AuthorityClass;
  governance_blast_radius: string;
  human_gate_required: boolean;
  needs_code_scan: boolean;
  aegis_gate: {
    overall: string;
    op1_read: string;
    op2_write: string;
    op3_execute: string;
    op4_deploy: string;
    op5_approve: string;
    gate_version?: string;
  };
  runtime_readiness: {
    tier: RuntimeReadinessTier;
    description: string;
    reason: string;
  };
  semantic_mask?: number;
}

export interface AegisEnforcementRequest {
  service_id: string;
  operation: string;
  requested_capability: string;
  caller_id?: string;
  session_id?: string;
  metadata?: Record<string, unknown>;
}

export interface AegisEnforcementDecision {
  service_id: string;
  operation: string;
  requested_capability: string;
  trust_mask: number;
  trust_mask_hex: string;
  authority_class: AuthorityClass;
  governance_blast_radius: string;
  runtime_readiness_tier: RuntimeReadinessTier;
  aegis_gate_result: string;
  enforcement_mode: EnforcementMode;
  decision: GateDecision;
  reason: string;
  pilot_scope: boolean;
  dry_run: boolean;
  timestamp: string;
  caller_id?: string;
  session_id?: string;
}

// Operations classified by risk
export const OPERATION_RISK_MAP: Record<string, OperationRisk> = {
  // READ always low
  read:   "low",
  get:    "low",
  list:   "low",
  query:  "low",
  search: "low",
  fetch:  "low",
  health: "low",
  state:  "low",
  // WRITE medium
  write:  "medium",
  update: "medium",
  create: "medium",
  patch:  "medium",
  // EXECUTE high
  execute:  "high",
  trigger:  "high",
  approve:  "high",
  reject:   "high",
  emit:     "high",
  // DEPLOY / FINANCIAL / DESTRUCTIVE critical
  deploy:   "critical",
  delete:   "critical",
  destroy:  "critical",
  "bl-issue":  "critical",
  "bл_issue":  "critical",
  book:     "critical",
  "rate-desk": "critical",
  "rate_desk": "critical",
  "ai-execute": "critical",
  "ai_execute": "critical",
  financial: "critical",
};

// High-consequence trust_mask bits — operations involving these always critical
// From @ankr/trust-constants: BOOK=8, BL_ISSUE=10, RATE_DESK=11, AI_EXECUTE=27, APPROVE=4
export const HIGH_CONSEQUENCE_BITS = (1 << 8) | (1 << 10) | (1 << 11) | (1 << 27) | (1 << 4);
