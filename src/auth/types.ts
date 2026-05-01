// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// 5-Dimensional Agent Authorization — Type Definitions
// @rule:AGS-002 five dimensions: Identity / Capability / Context / Provenance / Depth
// @rule:AGS-003 SDT = Nallasetu identity claim + Aegis delegation envelope
// @rule:AGS-007 12-field mandatory ABAC attribute set

export type AgentClass = "orchestrator" | "worker" | "reader" | "delegator";

// The Scoped Delegation Token — the artifact that carries dimensions 1-4.
// Dimension 5 (Depth) is enforced at issuance + validated at authorize time.
export interface ScopedDelegationToken {
  token_id: string;          // UUID, unique per issued token
  // Dimension 1 — Identity (signed by Nallasetu cross-org or "local" intra-org)
  identity: {
    agent_id: string;
    agent_class: AgentClass;
    spawner_id: string;      // "human:{session_id}" | parent agent_id
    signed_by: "nallasetu" | "local";
    signature?: string;      // Ed25519 signature from Nallasetu; omitted for local
  };
  // Dimensions 2-5 — Delegation (issued by Aegis)
  delegation: {
    delegated_mask: number;           // trust_mask bits granted to this agent
    depth: number;                    // 0 = human-direct, +1 per hop
    max_depth: number;                // hard cap on further delegation
    task_scope: string[];             // ["booking.vessel", "vessel.read"] — resource.action pairs
    max_transaction_value: number;    // 0 = no limit
    chain_hash: string;               // SHA-256 of parent SDT canonical JSON (or genesis sentinel)
    expiry: string;                   // ISO-8601 or "task_end"
    human_in_loop_required: boolean;
    origin_org: string;
  };
  issued_at: string;  // ISO-8601
}

export interface AuthorizeRequest {
  agent_token: ScopedDelegationToken;
  resource: string;    // e.g. "vessel.booking"
  action: string;      // e.g. "create"
  context?: {
    value?: number;      // transaction value — checked against max_transaction_value
    target_org?: string;
  };
}

export type AuthorizeStatus = "authorized" | "denied" | "pending";

export interface AuthorizeResponse {
  status: AuthorizeStatus;
  authorized: boolean;
  reason: string;
  audit_id: string;
  depth: number;
  effective_mask: number;
  escalation_id?: string;   // set when human_in_loop_required=true (status=pending)
}

export interface SdtIssueRequest {
  agent_id: string;
  agent_class: AgentClass;
  spawner_id: string;
  parent_token_id?: string;    // omit for root (human-issued) tokens
  requested_mask: number;      // Aegis will AND with parent effective_mask
  task_scope: string[];
  max_transaction_value?: number;
  max_depth?: number;
  expiry?: string;             // ISO-8601 or "task_end" (default)
  human_in_loop_required?: boolean;
  origin_org?: string;
}

export interface SdtIssueResponse {
  token: ScopedDelegationToken;
  effective_mask: number;
}
