// SPDX-License-Identifier: AGPL-3.0-only
// Nallasetu — Protocol Types
// Five primitives: BRIDGE_HELLO → ATTEST_OFFER → INTERSECT_PROPOSE → SESSION_CREDENTIAL → SESSION_RECEIPT
// @rule:NLS-001 bilateral attestation — both sides required
// @rule:NLS-003 no bit escalation — session ceiling = A.mask AND B.mask AND scope.mask

export const PROTOCOL_VERSION = "nallasetu/0.1";
export const ATTESTATION_FORMAT = "ankr-hmudrika-v1";

// ── Primitive 1: BRIDGE_HELLO ─────────────────────────────────────────────────

export interface BridgeHello {
  protocol_version: string;          // "nallasetu/0.1"
  supported_formats: string[];       // attestation formats this party accepts
  initiator_id: string;              // agent/service identifier
  timestamp: string;                 // ISO8601
  nonce: string;                     // 32-byte hex, replay protection
}

// ── Primitive 2: ATTEST_OFFER ─────────────────────────────────────────────────

export interface AttestOffer {
  agent_id: string;
  trust_mask: number;                // 32-bit capability bitmask
  grade: "A" | "B" | "C" | "D";    // posture grade from HanumanG
  format: string;                    // attestation format version
  issued_at: string;                 // ISO8601
  expires_at: string;                // ISO8601 — NLS-006 mandatory TTL
  nonce: string;                     // from BRIDGE_HELLO, binds to session
  signature: string;                 // HMAC-SHA256 of canonical payload, base64
  public_key_id: string;             // key ID in registry — NLS-002
}

// ── Primitive 3: INTERSECT_PROPOSE ───────────────────────────────────────────

export interface IntersectPropose {
  initiator_mask: number;
  responder_mask: number;
  scope_mask: number;                // requested session scope
  session_mask: number;              // = initiator_mask & responder_mask & scope_mask — NLS-003
  proposed_ttl_seconds: number;      // per NLS-006
  session_class: "ephemeral" | "conversational" | "autonomous";
}

// ── Primitive 4: SESSION_CREDENTIAL ──────────────────────────────────────────

export interface SessionCredential {
  session_id: string;
  initiator_id: string;
  responder_id: string;
  session_mask: number;              // capability ceiling for this session
  session_class: string;
  issued_at: string;
  expires_at: string;                // NLS-006
  credential_hash: string;           // SHA-256 of canonical session fields
  witness_nonce: string;             // for PRAMANA binding
}

// ── Primitive 5: SESSION_RECEIPT ─────────────────────────────────────────────

export interface SessionReceipt {
  session_id: string;
  initiator_id: string;
  responder_id: string;
  session_mask: number;
  outcome: "completed" | "revoked" | "expired" | "early_termination";
  early_termination?: boolean;
  termination_reason?: string;
  receipt_hash: string;              // SHA-256 of credential + outcome
  pramana_witness: string;           // chain hash — NLS-010
  issued_at: string;
  rule_ref: "NLS-010";
}

// ── Handshake request / result ────────────────────────────────────────────────

export interface HandshakeRequest {
  initiator: {
    agent_id: string;
    trust_mask: number;
    grade?: "A" | "B" | "C" | "D";
  };
  scope_mask: number;                // what the initiator wants to do
  session_class?: "ephemeral" | "conversational" | "autonomous";
  responder_id: string;              // who they want to talk to
}

export type HandshakeDecision =
  | "session_issued"
  | "attestation_unverifiable"
  | "no_common_capability"
  | "scope_counter_proposed"
  | "handshake_rate_limit_exceeded"
  | "handshake_timeout"
  | "attestation_format_incompatible";

export interface HandshakeResult {
  decision: HandshakeDecision;
  session?: SessionCredential;
  receipt?: SessionReceipt;
  intersect?: IntersectPropose;
  counter_scope_mask?: number;       // NLS-YK-003 counter-proposal
  error?: string;
  policy_hash: string;
  latency_ms: number;
  rule_ref: string;
}

// ── DB row types ──────────────────────────────────────────────────────────────

export interface SessionRow {
  session_id: string;
  initiator_id: string;
  responder_id: string;
  session_mask: number;
  session_class: string;
  credential_json: string;
  receipt_json: string | null;
  status: "active" | "expired" | "revoked";
  issued_at: string;
  expires_at: string;
  pramana_hash: string;
}

export interface KeyRegistryRow {
  agent_id: string;
  hmac_secret: string;               // shared secret for HMAC-SHA256 attestation signing
  public_key_id: string;
  trust_mask: number;                // capability ceiling — never auto-granted all-bits (Bit 10)
  registered_at: string;
  source: "self" | "sakshi" | "registry";
  revoked?: number;                  // 1 = revoked — NLS-YK-008 known-revoked partner → REJECT
}
