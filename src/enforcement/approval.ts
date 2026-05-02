// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Approval Store — GATE decision management
//
// GATE = pause + request approval + allow only with token.
// This is NOT silent deny. The caller receives an approval_token and a
// continue_with endpoint. Without approval, the gate holds.
//
// @rule:AEG-E-012 — GATE means pause, not deny; approval_token is the key
// @rule:AEG-E-013 — approval tokens expire in 10 minutes; no stale overrides
// @rule:AEG-E-014 — bypass_reason is mandatory; blank reason is rejected

import { randomBytes } from "crypto";
import type { GateApprovalRecord, AegisEnforcementDecision } from "./types";

const APPROVAL_TTL_MS = 10 * 60 * 1000; // 10 minutes

// In-memory store — survives process restart only via decision log replay
// Bounded to 1000 entries; LRU eviction on overflow
const store = new Map<string, GateApprovalRecord>();
const MAX_STORE_SIZE = 1000;

function evictOldest(): void {
  const oldest = store.keys().next().value;
  if (oldest) store.delete(oldest);
}

// @rule:AEG-E-013 — generate token + set expiry; returned on every GATE decision
export function issueApprovalToken(decision: AegisEnforcementDecision): GateApprovalRecord {
  const token = randomBytes(16).toString("hex");
  const now = new Date();
  const expires = new Date(now.getTime() + APPROVAL_TTL_MS);

  const record: GateApprovalRecord = {
    token,
    service_id: decision.service_id,
    operation: decision.operation,
    requested_capability: decision.requested_capability,
    created_at: now.toISOString(),
    expires_at: expires.toISOString(),
    status: "pending",
    original_decision: decision,
  };

  if (store.size >= MAX_STORE_SIZE) evictOldest();
  store.set(token, record);
  return record;
}

// @rule:AEG-E-014 — bypass_reason required; empty string is rejected
export function approveToken(
  token: string,
  approval_reason: string,
  approved_by: string,
): { ok: boolean; record?: GateApprovalRecord; error?: string } {
  if (!approval_reason?.trim()) {
    return { ok: false, error: "bypass_reason is required and must not be blank (AEG-E-014)" };
  }

  const record = store.get(token);
  if (!record) return { ok: false, error: "approval token not found" };
  if (record.status !== "pending") return { ok: false, error: `token already ${record.status}` };

  if (new Date() > new Date(record.expires_at)) {
    record.status = "expired";
    return { ok: false, error: "approval token expired (TTL: 10 minutes)" };
  }

  record.status = "approved";
  record.approval_reason = approval_reason.trim();
  record.approved_by = approved_by;
  record.approved_at = new Date().toISOString();

  return { ok: true, record };
}

export function revokeToken(token: string): boolean {
  const record = store.get(token);
  if (!record || record.status !== "pending") return false;
  record.status = "revoked";
  return true;
}

export function getApproval(token: string): GateApprovalRecord | undefined {
  return store.get(token);
}

export function listPending(): GateApprovalRecord[] {
  const now = new Date();
  return [...store.values()].filter(r => {
    if (r.status === "pending" && new Date(r.expires_at) < now) {
      r.status = "expired"; // mark expired lazily
    }
    return r.status === "pending";
  });
}

export function pendingCount(): number {
  return listPending().length;
}

export function storeSize(): number {
  return store.size;
}
