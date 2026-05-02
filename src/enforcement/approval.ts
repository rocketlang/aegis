// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// AEGIS Approval Store — full GATE lifecycle
//
// Lifecycle: pending → (approved → consumed) | denied | expired | revoked
//
// GATE = pause, not deny. The caller receives an approval_token and a
// continue_with endpoint. Without a valid approval, the gate holds.
//
// @rule:AEG-E-012 — GATE means pause, not deny; approval_token is the continuation key
// @rule:AEG-E-013 — tokens expire in 15 min; expired tokens cannot approve
// @rule:AEG-E-014 — approval_reason required; blank rejected
// @rule:AEG-E-015 — consumed tokens cannot be reused (replay protection)
// @rule:AEG-E-016 — token binds to service_id + operation + requested_capability; mismatch = reject
// @rule:AEG-E-017 — denial is a first-class outcome; logged as aegis.approval.v1

import { randomBytes } from "crypto";
import { appendFileSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import type { GateApprovalRecord, AegisEnforcementDecision } from "./types";

// @rule:AEG-E-013 — 15 minutes TTL (extended from Batch 18's 10 min)
const APPROVAL_TTL_MS = 15 * 60 * 1000;

// In-memory store — bounded, LRU-evict on overflow
// Survives only for process lifetime; decision log is the durable record
const store = new Map<string, GateApprovalRecord>();
const MAX_STORE_SIZE = 1000;

function evictOldest(): void {
  const oldest = store.keys().next().value;
  if (oldest) store.delete(oldest);
}

// ── Approval audit log ────────────────────────────────────────────────────────
// Separate from the decision log — tracks approval lifecycle events only
// schema_version: "aegis.approval.v1" so Pulse can distinguish

function resolveApprovalLogPath(): string {
  return process.env.AEGIS_APPROVAL_LOG_PATH ??
    join(process.env.HOME ?? "/root", ".aegis", "aegis_approval.log");
}

function logApprovalEvent(event: Record<string, unknown>): void {
  try {
    const path = resolveApprovalLogPath();
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const line = JSON.stringify({ schema_version: "aegis.approval.v1", ...event }) + "\n";
    appendFileSync(path, line, "utf-8");
  } catch {
    // log failure must never block approval decision
  }
}

// ── Lifecycle helpers ─────────────────────────────────────────────────────────

function isExpired(record: GateApprovalRecord): boolean {
  return new Date() > new Date(record.expires_at);
}

function markExpiredLazily(record: GateApprovalRecord): void {
  if (record.status === "pending" && isExpired(record)) {
    record.status = "expired";
    logApprovalEvent({
      event: "token_expired",
      token: record.token,
      service_id: record.service_id,
      operation: record.operation,
      expired_at: new Date().toISOString(),
    });
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

// @rule:AEG-E-013 — generate token + expiry; binds to (service_id, operation, capability)
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
    ttl_ms: APPROVAL_TTL_MS,
    status: "pending",
    original_decision: decision,
  };

  if (store.size >= MAX_STORE_SIZE) evictOldest();
  store.set(token, record);

  logApprovalEvent({
    event: "token_issued",
    token,
    service_id: decision.service_id,
    operation: decision.operation,
    requested_capability: decision.requested_capability,
    authority_class: decision.authority_class,
    governance_blast_radius: decision.governance_blast_radius,
    enforcement_phase: decision.enforcement_phase,
    expires_at: expires.toISOString(),
  });

  return record;
}

// @rule:AEG-E-014 — approval_reason required
// @rule:AEG-E-015 — consumed/denied/expired/revoked tokens cannot be re-approved
// @rule:AEG-E-016 — binding check: service_id + operation + capability must match token
export function approveToken(
  token: string,
  approval_reason: string,
  approved_by: string,
  binding?: { service_id?: string; operation?: string; requested_capability?: string },
): { ok: boolean; record?: GateApprovalRecord; error?: string } {
  if (!approval_reason?.trim()) {
    return { ok: false, error: "approval_reason is required and must not be blank (AEG-E-014)" };
  }
  if (!approved_by?.trim()) {
    return { ok: false, error: "approved_by is required" };
  }

  const record = store.get(token);
  if (!record) return { ok: false, error: "approval token not found" };

  markExpiredLazily(record);

  if (record.status !== "pending") {
    return { ok: false, error: `token already ${record.status} — replay protection (AEG-E-015)` };
  }

  // @rule:AEG-E-016 — binding check
  if (binding) {
    if (binding.service_id && binding.service_id !== record.service_id) {
      return { ok: false, error: `token binding mismatch: service_id '${binding.service_id}' != '${record.service_id}' (AEG-E-016)` };
    }
    if (binding.operation && binding.operation !== record.operation) {
      return { ok: false, error: `token binding mismatch: operation '${binding.operation}' != '${record.operation}' (AEG-E-016)` };
    }
    if (binding.requested_capability && binding.requested_capability !== record.requested_capability) {
      return { ok: false, error: `token binding mismatch: capability '${binding.requested_capability}' != '${record.requested_capability}' (AEG-E-016)` };
    }
  }

  const now = new Date().toISOString();
  record.status = "approved";
  record.approval_reason = approval_reason.trim();
  record.approved_by = approved_by.trim();
  record.approved_at = now;

  logApprovalEvent({
    event: "token_approved",
    token,
    service_id: record.service_id,
    operation: record.operation,
    requested_capability: record.requested_capability,
    approval_reason: record.approval_reason,
    approved_by: record.approved_by,
    approved_at: now,
  });

  return { ok: true, record };
}

// @rule:AEG-E-015 — consume after use; consumed token cannot be reused
export function consumeToken(token: string): boolean {
  const record = store.get(token);
  if (!record || record.status !== "approved") return false;
  record.status = "consumed";
  logApprovalEvent({
    event: "token_consumed",
    token,
    service_id: record.service_id,
    operation: record.operation,
    consumed_at: new Date().toISOString(),
  });
  return true;
}

// @rule:AEG-E-017 — denial is a first-class outcome
export function denyToken(
  token: string,
  denial_reason: string,
  denied_by: string,
): { ok: boolean; record?: GateApprovalRecord; error?: string } {
  if (!denial_reason?.trim()) {
    return { ok: false, error: "denial_reason is required" };
  }

  const record = store.get(token);
  if (!record) return { ok: false, error: "approval token not found" };

  markExpiredLazily(record);

  if (record.status !== "pending") {
    return { ok: false, error: `token already ${record.status} — cannot deny` };
  }

  const now = new Date().toISOString();
  record.status = "denied";
  record.denial_reason = denial_reason.trim();
  record.denied_by = denied_by.trim();
  record.denied_at = now;

  logApprovalEvent({
    event: "AEGIS_APPROVAL_DENIED",
    token,
    service_id: record.service_id,
    operation: record.operation,
    requested_capability: record.requested_capability,
    denial_reason: record.denial_reason,
    denied_by: record.denied_by,
    denied_at: now,
  });

  return { ok: true, record };
}

export function revokeToken(
  token: string,
  revoked_by?: string,
): boolean {
  const record = store.get(token);
  if (!record || record.status !== "pending") return false;
  const now = new Date().toISOString();
  record.status = "revoked";
  record.revoked_by = revoked_by;
  record.revoked_at = now;
  logApprovalEvent({
    event: "token_revoked",
    token,
    service_id: record.service_id,
    operation: record.operation,
    revoked_by: revoked_by ?? "system",
    revoked_at: now,
  });
  return true;
}

export function getApproval(token: string): GateApprovalRecord | undefined {
  const record = store.get(token);
  if (record) markExpiredLazily(record);
  return record;
}

export function listPending(): GateApprovalRecord[] {
  return [...store.values()].filter(r => {
    markExpiredLazily(r);
    return r.status === "pending";
  });
}

export function listAll(): GateApprovalRecord[] {
  [...store.values()].forEach(markExpiredLazily);
  return [...store.values()];
}

export function pendingCount(): number {
  return listPending().length;
}

export function storeSize(): number {
  return store.size;
}

export function approvalLogPath(): string {
  return resolveApprovalLogPath();
}

// ── Rollback drill ────────────────────────────────────────────────────────────
// Verify that kill switch forces shadow mode on all canary services.
// Returns a report suitable for logging — does not change env vars.

export interface RollbackDrillResult {
  drill_at: string;
  runtime_enabled_before: boolean;
  all_shadow_after_kill: boolean;
  services_checked: Array<{
    service_id: string;
    phase_before: string;
    phase_after_kill: string;
    tokens_issued: boolean;
    verdict: "ok" | "fail";
  }>;
  pending_tokens_before: number;
  verdict: "PASS" | "FAIL";
}

export function runRollbackDrill(
  evaluate: (req: { service_id: string; operation: string; requested_capability: string }) => { enforcement_phase: string; approval_token?: string },
  canaryServices: string[],
  operations: Array<{ operation: string; requested_capability: string }>,
): RollbackDrillResult {
  const now = new Date().toISOString();
  const pendingBefore = pendingCount();
  const runtimeBefore = process.env.AEGIS_RUNTIME_ENABLED !== "false";

  // Kill switch
  const savedEnabled = process.env.AEGIS_RUNTIME_ENABLED;
  process.env.AEGIS_RUNTIME_ENABLED = "false";

  const servicesChecked = canaryServices.map(svc => {
    let anyNotShadow = false;
    let anyToken = false;

    for (const op of operations) {
      const d = evaluate({ service_id: svc, ...op });
      if (d.enforcement_phase !== "shadow") anyNotShadow = true;
      if (d.approval_token) anyToken = true;
    }

    return {
      service_id: svc,
      phase_before: runtimeBefore ? "soft_canary" : "shadow",
      phase_after_kill: anyNotShadow ? "NOT_SHADOW" : "shadow",
      tokens_issued: anyToken,
      verdict: (!anyNotShadow && !anyToken) ? "ok" as const : "fail" as const,
    };
  });

  // Restore env
  if (savedEnabled === undefined) {
    delete process.env.AEGIS_RUNTIME_ENABLED;
  } else {
    process.env.AEGIS_RUNTIME_ENABLED = savedEnabled;
  }

  const allOk = servicesChecked.every(s => s.verdict === "ok");

  logApprovalEvent({
    event: "rollback_drill",
    drill_at: now,
    verdict: allOk ? "PASS" : "FAIL",
    services_checked: canaryServices,
    all_shadow_after_kill: allOk,
    pending_tokens_before: pendingBefore,
  });

  return {
    drill_at: now,
    runtime_enabled_before: runtimeBefore,
    all_shadow_after_kill: allOk,
    services_checked: servicesChecked,
    pending_tokens_before: pendingBefore,
    verdict: allOk ? "PASS" : "FAIL",
  };
}
