// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Aegis ABAC Authorization Gate — 6-condition evaluation
// POST /api/v1/aegis/authorize
//
// @rule:AGS-001 Aegis is the ABAC binding layer — one question, real time
// @rule:AGS-008 6-condition gate: chain / expiry / mask / depth / scope / value
// @rule:AGS-010 human_in_loop_required=true → 202 pending + escalation_id
// @rule:AGS-015 every authorize decision sealed as PRAMANA receipt (audit_id)
// @rule:INF-AGS-001 mask_overflow → CHAIN_BROKEN + quarantine issuing agent
// @rule:INF-AGS-002 expired token → TOKEN_EXPIRED → re-delegate or escalate
// @rule:INF-AGS-003 CHAIN_NOT_FOUND → ambiguous, human review required
// @rule:INF-AGS-004 depth_limit_reached → block spawn, don't quarantine
// @rule:INF-AGS-005 human_in_loop + depth>2 + financial → DAN-3
// @rule:INF-AGS-006 effective_mask=0 → ZERO_CAPABILITY → config error

import { randomUUID } from "crypto";
import type { AuthorizeRequest, AuthorizeResponse } from "./types";
import { validateChain, isExpired } from "./sdt";
import { getDb } from "../core/db";
import { addAlert } from "../core/db";

// ── Audit seal ────────────────────────────────────────────────────────────────

function sealAudit(
  agentId: string,
  resource: string,
  action: string,
  authorized: boolean,
  reason: string,
  effectiveMask: number,
  latencyUs: number,
): string {
  const auditId = randomUUID();
  const db = getDb();
  try {
    db.run(
      `INSERT INTO sdt_authorize_log
         (audit_id, agent_id, resource, action, authorized, reason, effective_mask, latency_us, decided_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [auditId, agentId, resource, action, authorized ? 1 : 0, reason, effectiveMask, latencyUs,
       new Date().toISOString()],
    );
  } catch { /* non-fatal — audit failure never blocks */ }
  return auditId;
}

// ── Escalation store ──────────────────────────────────────────────────────────

function createEscalation(agentId: string, resource: string, action: string): string {
  const escalationId = randomUUID();
  const db = getDb();
  db.run(
    `INSERT INTO sdt_escalations
       (escalation_id, agent_id, resource, action, status, created_at)
     VALUES (?, ?, ?, ?, 'pending', ?)`,
    [escalationId, agentId, resource, action, new Date().toISOString()],
  );
  return escalationId;
}

export function getEscalation(escalationId: string): {
  status: "pending" | "approved" | "rejected";
  decided_at?: string;
} | null {
  const db = getDb();
  const row = db.query<
    { status: string; decided_at: string | null },
    [string]
  >("SELECT status, decided_at FROM sdt_escalations WHERE escalation_id = ? LIMIT 1")
    .get(escalationId);
  if (!row) return null;
  return {
    status: row.status as "pending" | "approved" | "rejected",
    decided_at: row.decided_at ?? undefined,
  };
}

export function decideEscalation(escalationId: string, decision: "approved" | "rejected"): boolean {
  const db = getDb();
  const r = db.run(
    "UPDATE sdt_escalations SET status = ?, decided_at = ? WHERE escalation_id = ? AND status = 'pending'",
    [decision, new Date().toISOString(), escalationId],
  );
  return (r.changes ?? 0) > 0;
}

// ── Task scope check ──────────────────────────────────────────────────────────

// task_scope entries: "resource.action" (exact) or "resource.*" (all actions on resource)
function inTaskScope(scope: string[], resource: string, action: string): boolean {
  const exact = `${resource}.${action}`;
  const wildcard = `${resource}.*`;
  return scope.some(s => s === exact || s === wildcard || s === resource);
}

// ── The 6-condition gate ──────────────────────────────────────────────────────

export async function authorize(req: AuthorizeRequest): Promise<AuthorizeResponse> {
  const start = process.hrtime.bigint();
  const token = req.agent_token;
  const agentId = token.identity.agent_id;
  let effectiveMask = 0;

  const deny = (reason: string): AuthorizeResponse => {
    const latency = Number(process.hrtime.bigint() - start) / 1000;
    const auditId = sealAudit(agentId, req.resource, req.action, false, reason, effectiveMask, latency);
    return { status: "denied", authorized: false, reason, audit_id: auditId, depth: token.delegation.depth, effective_mask: effectiveMask };
  };

  // ── Condition 1: chain_hash valid and unbroken ─────────────────────────────
  // @rule:AGS-005 @rule:AGS-012 @rule:INF-AGS-001 @rule:INF-AGS-003
  const chainResult = validateChain(token);
  if (!chainResult.valid) {
    const isOverflow = chainResult.reason === "MASK_OVERFLOW";
    if (isOverflow) {
      // INF-AGS-001: mask_overflow → alert + flag issuing agent
      try {
        addAlert("sdt_mask_overflow", "critical",
          `SDT mask overflow detected for agent ${agentId} — possible forged token`,
          agentId);
      } catch {}
    }
    return deny(chainResult.reason);
  }
  effectiveMask = chainResult.effective_mask;

  // INF-AGS-006: effective_mask=0 → ZERO_CAPABILITY
  if (effectiveMask === 0) {
    try {
      addAlert("sdt_zero_capability", "warning",
        `Agent ${agentId} has effective_mask=0 — delegation chain narrowed to zero bits`,
        agentId);
    } catch {}
    return deny("ZERO_CAPABILITY");
  }

  // ── Condition 2: token not expired ────────────────────────────────────────
  // @rule:AGS-009 @rule:INF-AGS-002
  if (isExpired(token)) {
    return deny("TOKEN_EXPIRED");
  }

  // ── Condition 3: trust_mask & requested_capability ≠ 0 ───────────────────
  // Map resource.action to a capability bit. For now we use a simple convention:
  // if the effective_mask has READ bit (2) and action is a read, or WRITE (3) and write, etc.
  // The caller passes context; we check if ANY bit in effective_mask is set that covers
  // the requested resource class. Full bit→resource mapping lives in the BITS constants.
  // Simplified: if effective_mask > 0 and scope passes → capability check passes.
  // TODO: wire per-bit resource mapping (separate PR)
  const hasCapability = effectiveMask > 0;
  if (!hasCapability) {
    return deny("CAPABILITY_DENIED");
  }

  // ── Condition 4: delegation_depth < max_depth ─────────────────────────────
  // @rule:AGS-006 @rule:INF-AGS-004
  if (token.delegation.depth >= token.delegation.max_depth) {
    return deny("DEPTH_LIMIT_REACHED");
  }

  // ── Condition 5: requested_capability ∈ task_scope ───────────────────────
  if (token.delegation.task_scope.length > 0 &&
      !inTaskScope(token.delegation.task_scope, req.resource, req.action)) {
    return deny("OUT_OF_SCOPE");
  }

  // ── Condition 6: financial limit ─────────────────────────────────────────
  const txValue = req.context?.value ?? 0;
  const maxTx = token.delegation.max_transaction_value;
  if (maxTx > 0 && txValue > maxTx) {
    return deny("TRANSACTION_LIMIT_EXCEEDED");
  }

  // ── All 6 passed ─────────────────────────────────────────────────────────

  // human_in_loop_required check (AGS-010, INF-AGS-005)
  const needsHIL = token.delegation.human_in_loop_required
    || (token.delegation.depth > 2 && txValue > 0); // INF-AGS-005 auto-escalate

  if (needsHIL) {
    const escalationId = createEscalation(agentId, req.resource, req.action);
    const latency = Number(process.hrtime.bigint() - start) / 1000;
    const auditId = sealAudit(agentId, req.resource, req.action, false, "HIL_PENDING", effectiveMask, latency);
    // Fire DAN-3 alert for awareness
    try {
      addAlert("sdt_hil_required", "warning",
        `Human-in-loop required for agent ${agentId}: ${req.resource}.${req.action}`,
        agentId);
    } catch {}
    return {
      status: "pending",
      authorized: false,
      reason: "HIL_PENDING",
      audit_id: auditId,
      depth: token.delegation.depth,
      effective_mask: effectiveMask,
      escalation_id: escalationId,
    };
  }

  // Authorized
  const latency = Number(process.hrtime.bigint() - start) / 1000;
  const auditId = sealAudit(agentId, req.resource, req.action, true, "AUTHORIZED", effectiveMask, latency);
  return {
    status: "authorized",
    authorized: true,
    reason: "AUTHORIZED",
    audit_id: auditId,
    depth: token.delegation.depth,
    effective_mask: effectiveMask,
  };
}
