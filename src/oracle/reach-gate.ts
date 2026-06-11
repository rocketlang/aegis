// BitMask OS Phase 2 — Reach Gate (cross-service)
// @rule:BMOS-006 Reach gate: (caller_trust_mask & target.reach_permissions[caller_class]) !== 0
// @rule:BMOS-YK-002 reach_permissions derived from depends_on; string stays for humans, integer enforces
// @rule:BMOS-YK-004 services with depends_on but no reach_permissions are the gap set
//
// Closes the cross-service gap: `depends_on` is a descriptive string array — any
// service can list any dependency without capability proof. The reach gate replaces
// the string check with an integer gate, exactly as the spawn gate did for spawning.
//
// Rollout mirrors GTP's L0→L2 ladder: a target with NO reach_permissions yields
// UNDECLARED (callers log, never block) so enforcement can graduate service-by-service
// without a fleet-wide flag day. A declared entry is binary: AUTHORIZED or DENIED.

import { appendFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { randomUUID } from "crypto";

const SESSIONS_DIR = join(process.env.HOME ?? "/root", ".aegis", "sessions");
const REACH_AUDIT_FILE = join(SESSIONS_DIR, "reach-audit.jsonl");

/** Caller classes align with GTP driver classes + the canonical AGI tier. */
export type CallerClass = "service" | "agent" | "human";

/** Per-target declaration: which bits a caller of each class must hold. "*" = default (0 = deny). */
export interface ReachPermissions {
  [callerClass: string]: number;
}

export type ReachStatus = "AUTHORIZED" | "DENIED" | "UNDECLARED";

export interface ReachVerdict {
  audit_ref: string;
  status: ReachStatus;
  caller_id: string;
  caller_class: CallerClass;
  caller_trust_mask: number;
  target_id: string;
  required_mask: number | null; // null = target has no reach_permissions (UNDECLARED)
  matched_bits: number;
}

// @rule:BMOS-006 — the gate is one bitwise AND, no string interpretation
export function checkReachGate(
  callerId: string,
  callerTrustMask: number,
  callerClass: CallerClass,
  targetId: string,
  targetReachPermissions: ReachPermissions | null | undefined,
): ReachVerdict {
  let status: ReachStatus;
  let required: number | null = null;
  let matched = 0;

  if (!targetReachPermissions || Object.keys(targetReachPermissions).length === 0) {
    status = "UNDECLARED"; // migration state — callers log, never block (BMOS-YK-004 gap set)
  } else {
    required = (targetReachPermissions[callerClass] ?? targetReachPermissions["*"] ?? 0) >>> 0;
    matched = ((callerTrustMask >>> 0) & required) >>> 0;
    status = matched !== 0 ? "AUTHORIZED" : "DENIED";
  }

  const verdict: ReachVerdict = {
    audit_ref: randomUUID(),
    status,
    caller_id: callerId,
    caller_class: callerClass,
    caller_trust_mask: callerTrustMask >>> 0,
    target_id: targetId,
    required_mask: required,
    matched_bits: matched,
  };
  writeReachAudit(verdict);
  return verdict;
}

// Append-only JSONL, fail-open on audit error (same as spawn gate — SOR-004)
function writeReachAudit(v: ReachVerdict): void {
  try {
    if (!existsSync(SESSIONS_DIR)) mkdirSync(SESSIONS_DIR, { recursive: true });
    appendFileSync(REACH_AUDIT_FILE, JSON.stringify({ ...v, checked_at: new Date().toISOString() }) + "\n", "utf-8");
  } catch {
    // never block a reach check on audit failure
  }
}
