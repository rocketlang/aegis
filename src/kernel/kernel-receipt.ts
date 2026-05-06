// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-005 PRAMANA seal for every kernel violation event

import { createHash, randomBytes } from "crypto";
import { recordKernelReceipt, getReceiptChain } from "./profile-store";

// @rule:KAV-089 DAN_APPROVAL added — every human approval sealed as PRAMANA receipt
export type KernelEventType = "SECCOMP_BLOCK" | "FALCO_ALERT" | "PROFILE_DRIFT" | "RATE_EXCEEDED" | "DAN_APPROVAL";

export interface KernelViolationEvent {
  session_id: string;
  agent_id: string | null;
  event_type: KernelEventType;
  syscall?: string;
  falco_rule?: string;
  violation_details?: string;
  profile_hash?: string;
  severity?: "WARN" | "ERROR" | "CRITICAL";
  delegation_depth?: number;  // @rule:KOS-094 — depth sealed into receipt hash
}

export interface KernelReceipt {
  receipt_id: string;
  session_id: string;
  event_type: KernelEventType;
  receipt_hash: string;
  prev_receipt_hash: string | null;
  sealed_at: string;
  delegation_depth: number;   // @rule:KOS-094 — depth regression between receipts = tamper indicator
  pramana_version: "1.1";
  rule_ref: "KOS-005";
}

// @rule:KOS-005 seal every kernel violation as a PRAMANA receipt with SHA-256 chain
// @rule:KOS-094 delegation_depth is mandatory in every receipt — depth sealed into hash
export function sealKernelViolation(event: KernelViolationEvent): KernelReceipt {
  const receiptId = `KOS-PRAMANA-${randomBytes(8).toString("hex").toUpperCase()}`;
  const sealedAt = new Date().toISOString();
  const delegationDepth = event.delegation_depth ?? 1;

  // Get the hash of the last receipt in this session's chain (for chain linkage)
  const chain = getReceiptChain(event.session_id);
  const prevHash = chain.length > 0 ? chain[chain.length - 1].receipt_hash : null;

  // Receipt hash: SHA-256 of (receiptId|sessionId|eventType|sealedAt|prevHash|delegationDepth)
  // @rule:KOS-094 depth included in hash — depth regression between sequential receipts = tamper
  const receiptHash = createHash("sha256")
    .update(`${receiptId}|${event.session_id}|${event.event_type}|${sealedAt}|${prevHash ?? "GENESIS"}|${delegationDepth}`)
    .digest("hex");

  recordKernelReceipt(receiptId, event.session_id, event.agent_id ?? null, event.event_type, {
    syscall: event.syscall,
    falco_rule: event.falco_rule,
    severity: event.severity ?? "WARN",
    violation_details: event.violation_details,
    profile_hash: event.profile_hash,
    prev_receipt_hash: prevHash ?? undefined,
    receipt_hash: receiptHash,
    delegation_depth: delegationDepth,
  });

  return {
    receipt_id: receiptId,
    session_id: event.session_id,
    event_type: event.event_type,
    receipt_hash: receiptHash,
    prev_receipt_hash: prevHash,
    sealed_at: sealedAt,
    delegation_depth: delegationDepth,
    pramana_version: "1.1",
    rule_ref: "KOS-005",
  };
}

// Parse Falco output line (stdout from falco --json-output)
// Format: {"output":"...","priority":"...","rule":"...","time":"...","output_fields":{...}}
export function parseFalcoEvent(line: string): KernelViolationEvent | null {
  try {
    const parsed = JSON.parse(line);
    const priority = (parsed.priority ?? "WARNING").toUpperCase();
    const severity: "WARN" | "ERROR" | "CRITICAL" =
      priority === "CRITICAL" || priority === "ERROR" ? "CRITICAL" :
      priority === "WARNING" ? "WARN" : "WARN";

    return {
      session_id: parsed.output_fields?.proc_env?.KAVACHOS_SESSION_ID ?? "unknown",
      agent_id: parsed.output_fields?.proc_env?.KAVACHOS_AGENT_ID ?? null,
      event_type: "FALCO_ALERT",
      falco_rule: parsed.rule,
      violation_details: parsed.output,
      severity,
    };
  } catch {
    return null;
  }
}

// @rule:INF-KOS-002 rate check: >5 violations/min → emit rate_exceeded event
export function checkViolationRate(
  events: KernelReceipt[],
  windowMs: number = 60_000
): boolean {
  const cutoff = Date.now() - windowMs;
  const recent = events.filter((e) => new Date(e.sealed_at).getTime() > cutoff);
  return recent.length > 5;
}
