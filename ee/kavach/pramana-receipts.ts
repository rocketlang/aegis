// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See ee/LICENSE-EE for terms.

// [EE] AEGIS — PRAMANA Audit Receipts
// Generates tamper-evident audit receipts for every KAVACH governance decision.
// Each receipt is a self-verifying artifact: the evidence + decision + hash form a chain.
// Protocol: PRAMANA v1.1 — DOI 10.5281/zenodo.19273330
// @rule:KAV-046 PRAMANA audit receipts for every DAN gate decision

import { createHash } from "crypto";
import { existsSync, mkdirSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../../src/core/config";

export type ReceiptVerdict = "ALLOWED" | "BLOCKED" | "QUARANTINED" | "TIMEOUT_BLOCKED" | "DUAL_APPROVED";
export type ReceiptCategory = "DAN_GATE" | "INJECTION_SHIELD" | "HANUMANG" | "BUDGET_STOP" | "WATCHDOG";

export interface PramanaEvidence {
  command?: string;
  tool_name?: string;
  agent_id?: string;
  session_id?: string;
  dan_level?: number;
  rule_id?: string;
  reason?: string;
  approver?: string;
  second_approver?: string;
  context?: Record<string, unknown>;
}

export interface PramanaReceipt {
  // PRAMANA v1.1 required fields
  pramana_version: "1.1";
  receipt_id: string;           // KAVACH-PRAMANA-{ulid}
  issued_at: string;            // ISO timestamp
  category: ReceiptCategory;
  verdict: ReceiptVerdict;

  // Evidence — what was observed
  evidence: PramanaEvidence;

  // Decision — what was decided and by what rule
  decision: {
    rule_applied: string;
    decision_path: string;       // e.g. "DAN_GATE -> L3 -> TIMEOUT_BLOCKED"
    human_in_loop: boolean;
    latency_ms: number;
  };

  // Chain — links this receipt to prior receipts for the same session
  chain: {
    session_receipt_count: number;
    prior_receipt_id: string | null;
    chain_hash: string;          // SHA-256(prior_chain_hash + receipt_id + verdict)
  };

  // Self-verification — the receipt can verify itself
  self_hash: string;             // SHA-256 of all fields except self_hash
}

// In-memory chain state per session — receipt count + last chain hash
const chainState = new Map<string, { count: number; last_id: string | null; last_chain_hash: string }>();

function ulid(): string {
  return `${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

export function issueReceipt(
  category: ReceiptCategory,
  verdict: ReceiptVerdict,
  evidence: PramanaEvidence,
  decision: Omit<PramanaReceipt["decision"], "latency_ms"> & { latency_ms?: number },
  startedAt?: number,
): PramanaReceipt {
  const receipt_id = `KAVACH-PRAMANA-${ulid()}`;
  const issued_at = new Date().toISOString();
  const latency_ms = startedAt ? Date.now() - startedAt : 0;
  const sessionKey = evidence.session_id ?? "unknown";

  // Chain
  const state = chainState.get(sessionKey) ?? { count: 0, last_id: null, last_chain_hash: "0000000000000000" };
  state.count++;
  const chain_hash = sha256(`${state.last_chain_hash}${receipt_id}${verdict}`);
  const chain: PramanaReceipt["chain"] = {
    session_receipt_count: state.count,
    prior_receipt_id: state.last_id,
    chain_hash,
  };
  state.last_id = receipt_id;
  state.last_chain_hash = chain_hash;
  chainState.set(sessionKey, state);

  // Build receipt without self_hash
  const partial = {
    pramana_version: "1.1" as const,
    receipt_id,
    issued_at,
    category,
    verdict,
    evidence,
    decision: { ...decision, latency_ms },
    chain,
  };

  const self_hash = sha256(JSON.stringify(partial));
  const receipt: PramanaReceipt = { ...partial, self_hash };

  // Persist to disk
  persistReceipt(receipt, sessionKey);

  return receipt;
}

function persistReceipt(receipt: PramanaReceipt, sessionKey: string): void {
  try {
    const dir = join(getAegisDir(), "pramana", sessionKey.slice(0, 16));
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${receipt.receipt_id}.json`), JSON.stringify(receipt, null, 2));
  } catch { /* non-fatal */ }
}

export function verifyReceipt(receipt: PramanaReceipt): { valid: boolean; reason: string } {
  const { self_hash, ...rest } = receipt;
  const expected = sha256(JSON.stringify(rest));
  if (expected !== self_hash) {
    return { valid: false, reason: `self_hash mismatch: expected ${expected}, got ${self_hash}` };
  }
  return { valid: true, reason: "PRAMANA receipt self-hash verified" };
}

export function listReceipts(sessionId: string): PramanaReceipt[] {
  try {
    const dir = join(getAegisDir(), "pramana", sessionId.slice(0, 16));
    if (!existsSync(dir)) return [];
    const { readdirSync } = require("fs");
    return readdirSync(dir)
      .filter((f: string) => f.endsWith(".json"))
      .map((f: string) => {
        try { return JSON.parse(readFileSync(join(dir, f), "utf-8")) as PramanaReceipt; }
        catch { return null; }
      })
      .filter(Boolean) as PramanaReceipt[];
  } catch { return []; }
}

export function getChainIntegrity(sessionId: string): { intact: boolean; receipt_count: number; broken_at: string | null } {
  const receipts = listReceipts(sessionId).sort((a, b) => a.chain.session_receipt_count - b.chain.session_receipt_count);
  if (receipts.length === 0) return { intact: true, receipt_count: 0, broken_at: null };

  let runningHash = "0000000000000000";
  for (const r of receipts) {
    const expected = sha256(`${runningHash}${r.receipt_id}${r.verdict}`);
    if (expected !== r.chain.chain_hash) {
      return { intact: false, receipt_count: receipts.length, broken_at: r.receipt_id };
    }
    runningHash = r.chain.chain_hash;
  }

  return { intact: true, receipt_count: receipts.length, broken_at: null };
}
