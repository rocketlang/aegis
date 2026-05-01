// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// EU AI Act Article 15 — Accuracy, Robustness, Cybersecurity evidence collector
// Article 15 requires: technical robustness — resilience to errors, faults, attack.
// PRAMANA receipt chain = evidence the system logged faithfully and wasn't tampered with.
// A gap in the chain = tampered or corrupted session = NOT Article 15 compliant.
//
// @rule:KOS-071 Article 15 evidence: PRAMANA receipt chain export as verifiable audit trail
// @rule:INF-KOS-003 chain gap → session is NOT audit-clean → reject as EU AI Act evidence

import { getDb } from "../core/db";
import { verifyReceiptChain, getReceiptChain } from "../kernel/profile-store";

export interface SessionChainResult {
  session_id: string;
  receipt_count: number;
  chain_intact: boolean;
  gap_at: string | null;
  first_receipt_at: string | null;
  last_receipt_at: string | null;
}

export interface Article15Evidence {
  article: "15";
  title: "Accuracy, Robustness, Cybersecurity";
  effective_date: "2026-08-02";
  period_from: string;
  period_to: string;
  total_sessions_with_receipts: number;
  total_receipts: number;
  intact_sessions: number;
  compromised_sessions: number;
  integrity_rate_pct: number;
  compliant: boolean;
  compliance_note: string;
  sessions: SessionChainResult[];
}

// @rule:KOS-071
export function collectArticle15Evidence(
  from: Date,
  to: Date
): Article15Evidence {
  const db = getDb();

  // Get distinct sessions that have receipts in the period
  const sessionRows = db.query(
    `SELECT DISTINCT session_id,
            MIN(sealed_at) as first_receipt_at,
            MAX(sealed_at) as last_receipt_at,
            COUNT(*) as receipt_count
     FROM kernel_receipts
     WHERE sealed_at >= ? AND sealed_at <= ?
     GROUP BY session_id`
  ).all(from.toISOString(), to.toISOString()) as Array<{
    session_id: string;
    first_receipt_at: string;
    last_receipt_at: string;
    receipt_count: number;
  }>;

  const sessions: SessionChainResult[] = sessionRows.map((row) => {
    // verifyReceiptChain walks the full chain for the session (not period-limited)
    // A gap anywhere in the chain disqualifies the session — KOS-071 / INF-KOS-003
    const verification = verifyReceiptChain(row.session_id);

    return {
      session_id: row.session_id,
      receipt_count: row.receipt_count,
      chain_intact: verification.valid,
      gap_at: verification.gap_at ?? null,
      first_receipt_at: row.first_receipt_at,
      last_receipt_at: row.last_receipt_at,
    };
  });

  const totalReceipts = sessions.reduce((s, r) => s + r.receipt_count, 0);
  const intact = sessions.filter((s) => s.chain_intact).length;
  const compromised = sessions.length - intact;
  const integrityRate = sessions.length > 0 ? Math.round((intact / sessions.length) * 100) : 100;
  const compliant = sessions.length === 0 || integrityRate === 100;

  return {
    article: "15",
    title: "Accuracy, Robustness, Cybersecurity",
    effective_date: "2026-08-02",
    period_from: from.toISOString(),
    period_to: to.toISOString(),
    total_sessions_with_receipts: sessions.length,
    total_receipts: totalReceipts,
    intact_sessions: intact,
    compromised_sessions: compromised,
    integrity_rate_pct: integrityRate,
    compliant,
    compliance_note: sessions.length === 0
      ? "No kernel sessions with receipts in period."
      : compliant
        ? `All ${sessions.length} session chains intact. ${totalReceipts} PRAMANA receipts verified.`
        : `${compromised} session(s) have broken receipt chains. Investigate immediately — these sessions are NOT admissible as Article 15 evidence.`,
    sessions,
  };
}
