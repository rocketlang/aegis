// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — PRAMANA emit bridge (AGPL core → BSL-1.1 EE)
// Core enforcement paths call emitReceipt() to record a governance decision as
// a tamper-evident PRAMANA receipt. The receipt module is EE (BSL-1.1); core
// never hard-imports it — this shim lazy-requires it and no-ops when EE is not
// licensed or not present. Mirrors the lazy-require pattern already used for the
// EE Slack notifier in enforcer.ts / gate.ts.
// @rule:KAV-046 PRAMANA audit receipts for every governance decision

import type {
  ReceiptCategory,
  ReceiptVerdict,
  PramanaEvidence,
  PramanaReceipt,
} from "../../ee/kavach/pramana-receipts";

type IssueFn = (
  category: ReceiptCategory,
  verdict: ReceiptVerdict,
  evidence: PramanaEvidence,
  decision: Omit<PramanaReceipt["decision"], "latency_ms"> & { latency_ms?: number },
  startedAt?: number,
) => PramanaReceipt;

let _issue: IssueFn | null = null;
let _resolved = false;

// EE gate — matches ee/license.ts isEE() without importing the BSL module.
function eeLicensed(): boolean {
  return !!(process.env.AEGIS_EE_LICENSE_KEY && process.env.AEGIS_EE_LICENSE_KEY.trim().length > 0);
}

function resolveIssue(): IssueFn | null {
  if (_resolved) return _issue;
  _resolved = true;
  try {
    const pm = require("../../ee/kavach/pramana-receipts");
    _issue = (pm.issueReceipt as IssueFn) ?? null;
  } catch {
    _issue = null; // EE module absent (AGPL-only distribution)
  }
  return _issue;
}

/**
 * Emit a PRAMANA receipt for a governance decision.
 * Fire-and-forget: never throws, never blocks enforcement. No-ops when EE is
 * unlicensed or the receipt module is unavailable.
 */
export function emitReceipt(
  category: ReceiptCategory,
  verdict: ReceiptVerdict,
  evidence: PramanaEvidence,
  decision: { rule_applied: string; decision_path: string; human_in_loop: boolean; latency_ms?: number },
  startedAt?: number,
): void {
  if (!eeLicensed()) return;
  const issue = resolveIssue();
  if (!issue) return;
  try {
    issue(category, verdict, evidence, decision, startedAt);
  } catch {
    /* receipts must never break the enforcement path */
  }
}
