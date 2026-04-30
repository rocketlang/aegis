// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-012 audit command — profile hash + receipt chain verification

import { getProfile, verifyReceiptChain, getReceiptChain, checkProfileDrift } from "./profile-store";

export interface AuditResult {
  session_id: string;
  profile_found: boolean;
  profile_hash?: string;
  profile_drift: boolean;
  receipt_count: number;
  chain_valid: boolean;
  chain_gap_at?: string;
  eu_ai_act_eligible: boolean;
  verdict: "CLEAN" | "PROFILE_DRIFT" | "CHAIN_BROKEN" | "NO_SESSION";
  summary: string;
}

// @rule:KOS-012 + INF-KOS-003
export function auditSession(sessionId: string): AuditResult {
  const profile = getProfile(sessionId);

  if (!profile) {
    return {
      session_id: sessionId,
      profile_found: false,
      profile_drift: false,
      receipt_count: 0,
      chain_valid: false,
      eu_ai_act_eligible: false,
      verdict: "NO_SESSION",
      summary: `Session ${sessionId} not found in kernel_profiles table. Either it was not launched via kavachos run, or records were cleaned up.`,
    };
  }

  // Check profile drift
  const drift = checkProfileDrift(sessionId);

  // Verify PRAMANA receipt chain
  const chainVerification = verifyReceiptChain(sessionId);

  // EU AI Act eligible: no drift + unbroken chain (KOS-005, INF-KOS-003, KOS-008)
  const euEligible = !drift && chainVerification.valid;

  let verdict: AuditResult["verdict"] = "CLEAN";
  if (drift) verdict = "PROFILE_DRIFT";
  else if (!chainVerification.valid) verdict = "CHAIN_BROKEN";

  const verdictIcon = verdict === "CLEAN" ? "✅" : "❌";

  const summary = [
    `${verdictIcon} Session: ${sessionId}`,
    `   Profile hash:   ${profile.profile_hash.slice(0, 16)}... (${drift ? "DRIFTED" : "verified"})`,
    `   Trust mask:     0x${profile.trust_mask.toString(16).padStart(8, "0")}`,
    `   Domain:         ${profile.domain}`,
    `   Syscalls:       ${profile.syscall_count}`,
    `   Receipts:       ${chainVerification.receipt_count} (chain ${chainVerification.valid ? "✅ unbroken" : "❌ BROKEN at " + chainVerification.gap_at})`,
    `   EU AI Act §14:  ${euEligible ? "✅ eligible" : "❌ NOT eligible"}`,
    `   Verdict:        ${verdict}`,
  ].join("\n");

  return {
    session_id: sessionId,
    profile_found: true,
    profile_hash: profile.profile_hash,
    profile_drift: !!drift,
    receipt_count: chainVerification.receipt_count,
    chain_valid: chainVerification.valid,
    chain_gap_at: chainVerification.gap_at,
    eu_ai_act_eligible: euEligible,
    verdict,
    summary,
  };
}

export function listSessions(): Array<{ session_id: string; domain: string; trust_mask: number; stored_at: string; syscall_count: number }> {
  // Dynamic import to avoid circular deps with profile-store
  const { getDb } = require("../core/db") as typeof import("../core/db");
  const { ensureKernelSchema } = require("./profile-store") as typeof import("./profile-store");
  ensureKernelSchema();
  const db = getDb();
  return db.query<{ session_id: string; domain: string; trust_mask: number; stored_at: string; syscall_count: number }, []>(
    "SELECT session_id, domain, trust_mask, stored_at, syscall_count FROM kernel_profiles ORDER BY stored_at DESC LIMIT 50"
  ).all();
}

export function printAudit(result: AuditResult): void {
  console.log(result.summary);
  if (result.verdict !== "CLEAN") {
    console.log("\n  ACTION REQUIRED:");
    if (result.profile_drift) {
      console.log("  • Profile drift detected — this session is a security incident (KOS-012)");
      console.log("  • Emit kavach.kernel.violation.detected and quarantine session");
    }
    if (!result.chain_valid) {
      console.log(`  • Receipt chain broken at ${result.chain_gap_at} — tampered or missing evidence (INF-KOS-003)`);
      console.log("  • Session cannot be used as EU AI Act Article 14/15 evidence");
    }
  }
}
