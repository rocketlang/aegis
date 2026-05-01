// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-012 profile versioned by SHA-256 — drift = security incident

import { getDb } from "../core/db";
import type { SeccompProfile } from "./seccomp-profile-generator";
import { canonicalJson } from "./seccomp-profile-generator";
import { createHash } from "crypto";

export interface StoredProfile {
  id: number;
  session_id: string;
  agent_id: string | null;
  profile_hash: string;
  trust_mask: number;
  domain: string;
  agent_type: string;
  delegation_depth: number;   // @rule:KOS-092
  syscall_count: number;
  profile_json: string;
  stored_at: string;
  profile_path: string | null;  // where the temp profile file was written
}

export interface ProfileDriftEvent {
  session_id: string;
  stored_hash: string;
  actual_hash: string;
  detected_at: string;
}

// Ensure kernel tables exist in aegis.db
export function ensureKernelSchema(): void {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS kernel_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      agent_id TEXT,
      profile_hash TEXT NOT NULL,
      trust_mask INTEGER NOT NULL,
      domain TEXT NOT NULL,
      agent_type TEXT NOT NULL DEFAULT 'claude-code',
      delegation_depth INTEGER NOT NULL DEFAULT 1,
      syscall_count INTEGER NOT NULL,
      profile_json TEXT NOT NULL,
      stored_at TEXT NOT NULL,
      profile_path TEXT,
      UNIQUE(session_id)
    );

    CREATE TABLE IF NOT EXISTS kernel_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      session_id TEXT NOT NULL,
      agent_id TEXT,
      event_type TEXT NOT NULL,
      syscall TEXT,
      falco_rule TEXT,
      severity TEXT NOT NULL DEFAULT 'WARN',
      violation_details TEXT,
      profile_hash TEXT,
      receipt_hash TEXT NOT NULL,
      prev_receipt_hash TEXT,
      delegation_depth INTEGER NOT NULL DEFAULT 1,
      sealed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS kernel_drift_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      stored_hash TEXT NOT NULL,
      actual_hash TEXT NOT NULL,
      detected_at TEXT NOT NULL
    );
  `);

  // Additive migrations — columns added in KOS-092/094 update
  // SQLite does not support IF NOT EXISTS on ALTER TABLE; try/catch is the safe path.
  try { db.exec("ALTER TABLE kernel_profiles ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 1"); } catch { /* column already exists */ }
  try { db.exec("ALTER TABLE kernel_receipts ADD COLUMN delegation_depth INTEGER NOT NULL DEFAULT 1"); } catch { /* column already exists */ }
}

export function storeProfile(
  sessionId: string,
  agentId: string | null,
  profile: SeccompProfile,
  profilePath: string | null = null
): string {
  ensureKernelSchema();
  const db = getDb();

  const profileJson = JSON.stringify(profile);
  const hash = createHash("sha256").update(canonicalJson(profile)).digest("hex");
  const syscallCount = profile.syscalls[0]?.names.length ?? 0;

  db.run(
    `INSERT OR REPLACE INTO kernel_profiles
     (session_id, agent_id, profile_hash, trust_mask, domain, agent_type, delegation_depth, syscall_count, profile_json, stored_at, profile_path)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      sessionId,
      agentId,
      hash,
      profile._kavachos.trust_mask,
      profile._kavachos.domain,
      profile._kavachos.agent_type,
      profile._kavachos.delegation_depth,
      syscallCount,
      profileJson,
      new Date().toISOString(),
      profilePath,
    ]
  );

  return hash;
}

export function getProfile(sessionId: string): StoredProfile | null {
  ensureKernelSchema();
  const db = getDb();
  return db.query<StoredProfile, [string]>(
    "SELECT * FROM kernel_profiles WHERE session_id = ?",
  ).get(sessionId) ?? null;
}

// @rule:KOS-031 profile show — look up by agent_id (most recent session) or session_id
export function getProfileForAgent(agentId: string, sessionId: string | null): StoredProfile | null {
  ensureKernelSchema();
  const db = getDb();
  if (sessionId) {
    return db.query<StoredProfile, [string, string]>(
      "SELECT * FROM kernel_profiles WHERE agent_id = ? AND session_id = ? ORDER BY stored_at DESC LIMIT 1",
    ).get(agentId, sessionId) ?? null;
  }
  return db.query<StoredProfile, [string]>(
    "SELECT * FROM kernel_profiles WHERE agent_id = ? ORDER BY stored_at DESC LIMIT 1",
  ).get(agentId) ?? null;
}

// @rule:KOS-012 drift detection — stored hash vs recomputed hash
export function checkProfileDrift(sessionId: string): ProfileDriftEvent | null {
  const stored = getProfile(sessionId);
  if (!stored) return null;

  const profile = JSON.parse(stored.profile_json) as SeccompProfile;
  const actualHash = createHash("sha256").update(canonicalJson(profile)).digest("hex");

  if (actualHash !== stored.profile_hash) {
    const event: ProfileDriftEvent = {
      session_id: sessionId,
      stored_hash: stored.profile_hash,
      actual_hash: actualHash,
      detected_at: new Date().toISOString(),
    };

    const db = getDb();
    db.run(
      "INSERT INTO kernel_drift_events (session_id, stored_hash, actual_hash, detected_at) VALUES (?, ?, ?, ?)",
      [event.session_id, event.stored_hash, event.actual_hash, event.detected_at]
    );

    return event;
  }

  return null;
}

export function recordKernelReceipt(
  receiptId: string,
  sessionId: string,
  agentId: string | null,
  eventType: "SECCOMP_BLOCK" | "FALCO_ALERT" | "PROFILE_DRIFT" | "RATE_EXCEEDED",
  details: {
    syscall?: string;
    falco_rule?: string;
    severity?: string;
    violation_details?: string;
    profile_hash?: string;
    prev_receipt_hash?: string;
    receipt_hash: string;
    delegation_depth?: number;
  }
): void {
  ensureKernelSchema();
  const db = getDb();
  db.run(
    `INSERT OR IGNORE INTO kernel_receipts
     (receipt_id, session_id, agent_id, event_type, syscall, falco_rule, severity,
      violation_details, profile_hash, receipt_hash, prev_receipt_hash, delegation_depth, sealed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      receiptId,
      sessionId,
      agentId,
      eventType,
      details.syscall ?? null,
      details.falco_rule ?? null,
      details.severity ?? "WARN",
      details.violation_details ?? null,
      details.profile_hash ?? null,
      details.receipt_hash,
      details.prev_receipt_hash ?? null,
      details.delegation_depth ?? 1,
      new Date().toISOString(),
    ]
  );
}

export function getReceiptChain(sessionId: string): Array<{
  receipt_id: string;
  receipt_hash: string;
  prev_receipt_hash: string | null;
  sealed_at: string;
}> {
  ensureKernelSchema();
  const db = getDb();
  return db.query(
    "SELECT receipt_id, receipt_hash, prev_receipt_hash, sealed_at FROM kernel_receipts WHERE session_id = ? ORDER BY id ASC",
  ).all(sessionId) as Array<{ receipt_id: string; receipt_hash: string; prev_receipt_hash: string | null; sealed_at: string }>;
}

// @rule:INF-KOS-003 chain gap → session invalid for EU AI Act evidence
export function verifyReceiptChain(sessionId: string): { valid: boolean; gap_at?: string; receipt_count: number } {
  const chain = getReceiptChain(sessionId);
  if (chain.length === 0) return { valid: true, receipt_count: 0 };

  let prevHash: string | null = null;
  for (const receipt of chain) {
    if (receipt.prev_receipt_hash !== prevHash) {
      return { valid: false, gap_at: receipt.receipt_id, receipt_count: chain.length };
    }
    prevHash = receipt.receipt_hash;
  }

  return { valid: true, receipt_count: chain.length };
}
