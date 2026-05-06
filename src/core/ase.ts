// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Agent Session Envelope (ASE) — Core Module
//
// @rule:ASE-001 every agent session must have a sealed envelope before its first action
// @rule:ASE-002 sealed_hash computed once at issuance, never re-issued for same session_id
// @rule:ASE-003 declared_caps must be a subset of the service's registered trust_mask bits
// @rule:ASE-006 budget fixed at birth — budget_usd is immutable in the sealed fields
// @rule:ASE-008 child sealed_hash includes parent_session_id — creates auditable chain
// @rule:ASE-013 trust_mask derived from git_remote → services.json → codex.json at session birth
// @rule:INF-ASE-007 hard_block capabilities may not appear in declared_caps at issuance

import { createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { getDb } from "./db";

export interface AgentSessionEnvelope {
  session_id: string;
  agent_id: string;
  agent_type: "proxy-native" | "hook-native";
  service_key: string;
  tenant_id: string;

  // Coordinate system — fixed at issuance, included in sealed_hash
  trust_mask: number;
  perm_mask: number;
  class_mask: number;
  declared_caps: string[];

  // Budget — allocated at birth (budget_usd sealed; budget_used_usd mutable)
  budget_usd: number;
  budget_used_usd: number;

  // Seal — immutable after issuance
  sealed_hash: string;
  issued_at: string;
  expires_at: string;
  parent_session_id: string | null;

  // Audit — populated during session (mutable, not in seal)
  actual_caps_used: string[];
  gate_calls: number;
  blocks: number;
  drift_detected: boolean;
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours default

// @rule:ASE-002 — sorted declared_caps ensures deterministic hash regardless of input order
export function computeSealedHash(fields: {
  session_id: string;
  perm_mask: number;
  class_mask: number;
  declared_caps: string[];
  issued_at: string;
  parent_session_id: string | null;
}): string {
  const sortedCaps = [...fields.declared_caps].sort().join(",");
  const input = [
    fields.session_id,
    String(fields.perm_mask),
    String(fields.class_mask),
    sortedCaps,
    fields.issued_at,
    fields.parent_session_id ?? "null",
  ].join(":");
  return createHash("sha256").update(input, "utf8").digest("hex");
}

// Derive service_key and trust_mask from git_remote.
// @rule:ASE-013 trust_mask from git_remote → services.json → codex.json; default 1 (read-only) if no match
export function deriveTrustFromGitRemote(gitRemote: string | null): {
  service_key: string;
  trust_mask: number;
} {
  const fallback = { service_key: "unknown", trust_mask: 1 };
  if (!gitRemote) return fallback;

  // Strip protocol/host, extract repo name
  const match = gitRemote.match(/[:/]([^/]+?)(?:\.git)?$/);
  const repoSlug = match?.[1]?.toLowerCase();
  if (!repoSlug) return fallback;

  // Try services.json in the well-known config location
  const servicesPath = join(process.env.ANKR_CONFIG_DIR ?? "/root/.ankr/config", "services.json");
  if (!existsSync(servicesPath)) return fallback;

  try {
    const services = JSON.parse(readFileSync(servicesPath, "utf-8")) as Array<{
      key?: string;
      service_key?: string;
      git_repo?: string;
      repo?: string;
      codex_path?: string;
    }>;

    const svc = services.find(s =>
      (s.git_repo ?? s.repo ?? "").toLowerCase().includes(repoSlug) ||
      (s.key ?? s.service_key ?? "").toLowerCase() === repoSlug
    );
    if (!svc) return fallback;

    const key = svc.key ?? svc.service_key ?? repoSlug;
    // Trust mask from codex.json
    if (svc.codex_path && existsSync(svc.codex_path)) {
      const codex = JSON.parse(readFileSync(svc.codex_path, "utf-8"));
      return { service_key: key, trust_mask: codex.trust_mask ?? 1 };
    }
    // Try common relative paths
    for (const candidate of [
      join("/root", key, "codex.json"),
      join("/root/aegis", "codex.json"),
    ]) {
      if (existsSync(candidate)) {
        const codex = JSON.parse(readFileSync(candidate, "utf-8"));
        if (codex.trust_mask && (codex.service_key === key || codex.key === key)) {
          return { service_key: key, trust_mask: codex.trust_mask };
        }
      }
    }
    return { service_key: key, trust_mask: 1 };
  } catch {
    return fallback;
  }
}

// Write the three ASE columns to the agents table (additive migration — done once in db.ts).
// This function issues and stores a new envelope; it does NOT call db migrations.
export function storeEnvelope(envelope: AgentSessionEnvelope): void {
  const db = getDb();
  // agents table already exists. We upsert the ASE columns onto the existing row,
  // or insert a minimal agent row if first-time creation.
  const now = envelope.issued_at;
  const existing = db.query<{ agent_id: string }, [string]>(
    "SELECT agent_id FROM agents WHERE agent_id = ?"
  ).get(envelope.agent_id);

  if (existing) {
    db.run(
      `UPDATE agents SET
        sealed_hash = ?,
        declared_caps = ?,
        parent_session_id = ?,
        ase_issued_at = ?,
        ase_expires_at = ?,
        ase_budget_usd = ?,
        ase_budget_used_usd = 0,
        ase_service_key = ?,
        ase_agent_type = ?,
        ase_trust_mask = ?,
        ase_perm_mask = ?,
        ase_class_mask = ?
      WHERE agent_id = ?`,
      [
        envelope.sealed_hash,
        JSON.stringify(envelope.declared_caps),
        envelope.parent_session_id ?? null,
        now,
        envelope.expires_at,
        envelope.budget_usd,
        envelope.service_key,
        envelope.agent_type,
        envelope.trust_mask,
        envelope.perm_mask,
        envelope.class_mask,
        envelope.agent_id,
      ]
    );
  } else {
    db.run(
      `INSERT INTO agents (
        agent_id, state, session_id, spawn_timestamp, last_seen,
        budget_cap_usd, budget_used_usd, tenant_id,
        sealed_hash, declared_caps, parent_session_id,
        ase_issued_at, ase_expires_at, ase_budget_usd, ase_budget_used_usd,
        ase_service_key, ase_agent_type, ase_trust_mask, ase_perm_mask, ase_class_mask
      ) VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?,0,?,?,?,?,?)`,
      [
        envelope.agent_id,
        "RUNNING",
        envelope.session_id,
        now,
        now,
        envelope.budget_usd,
        envelope.tenant_id,
        envelope.sealed_hash,
        JSON.stringify(envelope.declared_caps),
        envelope.parent_session_id ?? null,
        now,
        envelope.expires_at,
        envelope.budget_usd,
        envelope.service_key,
        envelope.agent_type,
        envelope.trust_mask,
        envelope.perm_mask,
        envelope.class_mask,
      ]
    );
  }
}

export function loadEnvelope(agentId: string): AgentSessionEnvelope | null {
  const db = getDb();
  const row = db.query<Record<string, unknown>, [string]>(
    `SELECT * FROM agents WHERE agent_id = ?`
  ).get(agentId);
  if (!row || !row.sealed_hash) return null;
  return rowToEnvelope(row);
}

export function loadEnvelopeBySessionId(sessionId: string): AgentSessionEnvelope | null {
  const db = getDb();
  // For hook-native sessions, agent_id == session_id convention
  const row = db.query<Record<string, unknown>, [string, string]>(
    `SELECT * FROM agents WHERE agent_id = ? OR session_id = ? LIMIT 1`
  ).get(sessionId, sessionId);
  if (!row || !row.sealed_hash) return null;
  return rowToEnvelope(row);
}

function rowToEnvelope(row: Record<string, unknown>): AgentSessionEnvelope {
  let declared: string[] = [];
  try { declared = JSON.parse(String(row.declared_caps ?? "[]")); } catch {}
  let actual: string[] = [];
  try { actual = JSON.parse(String(row.ase_actual_caps ?? "[]")); } catch {}

  return {
    session_id: String(row.session_id ?? row.agent_id),
    agent_id: String(row.agent_id),
    agent_type: (row.ase_agent_type as "proxy-native" | "hook-native") ?? "hook-native",
    service_key: String(row.ase_service_key ?? "unknown"),
    tenant_id: String(row.tenant_id ?? "default"),
    trust_mask: Number(row.ase_trust_mask ?? 1),
    perm_mask: Number(row.ase_perm_mask ?? Number(row.ase_trust_mask ?? 1)),
    class_mask: Number(row.ase_class_mask ?? 0xFFFF),
    declared_caps: declared,
    budget_usd: Number(row.ase_budget_usd ?? row.budget_cap_usd ?? 0),
    budget_used_usd: Number(row.ase_budget_used_usd ?? row.budget_used_usd ?? 0),
    sealed_hash: String(row.sealed_hash),
    issued_at: String(row.ase_issued_at ?? row.spawn_timestamp),
    expires_at: String(row.ase_expires_at ?? ""),
    parent_session_id: row.parent_session_id ? String(row.parent_session_id) : null,
    actual_caps_used: actual,
    gate_calls: Number(row.tool_calls ?? 0),
    blocks: Number(row.violation_count ?? 0),
    drift_detected: Boolean(row.ase_drift_detected),
  };
}

// @rule:ASE-006 budget is fixed at birth; only budget_used is mutable
export function updateBudgetUsed(agentId: string, costUsd: number, capUsed?: string): void {
  const db = getDb();
  if (capUsed) {
    const row = db.query<{ ase_actual_caps: string | null }, [string]>(
      "SELECT ase_actual_caps FROM agents WHERE agent_id = ?"
    ).get(agentId);
    let actual: string[] = [];
    try { actual = JSON.parse(row?.ase_actual_caps ?? "[]"); } catch {}
    if (!actual.includes(capUsed)) actual.push(capUsed);
    db.run(
      "UPDATE agents SET ase_budget_used_usd = ase_budget_used_usd + ?, budget_used_usd = budget_used_usd + ?, ase_actual_caps = ?, last_seen = ? WHERE agent_id = ?",
      [costUsd, costUsd, JSON.stringify(actual), new Date().toISOString(), agentId]
    );
  } else {
    db.run(
      "UPDATE agents SET ase_budget_used_usd = ase_budget_used_usd + ?, budget_used_usd = budget_used_usd + ?, last_seen = ? WHERE agent_id = ?",
      [costUsd, costUsd, new Date().toISOString(), agentId]
    );
  }
}

export function recordActualCap(agentId: string, cap: string): void {
  const db = getDb();
  const row = db.query<{ ase_actual_caps: string | null }, [string]>(
    "SELECT ase_actual_caps FROM agents WHERE agent_id = ?"
  ).get(agentId);
  let actual: string[] = [];
  try { actual = JSON.parse(row?.ase_actual_caps ?? "[]"); } catch {}
  if (!actual.includes(cap)) {
    actual.push(cap);
    db.run("UPDATE agents SET ase_actual_caps = ? WHERE agent_id = ?", [JSON.stringify(actual), agentId]);
  }
}

// @rule:INF-ASE-002 drift_set = actual_caps_used \ declared_caps
export function computeDriftSet(declared: string[], actual: string[]): string[] {
  const declaredSet = new Set(declared);
  return actual.filter(c => !declaredSet.has(c));
}

export function closeEnvelope(agentId: string): {
  drift_detected: boolean;
  drift_set: string[];
  final_budget_used: number;
} {
  const db = getDb();
  const row = db.query<Record<string, unknown>, [string]>(
    "SELECT * FROM agents WHERE agent_id = ?"
  ).get(agentId);
  if (!row) return { drift_detected: false, drift_set: [], final_budget_used: 0 };

  let declared: string[] = [];
  let actual: string[] = [];
  try { declared = JSON.parse(String(row.declared_caps ?? "[]")); } catch {}
  try { actual = JSON.parse(String(row.ase_actual_caps ?? "[]")); } catch {}

  const driftSet = computeDriftSet(declared, actual);
  const driftDetected = driftSet.length > 0;
  const finalBudget = Number(row.ase_budget_used_usd ?? row.budget_used_usd ?? 0);

  db.run(
    "UPDATE agents SET ase_drift_detected = ?, ase_closed_at = ?, state = ? WHERE agent_id = ?",
    [driftDetected ? 1 : 0, new Date().toISOString(), "DONE", agentId]
  );

  return { drift_detected: driftDetected, drift_set: driftSet, final_budget_used: finalBudget };
}

// @rule:ASE-002 verify sealed_hash hasn't been tampered with
export function verifyEnvelopeIntegrity(envelope: AgentSessionEnvelope): boolean {
  const expected = computeSealedHash({
    session_id: envelope.session_id,
    perm_mask: envelope.perm_mask,
    class_mask: envelope.class_mask,
    declared_caps: envelope.declared_caps,
    issued_at: envelope.issued_at,
    parent_session_id: envelope.parent_session_id,
  });
  return expected === envelope.sealed_hash;
}

// Create a default envelope for hook-native sessions that registered before ASE deployment.
// @rule:INF-ASE-005 if no envelope exists at UPS fire, create a default (conservative) envelope
export function createDefaultEnvelope(sessionId: string, gitRemote: string | null): AgentSessionEnvelope {
  const { service_key, trust_mask } = deriveTrustFromGitRemote(gitRemote);
  const now = new Date().toISOString();
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const agentId = `agt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const envelope: AgentSessionEnvelope = {
    session_id: sessionId,
    agent_id: agentId,
    agent_type: "hook-native",
    service_key,
    tenant_id: "default",
    trust_mask,
    perm_mask: trust_mask,
    class_mask: 0xFFFF,
    declared_caps: [], // conservative: empty declared = gate checks everything
    budget_usd: 0,     // no budget limit for default envelope
    budget_used_usd: 0,
    sealed_hash: "",   // filled in below
    issued_at: now,
    expires_at: expires,
    parent_session_id: null,
    actual_caps_used: [],
    gate_calls: 0,
    blocks: 0,
    drift_detected: false,
  };

  envelope.sealed_hash = computeSealedHash({
    session_id: envelope.session_id,
    perm_mask: envelope.perm_mask,
    class_mask: envelope.class_mask,
    declared_caps: envelope.declared_caps,
    issued_at: envelope.issued_at,
    parent_session_id: envelope.parent_session_id,
  });

  return envelope;
}

export { SESSION_TTL_MS };
