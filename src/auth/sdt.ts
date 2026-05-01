// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// SDT — Scoped Delegation Token engine
// Issues tokens, validates chains, computes effective masks.
//
// @rule:AGS-004 delegation narrows: B.mask = A.effective_mask & requested — never union
// @rule:AGS-005 chain_hash = SHA-256 of parent SDT canonical JSON
// @rule:AGS-006 depth starts at 0, increments by 1, never resets
// @rule:AGS-009 expiry = min(task_end, ISO timestamp) — never unbounded
// @rule:AGS-012 Mode D (Trustwashing) — chain_hash is the lie detector
// @rule:AGS-014 chain store retention >= max(child.expiry) + 1hr

import { createHash, randomUUID } from "crypto";
import type { ScopedDelegationToken, SdtIssueRequest, SdtIssueResponse } from "./types";
import { getDb } from "../core/db";

// ── Chain hash ────────────────────────────────────────────────────────────────

// Canonical JSON = lexicographically sorted keys, no whitespace
function canonicalJson(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  const sorted = Object.keys(obj as Record<string, unknown>).sort();
  return "{" + sorted.map(k => `${JSON.stringify(k)}:${canonicalJson((obj as Record<string, unknown>)[k])}`).join(",") + "}";
}

export function computeChainHash(token: ScopedDelegationToken): string {
  return createHash("sha256").update(canonicalJson(token)).digest("hex");
}

// Genesis chain_hash for root (human) tokens — deterministic per session
export function genesisChainHash(sessionId: string): string {
  return createHash("sha256").update("genesis:" + sessionId).digest("hex");
}

// ── DB operations ─────────────────────────────────────────────────────────────

export function storeSdt(token: ScopedDelegationToken): void {
  const db = getDb();
  const hash = computeChainHash(token);
  db.run(
    `INSERT OR REPLACE INTO sdt_chain_store
       (token_id, chain_hash, token_json, depth, expiry, issued_at, agent_id, spawner_id, delegated_mask, max_depth)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      token.token_id,
      hash,
      JSON.stringify(token),
      token.delegation.depth,
      token.delegation.expiry,
      token.issued_at,
      token.identity.agent_id,
      token.identity.spawner_id,
      token.delegation.delegated_mask,
      token.delegation.max_depth,
    ],
  );
}

export function getSdtByHash(chainHash: string): ScopedDelegationToken | null {
  const db = getDb();
  const row = db.query<{ token_json: string }, [string]>(
    "SELECT token_json FROM sdt_chain_store WHERE chain_hash = ? LIMIT 1",
  ).get(chainHash);
  if (!row) return null;
  try { return JSON.parse(row.token_json) as ScopedDelegationToken; } catch { return null; }
}

export function getSdtById(tokenId: string): ScopedDelegationToken | null {
  const db = getDb();
  const row = db.query<{ token_json: string }, [string]>(
    "SELECT token_json FROM sdt_chain_store WHERE token_id = ? LIMIT 1",
  ).get(tokenId);
  if (!row) return null;
  try { return JSON.parse(row.token_json) as ScopedDelegationToken; } catch { return null; }
}

// ── Chain validation ──────────────────────────────────────────────────────────

export type ChainValidationResult =
  | { valid: true; depth: number; effective_mask: number }
  | { valid: false; reason: string };

// Walk the chain from the presented token up to the root.
// Returns effective_mask = intersection of all delegated_masks in chain.
// @rule:AGS-005 each token's chain_hash must resolve to its parent
// @rule:AGS-006 depth must be monotonically increasing from root to tip
// @rule:AGS-012 depth reset attack: hash resolves to wrong depth → CHAIN_TAMPERED
export function validateChain(token: ScopedDelegationToken): ChainValidationResult {
  const visited = new Set<string>();
  let current: ScopedDelegationToken = token;
  let effectiveMask = token.delegation.delegated_mask;

  // For root tokens (depth=0): chain_hash must match the genesis sentinel.
  // This is the Mode D defense at the root level: a tampered child claiming depth=0
  // will have a chain_hash that doesn't match genesis(spawner_id), so it fails.
  if (current.delegation.depth === 0) {
    const expectedGenesis = genesisChainHash(current.identity.spawner_id);
    if (current.delegation.chain_hash !== expectedGenesis) {
      // chain_hash doesn't match genesis — either tampered or from a different spawner
      // Check if the presented hash exists in the chain store as a real parent
      // (Mode D: attacker set depth=0 but kept the real parent's hash)
      const storeEntry = getSdtByHash(current.delegation.chain_hash);
      if (storeEntry) {
        // Hash resolves to a real token in the chain store — depth was laundered
        return { valid: false, reason: "CHAIN_TAMPERED" };
      }
      // Hash is unknown and doesn't match genesis — forged root
      return { valid: false, reason: "CHAIN_TAMPERED" };
    }
    return { valid: true, depth: 0, effective_mask: effectiveMask };
  }

  // For depth > 0: walk chain to root
  while (current.delegation.depth > 0) {
    if (visited.has(current.token_id)) {
      return { valid: false, reason: "CHAIN_CYCLE" };
    }
    visited.add(current.token_id);

    const parent = getSdtByHash(current.delegation.chain_hash);
    if (!parent) {
      return { valid: false, reason: "CHAIN_NOT_FOUND" };
    }

    // Depth must decrement by exactly 1 per hop (AGS-006)
    if (parent.delegation.depth !== current.delegation.depth - 1) {
      return { valid: false, reason: "CHAIN_TAMPERED" };
    }

    // Parent's effective mask must be a superset of child's delegated_mask (AGS-004)
    if ((parent.delegation.delegated_mask & current.delegation.delegated_mask)
        !== current.delegation.delegated_mask) {
      return { valid: false, reason: "MASK_OVERFLOW" };
    }

    effectiveMask &= parent.delegation.delegated_mask;
    current = parent;
  }

  // Reached depth=0 — validate root's genesis hash
  const expectedGenesis = genesisChainHash(current.identity.spawner_id);
  if (current.delegation.chain_hash !== expectedGenesis) {
    return { valid: false, reason: "CHAIN_TAMPERED" };
  }

  return { valid: true, depth: token.delegation.depth, effective_mask: effectiveMask };
}

// ── Expiry check ──────────────────────────────────────────────────────────────

export function isExpired(token: ScopedDelegationToken): boolean {
  if (token.delegation.expiry === "task_end") return false; // valid while task runs
  try {
    return new Date(token.delegation.expiry).getTime() < Date.now();
  } catch {
    return true; // unparseable expiry = treat as expired
  }
}

// ── Issuer ────────────────────────────────────────────────────────────────────

// @rule:AGS-004 delegation narrows: child.delegated_mask = parent.effective_mask & requested
// @rule:AGS-009 expiry defaults to "task_end" — never unbounded
export function issueSdt(req: SdtIssueRequest): SdtIssueResponse {
  let parentEffectiveMask = 0xFFFFFFFF; // root has full mask
  let depth = 0;
  let chainHash: string;
  let maxDepth = req.max_depth ?? 5;

  if (req.parent_token_id) {
    const parent = getSdtById(req.parent_token_id);
    if (!parent) throw new Error("PARENT_NOT_FOUND");

    const chainResult = validateChain(parent);
    if (!chainResult.valid) throw new Error("PARENT_CHAIN_INVALID: " + chainResult.reason);

    parentEffectiveMask = chainResult.effective_mask;
    depth = parent.delegation.depth + 1;
    maxDepth = Math.min(maxDepth, parent.delegation.max_depth); // child cannot exceed parent limit
    chainHash = computeChainHash(parent);
  } else {
    // Root token — genesis chain hash uses spawner_id (session_id of the human)
    chainHash = genesisChainHash(req.spawner_id);
  }

  // Delegation invariant: child mask = parent effective_mask & requested_mask
  const delegatedMask = parentEffectiveMask & req.requested_mask;

  const token: ScopedDelegationToken = {
    token_id: randomUUID(),
    identity: {
      agent_id: req.agent_id,
      agent_class: req.agent_class,
      spawner_id: req.spawner_id,
      signed_by: "local",
    },
    delegation: {
      delegated_mask: delegatedMask,
      depth,
      max_depth: maxDepth,
      task_scope: req.task_scope,
      max_transaction_value: req.max_transaction_value ?? 0,
      chain_hash: chainHash,
      expiry: req.expiry ?? "task_end",
      human_in_loop_required: req.human_in_loop_required ?? false,
      origin_org: req.origin_org ?? "ankr",
    },
    issued_at: new Date().toISOString(),
  };

  storeSdt(token);
  return { token, effective_mask: delegatedMask };
}
