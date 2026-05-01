// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-T040 CT-style Merkle tree over hourly PRAMANA receipt batches
// @rule:KOS-T041 Ed25519-signed STH — signing pattern reused from SDGE (ankr-sovereign-doc.ts)

import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { getDb } from "../core/db";
import { getAegisDir } from "../core/config";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface MerkleCheckpoint {
  checkpoint_id: string;           // "KOS-MERKLE-{timestamp}-{count}"
  created_at: string;
  period_start: string;
  period_end: string;
  tree_size: number;               // number of leaves
  sha256_root_hash: string;        // Merkle root (hex)
  leaf_hashes: string[];           // all receipt_hashes in batch (for local proof gen)
  signature: string;               // Ed25519(canonical STH fields) — base64
  public_key_hex: string;          // SPKI DER hex of signing key
  pramana_version: "1.1";
  rule_ref: "KOS-T040";
}

export interface InclusionProof {
  leaf_hash: string;
  leaf_index: number;
  tree_size: number;
  audit_path: string[];            // sibling hashes bottom-up
  root_hash: string;
}

export interface VerifyChainResult {
  session_id: string;
  valid: boolean;
  receipt_count: number;
  broken_at_receipt?: string;      // receipt_id where chain breaks
  broken_reason?: string;
  checkpoint_id?: string;          // if batch was checkpointed
  included_in_merkle?: boolean;
  checked_at: string;
}

// ── Key management ────────────────────────────────────────────────────────────

const KEY_FILE = () => join(getAegisDir(), "merkle-key.json");

interface MerkleKeyState {
  privateKeyHex: string;
  publicKeyHex: string;
  created_at: string;
}

function getMerkleKey(): MerkleKeyState {
  const path = KEY_FILE();
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf8"));
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const state: MerkleKeyState = {
    privateKeyHex: privateKey.export({ type: "pkcs8", format: "der" }).toString("hex"),
    publicKeyHex:  publicKey.export({ type: "spki",  format: "der" }).toString("hex"),
    created_at: new Date().toISOString(),
  };
  mkdirSync(join(getAegisDir()), { recursive: true });
  writeFileSync(path, JSON.stringify(state, null, 2), "utf8");
  return state;
}

// ── Signing helpers (SDGE pattern) ────────────────────────────────────────────

function signData(data: string, privateKeyHex: string): string {
  const keyBuf  = Buffer.from(privateKeyHex, "hex");
  const dataBuf = Buffer.from(data, "utf8");
  return cryptoSign(null, dataBuf, { key: keyBuf, format: "der", type: "pkcs8" }).toString("base64");
}

export function verifySthSignature(data: string, signatureB64: string, publicKeyHex: string): boolean {
  try {
    const keyBuf  = Buffer.from(publicKeyHex, "hex");
    const dataBuf = Buffer.from(data, "utf8");
    const sigBuf  = Buffer.from(signatureB64, "base64");
    return cryptoVerify(null, dataBuf, { key: keyBuf, format: "der", type: "spki" }, sigBuf);
  } catch {
    return false;
  }
}

// ── Merkle tree construction (RFC 6962 style) ─────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

// Leaf hash: sha256("leaf:" + hash) — domain-separates leaves from interior nodes
function leafHash(receiptHash: string): string {
  return sha256("leaf:" + receiptHash);
}

// Interior node: sha256("node:" + left + right)
function nodeHash(left: string, right: string): string {
  return sha256("node:" + left + right);
}

export function buildMerkleRoot(receiptHashes: string[]): { root: string; tree: string[][] } {
  if (receiptHashes.length === 0) return { root: sha256("empty"), tree: [] };

  let layer: string[] = receiptHashes.map(leafHash);
  const tree: string[][] = [layer];

  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      // RFC 6962: odd leaf duplicates itself
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      next.push(nodeHash(layer[i], right));
    }
    layer = next;
    tree.push(layer);
  }

  return { root: layer[0], tree };
}

export function generateInclusionProof(receiptHashes: string[], leafIndex: number): InclusionProof {
  const { root, tree } = buildMerkleRoot(receiptHashes);
  const auditPath: string[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    const layer = tree[level];
    const sibling = idx % 2 === 0
      ? (idx + 1 < layer.length ? layer[idx + 1] : layer[idx])
      : layer[idx - 1];
    auditPath.push(sibling);
    idx = Math.floor(idx / 2);
  }

  return {
    leaf_hash: leafHash(receiptHashes[leafIndex]),
    leaf_index: leafIndex,
    tree_size: receiptHashes.length,
    audit_path: auditPath,
    root_hash: root,
  };
}

export function verifyInclusionProof(proof: InclusionProof): boolean {
  let current = proof.leaf_hash;
  let idx = proof.leaf_index;

  for (const sibling of proof.audit_path) {
    current = idx % 2 === 0 ? nodeHash(current, sibling) : nodeHash(sibling, current);
    idx = Math.floor(idx / 2);
  }

  return current === proof.root_hash;
}

// ── Schema ────────────────────────────────────────────────────────────────────

export function ensureMerkleSchema(): void {
  const db = getDb();
  db.exec(`
    CREATE TABLE IF NOT EXISTS merkle_checkpoints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      checkpoint_id TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      tree_size INTEGER NOT NULL,
      sha256_root_hash TEXT NOT NULL,
      leaf_hashes_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      public_key_hex TEXT NOT NULL,
      anchor_ref TEXT,
      anchored_at TEXT
    );
  `);
}

function saveCheckpoint(cp: MerkleCheckpoint, anchorRef?: string): void {
  ensureMerkleSchema();
  const db = getDb();
  db.run(
    `INSERT OR IGNORE INTO merkle_checkpoints
     (checkpoint_id, created_at, period_start, period_end, tree_size,
      sha256_root_hash, leaf_hashes_json, signature, public_key_hex, anchor_ref)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      cp.checkpoint_id, cp.created_at, cp.period_start, cp.period_end,
      cp.tree_size, cp.sha256_root_hash, JSON.stringify(cp.leaf_hashes),
      cp.signature, cp.public_key_hex, anchorRef ?? null,
    ]
  );
}

export function getCheckpoint(checkpointId: string): MerkleCheckpoint | null {
  ensureMerkleSchema();
  const db = getDb();
  const row = db.prepare(
    "SELECT * FROM merkle_checkpoints WHERE checkpoint_id = ?"
  ).get(checkpointId) as any;
  if (!row) return null;
  return {
    checkpoint_id: row.checkpoint_id,
    created_at: row.created_at,
    period_start: row.period_start,
    period_end: row.period_end,
    tree_size: row.tree_size,
    sha256_root_hash: row.sha256_root_hash,
    leaf_hashes: JSON.parse(row.leaf_hashes_json),
    signature: row.signature,
    public_key_hex: row.public_key_hex,
    pramana_version: "1.1",
    rule_ref: "KOS-T040",
  };
}

export function listCheckpoints(limit = 20): Array<Omit<MerkleCheckpoint, "leaf_hashes">> {
  ensureMerkleSchema();
  const db = getDb();
  return (db.prepare(
    "SELECT checkpoint_id, created_at, period_start, period_end, tree_size, sha256_root_hash, signature, public_key_hex, anchor_ref, anchored_at FROM merkle_checkpoints ORDER BY id DESC LIMIT ?"
  ).all(limit) as any[]).map(r => ({
    checkpoint_id: r.checkpoint_id,
    created_at: r.created_at,
    period_start: r.period_start,
    period_end: r.period_end,
    tree_size: r.tree_size,
    sha256_root_hash: r.sha256_root_hash,
    signature: r.signature,
    public_key_hex: r.public_key_hex,
    pramana_version: "1.1" as const,
    rule_ref: "KOS-T040" as const,
  }));
}

// ── Hourly checkpoint ─────────────────────────────────────────────────────────

// @rule:KOS-T040 batch receipts from past hour → Merkle checkpoint → Ed25519 STH
export async function runHourlyCheckpoint(periodHours = 1): Promise<MerkleCheckpoint | null> {
  ensureMerkleSchema();
  const db = getDb();

  const now = new Date();
  const periodEnd = now.toISOString();
  const periodStart = new Date(now.getTime() - periodHours * 60 * 60 * 1000).toISOString();

  const rows = db.prepare(
    "SELECT receipt_hash FROM kernel_receipts WHERE sealed_at >= ? AND sealed_at < ? ORDER BY id ASC"
  ).all(periodStart, periodEnd) as Array<{ receipt_hash: string }>;

  if (rows.length === 0) return null;

  const receiptHashes = rows.map(r => r.receipt_hash);
  const { root } = buildMerkleRoot(receiptHashes);
  const key = getMerkleKey();

  const checkpointId = `KOS-MERKLE-${now.getTime()}-${rows.length}`;

  // STH canonical fields (CT-style)
  const sthPayload = JSON.stringify({
    checkpoint_id: checkpointId,
    tree_size: receiptHashes.length,
    sha256_root_hash: root,
    period_start: periodStart,
    period_end: periodEnd,
    pramana_version: "1.1",
  });

  const signature = signData(sthPayload, key.privateKeyHex);

  const checkpoint: MerkleCheckpoint = {
    checkpoint_id: checkpointId,
    created_at: now.toISOString(),
    period_start: periodStart,
    period_end: periodEnd,
    tree_size: receiptHashes.length,
    sha256_root_hash: root,
    leaf_hashes: receiptHashes,
    signature,
    public_key_hex: key.publicKeyHex,
    pramana_version: "1.1",
    rule_ref: "KOS-T040",
  };

  saveCheckpoint(checkpoint);
  return checkpoint;
}

// ── Chain verifier ────────────────────────────────────────────────────────────

// @rule:KOS-T042 re-walk PRAMANA SHA-256 chain; verify inclusion in Merkle checkpoint
export function verifyReceiptChain(sessionId: string): VerifyChainResult {
  const db = getDb();
  const receipts = db.prepare(
    "SELECT receipt_id, receipt_hash, prev_receipt_hash, sealed_at FROM kernel_receipts WHERE session_id = ? ORDER BY id ASC"
  ).all(sessionId) as Array<{ receipt_id: string; receipt_hash: string; prev_receipt_hash: string | null; sealed_at: string }>;

  const checked_at = new Date().toISOString();

  if (receipts.length === 0) {
    return { session_id: sessionId, valid: true, receipt_count: 0, checked_at };
  }

  // Walk the SHA-256 chain
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    const expectedPrev = i === 0 ? null : receipts[i - 1].receipt_hash;
    if (r.prev_receipt_hash !== expectedPrev) {
      return {
        session_id: sessionId,
        valid: false,
        receipt_count: receipts.length,
        broken_at_receipt: r.receipt_id,
        broken_reason: `prev_receipt_hash mismatch at position ${i}: expected ${expectedPrev ?? "null"}, got ${r.prev_receipt_hash}`,
        checked_at,
      };
    }
  }

  // Check if last receipt is included in a Merkle checkpoint
  ensureMerkleSchema();
  const lastHash = receipts[receipts.length - 1].receipt_hash;
  const lastSealed = receipts[receipts.length - 1].sealed_at;

  const cpRow = db.prepare(
    "SELECT checkpoint_id, leaf_hashes_json FROM merkle_checkpoints WHERE period_end >= ? ORDER BY id ASC LIMIT 1"
  ).get(lastSealed) as any;

  let checkpointId: string | undefined;
  let includedInMerkle = false;

  if (cpRow) {
    const leaves: string[] = JSON.parse(cpRow.leaf_hashes_json);
    includedInMerkle = leaves.includes(lastHash);
    checkpointId = cpRow.checkpoint_id;
  }

  return {
    session_id: sessionId,
    valid: true,
    receipt_count: receipts.length,
    checkpoint_id: checkpointId,
    included_in_merkle: includedInMerkle,
    checked_at,
  };
}
