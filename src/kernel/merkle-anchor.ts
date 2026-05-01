// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-T041 anchor Merkle STH to customer-controlled S3 (or local fallback)

import { existsSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import type { MerkleCheckpoint } from "./merkle-ledger";
import { getDb } from "../core/db";
import { ensureMerkleSchema } from "./merkle-ledger";

export interface AnchorResult {
  checkpoint_id: string;
  method: "s3" | "local";
  ref: string;           // S3 object key or local file path
  anchored_at: string;
}

// ── Local fallback ────────────────────────────────────────────────────────────

function localCheckpointDir(): string {
  const dir = join(getAegisDir(), "merkle", "checkpoints");
  mkdirSync(dir, { recursive: true });
  return dir;
}

function anchorLocal(cp: MerkleCheckpoint): AnchorResult {
  const dir = localCheckpointDir();
  const filename = `${cp.checkpoint_id}.json`;
  const path = join(dir, filename);
  writeFileSync(path, JSON.stringify(cp, null, 2), "utf8");
  return { checkpoint_id: cp.checkpoint_id, method: "local", ref: path, anchored_at: new Date().toISOString() };
}

// ── S3 anchor ─────────────────────────────────────────────────────────────────

// Reads config from env: KAVACHOS_S3_BUCKET, AWS_REGION (+ standard AWS credentials)
// Object Lock: set KAVACHOS_S3_OBJECT_LOCK=true for append-only (requires bucket with Object Lock enabled)
async function anchorS3(cp: MerkleCheckpoint): Promise<AnchorResult> {
  const bucket = process.env.KAVACHOS_S3_BUCKET;
  const region = process.env.AWS_REGION ?? "ap-south-1";
  if (!bucket) throw new Error("KAVACHOS_S3_BUCKET not set");

  // Dynamic import — AWS SDK v3 is optional; falls through to local if not installed
  const { S3Client, PutObjectCommand } = await import("@aws-sdk/client-s3");

  const client = new S3Client({ region });
  const key = `kavachos/checkpoints/${cp.checkpoint_id}.json`;
  const body = JSON.stringify(cp, null, 2);

  const cmd = new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: body,
    ContentType: "application/json",
    // Object Lock: COMPLIANCE mode — no deletion possible during retention period
    ...(process.env.KAVACHOS_S3_OBJECT_LOCK === "true" ? {
      ObjectLockMode: "COMPLIANCE",
      ObjectLockRetainUntilDate: new Date(Date.now() + 7 * 365 * 24 * 60 * 60 * 1000), // 7 years
    } : {}),
  });

  await client.send(cmd);
  const ref = `s3://${bucket}/${key}`;
  return { checkpoint_id: cp.checkpoint_id, method: "s3", ref, anchored_at: new Date().toISOString() };
}

// ── Public: anchor and record ─────────────────────────────────────────────────

// @rule:KOS-T041 anchor checkpoint: S3 preferred, local fallback
export async function anchorCheckpoint(cp: MerkleCheckpoint): Promise<AnchorResult> {
  let result: AnchorResult;

  try {
    if (process.env.KAVACHOS_S3_BUCKET) {
      result = await anchorS3(cp);
    } else {
      result = anchorLocal(cp);
    }
  } catch (err) {
    // Silently fall back to local — anchoring must never block the checkpoint write
    result = anchorLocal(cp);
    result.ref += ` (s3 error: ${(err as Error).message})`;
  }

  // Record anchor ref in DB
  ensureMerkleSchema();
  const db = getDb();
  db.run(
    "UPDATE merkle_checkpoints SET anchor_ref = ?, anchored_at = ? WHERE checkpoint_id = ?",
    [result.ref, result.anchored_at, cp.checkpoint_id]
  );

  return result;
}

// ── List local anchors ────────────────────────────────────────────────────────

export function listLocalAnchors(): string[] {
  const dir = localCheckpointDir();
  return readdirSync(dir).filter(f => f.endsWith(".json")).sort();
}

export function readLocalAnchor(checkpointId: string): MerkleCheckpoint | null {
  const path = join(localCheckpointDir(), `${checkpointId}.json`);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}
