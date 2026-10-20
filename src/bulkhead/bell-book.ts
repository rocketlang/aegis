// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The bell book: an append-only, hash-chained record of everything that crosses a bulkhead.
// @rule:BLK-005 every message, door decision, taint and taint drop is a row, written by the bulkhead
// @rule:BLK-006 hash-chained; a break is reported, never repaired in place

import { appendFileSync, existsSync, readFileSync } from "fs";
import { createHash } from "crypto";

export const GENESIS = "0".repeat(64);

export function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  return "{" + Object.keys(o).filter((k) => o[k] !== undefined).sort()
    .map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export interface BellRow {
  seq: number;
  at: string;
  event: string;
  [k: string]: unknown;
  prev_hash: string;
  hash: string;
}

export type VerifyResult =
  | { holds: true; rows: number; last_hash: string }
  | { holds: false; rows: number; broken_at: number; reason: string };

export class BellBook {
  private seq = 0;
  private last = GENESIS;

  constructor(readonly path: string) {
    if (existsSync(path)) {
      const v = verifyBellBook(path);
      if (!v.holds) throw new Error(`BLK-006: bell book broken at row ${v.broken_at}: ${v.reason} — not appending to a broken book`);
      this.seq = v.rows;
      this.last = v.last_hash;
    }
  }

  append(event: string, fields: Record<string, unknown>): BellRow {
    const row = { ...fields, seq: this.seq + 1, at: new Date().toISOString(), event, prev_hash: this.last } as Omit<BellRow, "hash">;
    const hash = sha256(canonical(row));
    const full = { ...row, hash } as BellRow;
    appendFileSync(this.path, JSON.stringify(full) + "\n");
    this.seq = full.seq;
    this.last = hash;
    return full;
  }
}

export function verifyBellBook(path: string): VerifyResult {
  if (!existsSync(path)) return { holds: true, rows: 0, last_hash: GENESIS };
  const lines = readFileSync(path, "utf-8").split("\n").filter((l) => l.length > 0);
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let row: BellRow;
    try { row = JSON.parse(lines[i]); } catch { return { holds: false, rows: lines.length, broken_at: i + 1, reason: "not JSON" }; }
    if (row.seq !== i + 1) return { holds: false, rows: lines.length, broken_at: i + 1, reason: `seq ${row.seq}, expected ${i + 1}` };
    if (row.prev_hash !== prev) return { holds: false, rows: lines.length, broken_at: i + 1, reason: "prev_hash does not match the row before" };
    const { hash, ...rest } = row;
    if (sha256(canonical(rest)) !== hash) return { holds: false, rows: lines.length, broken_at: i + 1, reason: "row changed after it was written" };
    prev = hash;
  }
  return { holds: true, rows: lines.length, last_hash: prev };
}
