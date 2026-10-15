// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// The flow-receipt chain (governed-turn-protocol §19, P5; gap 3 of the flow guardrails).
//
// Every flow receipt names the one before it: its `chain` field holds its sequence number and the SHA-256 of
// the previous receipt file, and it is signed with that field in it. An index, <aegis dir>/flow-receipts/
// chain.jsonl, lists each receipt's file and hash in order. Changing, removing or reordering any receipt
// breaks every link after it, and `aegis flow-receipts verify` says where.
//
// What this does not give, said plainly: the chain is kept and signed on this box, with a secret a session
// running as the same user can read. Cutting the END of the chain (removing the newest receipts and their
// index lines together) leaves a shorter chain that still verifies. That is what publishing the head in a
// public log closes: once a head is out, a later chain must contain it. `aegis flow-receipts head` prints the
// value to publish; sending it is the founder's step, with a key and a log of his choosing.

import { createHash, timingSafeEqual } from "crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmdirSync, statSync, writeFileSync } from "fs";
import { join } from "path";
import { getAegisDir } from "../core/config";
import { signWithMachineSecret } from "../kernel/mudrika";

export const GENESIS = "0".repeat(64);

export interface ChainLink { seq: number; prev: string }
export interface IndexLine { seq: number; file: string; hash: string; prev: string; at: string }

export const receiptsDir = (): string => join(getAegisDir(), "flow-receipts");
const indexPath = (): string => join(receiptsDir(), "chain.jsonl");
const lockPath = (): string => join(receiptsDir(), ".chain.lock");
const sha256 = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");

/** JSON with every object's keys sorted, at every depth. */
export function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v ?? null);
}

/** The text a receipt's signature covers: everything but the signature. */
export function canonicalOf(r: Record<string, unknown>): string {
  const { signature: _s, ...rest } = r;
  return stable(rest);
}

/** Heads published in a public log (public-anchor.ts writes them). */
export interface AnchorRecord { seq: number; hash: string; uuid: string; log_index: number | null; integrated_time: number | null; log: string; at: string }
export const anchorsPath = (): string => join(receiptsDir(), "anchors.jsonl");
export function readAnchors(): AnchorRecord[] {
  try { return readFileSync(anchorsPath(), "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l) as AnchorRecord); } catch { return []; }
}

function readIndex(): IndexLine[] {
  try {
    return readFileSync(indexPath(), "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l) as IndexLine);
  } catch { return []; }
}

/** A short lock: mkdir is atomic. A lock older than 10 s is taken as left behind by a dead process. */
function withLock<T>(fn: () => T): T | null {
  for (let i = 0; i < 80; i++) {
    try {
      mkdirSync(lockPath());
      try { return fn(); } finally { try { rmdirSync(lockPath()); } catch { /* gone */ } }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      try { if (Date.now() - statSync(lockPath()).mtimeMs > 10_000) rmdirSync(lockPath()); } catch { /* raced */ }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
    }
  }
  return null;
}

/**
 * Add one receipt to the chain: give it its link, sign it, write it owner-only, and append its index line,
 * all under the lock. Returns null when the lock could not be had (the caller writes the receipt unchained
 * and says so: a busy chain must never trap an agent).
 */
export function appendToChain<R extends Record<string, unknown>>(name: string, receipt: R): { path: string; link: ChainLink; hash: string } | null {
  const dir = receiptsDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return withLock(() => {
    const index = readIndex();
    const last = index[index.length - 1];
    const link: ChainLink = { seq: last ? last.seq + 1 : 1, prev: last ? last.hash : GENESIS };
    const signed: Record<string, unknown> = { ...receipt, chain: link };
    delete signed.signature;
    signed.signature = signWithMachineSecret(canonicalOf(signed));
    const text = JSON.stringify(signed, null, 2);
    const path = join(dir, name);
    writeFileSync(path, text, { mode: 0o600 });
    const hash = sha256(text);
    appendFileSync(indexPath(), JSON.stringify({ seq: link.seq, file: name, hash, prev: link.prev, at: new Date().toISOString() }) + "\n", { mode: 0o600 });
    return { path, link, hash };
  });
}

export interface ChainCheck { ok: boolean; count: number; head: { seq: number; hash: string } | null; problems: string[] }

/** Walk the whole chain: order, links, file hashes, the link inside each receipt, and each signature. */
export function verifyChain(): ChainCheck {
  const index = readIndex();
  const problems: string[] = [];
  let prev = GENESIS;
  index.forEach((line, i) => {
    const at = `seq ${line.seq}`;
    if (line.seq !== i + 1) problems.push(`${at}: out of order (expected ${i + 1})`);
    if (line.prev !== prev) problems.push(`${at}: names ${line.prev.slice(0, 12)} as previous, but the previous is ${prev.slice(0, 12)}`);
    prev = line.hash;
    let text: string;
    try { text = readFileSync(join(receiptsDir(), line.file), "utf8"); } catch { problems.push(`${at}: receipt file ${line.file} is missing`); return; }
    if (sha256(text) !== line.hash) { problems.push(`${at}: ${line.file} was changed after it was written`); return; }
    let r: Record<string, unknown>;
    try { r = JSON.parse(text); } catch { problems.push(`${at}: ${line.file} is not JSON`); return; }
    const link = r.chain as ChainLink | undefined;
    if (!link || link.seq !== line.seq || link.prev !== line.prev) problems.push(`${at}: the link inside the receipt does not match the index`);
    const want = Buffer.from(signWithMachineSecret(canonicalOf(r)));
    const got = Buffer.from(typeof r.signature === "string" ? r.signature : "");
    if (got.length !== want.length || !timingSafeEqual(got, want)) problems.push(`${at}: signature does not verify`);
  });
  // A head once published must still be in the chain, at its place: otherwise the chain was cut or rewritten
  // after it was anchored. (This reads the local list of anchors; the log itself holds them for good.)
  for (const a of readAnchors()) {
    const line = index[a.seq - 1];
    if (!line || line.hash !== a.hash) problems.push(`anchored head seq ${a.seq} (${a.hash.slice(0, 12)}, log entry ${a.log_index ?? a.uuid}) is no longer in the chain at its place`);
  }
  const last = index[index.length - 1];
  return { ok: problems.length === 0, count: index.length, head: last ? { seq: last.seq, hash: last.hash } : null, problems };
}
