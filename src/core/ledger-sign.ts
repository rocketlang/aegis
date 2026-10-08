// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ledger-sign — a sequenced, signed, hash-chained refusal/approval ledger (concealment rung 2).
//
// A log the agent can write is evidence against accidents, not against concealment (the point
// Shyan-Ming Perng of JieGou made in "The Log Only Keeps the Yes"). This makes an intentional edit
// or deletion DETECTABLE: every row carries a monotonic seq, the hash of the previous row, and an
// Ed25519 signature by an authority key held OFF the agent's uid (point 1 — Andrey Lazarev).
//
// What it catches: a deleted MIDDLE row (seq gap), an edited row (signature / chain break), a forged
// row (bad signature), and an unsigned ledger (reported UNVERIFIABLE, never OK).
// What it does NOT catch on-box (state it): TRUNCATION of the tail — removing the most recent rows
// leaves 1..k contiguous and chained. Detecting that needs an external high-water-mark (the off-box
// witness, rung 3): the verifier returns maxSeq so a collector that knows the true last seq catches it.

import { createHash, sign as edSign, verify as edVerify, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "crypto";

export interface LedgerPayload {
  ts: string;
  kind: string;
  gate: string;
  rule: string | null;
  session: string | null;
}
export interface SignedRow extends LedgerPayload {
  seq: number;
  prev_hash: string;
  sig: string;
}

/** The ledger authority's keypair. The private key stays with the authority (off the agent's uid). */
export function generateLedgerKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

// Deterministic bytes the signature and the chain hash both commit to — seq, prev_hash and the payload.
function canonical(seq: number, prevHash: string, p: LedgerPayload): string {
  return JSON.stringify({
    seq, prev_hash: prevHash,
    ts: p.ts, kind: p.kind, gate: p.gate, rule: p.rule ?? null, session: p.session ?? null,
  });
}

/** Hash of a row, used as the next row's prev_hash (the chain link). */
export function rowHash(r: SignedRow): string {
  return createHash("sha256").update(canonical(r.seq, r.prev_hash, r)).digest("hex");
}

/** Sign a payload at position seq, chained to prevHash, with the authority private key. */
export function signLedgerRow(payload: LedgerPayload, seq: number, prevHash: string, privateKeyPem: string | KeyObject): SignedRow {
  const key = typeof privateKeyPem === "string" ? createPrivateKey(privateKeyPem) : privateKeyPem;
  const sig = edSign(null, Buffer.from(canonical(seq, prevHash, payload), "utf8"), key).toString("base64");
  return { ...payload, seq, prev_hash: prevHash, sig };
}

/** Verify one row's Ed25519 signature over its canonical (seq, prev_hash, payload). */
export function verifyRowSig(row: SignedRow, publicKeyPem: string): boolean {
  try {
    return edVerify(null, Buffer.from(canonical(row.seq, row.prev_hash, row), "utf8"), createPublicKey(publicKeyPem), Buffer.from(row.sig, "base64"));
  } catch {
    return false;
  }
}

export type LedgerVerdict =
  | { ok: true; rows: number; maxSeq: number }
  | { ok: false; kind: "gap" | "chain" | "signature" | "unverifiable"; seq: number | null; detail: string };

/**
 * Verify a ledger: contiguous seq from 1, intact prev_hash chain, every signature valid under the
 * authority public key. Returns the FIRST break found, or ok with the row count and maxSeq (a caller
 * that holds an external high-water-mark compares maxSeq to catch tail truncation — rung 3).
 */
export function verifyLedgerRows(rows: unknown[], publicKeyPem: string | null): LedgerVerdict {
  if (!Array.isArray(rows) || rows.length === 0) return { ok: true, rows: 0, maxSeq: 0 };
  if (!publicKeyPem) return { ok: false, kind: "unverifiable", seq: null, detail: "no authority public key" };
  const typed = rows.filter((r): r is SignedRow => !!r && typeof r === "object");
  if (typed.length !== rows.length || typed.some((r) => typeof r.seq !== "number" || typeof r.sig !== "string" || typeof r.prev_hash !== "string")) {
    return { ok: false, kind: "unverifiable", seq: null, detail: "unsigned or malformed rows — this ledger carries no seq/sig/chain" };
  }
  let pub: KeyObject;
  try { pub = createPublicKey(publicKeyPem); } catch { return { ok: false, kind: "unverifiable", seq: null, detail: "authority public key is not a usable Ed25519 key" }; }

  let prev = "";
  for (let i = 0; i < typed.length; i++) {
    const r = typed[i];
    const expect = i + 1;
    if (r.seq !== expect) return { ok: false, kind: "gap", seq: expect, detail: `sequence gap: expected seq ${expect}, got ${r.seq} — a row was suppressed or deleted` };
    if (r.prev_hash !== prev) return { ok: false, kind: "chain", seq: r.seq, detail: `chain break at seq ${r.seq}: prev_hash does not match the prior row` };
    let good = false;
    try { good = edVerify(null, Buffer.from(canonical(r.seq, r.prev_hash, r), "utf8"), pub, Buffer.from(r.sig, "base64")); } catch { good = false; }
    if (!good) return { ok: false, kind: "signature", seq: r.seq, detail: `bad signature at seq ${r.seq}: the row was tampered or signed by another key` };
    prev = rowHash(r);
  }
  return { ok: true, rows: typed.length, maxSeq: typed[typed.length - 1].seq };
}
