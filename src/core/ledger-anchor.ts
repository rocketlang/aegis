// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ledger-anchor — the signed refusal ledger, anchored in a public transparency log (concealment rung 4).
//
// The witness of rung 3 is a second copy. On one box it is not a second trust domain: whoever can cut
// the ledger's tail can cut the witness's copy too. A public append-only log (Sigsum) is somebody
// else's machine, and what it has once shown to the world it cannot quietly take back.
//
// The anchor is one leaf. Its message is the hash of a plain statement, "this ledger, known as S,
// stands at row N and the hash of that row is H", and it is signed with the LEDGER'S OWN key, by the
// authority, which is the only holder of that key. The statement carries no time: a ledger that has
// not grown yields the very same leaf, which the log already holds, so nothing new is written.
//
// HOW A CUT-OFF TAIL SHOWS. The leaf in the log holds only a hash of the statement, not N. A verifier
// who holds the ledger file works out the leaf each of its rows WOULD have produced, then reads the
// log for leaves under this ledger's key. Every such leaf must be one the file can produce. One that
// the file cannot produce means the ledger once stood at a state this file does not contain: its tail
// was cut, or it was rewritten.
//
// WHERE THE TRUST SITS, stated at the point of use:
//   - The log operator can refuse to show a leaf. Reading the whole log and rebuilding its root
//     against the signed tree head catches that; a partial read (from an index) does not, and says so.
//   - The log's cosigning witnesses are NOT checked here. The tree head is checked against the log's
//     own key only. A log that shows different trees to different readers is not caught by this code.
//   - Rows added after the last anchor are not covered until the next one.
//   - A ledger cut back BEFORE its first anchor leaves nothing in the log to contradict it.
//   - On a box where the agent can read the ledger key, the agent can sign an anchor for a state that
//     never existed and so raise a false alarm. It cannot use an anchor to hide a cut.

import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "crypto";
import { rowHash, type SignedRow } from "./ledger-sign";

const LEAF_NAMESPACE = Buffer.from("sigsum.org/v1/tree-leaf\0", "utf8");
const sha = (...parts: Uint8Array[]): Buffer => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };

/** The 32 raw bytes of an Ed25519 public key given as PEM. */
export function rawPublicKey(publicKeyPem: string): Buffer {
  return Buffer.from(createPublicKey(publicKeyPem).export({ format: "der", type: "spki" })).subarray(-32);
}
const keyFromRaw = (raw: Buffer): KeyObject =>
  createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });

/** The statement an anchor commits to. Starts with "anchor" where a row starts with "seq" and a heartbeat with "hb". */
export function anchorStatement(source: string, maxSeq: number, tailHash: string): string {
  return JSON.stringify({ anchor: 1, source, max_seq: maxSeq, tail_hash: tailHash });
}

export interface Anchor {
  source: string;
  max_seq: number;
  tail_hash: string;
  statement: string;
  /** H(statement): the `message` of the add-leaf request. */
  message: string;
  /** H(message): what the log stores and what the signature covers. */
  checksum: string;
  signature: string;
  public_key: string;
  key_hash: string;
  leaf_hash: string;
}

/** The checksum the log would hold for a ledger standing at (source, seq, hash). */
export function anchorChecksum(source: string, maxSeq: number, tailHash: string): string {
  return sha(sha(Buffer.from(anchorStatement(source, maxSeq, tailHash), "utf8"))).toString("hex");
}

export function leafHash(checksumHex: string, signatureHex: string, keyHashHex: string): string {
  return sha(Buffer.from([0]), Buffer.from(checksumHex, "hex"), Buffer.from(signatureHex, "hex"), Buffer.from(keyHashHex, "hex")).toString("hex");
}

/** Sign an anchor for a ledger standing at (seq, hash). Only the authority calls this: it holds the key. */
export function signAnchor(source: string, maxSeq: number, tailHash: string, privateKeyPem: string, publicKeyPem: string): Anchor {
  const statement = anchorStatement(source, maxSeq, tailHash);
  const message = sha(Buffer.from(statement, "utf8"));
  const checksum = sha(message);
  const signature = edSign(null, Buffer.concat([LEAF_NAMESPACE, checksum]), createPrivateKey(privateKeyPem));
  const pub = rawPublicKey(publicKeyPem);
  const keyHash = sha(pub);
  return {
    source, max_seq: maxSeq, tail_hash: tailHash, statement,
    message: message.toString("hex"), checksum: checksum.toString("hex"), signature: signature.toString("hex"),
    public_key: pub.toString("hex"), key_hash: keyHash.toString("hex"),
    leaf_hash: leafHash(checksum.toString("hex"), signature.toString("hex"), keyHash.toString("hex")),
  };
}

/** Is this (checksum, signature) a leaf signed by the holder of publicKeyPem? */
export function verifyLeafSignature(checksumHex: string, signatureHex: string, publicKeyPem: string): boolean {
  try {
    return edVerify(null, Buffer.concat([LEAF_NAMESPACE, Buffer.from(checksumHex, "hex")]), createPublicKey(publicKeyPem), Buffer.from(signatureHex, "hex"));
  } catch { return false; }
}

/** An anchor as handed over by the authority: every field recomputed from the statement, nothing taken on trust. */
export function verifyAnchor(a: Anchor, publicKeyPem: string): boolean {
  try {
    if (!a || typeof a.statement !== "string" || a.statement !== anchorStatement(a.source, a.max_seq, a.tail_hash)) return false;
    const message = sha(Buffer.from(a.statement, "utf8")); const checksum = sha(message); const pub = rawPublicKey(publicKeyPem);
    if (a.message !== message.toString("hex") || a.checksum !== checksum.toString("hex")) return false;
    if (a.public_key !== pub.toString("hex") || a.key_hash !== sha(pub).toString("hex")) return false;
    if (a.leaf_hash !== leafHash(a.checksum, a.signature, a.key_hash)) return false;
    return verifyLeafSignature(a.checksum, a.signature, publicKeyPem);
  } catch { return false; }
}

/** For each row of a verified ledger, the checksum its anchor would have. Index i is row seq i+1. */
export function checksumsForRows(rows: SignedRow[], source: string): string[] {
  return rows.map((r) => anchorChecksum(source, r.seq, rowHash(r)));
}

// ── the log, by its written protocol (sigsum log.md) ────────────────────────────────────────────

export interface AnchorLog { url: string; publicKey: string }
export interface TreeHead { size: number; root_hash: string; signature: string; cosignatures: number }
export interface LoggedLeaf { index: number; checksum: string; signature: string; key_hash: string }

const kv = (text: string): [string, string][] =>
  text.split("\n").filter(Boolean).map((l) => { const i = l.indexOf("="); return [l.slice(0, i), l.slice(i + 1)] as [string, string]; });

async function http(log: AnchorLog, method: "GET" | "POST", path: string, body?: string, headers?: Record<string, string>): Promise<{ status: number; text: string }> {
  const r = await fetch(log.url.replace(/\/$/, "") + path, { method, body, headers, signal: AbortSignal.timeout(30_000) });
  return { status: r.status, text: await r.text() };
}

/** The log's current tree head, accepted only if the log's own key signed it. */
export async function getTreeHead(log: AnchorLog): Promise<TreeHead> {
  const r = await http(log, "GET", "/get-tree-head");
  if (r.status !== 200) throw new Error(`get-tree-head answered ${r.status}`);
  const pairs = kv(r.text); const get = (k: string) => pairs.find(([x]) => x === k)?.[1] ?? "";
  const head: TreeHead = { size: Number(get("size")), root_hash: get("root_hash"), signature: get("signature"), cosignatures: pairs.filter(([k]) => k === "cosignature").length };
  const logKey = Buffer.from(log.publicKey, "hex");
  const signed = `sigsum.org/v1/tree/${sha(logKey).toString("hex")}\n${head.size}\n${Buffer.from(head.root_hash, "hex").toString("base64")}\n`;
  let good = false;
  try { good = logKey.length === 32 && edVerify(null, Buffer.from(signed), keyFromRaw(logKey), Buffer.from(head.signature, "hex")); } catch { good = false; }
  if (!good || !Number.isInteger(head.size)) throw new Error("the tree head is not signed by the log key given for this log");
  return head;
}

/** RFC 6962 inclusion-proof check. */
export function verifyInclusion(leafHashHex: string, index: number, size: number, path: string[], rootHex: string): boolean {
  let fn = index, sn = size - 1;
  let r: Buffer = Buffer.from(leafHashHex, "hex");
  for (const hex of path) {
    const p = Buffer.from(hex, "hex");
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = sha(Buffer.from([1]), p, r);
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else r = sha(Buffer.from([1]), r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.toString("hex") === rootHex;
}

/** RFC 6962 root of a list of leaf hashes (largest power of two smaller than n splits the list). */
export function merkleRoot(leafHashes: Buffer[]): Buffer {
  if (leafHashes.length === 0) return sha();
  const sub = (lo: number, hi: number): Buffer => {
    if (hi - lo === 1) return leafHashes[lo];
    let k = 1; while (k * 2 < hi - lo) k *= 2;
    return sha(Buffer.from([1]), sub(lo, lo + k), sub(lo + k, hi));
  };
  return sub(0, leafHashes.length);
}

async function inclusionProof(log: AnchorLog, size: number, leafHashHex: string): Promise<{ index: number; path: string[] } | null> {
  if (size === 1) return { index: 0, path: [] };   // a one-leaf tree has no proof to ask for
  const r = await http(log, "GET", `/get-inclusion-proof/${size}/${leafHashHex}`);
  if (r.status !== 200) return null;
  const pairs = kv(r.text);
  return { index: Number(pairs.find(([k]) => k === "leaf_index")?.[1]), path: pairs.filter(([k]) => k === "node_hash").map(([, v]) => v) };
}

export interface AnchorReceipt {
  at: string; log: string; log_key: string;
  source: string; max_seq: number; tail_hash: string; statement: string;
  checksum: string; signature: string; key_hash: string; leaf_hash: string;
  leaf_index: number; tree_size: number; root_hash: string; cosignatures: number;
}

export type SubmitOutcome =
  | { ok: true; receipt: AnchorReceipt }
  | { ok: false; kind: "refused" | "pending" | "unproven"; detail: string };

/**
 * Submit an anchor and do not call it done until the log proves it: add-leaf until 200, then an
 * inclusion proof that verifies against a tree head the log's key signed.
 */
export async function submitAnchor(
  log: AnchorLog, a: Anchor, tokenHeader: string | null,
  opts: { tries?: number; waitMs?: number; say?: (line: string) => void } = {},
): Promise<SubmitOutcome> {
  const tries = opts.tries ?? 40, waitMs = opts.waitMs ?? 3000, say = opts.say ?? (() => {});
  const body = `message=${a.message}\nsignature=${a.signature}\npublic_key=${a.public_key}\n`;
  const headers = tokenHeader ? { "sigsum-token": tokenHeader.replace(/^sigsum-token:\s*/i, "") } : undefined;
  let status = 0;
  for (let i = 0; i < tries && status !== 200; i++) {
    const r = await http(log, "POST", "/add-leaf", body, headers);
    status = r.status;
    say(`add-leaf try ${i + 1}: http ${r.status} ${r.text.trim().slice(0, 120)}`);
    if (status !== 200 && status !== 202) return { ok: false, kind: "refused", detail: `the log answered ${r.status}: ${r.text.trim().slice(0, 200)}` };
    if (status !== 200) await new Promise((res) => setTimeout(res, waitMs));
  }
  if (status !== 200) return { ok: false, kind: "pending", detail: `accepted but not committed after ${tries} tries` };
  for (let i = 0; i < tries; i++) {
    const head = await getTreeHead(log);
    const p = await inclusionProof(log, head.size, a.leaf_hash);
    if (p) {
      if (!verifyInclusion(a.leaf_hash, p.index, head.size, p.path, head.root_hash)) return { ok: false, kind: "unproven", detail: "the log's inclusion proof does not verify against its signed tree head" };
      return { ok: true, receipt: {
        at: new Date().toISOString(), log: log.url, log_key: log.publicKey,
        source: a.source, max_seq: a.max_seq, tail_hash: a.tail_hash, statement: a.statement,
        checksum: a.checksum, signature: a.signature, key_hash: a.key_hash, leaf_hash: a.leaf_hash,
        leaf_index: p.index, tree_size: head.size, root_hash: head.root_hash, cosignatures: head.cosignatures,
      } };
    }
    await new Promise((res) => setTimeout(res, waitMs));
  }
  return { ok: false, kind: "unproven", detail: "committed, but no inclusion proof within the wait" };
}

export interface ScanResult {
  head: TreeHead;
  from: number;
  /** Leaves under the given key hash, in log order. */
  leaves: LoggedLeaf[];
  /** true = the whole log was read and its root rebuilt against the signed head. false = partial read; omission by the log is not ruled out. */
  whole_log_checked: boolean;
}

/**
 * Read the log from `from` and return every leaf under keyHash. Read from 0 and the leaves are
 * rebuilt into the root the log signed, so the log cannot have left one out. Read from further on
 * and each found leaf is proven included, which says nothing about a leaf the log did not show.
 */
export async function scanForKey(log: AnchorLog, keyHashHex: string, from = 0, say: (line: string) => void = () => {}): Promise<ScanResult> {
  const head = await getTreeHead(log);
  const start = Math.max(0, Math.min(from, head.size));
  const found: LoggedLeaf[] = []; const all: Buffer[] = [];
  let at = start;
  while (at < head.size) {
    const r = await http(log, "GET", `/get-leaves/${at}/${head.size}`);
    if (r.status !== 200) throw new Error(`get-leaves answered ${r.status} at index ${at}`);
    const got = kv(r.text).filter(([k]) => k === "leaf").map(([, v]) => v.split(" "));
    if (got.length === 0) throw new Error(`get-leaves returned nothing at index ${at} of ${head.size}`);
    for (const [checksum, signature, keyHash] of got) {
      if (at >= head.size) break;
      if (start === 0) all.push(Buffer.from(leafHash(checksum, signature, keyHash), "hex"));
      if (keyHash === keyHashHex) found.push({ index: at, checksum, signature, key_hash: keyHash });
      at++;
    }
    say(`read ${at - start} of ${head.size - start} leaves`);
  }
  if (start === 0) {
    if (merkleRoot(all).toString("hex") !== head.root_hash) throw new Error("the leaves the log returned do not rebuild the root it signed: a leaf was changed or left out");
    return { head, from: 0, leaves: found, whole_log_checked: true };
  }
  for (const l of found) {
    const lh = leafHash(l.checksum, l.signature, l.key_hash);
    const p = await inclusionProof(log, head.size, lh);
    if (!p || !verifyInclusion(lh, p.index, head.size, p.path, head.root_hash)) throw new Error(`leaf at index ${l.index} is not proven included in the signed tree`);
  }
  return { head, from: start, leaves: found, whole_log_checked: false };
}

export type AnchorVerdict =
  | { kind: "anchored"; upTo: number; maxSeq: number; anchors: number; leafIndex: number; wholeLog: boolean; cosignatures: number }
  | { kind: "contradicted"; unmatched: LoggedLeaf[]; anchors: number; wholeLog: boolean }
  | { kind: "none"; wholeLog: boolean; from: number; treeSize: number };

/**
 * Compare a VERIFIED on-box ledger with what the log holds under its key. Leaves under the key that
 * the key did not sign are ignored (anyone can name any key hash). A genuine anchor the file cannot
 * produce is the finding.
 */
export function judgeAnchors(rows: SignedRow[], source: string, publicKeyPem: string, scan: ScanResult): AnchorVerdict {
  const mine = checksumsForRows(rows, source);
  const genuine = scan.leaves.filter((l) => verifyLeafSignature(l.checksum, l.signature, publicKeyPem));
  if (genuine.length === 0) return { kind: "none", wholeLog: scan.whole_log_checked, from: scan.from, treeSize: scan.head.size };
  const unmatched = genuine.filter((l) => !mine.includes(l.checksum));
  if (unmatched.length) return { kind: "contradicted", unmatched, anchors: genuine.length, wholeLog: scan.whole_log_checked };
  let upTo = 0, leafIndex = -1;
  for (const l of genuine) { const seq = mine.indexOf(l.checksum) + 1; if (seq > upTo) { upTo = seq; leafIndex = l.index; } }
  return { kind: "anchored", upTo, maxSeq: rows.length ? rows[rows.length - 1].seq : 0, anchors: genuine.length, leafIndex, wholeLog: scan.whole_log_checked, cosignatures: scan.head.cosignatures };
}
