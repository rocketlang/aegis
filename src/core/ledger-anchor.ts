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
//   - The log's cosigning witnesses are checked only when a trust policy is given (parsePolicy,
//     checkCosignatures below). A witness cosigns a tree head only if it is consistent with every
//     head it saw before, so a quorum of them is what stops a log showing different trees to
//     different readers. Without a policy the tree head is checked against the log's own key only,
//     and the output says so. With one, the trust is in the policy's choice of witnesses.
//   - Rows added after the last anchor are not covered until the next one.
//   - A QUIET LEDGER AND A DEAD AUTHORITY looked the same in the log through 2.16.3: the statement
//     carried no time, so a ledger that had not grown added no leaf (pointed out by Andrey Lazarev,
//     11 October 2026). Since 2.17.0 an anchor can be DATED (form 2, `aegis ledger-anchor --dated`):
//     one leaf a day, grown or not. From the first dated leaf on, a day with no leaf is a day the
//     authority did not speak, and ledger-verify names it. What a dated leaf does NOT show:
//       · that this box or this daemon was alive, only that the holder of the ledger key signed that day;
//       · the missed day afterwards: the authority signs for today only, so a day lost to an
//         unreachable log stays a hole;
//       · anything to a reader who does not hold the ledger's tail (row number and hash): the leaf is
//         a hash. Someone given the tail once can check each later quiet day alone;
//       · WHEN the leaf reached the log, from the log alone. The log serves only its newest tree head.
//         The receipt kept at submission holds the cosigned head, whose witness times bound it
//         (checkLeafTimes); a dated leaf with no such receipt is dated on the key holder's word.
//     An empty ledger still has nothing to anchor, dated or not.
//   - A ledger cut back BEFORE its first anchor leaves nothing in the log to contradict it.
//   - On a box where the agent can read the ledger key, the agent can sign an anchor for a state that
//     never existed and so raise a false alarm. It cannot use an anchor to hide a cut.

import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "crypto";
import { rowHash, type SignedRow } from "./ledger-sign";
import { existsSync, readFileSync } from "fs";
import { join } from "path";

const LEAF_NAMESPACE = Buffer.from("sigsum.org/v1/tree-leaf\0", "utf8");
const sha = (...parts: Uint8Array[]): Buffer => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };

/** The 32 raw bytes of an Ed25519 public key given as PEM. */
export function rawPublicKey(publicKeyPem: string): Buffer {
  return Buffer.from(createPublicKey(publicKeyPem).export({ format: "der", type: "spki" })).subarray(-32);
}
const keyFromRaw = (raw: Buffer): KeyObject =>
  createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]), format: "der", type: "spki" });

/** A calendar day in UTC, "2026-10-11". The only form a dated anchor carries. */
export const isDay = (v: unknown): v is string => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v + "T00:00:00Z"));
export const utcDay = (d: Date = new Date()): string => d.toISOString().slice(0, 10);
const addDays = (day: string, n: number): string => utcDay(new Date(Date.parse(day + "T00:00:00Z") + n * 86_400_000));

/**
 * The statement an anchor commits to. Starts with "anchor" where a row starts with "seq" and a heartbeat with "hb".
 *
 * Without a day (form 1): "this ledger stands at row N with hash H". A ledger that has not grown yields the same
 * leaf again, so a quiet ledger and a dead authority look the same in the log.
 * With a day (form 2, since 2.17.0): "on this UTC day, this ledger stands at row N with hash H". One a day, grown
 * or not, so a day with no leaf is a day the authority did not speak. The day is the AUTHORITY'S clock, never the
 * asker's: nobody can ask it to sign for tomorrow or for yesterday.
 */
export function anchorStatement(source: string, maxSeq: number, tailHash: string, day?: string): string {
  return day === undefined
    ? JSON.stringify({ anchor: 1, source, max_seq: maxSeq, tail_hash: tailHash })
    : JSON.stringify({ anchor: 2, source, max_seq: maxSeq, tail_hash: tailHash, day });
}

export interface Anchor {
  source: string;
  max_seq: number;
  tail_hash: string;
  /** The UTC day a dated anchor speaks for. Absent on an undated (form 1) anchor. */
  day?: string;
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
export function anchorChecksum(source: string, maxSeq: number, tailHash: string, day?: string): string {
  return sha(sha(Buffer.from(anchorStatement(source, maxSeq, tailHash, day), "utf8"))).toString("hex");
}

export function leafHash(checksumHex: string, signatureHex: string, keyHashHex: string): string {
  return sha(Buffer.from([0]), Buffer.from(checksumHex, "hex"), Buffer.from(signatureHex, "hex"), Buffer.from(keyHashHex, "hex")).toString("hex");
}

/** Sign an anchor for a ledger standing at (seq, hash). Only the authority calls this: it holds the key. */
export function signAnchor(source: string, maxSeq: number, tailHash: string, privateKeyPem: string, publicKeyPem: string, day?: string): Anchor {
  if (day !== undefined && !isDay(day)) throw new Error(`'${day}' is not a day (YYYY-MM-DD)`);
  const statement = anchorStatement(source, maxSeq, tailHash, day);
  const message = sha(Buffer.from(statement, "utf8"));
  const checksum = sha(message);
  const signature = edSign(null, Buffer.concat([LEAF_NAMESPACE, checksum]), createPrivateKey(privateKeyPem));
  const pub = rawPublicKey(publicKeyPem);
  const keyHash = sha(pub);
  return {
    source, max_seq: maxSeq, tail_hash: tailHash, ...(day !== undefined ? { day } : {}), statement,
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
    if (a && a.day !== undefined && !isDay(a.day)) return false;
    if (!a || typeof a.statement !== "string" || a.statement !== anchorStatement(a.source, a.max_seq, a.tail_hash, a.day)) return false;
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
export interface Cosignature { key_hash: string; timestamp: number; signature: string }
export interface TreeHead { size: number; root_hash: string; signature: string; cosignatures: number; cosigs: Cosignature[]; checkpoint: string }
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
  const logKey = Buffer.from(log.publicKey, "hex");
  const signed = `sigsum.org/v1/tree/${sha(logKey).toString("hex")}\n${Number(get("size"))}\n${Buffer.from(get("root_hash"), "hex").toString("base64")}\n`;
  const cosigs = pairs.filter(([k]) => k === "cosignature").map(([, v]) => { const [key_hash, ts, signature] = v.split(" "); return { key_hash, timestamp: Number(ts), signature }; });
  const head: TreeHead = { size: Number(get("size")), root_hash: get("root_hash"), signature: get("signature"), cosignatures: cosigs.length, cosigs, checkpoint: signed };
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
  /** The UTC day of a dated anchor (form 2). Absent on an undated one. */
  day?: string;
  checksum: string; signature: string; key_hash: string; leaf_hash: string;
  leaf_index: number; tree_size: number; root_hash: string; cosignatures: number;
  /**
   * The tree head the proof was checked against, whole: the log's signature and every cosignature with its time.
   * Kept since 2.17.0 so that WHEN the leaf was in the log can be checked again later by anyone, on the witnesses'
   * signatures (checkLeafTimes). The log itself serves only its newest head.
   */
  head_signature?: string; cosigs?: Cosignature[];
  /** With a trust policy: the witnesses whose cosignature on that tree head verified, and the quorum rule met. Without: null. */
  witnessed_by?: string[] | null; quorum?: string | null;
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
  opts: { tries?: number; waitMs?: number; say?: (line: string) => void; policy?: TrustPolicy | null } = {},
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
  let lastCheck: CosignCheck | null = null;
  for (let i = 0; i < tries; i++) {
    const head = await getTreeHead(log);
    const check = opts.policy ? checkCosignatures(head, log, opts.policy) : null; lastCheck = check;
    const p = check && !check.met ? null : await inclusionProof(log, head.size, a.leaf_hash);
    if (p) {
      if (!verifyInclusion(a.leaf_hash, p.index, head.size, p.path, head.root_hash)) return { ok: false, kind: "unproven", detail: "the log's inclusion proof does not verify against its signed tree head" };
      return { ok: true, receipt: {
        at: new Date().toISOString(), log: log.url, log_key: log.publicKey,
        source: a.source, max_seq: a.max_seq, tail_hash: a.tail_hash, statement: a.statement, ...(a.day !== undefined ? { day: a.day } : {}),
        head_signature: head.signature, cosigs: head.cosigs,
        checksum: a.checksum, signature: a.signature, key_hash: a.key_hash, leaf_hash: a.leaf_hash,
        leaf_index: p.index, tree_size: head.size, root_hash: head.root_hash, cosignatures: head.cosignatures,
        witnessed_by: check ? check.witnessed : null, quorum: check ? check.quorum : null,
      } };
    }
    await new Promise((res) => setTimeout(res, waitMs));
  }
  if (lastCheck && !lastCheck.met) return { ok: false, kind: "unproven", detail: `committed, but no tree head cosigned by the policy's quorum ('${lastCheck.quorum}') was seen within the wait; verified witnesses on the last head: ${lastCheck.witnessed.join(", ") || "none"}` };
  return { ok: false, kind: "unproven", detail: "committed, but no inclusion proof within the wait" };
}

export interface ScanResult {
  head: TreeHead;
  from: number;
  /** Leaves under the given key hash, in log order. */
  leaves: LoggedLeaf[];
  /** true = the whole log was read and its root rebuilt against the signed head. false = partial read; omission by the log is not ruled out. */
  whole_log_checked: boolean;
  /** With a trust policy: which witnesses cosigned the head that was read, and whether the quorum is met. Without: null. */
  cosign: CosignCheck | null;
}

/**
 * Read the log from `from` and return every leaf under keyHash. Read from 0 and the leaves are
 * rebuilt into the root the log signed, so the log cannot have left one out. Read from further on
 * and each found leaf is proven included, which says nothing about a leaf the log did not show.
 */
export async function scanForKey(log: AnchorLog, keyHashHex: string, from = 0, say: (line: string) => void = () => {}, policy: TrustPolicy | null = null): Promise<ScanResult> {
  let head: TreeHead; let cosign: CosignCheck | null = null;
  if (policy) { const w = await getWitnessedTreeHead(log, policy); head = w.head; cosign = w.check; } else head = await getTreeHead(log);
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
    return { head, from: 0, leaves: found, whole_log_checked: true, cosign };
  }
  for (const l of found) {
    const lh = leafHash(l.checksum, l.signature, l.key_hash);
    const p = await inclusionProof(log, head.size, lh);
    if (!p || !verifyInclusion(lh, p.index, head.size, p.path, head.root_hash)) throw new Error(`leaf at index ${l.index} is not proven included in the signed tree`);
  }
  return { head, from: start, leaves: found, whole_log_checked: false, cosign };
}

/** A dated leaf found in the log and matched to a row of the file. */
export interface DatedLeaf { index: number; checksum: string; seq: number; day: string }

/** What the dated leaves say about the days since the first of them. null = the log holds no dated leaf for this ledger. */
export interface DatedReading {
  leaves: DatedLeaf[];
  first: string; last: string;
  /** Days after the first dated day and before the last one with no leaf: the authority came back afterwards. */
  holes: string[];
  /** Days after the last dated leaf, up to yesterday (UTC), with no leaf: as far as the log shows, the authority has not spoken since. */
  silentSince: string[];
}

export type AnchorVerdict =
  | { kind: "anchored"; upTo: number; maxSeq: number; anchors: number; leafIndex: number; wholeLog: boolean; cosignatures: number; dated: DatedReading | null }
  | { kind: "contradicted"; unmatched: LoggedLeaf[]; anchors: number; matched: number; wholeLog: boolean; future: DatedLeaf[]; outOfOrder: DatedLeaf[] }
  | { kind: "none"; wholeLog: boolean; from: number; treeSize: number };

/**
 * Compare a VERIFIED on-box ledger with what the log holds under its key. Leaves under the key that
 * the key did not sign are ignored (anyone can name any key hash). A genuine anchor the file cannot
 * produce is the finding.
 */
export function judgeAnchors(rows: SignedRow[], source: string, publicKeyPem: string, scan: ScanResult, now: Date = new Date()): AnchorVerdict {
  const mine = checksumsForRows(rows, source);
  const genuine = scan.leaves.filter((l) => verifyLeafSignature(l.checksum, l.signature, publicKeyPem));
  if (genuine.length === 0) return { kind: "none", wholeLog: scan.whole_log_checked, from: scan.from, treeSize: scan.head.size };

  // Dated leaves (form 2). A leaf holds only a hash, so the file must say which (row, day) it could be. Row N can
  // have been the tail on day D only if row N was written by then and row N+1 not before it, by the rows' own signed
  // times: those are the only candidates, and a dated leaf that is none of them is a state this file cannot account
  // for. The last row stays a candidate up to today; a little beyond today is tried too, only so that a leaf dated
  // in the future can be named as that rather than as an unknown leaf.
  const today = utcDay(new Date(now.getTime() + 10 * 60_000));   // ten minutes of clock difference at midnight
  const dated = new Map<string, { seq: number; day: string }>();
  for (let i = 0; i < rows.length; i++) {
    const from = String(rows[i].ts).slice(0, 10); if (!isDay(from)) continue;
    const next = i + 1 < rows.length ? String(rows[i + 1].ts).slice(0, 10) : addDays(today, 30);
    const hash = rowHash(rows[i]);
    for (let d = from, n = 0; d <= next && n < 4000; d = addDays(d, 1), n++) dated.set(anchorChecksum(source, rows[i].seq, hash, d), { seq: rows[i].seq, day: d });
  }
  const datedLeaves: DatedLeaf[] = []; const unmatched: LoggedLeaf[] = [];
  let upTo = 0, leafIndex = -1;
  for (const l of genuine) {
    const seq1 = mine.indexOf(l.checksum) + 1; const d = dated.get(l.checksum);
    if (seq1 > 0) { if (seq1 > upTo) { upTo = seq1; leafIndex = l.index; } }
    else if (d) { datedLeaves.push({ index: l.index, checksum: l.checksum, seq: d.seq, day: d.day }); if (d.seq > upTo) { upTo = d.seq; leafIndex = l.index; } }
    else unmatched.push(l);
  }
  // A leaf for a day that has not come was not made by an authority reading its own clock. A leaf for a day
  // EARLIER than a leaf already in the log before it was added afterwards: a day filled in late.
  const future = datedLeaves.filter((l) => l.day > today);
  const outOfOrder: DatedLeaf[] = []; let latest = "";
  for (const l of datedLeaves) { if (l.day < latest) outOfOrder.push(l); else latest = l.day; }
  if (unmatched.length || future.length || outOfOrder.length) {
    return { kind: "contradicted", unmatched, anchors: genuine.length, matched: genuine.length - unmatched.length, wholeLog: scan.whole_log_checked, future, outOfOrder };
  }
  let reading: DatedReading | null = null;
  if (datedLeaves.length) {
    const days = new Set(datedLeaves.map((l) => l.day)); const sorted = [...days].sort();
    const first = sorted[0], last = sorted[sorted.length - 1];
    const holes: string[] = []; for (let d = addDays(first, 1); d < last; d = addDays(d, 1)) if (!days.has(d)) holes.push(d);
    // Today's leaf may simply not have been sent yet: silence is counted up to yesterday.
    const yesterday = addDays(utcDay(now), -1);
    const silentSince: string[] = []; for (let d = addDays(last, 1); d <= yesterday; d = addDays(d, 1)) silentSince.push(d);
    reading = { leaves: datedLeaves, first, last, holes, silentSince };
  }
  return { kind: "anchored", upTo, maxSeq: rows.length ? rows[rows.length - 1].seq : 0, anchors: genuine.length, leafIndex, wholeLog: scan.whole_log_checked, cosignatures: scan.head.cosignatures, dated: reading };
}

/**
 * WHEN was each dated leaf in the log? The statement's day is the key holder's word. The log's cosigning
 * witnesses sign each tree head together with the time they saw it, and the receipt written at submission keeps
 * that head. A leaf whose receipt shows it inside a head the policy's quorum cosigned on its own day or the day
 * after was in the log then, on signatures the key holder cannot make. A leaf filled in days later has a head
 * with a later time, or no receipt.
 *
 * The receipt file is not trusted: the head in it is rebuilt and its signatures checked here.
 */
export interface LeafTimes { onTime: number; late: { leaf: DatedLeaf; seen: string }[]; noProof: DatedLeaf[] }
export function checkLeafTimes(leaves: DatedLeaf[], receipts: AnchorReceipt[], log: AnchorLog, policy: TrustPolicy): LeafTimes {
  const out: LeafTimes = { onTime: 0, late: [], noProof: [] };
  const logKey = Buffer.from(log.publicKey, "hex");
  for (const leaf of leaves) {
    let seen: number | null = null;
    for (const r of receipts) {
      try {
        if (r.checksum !== leaf.checksum || r.leaf_index !== leaf.index || !r.head_signature || !Array.isArray(r.cosigs)) continue;
        if (!(Number.isInteger(r.tree_size) && r.tree_size > leaf.index)) continue;
        const checkpoint = `sigsum.org/v1/tree/${sha(logKey).toString("hex")}\n${r.tree_size}\n${Buffer.from(r.root_hash, "hex").toString("base64")}\n`;
        if (!edVerify(null, Buffer.from(checkpoint), keyFromRaw(logKey), Buffer.from(r.head_signature, "hex"))) continue;
        const head: TreeHead = { size: r.tree_size, root_hash: r.root_hash, signature: r.head_signature, cosignatures: r.cosigs.length, cosigs: r.cosigs, checkpoint };
        const c = checkCosignatures(head, log, policy);
        if (!c.met || c.oldest === null) continue;
        seen = seen === null ? c.oldest : Math.min(seen, c.oldest);
      } catch { /* a receipt that cannot be read proves nothing */ }
    }
    if (seen === null) { out.noProof.push(leaf); continue; }
    const seenDay = utcDay(new Date(seen * 1000));
    if (seenDay >= leaf.day && seenDay <= addDays(leaf.day, 1)) out.onTime++; else out.late.push({ leaf, seen: seenDay });
  }
  return out;
}

// ── trust policy and cosigning witnesses (sigsum-go doc/policy.md; log.md 2.2.3) ────────────────────

export interface TrustPolicy {
  logs: { key: string; url: string | null }[];
  witnesses: Map<string, string>;                       // name → public key hex
  groups: Map<string, { k: number; members: string[] }>;
  quorum: string;                                       // a witness name, a group name, or "none"
}

/**
 * Parse a Sigsum policy file. Strict on purpose: an unknown line, a name used before it is defined, a
 * name defined twice or a missing quorum line is an error, never a guess. A policy that cannot be read
 * must not be mistaken for one that asks for nothing.
 */
export function parsePolicy(text: string): TrustPolicy {
  const p: TrustPolicy = { logs: [], witnesses: new Map(), groups: new Map(), quorum: "" };
  const isKey = (s: string | undefined) => !!s && /^[0-9a-f]{64}$/i.test(s);
  const defined = (n: string) => p.witnesses.has(n) || p.groups.has(n);
  const used = new Set<string>();
  text.split("\n").forEach((raw, i) => {
    const line = raw.replace(/#.*$/, "").trim(); if (!line) return;
    const f = line.split(/\s+/); const at = `policy line ${i + 1}`;
    if (f[0] === "log") {
      if (!isKey(f[1]) || f.length > 3) throw new Error(`${at}: log needs a 64-hex key and at most a URL`);
      p.logs.push({ key: f[1].toLowerCase(), url: f[2] ?? null });
    } else if (f[0] === "witness") {
      if (!f[1] || !isKey(f[2]) || f.length > 4) throw new Error(`${at}: witness needs a name and a 64-hex key`);
      if (f[1] === "none" || defined(f[1])) throw new Error(`${at}: the name '${f[1]}' is taken`);
      if ([...p.witnesses.values()].includes(f[2].toLowerCase())) throw new Error(`${at}: this witness key is already listed`);
      p.witnesses.set(f[1], f[2].toLowerCase());
    } else if (f[0] === "group") {
      const [, name, rule, ...members] = f;
      if (!name || !rule || members.length === 0) throw new Error(`${at}: group needs a name, a rule and members`);
      if (name === "none" || defined(name)) throw new Error(`${at}: the name '${name}' is taken`);
      for (const m of members) { if (!defined(m)) throw new Error(`${at}: '${m}' is not defined above`); if (used.has(m)) throw new Error(`${at}: '${m}' is already a member of a group`); used.add(m); }
      const k = rule === "all" ? members.length : rule === "any" ? 1 : /^[1-9][0-9]*$/.test(rule) ? Number(rule) : NaN;
      if (!Number.isInteger(k) || k > members.length) throw new Error(`${at}: the rule '${rule}' is not all, any, or a count the members can meet`);
      p.groups.set(name, { k, members });
    } else if (f[0] === "quorum") {
      if (p.quorum) throw new Error(`${at}: a second quorum line`);
      if (f.length !== 2 || (f[1] !== "none" && !defined(f[1]))) throw new Error(`${at}: quorum must name 'none' or something defined above`);
      p.quorum = f[1];
    } else throw new Error(`${at}: not a policy line: '${f[0]}'`);
  });
  if (!p.quorum) throw new Error("the policy has no quorum line");
  return p;
}

export interface CosignCheck {
  /** true when the policy's quorum rule is met by cosignatures that verify. */
  met: boolean;
  /** Names of the policy's witnesses whose cosignature on this tree head verifies. */
  witnessed: string[];
  /** Cosignatures by keys the policy does not name (ignored), and by named witnesses that do not verify. */
  unknown: number; invalid: number;
  quorum: string;
  /** The oldest cosignature time among those counted, in seconds since 1970 (null if none). */
  oldest: number | null;
}

/**
 * Which of the policy's witnesses cosigned this tree head, and is the quorum met. The head must be the
 * one getTreeHead returned (already checked against the log's key); the policy must name that log.
 */
export function checkCosignatures(head: TreeHead, log: AnchorLog, policy: TrustPolicy): CosignCheck {
  if (!policy.logs.some((l) => l.key === log.publicKey.toLowerCase())) throw new Error("the trust policy does not name this log's key");
  const byHash = new Map<string, string>();
  for (const [name, key] of policy.witnesses) byHash.set(sha(Buffer.from(key, "hex")).toString("hex"), name);
  const witnessed = new Set<string>(); let unknown = 0, invalid = 0, oldest: number | null = null;
  for (const c of head.cosigs) {
    const name = byHash.get(c.key_hash);
    if (!name) { unknown++; continue; }
    let good = false;
    try {
      good = Number.isInteger(c.timestamp) && edVerify(null, Buffer.from(`cosignature/v1\ntime ${c.timestamp}\n${head.checkpoint}`),
        keyFromRaw(Buffer.from(policy.witnesses.get(name) as string, "hex")), Buffer.from(c.signature, "hex"));
    } catch { good = false; }
    if (!good) { invalid++; continue; }
    witnessed.add(name); oldest = oldest === null ? c.timestamp : Math.min(oldest, c.timestamp);
  }
  const holds = (name: string): boolean => {
    if (policy.witnesses.has(name)) return witnessed.has(name);
    const g = policy.groups.get(name); return !!g && g.members.filter(holds).length >= g.k;
  };
  return { met: policy.quorum === "none" ? true : holds(policy.quorum), witnessed: [...witnessed].sort(), unknown, invalid, quorum: policy.quorum, oldest };
}

/** A tree head the log's key signed AND a quorum of the policy's witnesses cosigned; waits a little for cosignatures to gather. */
export async function getWitnessedTreeHead(log: AnchorLog, policy: TrustPolicy, tries = 4, waitMs = Number(process.env.AEGIS_ANCHOR_WAIT_MS) > 0 ? Number(process.env.AEGIS_ANCHOR_WAIT_MS) : 5000): Promise<{ head: TreeHead; check: CosignCheck }> {
  let head = await getTreeHead(log); let check = checkCosignatures(head, log, policy);
  for (let i = 1; i < tries && !check.met; i++) { await new Promise((r) => setTimeout(r, waitMs)); head = await getTreeHead(log); check = checkCosignatures(head, log, policy); }
  return { head, check };
}

/** A trust policy by file path, or by the name of one of the published policies kept in ./anchor-policies. */
export function loadPolicy(ref: string): { policy: TrustPolicy; from: string } {
  const builtin = join(import.meta.dir, "anchor-policies", `${ref}.policy`);
  const file = existsSync(ref) ? ref : /^[A-Za-z0-9._-]+$/.test(ref) && existsSync(builtin) ? builtin : null;
  if (!file) throw new Error(`no trust policy file '${ref}', and no published policy of that name`);
  return { policy: parsePolicy(readFileSync(file, "utf-8")), from: file === ref ? ref : `published policy ${ref}` };
}
