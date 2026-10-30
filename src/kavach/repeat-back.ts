// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Repeat-back — the release record (RPB-001..006). On the bridge a helm order is repeated back
// word for word before the wheel moves. Here the agent names the exact release, a person types
// it back, and the CI verdict at that moment is recorded beside the decision, yes or no.
//
// P1a: a record, not a gate. It refuses nothing yet; it makes the question "did the person's
// check add anything?" answerable (P0, 30 Oct 2026: no record held a refused release).
//
// Same host (RPB-YK-002): the hash chain shows an edit; it does not stop a root process from
// writing rows. Signing by the separate-account authority is the founder's change to make.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import { dirname, join } from "path";

export const RECORD_ENV = "AEGIS_REPEAT_BACK_FILE";
export const recordPath = (): string =>
  process.env[RECORD_ENV] || join(process.env.HOME || "/root", ".aegis", "repeat-back.jsonl");

export type Verdict = "green" | "red" | "pending" | "none";
export interface CheckRun { name: string; status: string; conclusion: string | null }
export interface Evidence { verdict: Verdict; checks: CheckRun[]; read_at: string }

export interface Act { repo: string; package: string; version: string; commit: string }

export interface RequestRow extends Act {
  type: "request"; id: string; asked_at: string; evidence: Evidence; prev: string; hash: string;
}
export interface DecisionRow {
  type: "decision"; id: string; decision: "approve" | "deny"; reason?: string; by: string;
  decided_at: string; evidence: Evidence; prev: string; hash: string;
}
export type Row = RequestRow | DecisionRow;

export class RecordBroken extends Error {}

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
const GENESIS = "0".repeat(64);

/** Keys sorted at every depth, so the same row always hashes the same. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v ?? null);
}

/** A row's hash covers every field but `hash` itself, nested evidence included. */
const rowHash = (row: Record<string, unknown>): string => sha256(canonical(row));

// @rule:RPB-003 / RPB-YK-001 — the verdict comes from the checks GitHub holds, never from the agent.
export function verdictOf(checks: CheckRun[]): Verdict {
  if (!checks.length) return "none";
  if (checks.some((c) => c.status === "completed" && ["failure", "cancelled", "timed_out", "action_required", "startup_failure"].includes(c.conclusion ?? ""))) return "red";
  if (checks.some((c) => c.status !== "completed")) return "pending";
  return "green";
}

// @rule:RPB-005 — read the whole record and check the chain; a break refuses every reader.
export function readRecord(path = recordPath()): Row[] {
  if (!existsSync(path)) return [];
  const rows: Row[] = [];
  let prev = GENESIS;
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  lines.forEach((line, i) => {
    let row: Row;
    try { row = JSON.parse(line); } catch { throw new RecordBroken(`line ${i + 1}: not JSON`); }
    const { hash, ...rest } = row;
    if (row.prev !== prev) throw new RecordBroken(`line ${i + 1}: chain broken (prev does not match)`);
    if (rowHash(rest) !== hash) throw new RecordBroken(`line ${i + 1}: row altered (hash does not match)`);
    prev = hash;
    rows.push(row);
  });
  return rows;
}

type Unsealed = Omit<RequestRow, "prev" | "hash"> | Omit<DecisionRow, "prev" | "hash">;

function append(row: Unsealed, path: string): Row {
  const rows = readRecord(path);
  const prev = rows.length ? rows[rows.length - 1].hash : GENESIS;
  const body = { ...row, prev };
  const full = { ...body, hash: rowHash(body) } as Row;
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(full) + "\n", { mode: 0o600 });
  return full;
}

// @rule:RPB-001 — the id is a hash of the exact act and the evidence at asking.
export function requestId(act: Act, evidence: Evidence): string {
  return sha256(JSON.stringify([act.repo, act.package, act.version, act.commit, evidence.verdict, evidence.checks])).slice(0, 12);
}

export function validateAct(act: Act): string | null {
  if (!/^[\w.-]+\/[\w.-]+$/.test(act.repo)) return "repo must be owner/name";
  if (!act.package) return "package is required";
  if (!act.version) return "version is required";
  if (!/^[0-9a-f]{40}$/.test(act.commit)) return "commit must be the full 40-character sha";
  return null;
}

export function recordRequest(act: Act, evidence: Evidence, now = new Date(), path = recordPath()): RequestRow {
  const bad = validateAct(act);
  if (bad) throw new Error(bad);
  const id = requestId(act, evidence);
  const rows = readRecord(path);
  const same = rows.find((r) => r.type === "request" && r.id === id) as RequestRow | undefined;
  if (same) return same; // asking twice for the same act with the same evidence is one request
  return append({ type: "request", id, ...act, asked_at: now.toISOString(), evidence }, path) as RequestRow;
}

/** The exact words the person must type back (RPB-002). */
export const repeatBackPhrase = (r: Act): string => `${r.package}@${r.version} ${r.commit.slice(0, 7)}`;

export function findRequest(id: string, rows: Row[]): RequestRow | undefined {
  return rows.find((r) => r.type === "request" && r.id === id) as RequestRow | undefined;
}
export function decisionFor(id: string, rows: Row[]): DecisionRow | undefined {
  return rows.find((r) => r.type === "decision" && r.id === id) as DecisionRow | undefined;
}

// @rule:RPB-002 / RPB-004 — a decision needs the exact words back; a no is recorded like a yes;
// one decision per request.
export function recordDecision(
  id: string, decision: "approve" | "deny", typed: string, evidence: Evidence,
  opts: { by: string; reason?: string; now?: Date; path?: string },
): DecisionRow {
  const path = opts.path ?? recordPath();
  const rows = readRecord(path);
  const req = findRequest(id, rows);
  if (!req) throw new Error(`no request ${id}`);
  if (decisionFor(id, rows)) throw new Error(`request ${id} is already decided; a changed act is a new request`);
  if (typed.trim() !== repeatBackPhrase(req)) throw new Error(`not repeated back: expected "${repeatBackPhrase(req)}"; nothing recorded`);
  if (decision === "deny" && !opts.reason?.trim()) throw new Error("a no needs a reason");
  const row: Omit<DecisionRow, "prev" | "hash"> = {
    type: "decision", id, decision, by: opts.by, decided_at: (opts.now ?? new Date()).toISOString(), evidence,
    ...(opts.reason ? { reason: opts.reason } : {}),
  };
  return append(row, path) as DecisionRow;
}

export type DecisionClass = "confirmed" | "overrode" | "changed" | "agreed";

// @rule:RPB-006 — classed against the verdict at the moment of decision.
export function classify(d: DecisionRow): DecisionClass {
  const green = d.evidence.verdict === "green";
  if (d.decision === "approve") return green ? "confirmed" : "overrode";
  return green ? "changed" : "agreed";
}

export interface Report {
  requests: number; decided: number; open: number;
  counts: Record<DecisionClass, number>;
  wait_minutes_median: number | null;
  overrides: { id: string; act: string; verdict: Verdict; by: string; at: string }[];
}

export function report(rows: Row[], since?: Date): Report {
  const inRange = (iso: string) => !since || new Date(iso) >= since;
  const reqs = rows.filter((r): r is RequestRow => r.type === "request" && inRange(r.asked_at));
  const counts: Record<DecisionClass, number> = { confirmed: 0, overrode: 0, changed: 0, agreed: 0 };
  const waits: number[] = [];
  const overrides: Report["overrides"] = [];
  let decided = 0;
  for (const q of reqs) {
    const d = decisionFor(q.id, rows);
    if (!d) continue;
    decided++;
    const c = classify(d);
    counts[c]++;
    waits.push((Date.parse(d.decided_at) - Date.parse(q.asked_at)) / 60000);
    if (c === "overrode") overrides.push({ id: q.id, act: repeatBackPhrase(q), verdict: d.evidence.verdict, by: d.by, at: d.decided_at });
  }
  waits.sort((a, b) => a - b);
  const median = waits.length ? Math.round(waits[Math.floor((waits.length - 1) / 2)] * 10) / 10 : null;
  return { requests: reqs.length, decided, open: reqs.length - decided, counts, wait_minutes_median: median, overrides };
}

// ── P1b: the signed approval that travels in the release tag (RPB-007..009) ─────────────────────
//
// CI cannot read this box, so a yes is signed here and carried in the annotated tag; the release
// workflow checks it against the public key pinned in the repo (scripts/repeat-back-check.mjs).
// The signature covers the exact payload line, so CI needs no canonical form to check it.


export const SIGNING_KEY_ENV = "AEGIS_REPEAT_BACK_KEY";
export const signingKeyPath = (): string =>
  process.env[SIGNING_KEY_ENV] || join(process.env.HOME || "/root", ".aegis", "repeat-back-signing.key");
export const TOKEN_HEADER = "Repeat-back approval v1";

export interface ApprovalPayload extends Act { id: string; decision: "approve"; decided_at: string; verdict: Verdict; by: string; row: string }

export function newKeyPair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

// @rule:RPB-007 — only an approve is signed, and the token names the exact act and the decision row.
export function approvalToken(req: RequestRow, d: DecisionRow, privatePem: string): string {
  if (d.decision !== "approve" || d.id !== req.id) throw new Error("only an approve of this request is signed");
  const payload: ApprovalPayload = {
    id: req.id, repo: req.repo, package: req.package, version: req.version, commit: req.commit,
    decision: "approve", decided_at: d.decided_at, verdict: d.evidence.verdict, by: d.by, row: d.hash,
  };
  const line = JSON.stringify(payload);
  const sig = edSign(null, Buffer.from(line), createPrivateKey(privatePem)).toString("base64");
  return `${TOKEN_HEADER}\n${line}\nsig:${sig}\n`;
}

/** Same check the CI script makes (scripts/repeat-back-check.mjs keeps its own copy, zero deps). */
export function readToken(text: string, publicPem: string): { ok: true; payload: ApprovalPayload } | { ok: false; why: string } {
  const lines = text.replace(/\r/g, "").split("\n").map((l) => l.trim()).filter(Boolean);
  const at = lines.indexOf(TOKEN_HEADER);
  if (at < 0 || lines.length < at + 3) return { ok: false, why: "no Repeat-back approval in the tag" };
  const line = lines[at + 1]; const sigLine = lines[at + 2];
  if (!sigLine.startsWith("sig:")) return { ok: false, why: "approval has no signature line" };
  let good = false;
  try { good = edVerify(null, Buffer.from(line), createPublicKey(publicPem), Buffer.from(sigLine.slice(4), "base64")); } catch { good = false; }
  if (!good) return { ok: false, why: "signature does not verify against the pinned key" };
  return { ok: true, payload: JSON.parse(line) };
}
