// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// refusal-ledger — one record of what the hook gates actually REFUSED.
//
// A gate that has only ever said yes has shown that it runs, not that it can refuse.
// "What was enforced" should be answerable from a record, per gate. anumati and tripwire
// keep their own ledgers; this records every exit 2 from budget, spawn, shield,
// destructive and chitta.
//
// It is armed ONCE, in cli/index.ts, and records at the process exit — the one place
// every block passes through — so a block site added later is recorded without anyone
// remembering to. It never throws and never changes a verdict: a ledger that cannot be
// written must not turn a block into an allow, or an allow into a block.
//
// The rule id is read back out of the gate's own refusal message, so it is the id the
// agent was shown. A message with no id records null.
//
// WHERE THE TRUST SITS: with no ledger authority configured, the ledger is a plain file
// written by the same user the gates constrain. It is not signed and not chained. It shows
// what was refused when nobody interfered with it; it is not evidence against a process
// that wanted to hide a refusal or invent one. With an authority configured (see
// askAuthority below) each refusal is also numbered, signed and chained by a separate
// account; the plain file stays, as the copy this user can read. Either way a gate that
// refuses and never reaches this module leaves no row.
//
// Ledger: $AEGIS_REFUSAL_LEDGER, else $AEGIS_HOME/refusals.jsonl, else ~/.aegis/refusals.jsonl.

import { appendFileSync, mkdirSync, existsSync, readFileSync } from "fs";
import { spawnSync } from "child_process";
import { homedir } from "os";
import { dirname, join } from "path";
import { randomBytes } from "crypto";
import {
  signLedgerRow, rowHash, verifyLedgerRows, verifyRowSig, verifyReceipt, ledgerField,
  type LedgerPayload, type SignedRow, type LedgerVerdict, type Receipt,
} from "./ledger-sign";

export function refusalLedgerPath(): string {
  return (
    process.env.AEGIS_REFUSAL_LEDGER ||
    join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "refusals.jsonl")
  );
}

/** The rule id as the gate printed it: "BLOCKED (rule)", "Rule: X", else the first ID-shaped token. */
export function parseRule(text: string): string | null {
  const t = String(text || "");
  const m =
    t.match(/BLOCKED\s*\(([^)\n]{1,60})\)/) ||
    t.match(/\bRule\s*:\s*([A-Za-z0-9_\-/.]{2,40})/) ||
    t.match(/\b([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d+[A-Z0-9]*)\b/);
  return m ? m[1].trim() : null;
}

const sessionId = (): string | null =>
  process.env.CLAUDE_CODE_SESSION_ID || process.env.CLAUDE_SESSION_ID || process.env.CLAUDE_AGENT_ID || null;

// ── The authority's signed ledger (hardened mode) ─────────────────────────────────────────────
// When a ledger authority is configured (AEGIS_LEDGER_SOCKET, else the approver's consume socket),
// the gate ASKS it to record the refusal: the authority, under its own uid, numbers, signs and
// chains the row (core/ledger-authority.ts). The gate holds no key.
//
// The refusal is recorded at process exit, where nothing asynchronous can run, so the ask is made
// by a short-lived child process that this one waits for. It costs a few tens of milliseconds, on
// a refusal only.
//
// It never changes a verdict. If the authority cannot be reached the local row says so
// (`authority_error`) and so does stderr — an unsigned refusal must not look like a signed one.

const ASK_AUTHORITY = `
const net = require("net");
let input = "";
const out = (o) => { process.stdout.write(JSON.stringify(o)); process.exit(0); };
process.stdin.on("data", (d) => { input += d; }).on("end", () => {
  let job; try { job = JSON.parse(input); } catch { return out({ ok: false, error: "bad request" }); }
  let buf = "";
  const s = net.createConnection(job.socket);
  s.setTimeout(3000, () => out({ ok: false, error: "authority timeout" }));
  s.on("error", (e) => out({ ok: false, error: "authority unreachable: " + e.message }));
  s.on("connect", () => s.write(JSON.stringify(job.req) + "\\n"));
  s.on("data", (d) => {
    buf += d; const nl = buf.indexOf("\\n"); if (nl === -1) return;
    try { out(JSON.parse(buf.slice(0, nl))); } catch { out({ ok: false, error: "malformed reply" }); }
  });
  s.on("end", () => out({ ok: false, error: "authority closed without a reply" }));
});`;

// Where the authority is, in order: AEGIS_LEDGER_SOCKET, the approver's consume socket, then a
// pointer file `ledger-socket` in the aegis home whose first line is the socket path. The file
// lets an operator switch every running session over (or back: delete it) without restarting them.
// Like the env var it is writable by the gate's own uid — it says where to ask, it proves nothing.
export const ledgerSocket = (): string | null => {
  const env = process.env.AEGIS_LEDGER_SOCKET || process.env.AEGIS_APPROVER_CONSUME_SOCKET;
  if (env) return env;
  try {
    const pointer = join(process.env.AEGIS_HOME || join(homedir(), ".aegis"), "ledger-socket");
    if (!existsSync(pointer)) return null;
    return readFileSync(pointer, "utf-8").split("\n")[0].trim() || null;
  } catch {
    return null;
  }
};

// ── Whose answer is it? The pinned key ────────────────────────────────────────────────────────
// The socket path proves nothing: through 2.16.2 anything listening there that answered "ok" and a
// number was taken for the authority (reported by Andrey Lazarev, 11 October 2026). The gate now
// checks the answer against the authority's PUBLIC key, read from a place the agent's uid should
// not be able to write:
//
//   1. /etc/aegis/ledger-signing.pub — a system file. If it exists it is the key, and nothing in
//      the environment or the aegis home can replace it.
//   2. else AEGIS_LEDGER_PUBKEY (the PEM) or AEGIS_LEDGER_PUBKEY_FILE (a path), from the
//      environment the harness gives the gate. Weaker: as safe as that environment.
//
// The copy in the aegis home (~/.aegis/ledger-signing.pub) is NOT read here, on purpose: the agent
// can write it.
//
// With no key pinned the answer cannot be checked. It is accepted as before, the local row says
// `authority_check: "unchecked"`, and since 2.17.1 the gate says so on stderr each time;
// `aegis ledger-verify --local` compares such rows with the signed ledger afterwards.
// `aegis ledger-pin` (as root) puts the key at the system path.
//
// WHAT THIS DOES NOT GIVE: where the gate runs as root, or as the account that owns the key file,
// the pin is a file that account can rewrite.
export const PINNED_LEDGER_KEY_PATH = "/etc/aegis/ledger-signing.pub";

export function pinnedLedgerKey(systemPath = PINNED_LEDGER_KEY_PATH): string | null {
  try {
    if (existsSync(systemPath)) return readFileSync(systemPath, "utf-8");
  } catch {
    // A system key that exists and cannot be read must not fall through to a weaker source.
    return "unreadable";
  }
  const env = process.env.AEGIS_LEDGER_PUBKEY;
  if (env && env.includes("BEGIN")) return env;
  const file = process.env.AEGIS_LEDGER_PUBKEY_FILE;
  if (file) { try { return readFileSync(file, "utf-8"); } catch { return "unreadable"; } }
  return null;
}

export type AuthorityAnswer = { seq: number; check: "verified" | "unchecked"; row_hash?: string } | { error: string };

// What the authority stores for a request (core/ledger-authority.ts, record): the same clipping, so
// the row that comes back can be compared with what was asked.
const clipTo = ledgerField;

/**
 * Judge the authority's reply to one ask. With a pinned key the reply must carry the signed row and
 * a receipt for OUR nonce, both valid under that key, and the row must be the refusal we asked for.
 */
export function checkAuthorityReply(
  req: { gate: string; rule: string | null; kind: string; session: string | null },
  nonce: string,
  reply: { ok?: boolean; value?: { seq?: unknown; row?: unknown; receipt?: unknown }; error?: unknown } | null | undefined,
  pinnedKey: string | null,
): AuthorityAnswer {
  if (!reply || !reply.ok) return { error: String((reply && reply.error) || "authority gave no answer") };
  const v = reply.value;
  if (!v || typeof v.seq !== "number") return { error: "authority gave no sequence number" };
  const row = v.row as SignedRow | undefined;
  const rowLooksSigned = !!row && typeof row === "object" && typeof row.seq === "number" && typeof row.sig === "string" && typeof row.prev_hash === "string";
  if (!pinnedKey) return { seq: v.seq, check: "unchecked", ...(rowLooksSigned ? { row_hash: rowHash(row as SignedRow) } : {}) };

  const no = (why: string): AuthorityAnswer => ({ error: `the answer did not verify against the pinned ledger key (${why}) — it is not taken as signed` });
  if (pinnedKey === "unreadable") return no("the pinned key could not be read");
  if (!rowLooksSigned || !row) return no("no signed row came back; an authority before 2.16.3 answers this way, and so does anything that is not the authority");
  const receipt = v.receipt as Receipt | undefined;
  if (!receipt || typeof receipt !== "object") return no("no receipt came back");
  if (!verifyRowSig(row, pinnedKey)) return no("the row's signature is not by that key");
  if (row.seq !== v.seq) return no("the row's number is not the number given");
  if (row.gate !== (clipTo(req.gate, 80) ?? "unknown") || (row.rule ?? null) !== clipTo(req.rule, 60)
    || row.kind !== expectedKind(req.kind) || (row.session ?? null) !== clipTo(req.session, 80)) {
    return no("the row is not the refusal that was asked for");
  }
  if (receipt.nonce !== nonce) return no("the receipt is for another ask");
  if (receipt.seq !== row.seq || receipt.row_hash !== rowHash(row)) return no("the receipt is for another row");
  if (!verifyReceipt(receipt, pinnedKey)) return no("the receipt's signature is not by that key");
  return { seq: row.seq, check: "verified", row_hash: receipt.row_hash };
}

// The kind a row comes back with, as the authority stores it (core/ledger-authority.ts, record).
const expectedKind = (k: string): string => (k === "override" || k === "bell-book" ? k : "refused");

/** Ask the authority to record a refusal. undefined = no authority configured. Never throws. */
export function askAuthority(r: { gate: string; rule?: string | null; kind?: "refused" | "override" | "bell-book"; session?: string }): AuthorityAnswer | undefined {
  let pinned: string | null = null;
  try { pinned = pinnedLedgerKey(); } catch { pinned = "unreadable"; }
  const socket = ledgerSocket();
  if (!socket) {
    // A key is pinned, so this box has an authority; nothing says where it is. Through 2.16.2 a deleted
    // pointer file left a plain row with no word of it.
    if (pinned) return { error: "a ledger key is pinned but no authority socket is configured (the pointer file is gone, or the environment names none)" };
    return undefined;
  }
  try {
    const nonce = randomBytes(16).toString("hex");
    const asked = { gate: r.gate, rule: r.rule ?? null, kind: r.kind || "refused", session: r.session ?? sessionId() };
    const req = { op: "refusal", ...asked, nonce };
    return checkAuthorityReply(asked, nonce, askOnce(socket, req), pinned);
  } catch (e) {
    return { error: `authority could not be asked: ${(e as Error).message}` };
  }
}

function askOnce(socket: string, req: Record<string, unknown>): any {
  const child = spawnSync(process.execPath, ["-e", ASK_AUTHORITY], {
    input: JSON.stringify({ socket, req }), encoding: "utf8", timeout: 5000, stdio: ["pipe", "pipe", "ignore"],
  });
  return JSON.parse(String(child.stdout || ""));
}

/**
 * aegis Bulkhead (BLK-020): ask the authority to sign "this bell book stood at row N with head H" as a
 * row of its own kind. An authority before 2.27.0 signs any kind but "override" as a REFUSAL, which
 * would put a false refusal in the signed ledger for good; so it is asked first whether it knows the
 * kind, and nothing is sent unless it says so. Never throws.
 */
export function askAuthorityBellBook(rows: number, head: string): AuthorityAnswer {
  const socket = ledgerSocket();
  if (!socket) return { error: "no ledger authority is configured on this box (no socket, no pointer file)" };
  let status: any;
  try { status = askOnce(socket, { op: "ledger-status" }); } catch (e) { return { error: `authority could not be asked: ${(e as Error).message}` }; }
  if (!status?.ok) return { error: `authority gave no status: ${String(status?.error ?? "no answer")}` };
  if (status.value?.bell_book !== true) {
    return { error: "the authority does not sign bell-book rows (it is older than aegis 2.27.0, and would sign this as a refusal) — nothing was sent" };
  }
  return askAuthority({ gate: "bulkhead", rule: null, kind: "bell-book", session: `rows=${rows} head=${head}` })!;
}

export function recordRefusal(r: { gate: string; rule?: string | null; kind?: "refused" | "override" }): boolean {
  // The signed row first. The local row below is the copy the agent's own uid can read; it
  // carries the authority's sequence number, or the reason there is none.
  let signed: AuthorityAnswer | undefined;
  try { signed = askAuthority(r); } catch (e) { signed = { error: `authority could not be asked: ${(e as Error).message}` }; }
  if (signed && "error" in signed) {
    try { process.stderr.write(`[aegis:ledger] this refusal was NOT signed — ${signed.error}\n`); } catch { /* */ }
  }
  // An authority is configured and no key is pinned: the answer was taken as it came. Through 2.17.0 the
  // local row said "unchecked" and nothing was said aloud, so an install with an authority and no pin
  // (which is every install where nobody ran the pin step) looked the same as a checked one from the
  // terminal (pointed out by Andrey Lazarev, 11 October 2026). AEGIS_LEDGER_UNPINNED_QUIET=1 stops the
  // line, not the row's "unchecked".
  if (signed && "seq" in signed && signed.check === "unchecked" && process.env.AEGIS_LEDGER_UNPINNED_QUIET !== "1") {
    try { process.stderr.write(`[aegis:ledger] this refusal's number (${signed.seq}) was NOT CHECKED — an authority socket is configured and no ledger key is pinned at ${PINNED_LEDGER_KEY_PATH}, so the answer could be anyone's. As root: aegis ledger-pin --from <authority store>/ledger-signing.pub\n`); } catch { /* */ }
  }
  try {
    const file = refusalLedgerPath();
    const row: Record<string, unknown> = {
      ts: new Date().toISOString(),
      kind: r.kind || "refused",
      gate: r.gate,
      rule: r.rule ?? null,
      session: sessionId(),
    };
    if (signed && "seq" in signed) {
      row.authority_seq = signed.seq;
      row.authority_check = signed.check;
      if (signed.row_hash) row.authority_row_hash = signed.row_hash;
    }
    if (signed && "error" in signed) row.authority_error = signed.error;
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, JSON.stringify(row) + "\n");
    return true;
  } catch {
    return false;
  }
}

// ── Signed, sequenced, hash-chained ledger (concealment rung 2 — JieGou/Perng) ─────────────────
// The AUTHORITY appends (it holds the signing key, off the agent's uid). seq and prev_hash are read
// from the tail, so the chain continues. Unlike recordRefusal this is NOT best-effort: a signer that
// cannot sign must fail loudly, never silently drop to an unsigned row that would read as clean.

function readLedgerRows(path: string): unknown[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf-8").split("\n").filter(Boolean).map((l) => {
    try { return JSON.parse(l); } catch { return { __malformed: true }; }
  });
}

/** Append a refusal row signed by the authority key, chained to the tail. Returns the new row. */
export function appendSignedRefusal(
  r: { gate: string; rule?: string | null; kind?: "refused" | "override" },
  authorityPrivateKeyPem: string,
  path = refusalLedgerPath(),
): SignedRow {
  const rows = readLedgerRows(path) as SignedRow[];
  const last = rows.length ? rows[rows.length - 1] : null;
  const seq = last && typeof last.seq === "number" ? last.seq + 1 : 1;
  const prev = last && typeof last.seq === "number" ? rowHash(last) : "";
  const payload: LedgerPayload = {
    ts: new Date().toISOString(),
    kind: r.kind || "refused",
    gate: r.gate,
    rule: r.rule ?? null,
    session: process.env.CLAUDE_CODE_SESSION_ID || process.env.CLAUDE_SESSION_ID || process.env.CLAUDE_AGENT_ID || null,
  };
  const row = signLedgerRow(payload, seq, prev, authorityPrivateKeyPem);
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(row) + "\n");
  return row;
}

/** Verify a ledger file against the authority public key. An unsigned/legacy file reads UNVERIFIABLE. */
export function verifyLedgerFile(path: string, authorityPublicKeyPem: string | null): LedgerVerdict {
  return verifyLedgerRows(readLedgerRows(path), authorityPublicKeyPem);
}

/** Arm the ledger for this gate process: every exit 2 is recorded. Never throws. */
export function armRefusalLedger(gate: string): boolean {
  try {
    let said = "";
    const grab = (c: unknown) => {
      try {
        if (said.length < 8000) said += typeof c === "string" ? c : Buffer.from(c as Uint8Array).toString("utf8");
      } catch { /* a message we cannot read is a null rule, not a failure */ }
    };
    // The exit hook first: if a tap below cannot be installed, the refusal is still
    // recorded, just without its rule id.
    process.on("exit", (code) => {
      if (code !== 2) return;
      recordRefusal({ gate, rule: parseRule(said) });
    });
    try {
      const write = process.stderr.write.bind(process.stderr) as (...a: unknown[]) => boolean;
      (process.stderr as unknown as { write: (...a: unknown[]) => boolean }).write = (chunk: unknown, ...rest: unknown[]) => {
        grab(chunk);
        return write(chunk, ...rest);
      };
    } catch { /* rule id will be null */ }
    try {
      const error = console.error.bind(console);
      console.error = (...a: unknown[]) => {
        grab(a.map((x) => (typeof x === "string" ? x : String(x))).join(" ") + "\n");
        error(...a);
      };
    } catch { /* rule id will be null */ }
    return true;
  } catch {
    return false;
  }
}
