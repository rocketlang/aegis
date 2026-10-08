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
import {
  signLedgerRow, rowHash, verifyLedgerRows,
  type LedgerPayload, type SignedRow, type LedgerVerdict,
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

/** Ask the authority to record a refusal. undefined = no authority configured. Never throws. */
export function askAuthority(r: { gate: string; rule?: string | null; kind?: "refused" | "override" }): { seq: number } | { error: string } | undefined {
  const socket = ledgerSocket();
  if (!socket) return undefined;
  try {
    const req = { op: "refusal", gate: r.gate, rule: r.rule ?? null, kind: r.kind || "refused", session: sessionId() };
    const child = spawnSync(process.execPath, ["-e", ASK_AUTHORITY], {
      input: JSON.stringify({ socket, req }), encoding: "utf8", timeout: 5000, stdio: ["pipe", "pipe", "ignore"],
    });
    const reply = JSON.parse(String(child.stdout || "")) as { ok?: boolean; value?: { seq?: unknown }; error?: string };
    if (reply.ok && typeof reply.value?.seq === "number") return { seq: reply.value.seq };
    return { error: String(reply.error || "authority gave no sequence number") };
  } catch (e) {
    return { error: `authority could not be asked: ${(e as Error).message}` };
  }
}

export function recordRefusal(r: { gate: string; rule?: string | null; kind?: "refused" | "override" }): boolean {
  // The signed row first. The local row below is the copy the agent's own uid can read; it
  // carries the authority's sequence number, or the reason there is none.
  const signed = askAuthority(r);
  if (signed && "error" in signed) {
    try { process.stderr.write(`[aegis:ledger] this refusal was NOT signed — ${signed.error}\n`); } catch { /* */ }
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
    if (signed && "seq" in signed) row.authority_seq = signed.seq;
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
