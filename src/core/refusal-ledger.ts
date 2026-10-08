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
// WHERE THE TRUST SITS: the ledger is a plain file written by the same user the gates
// constrain. It is not signed and not chained. It shows what was refused when nobody
// interfered with it; it is not evidence against a process that wanted to hide a
// refusal or invent one.
//
// Ledger: $AEGIS_REFUSAL_LEDGER, else $AEGIS_HOME/refusals.jsonl, else ~/.aegis/refusals.jsonl.

import { appendFileSync, mkdirSync, existsSync, readFileSync } from "fs";
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

export function recordRefusal(r: { gate: string; rule?: string | null; kind?: "refused" | "override" }): boolean {
  try {
    const file = refusalLedgerPath();
    const row = {
      ts: new Date().toISOString(),
      kind: r.kind || "refused",
      gate: r.gate,
      rule: r.rule ?? null,
      session:
        process.env.CLAUDE_CODE_SESSION_ID || process.env.CLAUDE_SESSION_ID || process.env.CLAUDE_AGENT_ID || null,
    };
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
