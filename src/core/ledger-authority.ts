// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ledger-authority — the one writer of the signed refusal ledger (concealment rungs 2 and 3, wired).
//
// It lives inside the separate-uid approver daemon. The gates, which run as the agent's uid, do
// not hold the signing key and do not write this file: they ASK the authority to record a refusal
// over the consume socket. The authority gives the row its number, its time, its link to the row
// before and its signature, appends it to a ledger in its own store, and sends it to the witness.
//
// One process numbers the rows, so two gates refusing at the same moment cannot take the same seq.
//
// WHERE THE TRUST SITS, stated at the point of use:
//   - The CONTENT of a row (gate, rule, session) is what the gate said. The authority attests the
//     order and the time it was told, not that the gate told the truth.
//   - A gate that refuses and never asks leaves no row and no gap. Nothing here closes that; it
//     needs the refusal itself to pass through the authority.
//   - The key and the ledger are safe from the agent only when this daemon runs as an account the
//     agent cannot use. On one uid this is a signature the agent could make itself.
//   - A witness on the same host is a second copy, not a second trust domain.

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import {
  generateLedgerKeypair, signLedgerRow, signHeartbeat, rowHash, verifyLedgerRows,
  type LedgerPayload, type SignedRow, type LedgerVerdict,
} from "./ledger-sign";
import { sendToWitness, sendHeartbeat, witnessHighWaterMark } from "./witness-client";
import { signAnchor, type Anchor } from "./ledger-anchor";

export interface LedgerAuthorityOptions {
  /** The store this authority owns. Key, public key and ledger live here. */
  storeDir: string;
  /** Witness base URL. Absent = no witness; status() says so, it is never implied. */
  witnessUrl?: string;
  /** The name this ledger is known by at the witness. */
  source?: string;
  /** How often the signed heartbeat goes out. Must be shorter than the witness's stall window. */
  heartbeatMs?: number;
  /** Also write the public key here, where a verifier outside the store can read it. */
  publicKeyOut?: string;
  log?: (line: string) => void;
}

export interface RefusalAsk {
  gate?: unknown;
  rule?: unknown;
  kind?: unknown;
  session?: unknown;
}

const clip = (v: unknown, max: number): string | null =>
  typeof v === "string" && v.length > 0 ? v.slice(0, max) : null;

export class LedgerAuthority {
  readonly ledgerPath: string;
  readonly publicKeyPath: string;
  readonly publicKey: string;
  readonly source: string;
  readonly witnessUrl: string | null;
  private privateKey: string;
  private rows: SignedRow[] = [];
  private startVerdict: LedgerVerdict;
  private delivered: number | null = null; // the witness's high-water-mark as far as we know
  private pumping = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  private log: (line: string) => void;
  private heartbeatMs: number;

  constructor(opts: LedgerAuthorityOptions) {
    this.log = opts.log ?? ((s) => process.stderr.write(`[aegis-ledger] ${s}\n`));
    this.source = opts.source || "aegis";
    this.witnessUrl = opts.witnessUrl || null;
    this.heartbeatMs = opts.heartbeatMs ?? 20_000;
    if (!existsSync(opts.storeDir)) mkdirSync(opts.storeDir, { recursive: true, mode: 0o700 });

    const keyPath = join(opts.storeDir, "ledger-signing.key");
    this.publicKeyPath = join(opts.storeDir, "ledger-signing.pub");
    this.ledgerPath = join(opts.storeDir, "refusals.signed.jsonl");
    if (!existsSync(keyPath)) {
      // A ledger with rows and no key cannot be continued under a new key without saying so.
      if (existsSync(this.ledgerPath) && readFileSync(this.ledgerPath, "utf-8").trim()) {
        throw new Error(`signed ledger exists at ${this.ledgerPath} but its key ${keyPath} is missing — refusing to start a new key over it`);
      }
      const kp = generateLedgerKeypair();
      writeFileSync(keyPath, kp.privateKey, { mode: 0o600, flag: "wx" });
      writeFileSync(this.publicKeyPath, kp.publicKey, { mode: 0o644 });
      this.log(`new ledger key made; public key at ${this.publicKeyPath}`);
    }
    try { chmodSync(keyPath, 0o600); } catch { /* ownership is provisioning's job */ }
    this.privateKey = readFileSync(keyPath, "utf-8");
    this.publicKey = readFileSync(this.publicKeyPath, "utf-8");
    if (opts.publicKeyOut) {
      try { writeFileSync(opts.publicKeyOut, this.publicKey, { mode: 0o644 }); }
      catch (e) { this.log(`could not write the public key to ${opts.publicKeyOut}: ${(e as Error).message}`); }
    }

    const raw: unknown[] = existsSync(this.ledgerPath)
      ? readFileSync(this.ledgerPath, "utf-8").split("\n").filter(Boolean).map((l) => {
          try { return JSON.parse(l); } catch { return { __malformed: true }; }
        })
      : [];
    this.startVerdict = verifyLedgerRows(raw, this.publicKey);
    if (!this.startVerdict.ok) {
      // Stopping the record would hide more than it protects. Keep writing; the break stays in the
      // file for `aegis ledger-verify` and is said here and in status().
      this.log(`LEDGER DOES NOT VERIFY at start — ${this.startVerdict.detail}. New rows continue after the last numbered row.`);
    }
    this.rows = raw.filter((r): r is SignedRow => !!r && typeof (r as SignedRow).seq === "number" && typeof (r as SignedRow).sig === "string");
  }

  private tail(): { seq: number; hash: string } {
    const last = this.rows.length ? this.rows[this.rows.length - 1] : null;
    return last ? { seq: last.seq, hash: rowHash(last) } : { seq: 0, hash: "" };
  }

  /** Number, sign and append one refusal. Throws if it cannot be written — the caller reports that. */
  record(ask: RefusalAsk): SignedRow {
    const t = this.tail();
    const payload: LedgerPayload = {
      ts: new Date().toISOString(),
      kind: ask.kind === "override" ? "override" : "refused",
      gate: clip(ask.gate, 80) ?? "unknown",
      rule: clip(ask.rule, 60),
      session: clip(ask.session, 80),
    };
    const row = signLedgerRow(payload, t.seq + 1, t.hash, this.privateKey);
    appendFileSync(this.ledgerPath, JSON.stringify(row) + "\n", { mode: 0o600 });
    this.rows.push(row);
    void this.pump();
    return row;
  }

  /**
   * A signed statement of where this ledger stands, in the leaf format of a public transparency log
   * (core/ledger-anchor.ts). The asker supplies nothing: the statement is this ledger's own tail, so
   * the key signs no bytes of anybody else's choosing. An empty ledger has nothing to anchor.
   */
  anchor(): Anchor {
    const t = this.tail();
    if (t.seq === 0) throw new Error("the ledger is empty — there is no row to anchor");
    return signAnchor(this.source, t.seq, t.hash, this.privateKey, this.publicKey);
  }

  status(): {
    rows: number; max_seq: number; public_key: string; ledger: string; source: string;
    verified_at_start: boolean; start_detail: string | null;
    witness: string | null; witness_holds: number | null;
  } {
    return {
      rows: this.rows.length,
      max_seq: this.tail().seq,
      public_key: this.publicKey,
      ledger: this.ledgerPath,
      source: this.source,
      verified_at_start: this.startVerdict.ok,
      start_detail: this.startVerdict.ok ? null : this.startVerdict.detail,
      witness: this.witnessUrl,
      witness_holds: this.delivered,
    };
  }

  /** Send, in order, every row the witness does not hold yet. A failure stops here and is retried. */
  async pump(): Promise<void> {
    if (!this.witnessUrl || this.pumping) return;
    this.pumping = true;
    try {
      if (this.delivered === null) this.delivered = await witnessHighWaterMark(this.witnessUrl, this.source);
      if (this.delivered === null) return;
      for (;;) {
        const next = this.rows.find((r) => r.seq === (this.delivered as number) + 1);
        if (!next) return;
        if (await sendToWitness(this.witnessUrl, this.source, next)) { this.delivered = next.seq; continue; }
        // Refused or unreachable. Ask where the witness stands; move on only if it moved.
        const held = await witnessHighWaterMark(this.witnessUrl, this.source);
        if (held !== null && held > this.delivered) { this.delivered = held; continue; }
        if (held === null) this.delivered = null;
        return;
      }
    } finally {
      this.pumping = false;
    }
  }

  /** One heartbeat: deliver what is owed, then state where this ledger stands, signed. */
  async beat(): Promise<boolean> {
    if (!this.witnessUrl) return false;
    await this.pump();
    const t = this.tail();
    const hb = signHeartbeat({ source: this.source, max_seq: t.seq, tail_hash: t.hash, ts: new Date().toISOString() }, this.privateKey);
    return sendHeartbeat(this.witnessUrl, this.source, hb);
  }

  start(): void {
    if (!this.witnessUrl) {
      this.log("no witness configured — rows are signed and chained here, and held nowhere else");
      return;
    }
    this.log(`witness ${this.witnessUrl}, source '${this.source}', heartbeat every ${this.heartbeatMs}ms`);
    void this.beat();
    this.timer = setInterval(() => { void this.beat(); }, this.heartbeatMs);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
