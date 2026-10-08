// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// witness — the off-box collector (concealment rung 3).
//
// Rung 2 (ledger-sign) makes an edited or deleted MIDDLE row detectable on-box, but it cannot catch
// TAIL TRUNCATION (chopping off the latest rows) or an agent that simply goes SILENT — because the
// on-box record is the only record. The witness is an INDEPENDENT holder of the record, in a trust
// domain the agent can't write as. The governor streams its signed, sequenced rows (refusals AND
// periodic heartbeats) here; the witness keeps its own high-water-mark per source and ALARMS on:
//   gap        a seq it never received (a suppressed row)
//   chain      a prev_hash that doesn't follow (reorder/tamper)
//   signature  a row not signed by the authority key (forgery)
//   stall      a source that stopped sending within the heartbeat window (silence = alarm)
//   truncation an on-box ledger that now shows FEWER rows than the witness holds (reconcile())
//
// Honest ceiling: a fully compromised agent can stop sending — but silence trips `stall`, so "going
// quiet" is itself loud. The witness cannot be made to accept a forged row (it has only the public
// key) nor to lose rows it already holds (its store is off the agent's reach). It does NOT prove the
// agent sent EVERYTHING it should have in real time; it proves no row it received was later hidden,
// and that silence is surfaced. Full non-equivocation needs the witness itself attested/replicated.

import { verifyRowSig, verifyHeartbeat, rowHash, type SignedRow, type Heartbeat } from "./ledger-sign";

export type AlarmKind = "gap" | "chain" | "signature" | "stall" | "truncation";
export interface Alarm { source: string; kind: AlarmKind; seq: number | null; detail: string }

interface SourceState { maxSeq: number; tailHash: string; lastSeenMs: number }

export class Witness {
  private sources = new Map<string, SourceState>();
  private lastHeartbeatTs = new Map<string, number>();
  constructor(private publicKeyPem: string, private heartbeatTimeoutMs = 60_000) {}

  /** Ingest one signed row from a source. Returns an Alarm if it does not follow cleanly, else null. */
  ingest(source: string, row: SignedRow, now: number = Date.now()): Alarm | null {
    const s = this.sources.get(source) ?? { maxSeq: 0, tailHash: "", lastSeenMs: now };
    if (!verifyRowSig(row, this.publicKeyPem)) {
      s.lastSeenMs = now; this.sources.set(source, s);
      return { source, kind: "signature", seq: typeof row.seq === "number" ? row.seq : null, detail: `row not signed by the authority key` };
    }
    const expect = s.maxSeq + 1;
    if (row.seq !== expect) {
      s.lastSeenMs = now; this.sources.set(source, s);
      return { source, kind: "gap", seq: expect, detail: `expected seq ${expect} from '${source}', received ${row.seq} — a row was never delivered` };
    }
    if (row.prev_hash !== s.tailHash) {
      s.lastSeenMs = now; this.sources.set(source, s);
      return { source, kind: "chain", seq: row.seq, detail: `prev_hash at seq ${row.seq} does not follow the witnessed chain` };
    }
    s.maxSeq = row.seq; s.tailHash = rowHash(row); s.lastSeenMs = now;
    this.sources.set(source, s);
    return null;
  }

  /**
   * A signed heartbeat from the authority: "my ledger stands at max_seq, tail_hash". It keeps the
   * source alive, and it is where a quiet failure becomes loud — the authority holding MORE than
   * the witness received is a row that never arrived; holding FEWER is a ledger cut short on-box.
   * A heartbeat that is unsigned, for another source, or not newer than the last one is ignored:
   * it does not keep the source alive, so a replayed heartbeat ends in `stall`.
   */
  heartbeat(source: string, hb: Heartbeat, now: number = Date.now()): Alarm | null {
    if (!verifyHeartbeat(hb, this.publicKeyPem) || hb.source !== source) {
      return { source, kind: "signature", seq: null, detail: `heartbeat not signed by the authority key for '${source}'` };
    }
    const at = Date.parse(hb.ts);
    const last = this.lastHeartbeatTs.get(source) ?? -Infinity;
    if (Number.isNaN(at) || at <= last) return null;
    this.lastHeartbeatTs.set(source, at);
    const s = this.sources.get(source) ?? { maxSeq: 0, tailHash: "", lastSeenMs: now };
    s.lastSeenMs = now;
    this.sources.set(source, s);
    if (hb.max_seq < s.maxSeq) {
      return { source, kind: "truncation", seq: hb.max_seq, detail: `the authority for '${source}' reports seq ${hb.max_seq}, the witness holds ${s.maxSeq} — ${s.maxSeq - hb.max_seq} row(s) gone from the on-box ledger` };
    }
    if (hb.max_seq > s.maxSeq) {
      return { source, kind: "gap", seq: s.maxSeq + 1, detail: `the authority for '${source}' reports seq ${hb.max_seq}, the witness holds ${s.maxSeq} — ${hb.max_seq - s.maxSeq} row(s) never delivered` };
    }
    if (hb.tail_hash !== s.tailHash) {
      return { source, kind: "chain", seq: hb.max_seq, detail: `the authority's tail at seq ${hb.max_seq} is not the row the witness holds` };
    }
    return null;
  }

  /** Sources that have gone silent past the heartbeat window — silence is an alarm. */
  stale(now: number = Date.now()): Alarm[] {
    const out: Alarm[] = [];
    for (const [source, s] of this.sources) {
      if (now - s.lastSeenMs > this.heartbeatTimeoutMs) {
        out.push({ source, kind: "stall", seq: s.maxSeq, detail: `'${source}' silent for ${Math.round((now - s.lastSeenMs) / 1000)}s (last seq ${s.maxSeq}) — past the heartbeat window` });
      }
    }
    return out;
  }

  /** Compare an on-box ledger's own max seq against what the witness holds — catches tail truncation. */
  reconcile(source: string, onboxMaxSeq: number): Alarm | null {
    const s = this.sources.get(source);
    if (!s) return null;
    if (onboxMaxSeq < s.maxSeq) {
      return { source, kind: "truncation", seq: onboxMaxSeq, detail: `on-box ledger for '${source}' shows seq ${onboxMaxSeq}, the witness holds ${s.maxSeq} — ${s.maxSeq - onboxMaxSeq} row(s) truncated on-box` };
    }
    return null;
  }

  highWaterMark(source: string): number { return this.sources.get(source)?.maxSeq ?? 0; }
  knownSources(): string[] { return [...this.sources.keys()]; }
}
