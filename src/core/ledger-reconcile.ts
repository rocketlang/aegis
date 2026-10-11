// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ledger-reconcile — does the gates' own copy agree with the signed ledger?
//
// The gates keep a plain local copy of every refusal (core/refusal-ledger.ts). A row there says
// which signed row it became (`authority_seq`), or why there is none (`authority_error`). Through
// 2.16.2 nothing compared the two files, so a local row could name a number the authority never
// gave, or carry no number and no reason, and every check still read clean (reported by Andrey
// Lazarev, 11 October 2026).
//
// Three findings:
//   mismatch  — a local row names seq N, and the signed ledger has no row N, or row N is another
//               refusal, or two local rows claim the same N. Something other than the authority
//               answered the gate, or one of the two files was changed.
//   silent    — a local row with no number and no reason, written after the signed ledger's first
//               row. The gate did not ask: the authority was not configured for that process (the
//               pointer file was missing, by an operator's rollback or otherwise).
//   declared  — a local row that says it was not signed and why. Already said aloud at the time;
//               counted here, not a finding.
//
// WHAT THIS DOES NOT GIVE: the local file is written by the agent's own uid. A process that
// removes its local row as well leaves nothing to compare. Reconciliation catches a refusal that
// was diverted, not one that was erased from both sides; that needs the refusal itself to pass
// through the authority.

import { rowHash, ledgerField, visible, type SignedRow } from "./ledger-sign";

export interface LocalRow {
  ts?: string; kind?: string; gate?: string; rule?: string | null; session?: string | null;
  authority_seq?: unknown; authority_error?: unknown; authority_check?: unknown; authority_row_hash?: unknown;
}

export interface Reconciliation {
  /** local rows that carry a number */
  numbered: number;
  /** of those, rows the gate itself verified against a pinned key when it wrote them */
  verifiedAtWrite: number;
  mismatches: string[];
  silent: LocalRow[];
  declared: number;
}

const clip = ledgerField;

/**
 * @param local   the gates' local rows, as read
 * @param signed  the signed ledger's rows, already verified whole by the caller
 * @param since   ignore local rows written before this time (ISO); default: the first signed row's time
 */
export function reconcileLocal(local: unknown[], signed: SignedRow[], since?: string): Reconciliation {
  const bySeq = new Map<number, SignedRow>();
  for (const r of signed) bySeq.set(r.seq, r);
  const first = signed.length ? signed[0].ts : null;
  const maxSeq = signed.length ? signed[signed.length - 1].seq : 0;
  const from = since || first;
  const out: Reconciliation = { numbered: 0, verifiedAtWrite: 0, mismatches: [], silent: [], declared: 0 };
  const claimed = new Map<number, number>();

  for (const raw of local) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as LocalRow;
    // The local file is written by the gates' own account: what is quoted from it is shown, never sent raw.
    const when = visible(`${r.ts ?? "no time"}, ${r.gate ?? "no gate"}`.slice(0, 140));
    if (since && typeof r.ts === "string" && r.ts < since) continue;

    if (r.authority_seq !== undefined) {
      const n = r.authority_seq;
      out.numbered++;
      if (r.authority_check === "verified") out.verifiedAtWrite++;
      if (typeof n !== "number" || !Number.isInteger(n) || n < 1) { out.mismatches.push(`a local row (${when}) carries '${String(n)}' as its number`); continue; }
      claimed.set(n, (claimed.get(n) ?? 0) + 1);
      const s = bySeq.get(n);
      if (!s) { out.mismatches.push(`a local row (${when}) names seq ${n}; the signed ledger has no such row (it ends at ${maxSeq})`); continue; }
      const same = s.gate === (clip(r.gate, 80) ?? "unknown") && (s.rule ?? null) === clip(r.rule, 60)
        && s.kind === (r.kind === "override" ? "override" : "refused") && (s.session ?? null) === clip(r.session, 80);
      if (!same) { out.mismatches.push(`a local row (${when}) names seq ${n}; signed row ${n} is another refusal (${s.ts}, ${s.gate})`); continue; }
      if (typeof r.authority_row_hash === "string" && r.authority_row_hash !== rowHash(s)) {
        out.mismatches.push(`a local row (${when}) names seq ${n} with a row hash that is not signed row ${n}'s`);
      }
      continue;
    }
    if (r.authority_error !== undefined) { out.declared++; continue; }
    // No number and no reason. Before the signed ledger existed that is simply how rows were written.
    if (from && typeof r.ts === "string" && r.ts > from) out.silent.push(r);
  }
  for (const [n, times] of claimed) {
    if (times > 1 && bySeq.has(n)) out.mismatches.push(`${times} local rows claim seq ${n}; the authority gives a number once`);
  }
  return out;
}
