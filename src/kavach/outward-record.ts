// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the outward record: what the person did with the acts put to them, per kind and lane.
// @rule:ANU-018 the data a loosening rests on: how often an asked act was approved, declined, left to
//               lapse or redrafted, and how many acts said why
//
// Read-only and pure over the ledger. One count per proposal (a proposal judged three times is one
// act). It reports; it loosens nothing. Moving a lane from "ask every message" to sampling is the
// founder's ruling, on these numbers.
//
// What it does NOT see (say it): an approval given in the authority for an act that was never run
// again (the approval is in the authority's store, not in outward.jsonl), so it shows as lapsed; an
// edit made outside a redraft (a new proposal that does not name `supersedes`) is a new act, not an
// edit; whether a sent message was right.

import { PENDING_TTL_MS, APPROVAL_TTL_MS } from "./destructive-approval";
import type { OutwardLedgerEntry } from "./outward";

/** An ask with no answer after the pending code and an approval could both have run out. */
export const LAPSE_MS = PENDING_TTL_MS + APPROVAL_TTL_MS;

export interface OutwardTally {
  kind: string;
  budget_key: string | null;
  proposals: number;
  refused: number;     // judged REFUSE every time, never sent
  asked: number;       // put to the person
  approved: number;    // of the asked: the person approved, and the run came back
  declined: number;    // of the asked: the person said no (ANU-019)
  cleared: number;     // of the asked: sent with no approval, because a later judgement no longer asked
  lapsed: number;      // of the asked: no answer within LAPSE_MS
  waiting: number;     // of the asked: still inside LAPSE_MS
  sent: number;        // executed
  redrafts: number;    // named the draft they replace
  with_why: number;    // gave a usable reason
}

interface Act { kind: string; key: string | null; first: number; asked: boolean; permitted: boolean;
  approved: boolean; declined: boolean; executed: boolean; redraft: boolean; why: boolean }

export function outwardRecord(ledger: OutwardLedgerEntry[], opts: { now: Date; since?: Date }): OutwardTally[] {
  const since = opts.since?.getTime() ?? 0;
  const acts = new Map<string, Act>();
  for (const e of ledger) {
    if (!e || typeof e.proposal_hash !== "string" || typeof e.kind !== "string") continue;
    const t = Date.parse(e.ts);
    if (!Number.isFinite(t)) continue;
    const id = `${e.kind}\0${e.proposal_hash}`;
    let a = acts.get(id);
    if (!a) {
      if (e.event !== "decided") continue; // a row with no decision before it is not an act this record can place
      a = { kind: e.kind, key: e.budget_key ?? null, first: t, asked: false, permitted: false, approved: false, declined: false, executed: false, redraft: false, why: false };
      acts.set(id, a);
    }
    if (e.event === "decided") {
      if (e.verdict === "PERMIT") a.permitted = true;
      if (e.ask) a.asked = true;
      if (e.supersedes) a.redraft = true;
      if (e.why) a.why = true;
      if (a.key === null && e.budget_key) a.key = e.budget_key;
    }
    if (e.event === "approved") a.approved = true;
    if (e.event === "declined") a.declined = true;
    if (e.event === "executed") a.executed = true;
  }

  const out = new Map<string, OutwardTally>();
  for (const a of acts.values()) {
    if (a.first < since) continue;
    const k = `${a.kind}\0${a.key ?? ""}`;
    let t = out.get(k);
    if (!t) {
      t = { kind: a.kind, budget_key: a.key, proposals: 0, refused: 0, asked: 0, approved: 0, declined: 0, cleared: 0, lapsed: 0, waiting: 0, sent: 0, redrafts: 0, with_why: 0 };
      out.set(k, t);
    }
    t.proposals++;
    if (!a.permitted && !a.executed) t.refused++;
    if (a.asked) {
      t.asked++;
      if (a.declined) t.declined++; // a decline overrides an earlier approval: ANU-019 refuses it at hand-off
      else if (a.approved) t.approved++;
      else if (a.executed) t.cleared++; // seen 21 Oct 2026: asked, then the mandate was widened and a later judgement did not ask
      else {
        if (opts.now.getTime() - a.first >= LAPSE_MS) t.lapsed++;
        else t.waiting++;
      }
    }
    if (a.executed) t.sent++;
    if (a.redraft) t.redrafts++;
    if (a.why) t.with_why++;
  }
  return [...out.values()].sort((x, y) => x.kind.localeCompare(y.kind) || String(x.budget_key).localeCompare(String(y.budget_key)));
}

/** Approved over answered-or-lapsed, or null when nothing was asked long enough ago to count. */
export function approvalRate(t: OutwardTally): number | null {
  const base = t.approved + t.declined + t.lapsed;
  return base ? t.approved / base : null;
}
