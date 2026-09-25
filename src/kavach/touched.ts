// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the answerability aggregation (AF-T-709, AFW-YK-009, AFW-008).
//
// "What did our agents touch in window W?" must be ONE command over the ledgers, not log
// archaeology. This module is the pure half: given raw anumati + tripwire ledger lines and
// a window, it returns per-principal activity — enforced refusals, observations by
// invariant (the shadow evidence), outward provenance (publishes), tripwire tells and
// containment. The CLI adds receipt-chain verification and prints the ceiling.
//
// FP-018: everything here is COMPUTE over ledger rows; nothing is generated. An empty
// answer for a principal means "nothing LEDGERED", never "nothing happened" — the ledgers
// see tool-route and tripwire-visible activity, and that bound is stated in the render.

export interface TouchedPrincipal {
  principal: string;
  anumati: {
    enforced_refusals: number;
    /** observation counts by invariant id — the shadow evidence promotions read */
    observations: Record<string, number>;
    /** outward-write provenance rows (AFW-012), verdict included */
    provenance: { ts: string; verdict: string; detail: string }[];
    /** last few targets touched by refused/observed actions, for the human scanning */
    sample_targets: string[];
  };
  tripwire: {
    hits: number;
    kinds: string[];
    containment: { ts: string; stage: string; applied: boolean }[];
  };
}

export interface TouchedReport {
  since: string;
  until: string;
  principals: TouchedPrincipal[];
  totals: { anumati_rows: number; tripwire_rows: number; unparseable: number; synthetic_excluded: number };
}

import { isSyntheticPrincipal } from "./synthetic";

const parse = (line: string): any | null => {
  if (!line.trim()) return null;
  try { return JSON.parse(line); } catch { return "unparseable"; }
};

export function aggregateTouched(
  anumatiLines: string[],
  tripwireLines: string[],
  sinceMs: number,
  untilMs: number,
  opts: { includeSynthetic?: boolean } = {},
): TouchedReport {
  const by = new Map<string, TouchedPrincipal>();
  const get = (p: string): TouchedPrincipal => {
    let t = by.get(p);
    if (!t) {
      t = {
        principal: p,
        anumati: { enforced_refusals: 0, observations: {}, provenance: [], sample_targets: [] },
        tripwire: { hits: 0, kinds: [], containment: [] },
      };
      by.set(p, t);
    }
    return t;
  };

  let anumatiRows = 0, tripwireRows = 0, unparseable = 0;
  const inWindow = (ts: unknown): boolean => {
    const t = Date.parse(String(ts ?? ""));
    return Number.isFinite(t) && t >= sinceMs && t <= untilMs;
  };

  for (const line of anumatiLines) {
    const r = parse(line);
    if (r === null) continue;
    if (r === "unparseable") { unparseable++; continue; }
    if (!inWindow(r.ts)) continue;
    anumatiRows++;
    const t = get(String(r.session ?? "unknown"));
    if (r.enforced) t.anumati.enforced_refusals++;
    for (const o of r.observations ?? []) {
      t.anumati.observations[o.id] = (t.anumati.observations[o.id] ?? 0) + 1;
    }
    for (const p of r.provenance ?? []) {
      t.anumati.provenance.push({ ts: String(r.ts), verdict: String(p.verdict), detail: String(p.detail) });
    }
    if (r.target && ((r.refusals ?? []).length || (r.observations ?? []).length) && t.anumati.sample_targets.length < 5) {
      t.anumati.sample_targets.push(String(r.target).slice(0, 120));
    }
  }

  for (const line of tripwireLines) {
    const r = parse(line);
    if (r === null) continue;
    if (r === "unparseable") { unparseable++; continue; }
    if (!inWindow(r.ts)) continue;
    tripwireRows++;
    const t = get(String(r.session ?? "unknown"));
    if (r.kind === "containment") {
      t.tripwire.containment.push({ ts: String(r.ts), stage: String(r.stage), applied: r.applied === true });
    } else {
      t.tripwire.hits++;
      if (r.kind && !t.tripwire.kinds.includes(String(r.kind))) t.tripwire.kinds.push(String(r.kind));
    }
  }

  // Drop the project's own test-harness sessions unless explicitly asked to keep them, so
  // the launch numbers count real agents. The count of what was dropped is reported — a
  // filter that hides its own effect is the kind of thing this stack exists to refuse.
  let all = [...by.values()];
  let syntheticExcluded = 0;
  if (!opts.includeSynthetic) {
    const before = all.length;
    all = all.filter((p) => !isSyntheticPrincipal(p.principal));
    syntheticExcluded = before - all.length;
  }

  // Busiest first: enforced refusals, then tripwire hits, then observation volume.
  const principals = all.sort((a, b) => {
    const score = (x: TouchedPrincipal) =>
      x.anumati.enforced_refusals * 1000 + x.tripwire.hits * 100 +
      Object.values(x.anumati.observations).reduce((s, n) => s + n, 0);
    return score(b) - score(a);
  });

  return {
    since: new Date(sinceMs).toISOString(),
    until: new Date(untilMs).toISOString(),
    principals,
    totals: { anumati_rows: anumatiRows, tripwire_rows: tripwireRows, unparseable, synthetic_excluded: syntheticExcluded },
  };
}

/** `24h`, `7d`, `90m`, or an ISO date → epoch ms. null = unparseable. */
export function parseSince(spec: string, nowMs: number): number | null {
  const m = /^(\d+)([hdm])$/.exec(spec);
  if (m) {
    const n = Number(m[1]);
    const unit = m[2] === "h" ? 3600e3 : m[2] === "d" ? 86400e3 : 60e3;
    return nowMs - n * unit;
  }
  const t = Date.parse(spec);
  return Number.isFinite(t) ? t : null;
}
