// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// Agent Tripwire — registry reconciliation (AF-T-604).
//
// AFW-010: own agents carry an issued identity; everything else is unowned by default. This
// reconciles the REGISTERED set (sessions the registry knows + mudrika-issued identities)
// against the OBSERVED-ACTING set (principals that actually did something — every distinct
// `session` in the anumati/tripwire ledgers). A principal that ACTED but is not registered is
// an unregistered actor: a lurker candidate. This is the "prove ours, everything else is
// unowned" principle made into a list you can look at.
//
// HONEST limit (same discipline as the ledger review): "observed" is only the principals that
// LEFT A TRACE in a ledger — it is not a live process scan, and a lurker that made no gated
// call leaves nothing here. And a first cut cannot tell a benign unregistered scenario/test
// run from a real intruder, so lurkers are CLASSIFIED (likely-test vs unexplained), never
// auto-judged. Pure module; the caller gathers the sets and does the I/O.

export interface Reconciliation {
  registeredCount: number;
  observedCount: number;
  matched: string[];   // acted AND registered
  lurkers: string[];   // acted but NOT registered — unregistered actors
}

export function reconcile(registered: Iterable<string>, observed: Iterable<string>): Reconciliation {
  const reg = new Set([...registered].filter(Boolean));
  const obs = new Set([...observed].filter(Boolean));
  const matched: string[] = [];
  const lurkers: string[] = [];
  for (const id of obs) (reg.has(id) ? matched : lurkers).push(id);
  return { registeredCount: reg.size, observedCount: obs.size, matched: matched.sort(), lurkers: lurkers.sort() };
}

// Default: scenario/test principals that are legitimately unregistered on this box (the
// scenario runner, and this project's own verification sessions). They ARE unregistered actors
// honestly — separating them keeps the real signal from drowning, it does not excuse them.
export const DEFAULT_TEST_ACTOR = /^(smoke|test|sem-verify|multic|promo-verify|pv|s|live)(-|$)/i;

export interface LurkerClasses { likelyTest: string[]; unexplained: string[] }

/** Split lurkers into recognisable test/scenario runs vs the ones that need a human look. */
export function classifyLurkers(lurkers: string[], testActor: RegExp = DEFAULT_TEST_ACTOR): LurkerClasses {
  const likelyTest: string[] = [];
  const unexplained: string[] = [];
  for (const id of lurkers) (testActor.test(id) ? likelyTest : unexplained).push(id);
  return { likelyTest, unexplained };
}
