// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// KAVACH — the ONE definition of "a synthetic (test-harness) principal".
//
// The answerability views (touched, quarterly, cockpit) and the lurker/UNKNOWN reviews
// all need to tell real agent activity apart from the project's own verification runs.
// Before this module there were two divergent regexes (reconcile, anumati-ledger-review)
// and the launch numbers counted the harness's own test sessions as real agents. One
// source now, a superset of both, so a launch report says "real agents", not "our tests".
//
// A principal is synthetic when its id is SESSION-SHAPED harness noise: a known test
// prefix followed by a separator, a digit, or end-of-string. Deliberately NOT matched:
//   - real session ids (`ses_177…`, `sess-uuid-A`) — the prefix must hit a boundary, and
//     `ses`/`sess` continue into a letter, so they survive;
//   - `ext:<ip>` external MCP callers — a real external caller is real signal, never
//     filtered by shape (a test one is disposed of by `aegis tripwire-clear`, recorded).

// Two shapes: a word prefix that ends at a separator or end-of-string (so `s1234`, a real
// session, is NOT caught — the boundary must be `-` or end, never a digit), and the AF-T
// verification prefixes `afv`/`afr` which are always followed by digits (`afv704-check`).
export const DEFAULT_SYNTHETIC_PRINCIPAL =
  /^(smoke|test|test-staging|sem-verify|multic|promo-verify|pv|s|live|wire-verify|probe-x|lurker)(-|$)|^(afv|afr)\d/i;

/** True when a principal id is the project's own test-harness noise, not a real agent. */
export function isSyntheticPrincipal(name: string, re: RegExp = DEFAULT_SYNTHETIC_PRINCIPAL): boolean {
  return re.test(name);
}
