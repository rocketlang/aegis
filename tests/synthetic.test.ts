// SPDX-License-Identifier: AGPL-3.0-only
// The one synthetic-principal definition, and its use in the answerability aggregation.
// Both outcomes per branch (@rule:guards-assert-both-outcomes), and the regression that
// forced the fix: a real session id starting with `s` + digits must NOT be called synthetic.
import { describe, it, expect } from "bun:test";
import { isSyntheticPrincipal } from "../src/kavach/synthetic";
import { aggregateTouched } from "../src/kavach/touched";

describe("isSyntheticPrincipal", () => {
  it("catches the project's test-harness sessions", () => {
    for (const s of ["afv704-check", "afv702-test", "smoke-1", "smoke", "test-staging-9", "sem-verify", "multic-x", "pv-1", "s-1", "s", "wire-verify-701", "probe-x", "lurker-1"]) {
      expect(isSyntheticPrincipal(s)).toBe(true);
    }
  });

  it("does NOT catch real agents, real sessions, or external callers", () => {
    for (const s of ["ses_1777560540076", "sess-uuid-A", "s1234", "startup-agent", "server-7", "intruder-xyz", "weird-agent-9", "ext:203.0.113.9", "claude-main"]) {
      expect(isSyntheticPrincipal(s)).toBe(false);
    }
  });
});

describe("aggregateTouched — synthetic filter (the launch-number cleanup)", () => {
  const now = Date.parse("2026-09-25T12:00:00Z");
  const at = (min: number) => new Date(now - min * 60e3).toISOString();
  const line = (o: unknown) => JSON.stringify(o);
  const rows = [
    line({ ts: at(5), session: "afv704-check", tool: "Bash", target: "x", enforced: true, refusals: [{ id: "ANU-I-005", verdict: "REFUSE", detail: "test" }], observations: [] }),
    line({ ts: at(6), session: "real-agent-1", tool: "Bash", target: "y", enforced: true, refusals: [{ id: "ANU-I-006", verdict: "REFUSE", detail: "prod" }], observations: [] }),
    line({ ts: at(7), session: "s1234", tool: "Bash", target: "z", enforced: false, refusals: [], observations: [{ id: "ANU-I-007", verdict: "REFUSE", detail: "egress" }] }),
  ];

  it("excludes synthetic principals by default and counts what it hid", () => {
    const r = aggregateTouched(rows, [], now - 3600e3, now);
    const ids = r.principals.map((p) => p.principal).sort();
    expect(ids).toEqual(["real-agent-1", "s1234"]); // afv704-check dropped, s1234 kept
    expect(r.totals.synthetic_excluded).toBe(1);
  });

  it("includes them when explicitly asked, and reports zero hidden", () => {
    const r = aggregateTouched(rows, [], now - 3600e3, now, { includeSynthetic: true });
    expect(r.principals.length).toBe(3);
    expect(r.totals.synthetic_excluded).toBe(0);
  });
});
