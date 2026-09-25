// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-404 — quarterly answerability report. Both outcomes per branch: compose aggregates
// the lead correctly; the digest breaks on tamper; the diff surfaces regressions FIRST and
// says "no change" only when nothing changed.
import { describe, it, expect } from "bun:test";
import { composeQuarterly, diffQuarterly, type QuarterlyParts, type QuarterlyReport } from "../src/redteam/quarterly";

const TS = "2026-09-25T00:00:00.000Z";

function parts(overrides: Partial<{ failed: string[]; catchable: number; undeclared: number; obs: number }> = {}): QuarterlyParts {
  const failed = overrides.failed ?? [];
  return {
    touched: {
      since: "2026-06-27T00:00:00.000Z", until: TS,
      principals: [{
        principal: "s1",
        anumati: { enforced_refusals: 3, observations: { "ANU-I-007": overrides.obs ?? 2 }, provenance: [{ ts: TS, verdict: "PERMIT", detail: "x" }], sample_targets: [] },
        tripwire: { hits: 1, kinds: ["honeypot"], containment: [] },
      }],
      totals: { anumati_rows: 4, tripwire_rows: 1, unparseable: 0 },
    } as any,
    rehearsal: { schema: "s", ts: TS, all_pass: failed.length === 0, note: "", digest: "d".repeat(64),
      steps: [{ id: "a", pass: !failed.includes("a") }, { id: "b", pass: !failed.includes("b") }] } as any,
    redteam: { catchableAsr: 0, fpr: 0, catchableGaps: Array(overrides.catchable ?? 0).fill({}), ceilingGaps: Array(18).fill({}) } as any,
    posture: { score: 100 - (overrides.catchable ?? 0) * 10, grade: "A" } as any,
    shield: { injection: { misses: [], robustnessGaps: [], falsePositives: [] }, persistence: { misses: [], variantGaps: [], falsePositives: [] } } as any,
    exfil: { credential: { misses: [], variantGaps: [], falsePositives: [{ path: "/x/.env.example", credPath: "/.env" }] }, exfil: { mismatches: [] } } as any,
    ci: { audits: [{ thirdPartyActions: ["a@v4"] }], undeclaredPublishes: overrides.undeclared ?? 0 } as any,
  };
}

describe("composeQuarterly (AF-T-404)", () => {
  it("the lead aggregates refusals, observations, provenance and tells across principals", () => {
    const r = composeQuarterly(parts(), TS);
    expect(r.answerability.enforced_refusals).toBe(3);
    expect(r.answerability.observations_by_invariant["ANU-I-007"]).toBe(2);
    expect(r.answerability.provenance_rows).toBe(1);
    expect(r.answerability.tripwire_tells).toBe(1);
    expect(r.rehearsal.all_pass).toBe(true);
  });

  it("digest is reproducible and breaks when anything changes", () => {
    expect(composeQuarterly(parts(), TS).digest).toBe(composeQuarterly(parts(), TS).digest);
    expect(composeQuarterly(parts({ undeclared: 1 }), TS).digest).not.toBe(composeQuarterly(parts(), TS).digest);
  });
});

describe("diffQuarterly", () => {
  const base = composeQuarterly(parts(), TS);

  it("no change → exactly the no-change headline", () => {
    const d = diffQuarterly(base, composeQuarterly(parts(), TS));
    expect(d.headline).toEqual(["no change against the previous period"]);
  });

  it("regressions surface FIRST: new rehearsal failure, new catchable gap, new undeclared publish", () => {
    const worse = composeQuarterly(parts({ failed: ["b"], catchable: 1, undeclared: 1 }), TS);
    const d = diffQuarterly(base, worse);
    expect(d.rehearsal_regressions).toEqual(["b"]);
    expect(d.new_catchable_gaps).toBe(1);
    expect(d.undeclared_publish_delta).toBe(1);
    expect(d.headline[0]).toContain("REGRESSION");
  });

  it("recovery and observation growth are reported without crying regression", () => {
    const prevBad = composeQuarterly(parts({ failed: ["a"] }), TS);
    const d = diffQuarterly(prevBad, composeQuarterly(parts({ obs: 5 }), TS));
    expect(d.rehearsal_recoveries).toEqual(["a"]);
    expect(d.headline.join(" ")).toContain("recovered");
    expect(d.observations_delta).toBe(3);
    expect(d.headline.join(" ")).not.toContain("REGRESSION");
  });
});
