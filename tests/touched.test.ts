// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-709 — answerability aggregation (AFW-YK-009). Both outcomes per branch: rows in
// and out of the window, provenance carried, containment split from tells, unparseable
// lines counted and skipped (never evidence), since-spec parsing both ways.
import { describe, it, expect } from "bun:test";
import { aggregateTouched, parseSince } from "../src/kavach/touched";

const T0 = Date.parse("2026-09-25T10:00:00Z");
const at = (min: number) => new Date(T0 + min * 60e3).toISOString();
const line = (o: unknown) => JSON.stringify(o);

describe("aggregateTouched (AF-T-709)", () => {
  const anumati = [
    line({ ts: at(10), session: "s1", tool: "Bash", target: "psql -d prod -c ...", enforced: true, refusals: [{ id: "ANU-I-006", verdict: "REFUSE", detail: "x" }], observations: [] }),
    line({ ts: at(20), session: "s1", tool: "Bash", target: "curl https://evil.example", enforced: false, refusals: [], observations: [{ id: "ANU-I-007", verdict: "REFUSE", detail: "y" }] }),
    line({ ts: at(30), session: "s2", tool: "Bash", target: "docker push a:1", enforced: false, refusals: [], observations: [], provenance: [{ id: "ANU-I-010", verdict: "PERMIT", detail: "publish under mandate" }] }),
    line({ ts: at(-600), session: "s1", tool: "Bash", target: "old", enforced: true, refusals: [{ id: "ANU-I-001", verdict: "REFUSE", detail: "old" }], observations: [] }),
    "garbage not json",
  ];
  const tripwire = [
    line({ ts: at(5), session: "s3", kind: "honeypot", stage: "watch" }),
    line({ ts: at(6), session: "s3", kind: "canary", stage: "watch" }),
    line({ ts: at(7), session: "s3", kind: "containment", stage: "throttle", applied: false }),
  ];

  it("aggregates per principal inside the window; outside rows and garbage are excluded/counted", () => {
    const r = aggregateTouched(anumati, tripwire, T0, T0 + 3600e3);
    expect(r.totals.anumati_rows).toBe(3); // the -600min row is out of window
    expect(r.totals.unparseable).toBe(1);

    const s1 = r.principals.find((p) => p.principal === "s1")!;
    expect(s1.anumati.enforced_refusals).toBe(1);
    expect(s1.anumati.observations["ANU-I-007"]).toBe(1);
    expect(s1.anumati.observations["ANU-I-001"]).toBeUndefined(); // out of window

    const s2 = r.principals.find((p) => p.principal === "s2")!;
    expect(s2.anumati.provenance.length).toBe(1);
    expect(s2.anumati.provenance[0].verdict).toBe("PERMIT");

    const s3 = r.principals.find((p) => p.principal === "s3")!;
    expect(s3.tripwire.hits).toBe(2); // containment rows are actions we took, not tells
    expect(s3.tripwire.kinds.sort()).toEqual(["canary", "honeypot"]);
    expect(s3.tripwire.containment).toEqual([{ ts: at(7), stage: "throttle", applied: false }]);
  });

  it("ranks the busiest principal first (enforced refusals outrank observations)", () => {
    const r = aggregateTouched(anumati, tripwire, T0, T0 + 3600e3);
    expect(r.principals[0].principal).toBe("s1");
  });
});

describe("parseSince", () => {
  it("parses h/d/m windows and ISO dates; rejects nonsense", () => {
    const now = 1_700_000_000_000;
    expect(parseSince("24h", now)).toBe(now - 24 * 3600e3);
    expect(parseSince("7d", now)).toBe(now - 7 * 86400e3);
    expect(parseSince("90m", now)).toBe(now - 90 * 60e3);
    expect(parseSince("2026-09-25T00:00:00Z", now)).toBe(Date.parse("2026-09-25T00:00:00Z"));
    expect(parseSince("soonish", now)).toBeNull();
  });
});
