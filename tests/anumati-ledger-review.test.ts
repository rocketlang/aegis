// SPDX-License-Identifier: AGPL-3.0-only
// The AF-R-002 review, both outcomes forced: an empty/short/synthetic ledger KEEPS OBSERVING;
// a ledger with real observations spanning the window is READY_FOR_REVIEW and lists the
// distinct commands. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { reviewAnumatiLedger } from "../src/kavach/anumati-ledger-review";

const obs = (session: string, ts: string, target: string) =>
  JSON.stringify({ ts, session, tool: "Bash", target, refusals: [], observations: [{ id: "ANU-I-006", verdict: "UNKNOWN", detail: "…" }] });

describe("reviewAnumatiLedger (AF-R-002)", () => {
  it("KEEP_OBSERVING when only synthetic test sessions are present", () => {
    const r = reviewAnumatiLedger([
      obs("sem-verify", "2026-09-23T21:00:00Z", 'psql -c "$SQL"'),
      obs("multic", "2026-09-23T22:00:00Z", "psql -c 'SELECT 1' -c 'DROP TABLE x'"),
      obs("smoke-123", "2026-09-24T00:00:00Z", "psql -c 'INSERT...'"),
    ]);
    expect(r.realCount).toBe(0);
    expect(r.excludedSynthetic).toBe(3);
    expect(r.recommendation).toBe("KEEP_OBSERVING");
  });

  it("KEEP_OBSERVING when real observations span less than the window", () => {
    const r = reviewAnumatiLedger([
      obs("build-42", "2026-09-24T09:00:00Z", "psql -c 'INSERT INTO t VALUES (1)'"),
      obs("build-42", "2026-09-24T15:00:00Z", "psql -c 'UPDATE t SET x=1'"),
    ], { minDays: 7 });
    expect(r.realCount).toBe(2);
    expect(r.recommendation).toBe("KEEP_OBSERVING");
    expect(r.spanDays).toBeLessThan(7);
  });

  it("READY_FOR_REVIEW once real observations span the window, listing distinct commands", () => {
    const r = reviewAnumatiLedger([
      obs("build-42", "2026-09-01T09:00:00Z", "psql -c 'INSERT INTO t VALUES (1)'"),
      obs("cron-x", "2026-09-05T09:00:00Z", "psql -c 'INSERT INTO t VALUES (1)'"), // same cmd, other session
      obs("cron-y", "2026-09-12T09:00:00Z", "psql -c 'UPDATE metrics SET n=n+1'"),
    ], { minDays: 7 });
    expect(r.realCount).toBe(3);
    expect(r.recommendation).toBe("READY_FOR_REVIEW");
    expect(r.spanDays).toBeGreaterThanOrEqual(7);
    // deduped: 2 distinct commands, the INSERT seen in 2 sessions
    expect(r.distinct.length).toBe(2);
    const insert = r.distinct.find((d) => d.cmd.includes("INSERT INTO t"))!;
    expect(insert.count).toBe(2);
    expect(insert.sessions).toBe(2);
  });
});
