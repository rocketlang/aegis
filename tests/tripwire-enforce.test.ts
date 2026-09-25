// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-702 — containment enforcement bridge. Invariants forced BOTH ways per branch
// (@rule:guards-assert-both-outcomes): evidence honours a human clear; containment records
// never feed their own evidence; observe never touches the valve, enforce does; watch never
// ledgers a containment action; a hand-set mode cannot arm enforcement (env aside).
import { describe, it, expect } from "bun:test";
import { parseEvidence, stageToValveAction, applyContainment, type ValveActions } from "../src/tripwire/enforce";
import { containmentStage } from "../src/tripwire/containment";

const line = (o: Record<string, unknown>) => JSON.stringify(o);

describe("parseEvidence (AF-T-702)", () => {
  const lines = [
    line({ ts: "2026-09-25T10:00:00Z", session: "mallory", kind: "honeypot" }),
    line({ ts: "2026-09-25T10:01:00Z", session: "mallory", kind: "canary" }),
    line({ ts: "2026-09-25T10:02:00Z", session: "alice", kind: "honeypot" }),
    line({ ts: "2026-09-25T10:03:00Z", session: "mallory", kind: "containment", stage: "throttle" }),
    "not json at all",
    "",
  ];

  it("counts only the principal's tells; containment records and garbage are not evidence", () => {
    const ev = parseEvidence(lines, "mallory");
    expect(ev.hits).toBe(2);
    expect(ev.distinctKinds).toBe(2);
    expect(parseEvidence(lines, "alice")).toEqual({ hits: 1, distinctKinds: 1 });
    expect(parseEvidence(lines, "nobody")).toEqual({ hits: 0, distinctKinds: 0 });
  });

  it("a human clear cuts off older evidence — newer evidence still counts", () => {
    const clear = { cleared_at: "2026-09-25T10:00:30Z", by: "human", reason: "judged benign" };
    const ev = parseEvidence(lines, "mallory", clear);
    expect(ev.hits).toBe(1); // only the 10:01 canary survives the cutoff
    expect(ev.distinctKinds).toBe(1);
    const clearAll = { cleared_at: "2026-09-25T11:00:00Z", by: "human", reason: "all reviewed" };
    expect(parseEvidence(lines, "mallory", clearAll)).toEqual({ hits: 0, distinctKinds: 0 });
  });
});

describe("stageToValveAction", () => {
  it("maps the ladder onto the valve; watch maps to nothing", () => {
    expect(stageToValveAction("watch")).toBeNull();
    expect(stageToValveAction("throttle")).toBe("throttle");
    expect(stageToValveAction("quarantine")).toBe("close");
    expect(stageToValveAction("revoke")).toBe("lock");
  });
});

describe("applyContainment (observe vs enforce)", () => {
  function fakeValve() {
    const calls: string[] = [];
    const valve: ValveActions = {
      throttle: (id) => calls.push(`throttle:${id}`),
      close: (id) => calls.push(`close:${id}`),
      lock: (id) => calls.push(`lock:${id}`),
    };
    return { calls, valve };
  }

  it("watch: no valve action, no containment ledger entry", () => {
    const { calls, valve } = fakeValve();
    const written: unknown[] = [];
    const r = applyContainment("p1", containmentStage({ hits: 1, distinctKinds: 1 }), "enforce", valve, (rec) => written.push(rec));
    expect(r.action).toBeNull();
    expect(r.applied).toBe(false);
    expect(calls).toEqual([]);
    expect(written).toEqual([]);
  });

  it("observe: reports and ledgers applied:false, NEVER touches the valve (AFW-006)", () => {
    const { calls, valve } = fakeValve();
    const written: any[] = [];
    const r = applyContainment("p1", containmentStage({ hits: 4, distinctKinds: 1 }), "observe", valve, (rec) => written.push(rec));
    expect(r.stage).toBe("quarantine");
    expect(r.applied).toBe(false);
    expect(r.detail).toContain("WOULD close");
    expect(calls).toEqual([]);
    expect(written.length).toBe(1);
    expect(written[0].kind).toBe("containment");
    expect(written[0].applied).toBe(false);
  });

  it("enforce: throttle→throttle, quarantine→close, revoke→lock — and ledgers applied:true", () => {
    const { calls, valve } = fakeValve();
    const written: any[] = [];
    applyContainment("p1", containmentStage({ hits: 2, distinctKinds: 1 }), "enforce", valve, (r) => written.push(r));
    applyContainment("p1", containmentStage({ hits: 4, distinctKinds: 1 }), "enforce", valve, (r) => written.push(r));
    applyContainment("p1", containmentStage({ hits: 0, distinctKinds: 0, verifiedCapture: true }), "enforce", valve, (r) => written.push(r));
    expect(calls).toEqual(["throttle:p1", "close:p1", "lock:p1"]);
    expect(written.every((w) => w.applied === true)).toBe(true);
    expect(written.map((w) => w.valve_action)).toEqual(["throttle", "close", "lock"]);
  });

  it("revoke is still capture-gated upstream — evidence alone never reaches lock", () => {
    const { calls, valve } = fakeValve();
    applyContainment("p1", containmentStage({ hits: 9999, distinctKinds: 2 }), "enforce", valve, () => {});
    expect(calls).toEqual(["close:p1"]); // quarantine, not lock
  });
});
