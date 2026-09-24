// SPDX-License-Identifier: AGPL-3.0-only
// Registry reconciliation (AF-T-604), both outcomes forced: an actor that acted but is not
// registered is a lurker; classification separates known test runners from the unexplained.
// @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { reconcile, classifyLurkers } from "../src/tripwire/reconcile";

describe("registry reconciliation (AF-T-604)", () => {
  it("an acting principal not in the registry is a lurker; a registered one matches", () => {
    const registered = ["sess-uuid-A", "ses_1777560540076"];
    const observed = ["sess-uuid-A", "ses_1777560540076", "intruder-xyz"];
    const r = reconcile(registered, observed);
    expect(r.matched).toEqual(["ses_1777560540076", "sess-uuid-A"]);
    expect(r.lurkers).toEqual(["intruder-xyz"]);
    expect(r.registeredCount).toBe(2);
    expect(r.observedCount).toBe(3);
  });

  it("all-registered observation yields no lurkers", () => {
    const r = reconcile(["a", "b"], ["a", "b"]);
    expect(r.lurkers).toEqual([]);
  });

  it("classification separates known test runners from the unexplained", () => {
    const { likelyTest, unexplained } = classifyLurkers(["smoke-123", "sem-verify", "intruder-xyz", "weird-agent-9"]);
    expect(likelyTest.sort()).toEqual(["sem-verify", "smoke-123"]);
    expect(unexplained.sort()).toEqual(["intruder-xyz", "weird-agent-9"]);
  });

  it("empty inputs are handled and drop falsy ids", () => {
    const r = reconcile([], ["", "x"]);
    expect(r.lurkers).toEqual(["x"]);
    expect(r.observedCount).toBe(1);
  });
});
