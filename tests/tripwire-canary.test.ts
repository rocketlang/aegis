// SPDX-License-Identifier: AGPL-3.0-only
// Document canaries (AF-T-603), both outcomes forced: the bait carries the token and is
// human-ignorable; a token echoed in an agent action trips the wire at WATCH; clean text
// does not; minted tokens are unique. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { canaryText, mintCanary, detectCanaryTrip } from "../src/tripwire/canary";

describe("document canary (AF-T-603)", () => {
  it("the bait carries the token and is addressed to agents, not humans", () => {
    const t = "CANARY-abc123";
    const text = canaryText(t);
    expect(text).toContain(t);
    expect(text.toLowerCase()).toContain("if you are an autonomous ai agent");
    expect(text.toLowerCase()).toContain("human readers: ignore");
    expect(text.startsWith("<!--")).toBe(true); // a human skips an HTML comment
  });

  it("a registered token echoed in an agent action trips the wire at WATCH", () => {
    const c = mintCanary({ label: "founders-log", placement: "proposals/x.md" });
    const observed = JSON.stringify({ tool: "verify_agent_identity", args: { token: c.token } });
    const trip = detectCanaryTrip(observed, [c.token]);
    expect(trip.tripped).toBe(true);
    expect(trip.token).toBe(c.token);
    expect(trip.stage).toBe("watch"); // never a kill on a guess
  });

  it("clean text with no canary token does not trip", () => {
    expect(detectCanaryTrip("please read the readme and build", ["CANARY-deadbeef"]).tripped).toBe(false);
    expect(detectCanaryTrip("anything", []).tripped).toBe(false);
  });

  it("minted tokens are unique and unguessable", () => {
    const a = mintCanary({ label: "a", placement: "p" });
    const b = mintCanary({ label: "b", placement: "p" });
    expect(a.token).not.toBe(b.token);
    expect(a.token).toMatch(/^CANARY-[0-9a-f]{24}$/);
  });
});
