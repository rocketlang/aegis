// SPDX-License-Identifier: AGPL-3.0-only
// The staged containment ladder (AF-T-605, AFW-011), invariants forced: evidence escalates
// watch→throttle→quarantine; revoke is UNREACHABLE without a verified capture; the ladder
// never de-escalates on its own. @rule:guards-assert-both-outcomes
import { describe, it, expect } from "bun:test";
import { containmentStage } from "../src/tripwire/containment";

describe("containment ladder (AF-T-605)", () => {
  it("escalates by evidence: watch → throttle → quarantine", () => {
    expect(containmentStage({ hits: 1, distinctKinds: 1 }).stage).toBe("watch");
    expect(containmentStage({ hits: 2, distinctKinds: 1 }).stage).toBe("throttle");
    expect(containmentStage({ hits: 1, distinctKinds: 2 }).stage).toBe("throttle"); // two independent tells
    expect(containmentStage({ hits: 4, distinctKinds: 1 }).stage).toBe("quarantine");
    expect(containmentStage({ hits: 3, distinctKinds: 2 }).stage).toBe("quarantine");
  });

  it("NEVER reaches revoke by evidence alone — only a verified capture (never a kill on a guess)", () => {
    expect(containmentStage({ hits: 9999, distinctKinds: 2 }).stage).toBe("quarantine");
    expect(containmentStage({ hits: 9999, distinctKinds: 2, verifiedCapture: false }).stage).toBe("quarantine");
    const r = containmentStage({ hits: 0, distinctKinds: 0, verifiedCapture: true });
    expect(r.stage).toBe("revoke");
    expect(r.reason).toContain("verified capture");
  });

  it("NEVER de-escalates on its own — a lower computed stage is held at the prior", () => {
    const d = containmentStage({ hits: 1, distinctKinds: 1 }, "quarantine");
    expect(d.stage).toBe("quarantine");
    expect(d.heldAtPrior).toBe(true);
    // and it still escalates upward past the prior when evidence warrants
    expect(containmentStage({ hits: 4, distinctKinds: 1 }, "throttle").stage).toBe("quarantine");
  });
});
