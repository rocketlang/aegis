// SPDX-License-Identifier: AGPL-3.0-only
// AF-T-708 — graded act-class identity requirement (ANU-I-011, AFW-010). Both outcomes
// per branch (@rule:guards-assert-both-outcomes): valid permits; absent refuses at
// OBSERVE (the AF-T-602 fail-open branch, never enforced at birth); present-but-invalid
// refuses at ENFORCE (the hot path already dies there — no new blocking surface).
import { describe, it, expect } from "bun:test";
import { mudrikaActVerdict, MUDRIKA_ABSENT_REASON } from "../src/kavach/mudrika-validator";

describe("mudrikaActVerdict (AF-T-708)", () => {
  it("a verified identity PERMITs", () => {
    const r = mudrikaActVerdict({ valid: true }, "session-abc");
    expect(r.verdict).toBe("PERMIT");
  });

  it("an ABSENT identity refuses at observe — required, but promoted only on evidence", () => {
    const r = mudrikaActVerdict({ valid: false, reason: MUDRIKA_ABSENT_REASON }, "session-abc");
    expect(r.verdict).toBe("REFUSE");
    expect(r.stage).toBe("observe");
    expect(r.detail).toContain("NO issued identity");
  });

  it("a PRESENT-but-INVALID identity refuses at enforce — a broken credential is worse than none", () => {
    const r = mudrikaActVerdict({ valid: false, reason: "signature mismatch" }, "session-abc");
    expect(r.verdict).toBe("REFUSE");
    expect(r.stage).toBe("enforce");
    expect(r.detail).toContain("INVALID mudrika");
  });
});
