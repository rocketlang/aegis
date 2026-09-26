// SPDX-License-Identifier: AGPL-3.0-only
// The local floor for the optional canon bricks (@ankr/approve, @ankr/mask-authorize) —
// what a PUBLIC install runs on when the private bricks 404. Both outcomes per branch.
import { describe, it, expect } from "bun:test";
import { __floor } from "../src/kavach/canon-bricks";

const { floorApprovalEngine, floorMaskAuthorize } = __floor;

describe("floorApprovalEngine (@ankr/approve floor)", () => {
  const machine = {
    approve: { from: ["pending"], to: "approved" },
    consume: { from: ["approved"], to: "consumed" },
    revoke: { from: ["pending"], to: "revoked" },
  };
  const eng = floorApprovalEngine(machine);

  it("returns the target state for a lawful transition", () => {
    expect(eng.assertLawful("pending", "approve")).toBe("approved");
    expect(eng.assertLawful("approved", "consume")).toBe("consumed");
  });

  it("throws on an unlawful transition (wrong source, or unknown action)", () => {
    expect(() => eng.assertLawful("approved", "approve")).toThrow(); // wrong source state
    expect(() => eng.assertLawful("pending", "consume")).toThrow();  // consume needs approved
    expect(() => eng.assertLawful("pending", "nonexistent")).toThrow();
  });
});

describe("floorMaskAuthorize (@ankr/mask-authorize floor)", () => {
  it("mode 'any': any shared required bit grants; none denies", () => {
    expect(floorMaskAuthorize({ caller: 0b0110n, required: 0b0100n, mode: "any" }).authorized).toBe(true);
    expect(floorMaskAuthorize({ caller: 0b0010n, required: 0b0100n, mode: "any" }).authorized).toBe(false);
  });

  it("mode 'all': every required bit must be present", () => {
    expect(floorMaskAuthorize({ caller: 0b0111n, required: 0b0101n, mode: "all" }).authorized).toBe(true);
    expect(floorMaskAuthorize({ caller: 0b0100n, required: 0b0101n, mode: "all" }).authorized).toBe(false);
  });

  it("a capability bit is AND-ed in — absent capability denies even a role match", () => {
    expect(floorMaskAuthorize({ caller: 0b0100n, required: 0b0100n, capability: 0b1000n, mode: "any" }).authorized).toBe(false);
    expect(floorMaskAuthorize({ caller: 0b1100n, required: 0b0100n, capability: 0b1000n, mode: "any" }).authorized).toBe(true);
  });

  it("required = 0 grants (no requirement) unless a capability is missing", () => {
    expect(floorMaskAuthorize({ caller: 0n, required: 0n }).authorized).toBe(true);
    expect(floorMaskAuthorize({ caller: 0n, required: 0n, capability: 0b1n }).authorized).toBe(false);
  });
});
