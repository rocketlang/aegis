// SPDX-License-Identifier: AGPL-3.0-only
// @rule:INF-KOS-009 — every combination of (supervisor verdict, opt-out flag), forced.
import { describe, it, expect } from "bun:test";
import { egressLaunchDecision } from "../src/kernel/egress-policy";

describe("egress launch decision", () => {
  it("proceeds when the supervisor returned a cgroup path", () => {
    expect(egressLaunchDecision("/sys/fs/cgroup/kavachos/s1", false).proceed).toBe(true);
    expect(egressLaunchDecision("/sys/fs/cgroup/kavachos/s1", true).proceed).toBe(true);
  });

  it("REFUSES a failed arm, with or without the flag", () => {
    expect(egressLaunchDecision("FAILED", false).proceed).toBe(false);
    // the whole point of the opt-out: it accepts a host that cannot enforce, never a fault
    expect(egressLaunchDecision("FAILED", true).proceed).toBe(false);
    expect(egressLaunchDecision("FAILED", true).reason).toContain("fault, not an environment");
  });

  it("REFUSES a timeout, with or without the flag", () => {
    expect(egressLaunchDecision("TIMEOUT", false).proceed).toBe(false);
    expect(egressLaunchDecision("TIMEOUT", true).proceed).toBe(false);
    expect(egressLaunchDecision("TIMEOUT", true).reason).toContain("Unknown is not permission");
  });

  it("REFUSES an unsupported host unless it was declared", () => {
    expect(egressLaunchDecision("UNAVAILABLE", false).proceed).toBe(false);
    expect(egressLaunchDecision("UNAVAILABLE", false).reason).toContain("--allow-unconstrained-egress");
    expect(egressLaunchDecision("UNAVAILABLE", true).proceed).toBe(true);
  });

  it("treats anything unrecognised as a failure, never as permission", () => {
    for (const v of ["", "ok", "READY", "yes", "true", "0", "ARMED", "sys/fs/cgroup/x"]) {
      expect(egressLaunchDecision(v, false).proceed).toBe(false);
      expect(egressLaunchDecision(v, true).proceed).toBe(false);
    }
  });

  it("only an absolute path counts as armed — a relative one does not", () => {
    expect(egressLaunchDecision("sys/fs/cgroup/kavachos/s1", true).proceed).toBe(false);
  });
});
