// SPDX-License-Identifier: AGPL-3.0-only
// @rule:XRA-R-008 — duplication is made VISIBLE, never adjudicated automatically.
//
// Both directions forced throughout. The tests that matter most are the ones asserting
// what the register REFUSES to do: it must not pick a winner, and it must not stop a
// running device on a guess.
import { describe, it, expect } from "bun:test";
import { IdentityRegister } from "../src/kernel/identity-register";

const S = (identity: string, instance: string, counter: number) =>
  ({ identity, instance, counter, progTag: "927b5c5e18d0c7ee", mapDigest: "deadbeef" });

describe("enrolment", () => {
  it("refuses an identity with no named voucher (XRA-R-007)", () => {
    const r = new IdentityRegister();
    expect(() => r.enrol({ identity: "dev-1", voucher: "" })).toThrow(/no voucher/);
    expect(() => r.enrol({ identity: "dev-1", voucher: "  " })).toThrow(/no voucher/);
  });

  it("accepts a named voucher, and records WHICH one", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "registrar-statement" });
    r.record(S("dev-1", "boot-a", 1));
    expect(r.verdict("dev-1").verdict).toBe("OK");
  });

  it("refuses re-enrolment — append-only means history cannot be erased", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "silicon" });
    expect(() => r.enrol({ identity: "dev-1", voucher: "silicon" })).toThrow(/already enrolled/);
  });
});

describe("the clone becomes visible", () => {
  it("one instance with advancing counters is OK", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "pump-7", voucher: "cloud-iid" });
    [1, 2, 3, 9].forEach(c => r.record(S("pump-7", "boot-a", c)));
    expect(r.verdict("pump-7").verdict).toBe("OK");
  });

  it("TWO instances of one identity is CONTESTED", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "pump-7", voucher: "cloud-iid" });
    r.record(S("pump-7", "boot-a", 1));
    r.record(S("pump-7", "boot-b", 1));          // the clone
    const f = r.verdict("pump-7");
    expect(f.verdict).toBe("CONTESTED");
    expect(f.reason).toMatch(/2 instances/);
    expect(f.evidence).toHaveLength(2);          // a human gets BOTH, not a summary
  });

  it("a replayed receipt under one instance is also CONTESTED", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "pump-7", voucher: "cloud-iid" });
    r.record(S("pump-7", "boot-a", 5));
    r.record(S("pump-7", "boot-a", 5));          // repeat
    expect(r.verdict("pump-7").verdict).toBe("CONTESTED");
  });

  it("a counter going BACKWARDS is CONTESTED", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "pump-7", voucher: "cloud-iid" });
    r.record(S("pump-7", "boot-a", 9));
    r.record(S("pump-7", "boot-a", 4));
    expect(r.verdict("pump-7").verdict).toBe("CONTESTED");
  });

  it("an identity nobody enrolled raises ALARM the first time it is seen", () => {
    const r = new IdentityRegister();
    r.record(S("ghost-1", "boot-x", 1));
    const f = r.verdict("ghost-1");
    expect(f.verdict).toBe("ALARM");
    expect(f.reason).toMatch(/never enrolled/);
  });
});

describe("the decoy — the honeypot in the only safe form", () => {
  it("a decoy never sighted is quiet", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "decoy-1", voucher: "registrar-statement", decoy: true });
    expect(r.verdict("decoy-1").verdict).toBe("OK");
  });

  it("ANY sighting of a decoy is ALARM — no genuine device can be misjudged", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "decoy-1", voucher: "registrar-statement", decoy: true });
    r.record(S("decoy-1", "boot-z", 1));
    const f = r.verdict("decoy-1");
    expect(f.verdict).toBe("ALARM");
    expect(f.reason).toMatch(/issued to no device/);
  });
});

describe("what the register REFUSES to do — the safety properties", () => {
  it("does NOT name a winner between two claimants", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "valve-2", voucher: "cluster" });
    r.record(S("valve-2", "boot-a", 1));
    r.record(S("valve-2", "boot-b", 1));
    const f = r.verdict("valve-2");
    // both instances appear; neither is labelled genuine or rogue anywhere
    expect(f.evidence.map(e => e.instance).sort()).toEqual(["boot-a", "boot-b"]);
    expect(f.reason).toMatch(/NOT decided here/);
    expect(f.reason).not.toMatch(/genuine device is|rogue is/);
  });

  it("withholds ESCALATION but never claims to stop a running device", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "valve-2", voucher: "cluster" });
    r.record(S("valve-2", "boot-a", 1));
    expect(r.mayGrantNewAuthority("valve-2").allow).toBe(true);

    r.record(S("valve-2", "boot-b", 1));                       // clone appears
    const g = r.mayGrantNewAuthority("valve-2");
    expect(g.allow).toBe(false);                               // no NEW authority
    expect(g.reason).toMatch(/Existing operation is untouched/); // and nothing is cut off
  });

  it("an ALARMED identity is also refused new authority", () => {
    const r = new IdentityRegister();
    r.record(S("ghost-1", "boot-x", 1));
    expect(r.mayGrantNewAuthority("ghost-1").allow).toBe(false);
  });
});

describe("the log is a register, not a report", () => {
  it("entries are never mutated by reading a verdict", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "silicon" });
    r.record(S("dev-1", "boot-a", 1));
    const before = r.digest();
    r.verdict("dev-1"); r.sweep(); r.mayGrantNewAuthority("dev-1");
    expect(r.digest()).toBe(before);
  });

  it("the digest changes when a sighting is appended, so removal is detectable", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "silicon" });
    r.record(S("dev-1", "boot-a", 1));
    const d1 = r.digest();
    r.record(S("dev-1", "boot-a", 2));
    expect(r.digest()).not.toBe(d1);
  });

  it("a sighting without an instance value is refused, never assumed unique", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "silicon" });
    expect(() => r.record({ identity: "dev-1", instance: "", counter: 1 })).toThrow(/no instance/);
  });

  it("sweep puts the things a human must act on first", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "ok-1", voucher: "silicon" });      r.record(S("ok-1", "b", 1));
    r.enrol({ identity: "quiet-1", voucher: "silicon" });
    r.enrol({ identity: "dup-1", voucher: "cluster" });
    r.record(S("dup-1", "b1", 1)); r.record(S("dup-1", "b2", 1));
    r.enrol({ identity: "decoy-1", voucher: "registrar-statement", decoy: true });
    r.record(S("decoy-1", "bz", 1));
    expect(r.sweep().map(f => f.verdict)).toEqual(["ALARM", "CONTESTED", "UNKNOWN", "OK"]);
  });
});
