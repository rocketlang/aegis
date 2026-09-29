// SPDX-License-Identifier: AGPL-3.0-only
// @rule:XRA-R-008 — duplication is made VISIBLE, never adjudicated automatically.
//
// Both directions forced throughout. The tests that matter most are the ones asserting
// what the register REFUSES to do: it must not pick a winner, and it must not stop a
// running device on a guess.
import { describe, it, expect } from "bun:test";
import { IdentityRegister } from "../src/kernel/identity-register";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

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

describe("merkle wiring — a published root anyone can check against", () => {
  const build = () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "usb-piv-token" });
    [1, 2, 3, 4, 5].forEach(c => r.record(S("dev-1", "boot-a", c)));
    return r;
  };

  it("every sighting proves against the published root", () => {
    const r = build();
    const root = r.merkleRoot();
    for (let i = 0; i < r.entries().length; i++) {
      const p = r.proofFor(i);
      expect(p.root_hash).toBe(root);
      expect(IdentityRegister.verifyProof(p)).toBe(true);
    }
  });

  it("a proof from one log does NOT verify against another root", () => {
    const a = build();
    const b = build(); b.record(S("dev-1", "boot-a", 6));
    const p = a.proofFor(0);
    expect(a.merkleRoot()).not.toBe(b.merkleRoot());
    expect(IdentityRegister.verifyProof({ ...p, root_hash: b.merkleRoot() })).toBe(false);
  });

  it("a tampered leaf breaks its own proof", () => {
    const r = build();
    const p = r.proofFor(2);
    expect(IdentityRegister.verifyProof({ ...p, leaf_hash: "0".repeat(64) })).toBe(false);
  });

  it("the leaf commits to the fields a verdict depends on", () => {
    const base = { identity: "d", instance: "i", counter: 1 };
    const leaves = [
      IdentityRegister.leafOf(base),
      IdentityRegister.leafOf({ ...base, counter: 2 }),
      IdentityRegister.leafOf({ ...base, instance: "j" }),
      IdentityRegister.leafOf({ ...base, progTag: "t" }),
      IdentityRegister.leafOf({ ...base, mapDigest: "m" }),
      IdentityRegister.leafOf({ ...base, tokenId: "k" }),
      IdentityRegister.leafOf({ ...base, hostId: "h" }),
    ];
    expect(new Set(leaves).size).toBe(leaves.length); // no two collide
  });

  it("refuses a proof for an index that is not there", () => {
    const r = build();
    expect(() => r.proofFor(99)).toThrow(/no sighting at index/);
    expect(() => r.proofFor(-1)).toThrow(/no sighting at index/);
  });
});

describe("removable credentials — the SIM/IMEI shape", () => {
  const P = (identity: string, instance: string, counter: number, tokenId: string, hostId: string) =>
    ({ identity, instance, counter, tokenId, hostId });

  it("a token staying on one host reports no pairing change", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "usb-piv-token" });
    r.record(P("dev-1", "b1", 1, "tok-A", "host-1"));
    r.record(P("dev-1", "b2", 2, "tok-A", "host-1"));
    expect(r.pairings("dev-1")).toHaveLength(0);
    expect(r.verdict("dev-1").verdict).toBe("CONTESTED"); // two boots = two instances
  });

  it("a token moved to another host is REPORTED", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "usb-piv-token" });
    r.record(P("dev-1", "b1", 1, "tok-A", "host-1"));
    r.record(P("dev-1", "b1", 2, "tok-A", "host-2"));
    const p = r.pairings("dev-1");
    expect(p).toHaveLength(1);
    expect(p[0].kind).toBe("token-moved-host");
    expect([p[0].from, p[0].to]).toEqual(["host-1", "host-2"]);
  });

  it("a host given a different token is REPORTED", () => {
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "usb-piv-token" });
    r.record(P("dev-1", "b1", 1, "tok-A", "host-1"));
    r.record(P("dev-1", "b1", 2, "tok-B", "host-1"));
    expect(r.pairings("dev-1").some(c => c.kind === "host-changed-token")).toBe(true);
  });

  it("a moved token does NOT by itself make the identity CONTESTED", () => {
    // The whole point of a removable credential is that it moves. Calling that a clone
    // would punish the engineer who swapped a failed board and kept the key.
    const r = new IdentityRegister();
    r.enrol({ identity: "dev-1", voucher: "usb-piv-token" });
    r.record(P("dev-1", "b1", 1, "tok-A", "host-1"));
    r.record(P("dev-1", "b1", 2, "tok-A", "host-2"));
    expect(r.verdict("dev-1").verdict).toBe("OK");
    expect(r.pairings("dev-1")).toHaveLength(1);   // seen, and kept separate
  });
});

describe("persistence — a register that dies on restart detects nothing", () => {
  const tmp = () => join(mkdtempSync(join(tmpdir(), "reg-")), "register.jsonl");

  it("a clone that appears AFTER a restart is still caught", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "pump-7", voucher: "usb-piv-token" });
    a.record(S("pump-7", "boot-a", 1));
    a.checkpoint();
    expect(a.verdict("pump-7").verdict).toBe("OK");

    // process restarts; the clone turns up while the first instance is forgotten
    const b = IdentityRegister.loadFrom(path);
    b.record(S("pump-7", "boot-b", 1));
    expect(b.verdict("pump-7").verdict).toBe("CONTESTED");   // the whole point
  });

  it("round-trips enrolments, decoys and sightings", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "dev-1", voucher: "silicon" });
    a.enrol({ identity: "decoy-1", voucher: "registrar-statement", decoy: true });
    a.record(S("dev-1", "boot-a", 1));
    a.record(S("dev-1", "boot-a", 2));
    const root = a.merkleRoot();

    const b = IdentityRegister.loadFrom(path);
    expect(b.merkleRoot()).toBe(root);
    expect(b.verdict("dev-1").verdict).toBe("OK");
    b.record(S("decoy-1", "boot-z", 1));
    expect(b.verdict("decoy-1").verdict).toBe("ALARM");      // decoy survived the restart
  });

  it("REFUSES to load a journal with a removed sighting", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "dev-1", voucher: "silicon" });
    [1, 2, 3].forEach(c => a.record(S("dev-1", "boot-a", c)));
    a.checkpoint();

    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    writeFileSync(path, [lines[0], lines[1], lines[3], lines[4]].join("\n") + "\n"); // drop one
    expect(() => IdentityRegister.loadFrom(path)).toThrow(/expected 3 sightings, replay has 2/);
  });

  it("REFUSES to load a journal with an ALTERED sighting", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "dev-1", voucher: "silicon" });
    [1, 2].forEach(c => a.record(S("dev-1", "boot-a", c)));
    a.checkpoint();

    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    const tampered = lines.map(l => l.includes('"counter":2') ? l.replace('"counter":2', '"counter":7') : l);
    writeFileSync(path, tampered.join("\n") + "\n");
    expect(() => IdentityRegister.loadFrom(path)).toThrow(/root MISMATCH/);
  });

  it("REFUSES an unreadable line rather than skipping it", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "dev-1", voucher: "silicon" });
    writeFileSync(path, readFileSync(path, "utf8") + "{not json\n");
    expect(() => IdentityRegister.loadFrom(path)).toThrow(/not JSON/);
  });

  it("REFUSES an unknown record type rather than ignoring it", () => {
    const path = tmp();
    const a = IdentityRegister.loadFrom(path);
    a.enrol({ identity: "dev-1", voucher: "silicon" });
    writeFileSync(path, readFileSync(path, "utf8") + JSON.stringify({ t: "revoke", identity: "dev-1" }) + "\n");
    expect(() => IdentityRegister.loadFrom(path)).toThrow(/unknown type/);
  });
});
