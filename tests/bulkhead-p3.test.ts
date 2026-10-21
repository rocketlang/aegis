// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead Phase 3 — doors between parties (BLK-T3.1..T3.4), every rule both ways.
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md (BLK-014..016, BLK-YK-005, INF-BLK-005)
//
// Runs under a throwaway HOME and AEGIS_DIR set before any aegis module loads, put back in afterAll.

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-p3-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { keygen, signTerms, termsOf, checkParties } = await import("../src/bulkhead/parties");
const { loadDoors } = await import("../src/bulkhead/doors");
const { verifyBellBook } = await import("../src/bulkhead/bell-book");
const { PERM, PERM_STANDARD } = await import("../src/kavach/perm-mask");
const { loadShieldRules, detectPersistenceWrite } = await import("../src/shield/injection-detector");
const { getAegisDir } = await import("../src/core/config");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

// Ship and shore: the engine agent on board belongs to the owner; fleet performance ashore is ours (home).
const AGENTS: Record<string, { mask: number; compartment: string }> = {
  "engine-agent": { mask: PERM.READ | PERM.DB_READ, compartment: "engine" },
  "fleet-agent": { mask: PERM_STANDARD, compartment: "fleet" },
  "voyage-agent": { mask: PERM_STANDARD, compartment: "voyage" },
};
const identity = {
  resolve(t: any) {
    const a = t && AGENTS[t.proof];
    return a ? { agent_id: t.proof, mask: a.mask, compartment: a.compartment, ceiling: PERM_STANDARD } : { error: "unknown" };
  },
  compartmentOf: (id: string) => (AGENTS[id] ? { compartment: AGENTS[id].compartment, ceiling: PERM_STANDARD } : null),
};
const tok = (a: string) => ({ proof: a });
const NOW = Date.parse("2026-10-21T12:00:00Z");
const UNTIL = "2026-12-31T00:00:00Z";
const DOOR = { id: "engine-to-fleet", from: "engine", to: "fleet", kinds: ["FINDING", "ACK"], fields: ["metric", "value"], valid_until: UNTIL };
const finding = { to: "fleet-agent", kind: "FINDING", subject: "ME exhaust temp", body: { metric: "exh_t_cyl3", value: 412 } };
const owner = keygen();

function setup(opts: { door?: object; doors?: object[]; parties?: object; sign?: false | object; key?: string | false; now?: number } = {}) {
  const dir = mkdtempSync(join(scratchHome, "bh-"));
  const door = opts.door ?? DOOR;
  writeFileSync(join(dir, "doors.json"), JSON.stringify({
    home: "manager",
    parties: opts.parties ?? { owner: { compartments: ["engine"] } },
    doors: opts.doors ?? [door, { id: "fleet-to-voyage", from: "fleet", to: "voyage", kinds: ["FINDING"] }],
  }));
  const pd = join(dir, "parties", "owner");
  mkdirSync(join(pd, "declarations"), { recursive: true });
  if (opts.key !== false) writeFileSync(join(pd, "party.pub"), opts.key ?? owner.publicKey);
  if (opts.sign !== false) {
    const dec = signTerms(termsOf((opts.sign ?? door) as any), owner.privateKey);
    writeFileSync(join(pd, "declarations", `${(door as any).id}.json`), JSON.stringify(dec));
  }
  const bh = new Bulkhead({ dir, identity, now: () => opts.now ?? NOW });
  return { dir, bh, copy: join(pd, "bell-book.jsonl") };
}
const rows = (f: string) => (existsSync(f) ? readFileSync(f, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

describe("BLK-014 — a door between parties needs the other party's signature on the same terms", () => {
  test("both keys present and the same terms: the finding crosses", () => {
    const { bh } = setup();
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: true, door: "engine-to-fleet" });
  });
  test("no public key placed for the party: shut", () => {
    const { bh } = setup({ key: false });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("no public key") });
  });
  test("the party has not signed: shut (our file alone does not open it)", () => {
    const { bh } = setup({ sign: false });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("has not signed") });
  });
  test("signed with a key other than the placed one: shut", () => {
    const { bh } = setup({ key: keygen().publicKey });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("does not verify") });
  });
  test("they signed fewer fields than we declare: shut", () => {
    const { bh } = setup({ sign: { ...DOOR, fields: ["metric"] } });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("different terms") });
  });
  test("they signed a later end date than we declare: shut", () => {
    const { bh } = setup({ sign: { ...DOOR, valid_until: "2027-12-31T00:00:00Z" } });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014" });
  });
  test("the declaration's terms changed after signing: shut", () => {
    const { dir, bh } = setup();
    const f = join(dir, "parties", "owner", "declarations", "engine-to-fleet.json");
    const dec = JSON.parse(readFileSync(f, "utf-8"));
    dec.terms.fields.push("crew_list");
    writeFileSync(f, JSON.stringify(dec));
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("does not verify") });
  });
  test("past valid_until: shut, even with a good signature", () => {
    const { bh } = setup({ now: Date.parse("2027-01-01T00:00:00Z") });
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-014", reason: expect.stringContaining("expired") });
  });
  test("order of kinds and fields does not matter", () => {
    const { bh } = setup({ sign: { ...DOOR, kinds: ["ACK", "FINDING"], fields: ["value", "metric"] } });
    expect(bh.send(tok("engine-agent"), finding).ok).toBe(true);
  });
  test("a door inside one party needs no signature and no field list", () => {
    const { bh } = setup({ sign: false, key: false });
    expect(bh.send(tok("fleet-agent"), { to: "voyage-agent", kind: "FINDING", subject: "eta", body: { anything: 1 } }).ok).toBe(true);
  });
  test("checkParties is checked at every decision: removing the declaration shuts the door at once", () => {
    const { dir, bh } = setup();
    expect(bh.send(tok("engine-agent"), finding).ok).toBe(true);
    rmSync(join(dir, "parties", "owner", "declarations", "engine-to-fleet.json"));
    expect(bh.send(tok("engine-agent"), { ...finding, subject: "2" })).toMatchObject({ ok: false, rule: "BLK-014" });
  });
});

describe("BLK-015 — a door between parties carries only the fields it lists", () => {
  test("a door between parties with no field list is dropped and reported", () => {
    const { dir, bh } = setup({ door: { ...DOOR, fields: undefined } });
    const t = loadDoors(join(dir, "doors.json"));
    expect(t.doors.find((d) => d.id === "engine-to-fleet")).toBeUndefined();
    expect(t.errors.join(" ")).toContain("BLK-015");
    expect(bh.send(tok("engine-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-002" });
  });
  test("a door between parties with no valid_until is dropped and reported", () => {
    const { dir } = setup({ door: { ...DOOR, valid_until: undefined } });
    expect(loadDoors(join(dir, "doors.json")).errors.join(" ")).toContain("valid_until");
  });
  test("a field outside the list is refused, and the refusal is in the party's copy too", () => {
    const { bh, copy } = setup();
    expect(bh.send(tok("engine-agent"), { ...finding, body: { metric: "x", value: 1, crew_list: ["..."] } })).toMatchObject({ ok: false, rule: "BLK-003" });
    expect(rows(copy).some((r) => r.event === "refused" && r.rule === "BLK-003")).toBe(true);
  });
  test("a compartment two parties claim: its doors are shut and the clash is reported", () => {
    const { dir, bh } = setup({ parties: { owner: { compartments: ["engine"] }, charterer: { compartments: ["engine"] } } });
    expect(loadDoors(join(dir, "doors.json")).errors.join(" ")).toContain("listed by parties");
    expect(bh.send(tok("engine-agent"), finding).ok).toBe(false);
  });
});

describe("BLK-016 — each party keeps its own hash-chained copy of the rows about its doors", () => {
  test("send, delivery, taint and the ACK back are in the owner's copy, which verifies on its own", () => {
    const { bh, copy } = setup();
    const s = bh.send(tok("engine-agent"), finding) as any;
    const got = bh.read(tok("fleet-agent")) as any[];
    expect(bh.send(tok("fleet-agent"), { to: "engine-agent", kind: "ACK", subject: "", in_reply_to: s.id, received_hash: got[0].hash }).ok).toBe(true);
    const events = rows(copy).map((r) => r.event);
    expect(events).toEqual(["sent", "delivered", "taint", "sent"]);
    expect(verifyBellBook(copy)).toMatchObject({ holds: true, rows: 4 });
  });
  test("rows about a door inside one party never reach the party's copy", () => {
    const { bh, copy } = setup();
    bh.send(tok("fleet-agent"), { to: "voyage-agent", kind: "FINDING", subject: "eta", body: {} });
    expect(rows(copy)).toEqual([]);
  });
  test("a broken copy shuts the door instead of being written past (BLK-006)", () => {
    const { bh, copy } = setup();
    expect(bh.send(tok("engine-agent"), finding).ok).toBe(true);
    const fresh = new Bulkhead({ dir: join(copy, "..", "..", ".."), identity, now: () => NOW });
    appendFileSync(copy, JSON.stringify({ seq: 99, event: "forged" }) + "\n");
    expect(fresh.send(tok("engine-agent"), { ...finding, subject: "2" })).toMatchObject({ ok: false, rule: "BLK-016" });
  });
  test("status shows the party's key fingerprint and whether each of its doors holds", () => {
    const { bh } = setup();
    const st = bh.status().parties.owner;
    expect(st.key).toMatch(/^[0-9a-f]{16}$/);
    expect(st.doors).toEqual([{ id: "engine-to-fleet", holds: true, valid_until: UNTIL }]);
    expect(setup({ sign: false }).bh.status().parties.owner.doors[0]).toMatchObject({ holds: false });
  });
});

describe("BLK-T3.2 — the commands, as each side runs them", () => {
  const cli = (args: string[], dir: string, cwd = join(import.meta.dir, "..")) => {
    const p = Bun.spawnSync(["bun", join(import.meta.dir, "..", "src/cli/index.ts"), "bulkhead", ...args], {
      cwd,
      env: { ...process.env, HOME: scratchHome, AEGIS_DIR: join(scratchHome, ".aegis"), AEGIS_BULKHEAD_DIR: dir },
    });
    return { code: p.exitCode, out: p.stdout.toString(), err: p.stderr.toString() };
  };
  test("party-terms → party-keygen → party-sign, placed by a person: the door holds", () => {
    const { dir, bh } = setup({ sign: false, key: false });
    const terms = cli(["party-terms", "engine-to-fleet"], dir);
    expect(terms.code).toBe(0);
    const theirs = mkdtempSync(join(scratchHome, "owner-box-"));
    writeFileSync(join(theirs, "terms.json"), terms.out);
    expect(cli(["party-keygen", join(theirs, "owner")], dir).code).toBe(0);
    expect(cli(["party-keygen", join(theirs, "owner")], dir).code).toBe(2); // never overwrites a key
    const signed = cli(["party-sign", join(theirs, "terms.json"), join(theirs, "owner.key")], dir);
    expect(signed.code).toBe(0);
    writeFileSync(join(dir, "parties", "owner", "party.pub"), readFileSync(join(theirs, "owner.pub")));
    writeFileSync(join(dir, "parties", "owner", "declarations", "engine-to-fleet.json"), signed.out);
    expect(bh.send(tok("engine-agent"), finding).ok).toBe(true);
  });
  test("verify walks each party's copy; a changed copy is exit 1", () => {
    const { dir, bh, copy } = setup();
    bh.send(tok("engine-agent"), finding);
    const ok = cli(["verify"], dir);
    expect(ok.code).toBe(0);
    expect(JSON.parse(ok.out).copies.owner).toMatchObject({ holds: true, rows: 1 });
    writeFileSync(copy, readFileSync(copy, "utf-8").replace("exh_t_cyl3", "x").replace("ME exhaust", "XX exhaust"));
    expect(cli(["verify"], dir).code).toBe(1);
  });
});

describe("the shield — party keys and declarations are a person's to place (KAV-096)", () => {
  const rules = loadShieldRules();
  const ctx = { cwd: join(scratchHome, "project"), home: scratchHome };
  const pd = join(getAegisDir(), "bulkhead", "parties", "owner");
  test("Write of a party key or declaration is refused", () => {
    for (const f of [join(pd, "party.pub"), join(pd, "declarations", "engine-to-fleet.json")]) {
      expect(detectPersistenceWrite(f, rules, ctx)).toMatchObject({ verdict: "QUARANTINE", rule_id: "KAV-096" });
    }
  });
});

describe("INF-BLK-005 — what the signature does not give", () => {
  test("checkParties on a door inside one party asks for no signature", () => {
    const { dir } = setup({ sign: false, key: false });
    const t = loadDoors(join(dir, "doors.json"));
    expect(checkParties(dir, t, t.doors.find((d) => d.id === "fleet-to-voyage")!, NOW)).toEqual({ ok: true, parties: [] });
  });
});
