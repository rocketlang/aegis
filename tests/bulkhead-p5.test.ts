// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead Phase 5 — between hosts, store and forward (BLK-T5.1..T5.3), every rule both ways.
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md (BLK-021..023, BLK-YK-007, INF-BLK-007)
//
// Two bulkheads, ship (party "owner") and shore (party "manager"), each with its own home key. The link
// between them is a file. Runs under a throwaway HOME and AEGIS_DIR, put back in afterAll.

import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-p5-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { keygen, signTerms, termsOf, signParcel } = await import("../src/bulkhead/parties");
const { PERM, PERM_STANDARD } = await import("../src/kavach/perm-mask");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

const DOOR = { id: "engine-to-fleet", from: "engine", to: "fleet", kinds: ["FINDING", "ACK"], fields: ["metric", "value"], valid_until: "2026-12-31T00:00:00Z" };
const BACK = { id: "fleet-to-engine", from: "fleet", to: "engine", kinds: ["REQUEST"], fields: ["question"], valid_until: "2026-12-31T00:00:00Z" };
const NOW = Date.parse("2026-10-21T12:00:00Z");
const shipKey = keygen(), shoreKey = keygen();

const local = (agents: Record<string, { mask: number; compartment: string }>) => ({
  resolve: (t: any) => (t && agents[t.proof] ? { agent_id: t.proof, mask: agents[t.proof].mask, compartment: agents[t.proof].compartment, ceiling: PERM_STANDARD } : { error: "unknown" }),
  compartmentOf: (id: string) => (agents[id] ? { compartment: agents[id].compartment, ceiling: PERM_STANDARD } : null),
});
const tok = (a: string) => ({ proof: a });

// One host: its doors file, the other party's key and its signatures on both doors, and its own home key.
function host(opts: { home: string; other: string; otherCompartment: string; otherAgent: string; ourKey: { privateKey: string }; theirKey: { publicKey: string; privateKey: string }; agents: Record<string, { mask: number; compartment: string }>; ceiling?: number; unsigned?: boolean }) {
  const dir = mkdtempSync(join(scratchHome, `${opts.home}-`));
  writeFileSync(join(dir, "doors.json"), JSON.stringify({
    home: opts.home,
    parties: { [opts.other]: { compartments: [opts.otherCompartment], agents: { [opts.otherAgent]: opts.otherCompartment }, ...(opts.ceiling !== undefined ? { ceiling: opts.ceiling } : {}) } },
    doors: [DOOR, BACK],
  }));
  const pd = join(dir, "parties", opts.other);
  mkdirSync(join(pd, "declarations"), { recursive: true });
  writeFileSync(join(pd, "party.pub"), opts.theirKey.publicKey);
  if (!opts.unsigned) for (const d of [DOOR, BACK]) writeFileSync(join(pd, "declarations", `${d.id}.json`), JSON.stringify(signTerms(termsOf(d as any), opts.theirKey.privateKey)));
  writeFileSync(join(dir, "home.key"), opts.ourKey.privateKey);
  return { dir, bh: new Bulkhead({ dir, identity: local(opts.agents), now: () => NOW }) };
}
const ship = (o: Partial<Parameters<typeof host>[0]> = {}) => host({ home: "owner", other: "manager", otherCompartment: "fleet", otherAgent: "fleet-agent", ourKey: shipKey, theirKey: shoreKey, agents: { "engine-agent": { mask: PERM.READ | PERM.DB_READ, compartment: "engine" } }, ...o });
const shore = (o: Partial<Parameters<typeof host>[0]> = {}) => host({ home: "manager", other: "owner", otherCompartment: "engine", otherAgent: "engine-agent", ourKey: shoreKey, theirKey: shipKey, agents: { "fleet-agent": { mask: PERM_STANDARD, compartment: "fleet" } }, ...o });
const finding = (subject = "exh temp") => ({ to: "fleet-agent", kind: "FINDING", subject, body: { metric: "exh_t_cyl3", value: 412 } });
const parcelFrom = (h: { bh: InstanceType<typeof Bulkhead> }, party: string) => { const r = h.bh.exportParcel(party) as any; expect(r.ok).toBe(true); return r.parcel; };

describe("BLK-021 — a round trip by parcel, ship to shore and the ACK back", () => {
  test("the finding crosses in a signed parcel, is read ashore, and the ACK returns with a matching hash", () => {
    const s = ship(), h = shore();
    const sent = s.bh.send(tok("engine-agent"), finding()) as any;
    expect(sent).toMatchObject({ ok: true, door: "engine-to-fleet" });
    const imp = h.bh.importParcel(parcelFrom(s, "manager")) as any;
    expect(imp).toMatchObject({ ok: true, from_party: "owner", seq: 1 });
    expect(imp.results).toEqual([expect.objectContaining({ id: sent.id, ok: true })]);
    const got = h.bh.read(tok("fleet-agent")) as any[];
    expect(got).toHaveLength(1);
    expect(got[0]).toMatchObject({ id: sent.id, from: "engine-agent", hash: sent.hash, untrusted: true });
    expect(h.bh.send(tok("fleet-agent"), { to: "engine-agent", kind: "ACK", subject: "", in_reply_to: sent.id, received_hash: got[0].hash }).ok).toBe(true);
    expect(s.bh.importParcel(parcelFrom(h, "owner"))).toMatchObject({ ok: true, from_party: "manager", seq: 1 });
    expect(existsSync(join(s.dir, "alarms.jsonl"))).toBe(false); // the repeat-back matched across hosts
  });
  test("each parcel is kept in the party's outbox, numbered", () => {
    const s = ship();
    s.bh.send(tok("engine-agent"), finding("1")); parcelFrom(s, "manager");
    s.bh.send(tok("engine-agent"), finding("2")); parcelFrom(s, "manager");
    expect(readdirSync(join(s.dir, "parties", "manager", "outbox")).sort()).toEqual(["owner-to-manager-000001.parcel.json", "owner-to-manager-000002.parcel.json"]);
  });
  test("a repeat, an out-of-order parcel, and the lost one sent again", () => {
    const s = ship(), h = shore();
    s.bh.send(tok("engine-agent"), finding("1")); const p1 = parcelFrom(s, "manager");
    s.bh.send(tok("engine-agent"), finding("2")); const p2 = parcelFrom(s, "manager");
    expect(h.bh.importParcel(p2)).toMatchObject({ ok: false, rule: "BLK-021", reason: expect.stringContaining("out of order") });
    expect(h.bh.importParcel(p1).ok).toBe(true);
    expect(h.bh.importParcel(p1)).toMatchObject({ ok: false, reason: expect.stringContaining("already taken") });
    expect(h.bh.importParcel(p2).ok).toBe(true);
  });
  test("a parcel changed on the way, signed by another key, or for another party is refused whole", () => {
    const s = ship(), h = shore();
    s.bh.send(tok("engine-agent"), finding());
    const p = parcelFrom(s, "manager");
    expect(h.bh.importParcel({ ...p, envelopes: [{ ...p.envelopes[0], body: { metric: "x", value: 1 } }] })).toMatchObject({ ok: false, reason: expect.stringContaining("not signed") });
    const { sig, ...rest } = p;
    expect(h.bh.importParcel(signParcel(rest, keygen().privateKey))).toMatchObject({ ok: false, reason: expect.stringContaining("not signed") });
    expect(h.bh.importParcel(signParcel({ ...rest, to_party: "charterer" }, shipKey.privateKey))).toMatchObject({ ok: false, reason: expect.stringContaining("for party charterer") });
    expect(h.bh.importParcel({ hello: 1 })).toMatchObject({ ok: false, rule: "BLK-021" });
    expect(h.bh.importParcel(p).ok).toBe(true); // the true parcel still goes in after the refusals
  });
  test("nothing queued, or no home key: no parcel", () => {
    const s = ship();
    expect(s.bh.exportParcel("manager")).toMatchObject({ ok: false, error: expect.stringContaining("nothing queued") });
    rmSync(join(s.dir, "home.key"));
    s.bh.send(tok("engine-agent"), finding());
    expect(s.bh.exportParcel("manager")).toMatchObject({ ok: false, error: expect.stringContaining("no home key") });
    expect(s.bh.exportParcel("nobody")).toMatchObject({ ok: false });
  });
});

describe("BLK-022 — an imported message passes every local check", () => {
  // A ship bulkhead that does not keep the rules signs whatever it likes; the shore must still refuse it.
  const forged = (envelope: Record<string, unknown>, seq = 1, prev = "") =>
    signParcel({ v: 1, from_party: "owner", to_party: "manager", seq, prev_hash: prev, created_at: new Date(NOW).toISOString(), envelopes: [envelope] }, shipKey.privateKey);
  const env = (o: Record<string, unknown> = {}) => ({ id: "0123456789abcdef", door: "engine-to-fleet", from: "engine-agent", to: "fleet-agent", kind: "FINDING", subject: "s", body: { metric: "m", value: 1 }, depth: 0, sent_at: new Date(NOW).toISOString(), sender_mask: PERM.READ, sender_ceiling: PERM.READ, ...o });
  test("a field the door does not list is refused ashore (BLK-003), the parcel itself taken", () => {
    const h = shore();
    const r = h.bh.importParcel(forged(env({ body: { metric: "m", crew_list: ["…"] } }))) as any;
    expect(r.ok).toBe(true);
    expect(r.results[0]).toMatchObject({ ok: false, rule: "BLK-003" });
  });
  test("a COMMAND, an agent the doors file does not declare, a receiver not of this host: refused", () => {
    const h = shore();
    const r = h.bh.importParcel(signParcel({ v: 1, from_party: "owner", to_party: "manager", seq: 1, prev_hash: "", created_at: "x", envelopes: [
      env({ kind: "COMMAND" }), env({ id: "1123456789abcdef", from: "stowaway-agent" }), env({ id: "2123456789abcdef", to: "nobody" }),
    ] }, shipKey.privateKey)) as any;
    expect(r.results.map((x: any) => x.rule)).toEqual(["BLK-003", "BLK-022", "BLK-022"]);
  });
  test("the shore's own two keys still hold: without the ship's signature on the door, the message is refused", () => {
    const h = shore({ unsigned: true });
    const r = h.bh.importParcel(forged(env())) as any;
    expect(r.results[0]).toMatchObject({ ok: false, rule: "BLK-014" });
  });
  test("a message id carried before is refused in a later parcel (BLK-021)", () => {
    const h = shore();
    const p1 = forged(env());
    expect((h.bh.importParcel(p1) as any).results[0].ok).toBe(true);
    const { parcelHash } = require("../src/bulkhead/parties");
    const r = h.bh.importParcel(forged(env(), 2, parcelHash(p1))) as any;
    expect(r.results[0]).toMatchObject({ ok: false, rule: "BLK-021" });
  });
  test("damage control counts imported messages like local ones", () => {
    const h = shore();
    writeFileSync(join(h.dir, "doors.json"), readFileSync(join(h.dir, "doors.json"), "utf-8").replace('"fields":["metric","value"]', '"fields":["metric","value"],"rate_per_min":1'));
    // rate_per_min is each side's own and not signed, so the declaration still holds
    const r = h.bh.importParcel(signParcel({ v: 1, from_party: "owner", to_party: "manager", seq: 1, prev_hash: "", created_at: "x", envelopes: [env(), env({ id: "1123456789abcdef", subject: "2" })] }, shipKey.privateKey)) as any;
    expect(r.results.map((x: any) => x.ok)).toEqual([true, false]);
  });
});

describe("BLK-023 — the party's ceiling caps what reading its message allows", () => {
  test("a ship that claims full authority still taints the shore agent down to read only (default)", () => {
    const h = shore();
    const p = signParcel({ v: 1, from_party: "owner", to_party: "manager", seq: 1, prev_hash: "", created_at: "x", envelopes: [
      { id: "0123456789abcdef", from: "engine-agent", to: "fleet-agent", kind: "FINDING", subject: "s", body: { metric: "m", value: 1 }, depth: 0, sent_at: new Date(NOW).toISOString(), sender_mask: 0x7fffffff, sender_ceiling: 0x7fffffff },
    ] }, shipKey.privateKey);
    expect((h.bh.importParcel(p) as any).results[0].ok).toBe(true);
    h.bh.read(tok("fleet-agent"));
    expect(h.bh.authority("fleet-agent", PERM_STANDARD).mask).toBe(PERM.READ);
  });
  test("a declared ceiling is used instead", () => {
    const s = ship(), h = shore({ ceiling: PERM.READ | PERM.DB_READ });
    s.bh.send(tok("engine-agent"), finding());
    h.bh.importParcel(parcelFrom(s, "manager"));
    h.bh.read(tok("fleet-agent"));
    expect(h.bh.authority("fleet-agent", PERM_STANDARD).mask).toBe(PERM.READ | PERM.DB_READ);
  });
});

describe("BLK-016 with parcels — each side's party copy records the parcels", () => {
  test("parcel_out on the ship's copy for the manager, parcel_in on the shore's copy for the owner", () => {
    const s = ship(), h = shore();
    s.bh.send(tok("engine-agent"), finding());
    h.bh.importParcel(parcelFrom(s, "manager"));
    const rows = (f: string) => readFileSync(f, "utf-8").trim().split("\n").map((l) => JSON.parse(l).event);
    expect(rows(join(s.dir, "parties", "manager", "bell-book.jsonl"))).toEqual(["sent", "exported", "parcel_out"]);
    expect(rows(join(h.dir, "parties", "owner", "bell-book.jsonl"))).toEqual(["parcel_in", "sent"]);
  });
});
