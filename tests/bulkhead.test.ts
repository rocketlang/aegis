// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead — every rule both ways (BLK-T1.10).
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md
//
// Runs under a throwaway HOME and AEGIS_DIR (the SDT store lives in $AEGIS_DIR/aegis.db), set before
// any aegis module loads, and put back in afterAll so the next test file is not sent here.

import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { BellBook, verifyBellBook } = await import("../src/bulkhead/bell-book");
const { loadDoors, raiseOpenEpoch } = await import("../src/bulkhead/doors");
const { serve, call } = await import("../src/bulkhead/server");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

// Three compartments. db is read-ish (ceiling 0b0111), app can deploy and restart (0b1111).
const AGENTS: Record<string, { mask: number; compartment: string }> = {
  "db-agent": { mask: 0b0011, compartment: "db" },
  "app-agent": { mask: 0b1111, compartment: "app" },
  "app-helper": { mask: 0b1111, compartment: "app" },
  "ops-agent": { mask: 0b1111, compartment: "ops" },
};
const CEIL: Record<string, number> = { db: 0b0111, app: 0b1111, ops: 0b1111 };
const fakeIdentity = {
  resolve(token: unknown) {
    const id = typeof token === "object" && token ? (token as any).proof : null;
    const a = id && AGENTS[id];
    if (!a) return { error: "unknown token" };
    return { agent_id: id, mask: a.mask, compartment: a.compartment, ceiling: CEIL[a.compartment] };
  },
  compartmentOf(agentId: string) {
    const a = AGENTS[agentId];
    return a ? { compartment: a.compartment, ceiling: CEIL[a.compartment] } : null;
  },
};
const tok = (agent: string) => ({ proof: agent });

const DOORS = [
  { id: "db-to-app", from: "db", to: "app", kinds: ["FINDING", "ACK"], fields: ["metric", "value", "query"], rate_per_min: 5, max_depth: 2, pingpong_max: 4 },
  { id: "app-to-ops", from: "app", to: "ops", kinds: ["FINDING", "REQUEST", "ACK"] },
];

let dir: string;
let clock: number;
let alarms: { text: string; rule?: string }[];
let bh: InstanceType<typeof Bulkhead>;

function fresh(doors: unknown = DOORS) {
  dir = mkdtempSync(join(scratchHome, "bh-"));
  writeFileSync(join(dir, "doors.json"), JSON.stringify(doors));
  clock = Date.parse("2026-10-21T10:00:00Z");
  alarms = [];
  bh = new Bulkhead({ dir, identity: fakeIdentity, onAlarm: (a) => alarms.push(a), now: () => clock });
}
beforeEach(() => fresh());

const finding = (to: string, extra: Record<string, unknown> = {}) =>
  ({ to, kind: "FINDING", subject: "slow query", body: { metric: "p99_ms", value: 900 }, ...extra });

describe("BLK-001 / BLK-002 — doors, one-way, shut unless declared", () => {
  test("through a declared door: carried", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent"));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.door).toBe("db-to-app");
  });
  test("no door: refused", () => {
    const r = bh.send(tok("db-agent"), finding("ops-agent"));
    expect(r).toMatchObject({ ok: false, rule: "BLK-002" });
  });
  test("one-way: the door db→app does not let app speak to db", () => {
    const r = bh.send(tok("app-agent"), { to: "db-agent", kind: "FINDING", subject: "x", body: {} });
    expect(r).toMatchObject({ ok: false, rule: "BLK-002" });
  });
  test("inside one compartment: carried without a door", () => {
    const r = bh.send(tok("app-agent"), { to: "app-helper", kind: "REQUEST", subject: "look", body: { note: "x" } });
    expect(r).toMatchObject({ ok: true, door: null });
  });
  test("a receiver in no compartment: refused", () => {
    expect(bh.send(tok("db-agent"), finding("stranger"))).toMatchObject({ ok: false, rule: "BLK-001" });
  });
  test("doors file: an unknown kind or a door to itself is dropped, with the error reported", () => {
    const p = join(dir, "doors2.json");
    writeFileSync(p, JSON.stringify([{ id: "x", from: "a", to: "b", kinds: ["COMMAND"] }, { id: "y", from: "a", to: "a", kinds: ["FINDING"] }, { id: "z", from: "a", to: "b", kinds: ["FINDING"] }]));
    const t = loadDoors(p);
    expect(t.doors.map((d) => d.id)).toEqual(["z"]);
    expect(t.errors.length).toBe(2);
  });
  test("a person's edit to the doors file takes effect at once; the bulkhead never writes it", () => {
    const before = readFileSync(join(dir, "doors.json"), "utf-8");
    bh.send(tok("db-agent"), finding("app-agent"));
    expect(readFileSync(join(dir, "doors.json"), "utf-8")).toBe(before);
    writeFileSync(join(dir, "doors.json"), "[]");
    expect(bh.send(tok("db-agent"), finding("app-agent"))).toMatchObject({ ok: false, rule: "BLK-002" });
  });
});

describe("BLK-003 — kinds and content", () => {
  test("COMMAND does not exist", () => {
    expect(bh.send(tok("db-agent"), { to: "app-agent", kind: "COMMAND", subject: "restart", body: {} })).toMatchObject({ ok: false, rule: "BLK-003" });
  });
  test("a door that does not carry REQUEST refuses one", () => {
    expect(bh.send(tok("db-agent"), { to: "app-agent", kind: "REQUEST", subject: "restart", body: {} })).toMatchObject({ ok: false, rule: "BLK-003" });
  });
  test("a field the door does not list is refused; listed fields pass", () => {
    expect(bh.send(tok("db-agent"), finding("app-agent", { body: { metric: "m", instruction: "restart the cluster" } }))).toMatchObject({ ok: false, rule: "BLK-003" });
    expect(bh.send(tok("db-agent"), finding("app-agent")).ok).toBe(true);
  });
  test("a body over 2 KB is refused", () => {
    expect(bh.send(tok("app-agent"), { to: "ops-agent", kind: "FINDING", subject: "big", body: { note: "x".repeat(3000) } })).toMatchObject({ ok: false, rule: "BLK-003" });
  });
  test("delivered messages are marked untrusted (INF-BLK-001)", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    const got = bh.read(tok("app-agent")) as any[];
    expect(got[0].untrusted).toBe(true);
  });
});

describe("BLK-YK-002 — a peer is proven by its token, never by its name", () => {
  test("no token, or a name in place of a token: refused and written", () => {
    expect(bh.send("db-agent", finding("app-agent"))).toMatchObject({ ok: false, rule: "BLK-YK-002" });
    expect(bh.send({ agent_id: "db-agent" }, finding("app-agent"))).toMatchObject({ ok: false, rule: "BLK-YK-002" });
    expect(readFileSync(join(dir, "bell-book.jsonl"), "utf-8")).toContain('"event":"refused"');
  });
  test("reading another agent's messages needs that agent's token", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    expect(bh.read({ agent_id: "app-agent" })).toHaveProperty("error");
  });
});

describe("BLK-004 — acting on a message runs under receiver & sender & ceilings", () => {
  test("after reading a db finding, app's authority falls to what db could do", () => {
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b1111);
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    const a = bh.authority("app-agent", 0b1111);
    expect(a.mask).toBe(0b0011);           // db 0b0011 & db ceiling 0b0111 & app ceiling 0b1111
    expect(a.tainted_by.length).toBe(1);
  });
  test("a message not yet read taints nobody", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b1111);
  });
  test("dropping the taint gives the authority back, and the drop is written (BLK-YK-003)", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    expect(bh.dropTaint(tok("app-agent"), (r as any).id).ok).toBe(true);
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b1111);
    expect(readFileSync(join(dir, "bell-book.jsonl"), "utf-8")).toContain('"event":"taint_dropped"');
  });
  test("one agent cannot drop another's taint", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    expect(bh.dropTaint(tok("app-helper"), (r as any).id).ok).toBe(false);
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b0011);
  });
  test("a taint expires after 10 minutes (BLK-YK-003)", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    clock += 10 * 60_000 + 1;
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b1111);
  });
  test("borrowed authority: a request passed on through a second agent keeps the first sender's cap", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "restart", body: { why: "db says slow" } });
    // the relay carries app's own mask, so ops is capped by app; app itself is still capped by db
    bh.read(tok("ops-agent"));
    expect(bh.authority("app-agent", 0b1111).mask).toBe(0b0011);
    expect(bh.authority("ops-agent", 0b1111).mask).toBe(0b1111);
  });
});

describe("BLK-005 / BLK-006 — the bell book", () => {
  test("sent, delivered and taint rows are written, and the chain holds", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    const events = readFileSync(join(dir, "bell-book.jsonl"), "utf-8").trim().split("\n").map((l) => JSON.parse(l).event);
    expect(events).toEqual(["sent", "delivered", "taint"]);
    expect(verifyBellBook(join(dir, "bell-book.jsonl"))).toMatchObject({ holds: true, rows: 3 });
  });
  test("a row changed after it was written breaks the chain at that row", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    const p = join(dir, "bell-book.jsonl");
    const lines = readFileSync(p, "utf-8").trim().split("\n");
    lines[1] = lines[1].replace('"event":"delivered"', '"event":"delivered-x"');
    writeFileSync(p, lines.join("\n") + "\n");
    expect(verifyBellBook(p)).toMatchObject({ holds: false, broken_at: 2 });
  });
  test("a removed row breaks the chain", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.read(tok("app-agent"));
    const p = join(dir, "bell-book.jsonl");
    const lines = readFileSync(p, "utf-8").trim().split("\n");
    writeFileSync(p, [lines[0], lines[2]].join("\n") + "\n");
    expect(verifyBellBook(p).holds).toBe(false);
  });
  test("a broken book is never appended to (reported, not repaired)", () => {
    const p = join(dir, "bell-book.jsonl");
    bh.send(tok("db-agent"), finding("app-agent"));
    writeFileSync(p, readFileSync(p, "utf-8").replace('"kind":"FINDING"', '"kind":"REQUEST"'));
    expect(() => new BellBook(p)).toThrow(/BLK-006/);
  });
});

describe("BLK-011 — telegraph repeat-back", () => {
  test("an ACK with the right hash: carried, no alarm", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent")) as any;
    const [m] = bh.read(tok("app-agent")) as any[];
    expect(m.hash).toBe(r.hash);
    expect(bh.send(tok("app-agent"), { to: "db-agent", kind: "ACK", subject: "", in_reply_to: r.id, received_hash: m.hash }).ok).toBe(true);
    expect(alarms.length).toBe(0);
  });
  test("an ACK whose hash differs from what was sent: the alarm sounds", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent")) as any;
    bh.read(tok("app-agent"));
    bh.send(tok("app-agent"), { to: "db-agent", kind: "ACK", subject: "", in_reply_to: r.id, received_hash: "0".repeat(64) });
    expect(alarms.map((a) => a.rule)).toContain("BLK-011");
  });
  test("an ACK may only answer a message sent to the acker", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent")) as any;
    expect(bh.send(tok("app-helper"), { to: "db-agent", kind: "ACK", subject: "", in_reply_to: r.id, received_hash: r.hash })).toMatchObject({ ok: false, rule: "BLK-011" });
  });
  test("an ACK through a door that does not carry ACK is refused", () => {
    fresh([{ id: "db-to-app", from: "db", to: "app", kinds: ["FINDING"] }]);
    const r = bh.send(tok("db-agent"), finding("app-agent")) as any;
    expect(bh.send(tok("app-agent"), { to: "db-agent", kind: "ACK", subject: "", in_reply_to: r.id, received_hash: r.hash })).toMatchObject({ ok: false, rule: "BLK-003" });
  });
  test("reading an ACK taints nobody", () => {
    const r = bh.send(tok("db-agent"), finding("app-agent")) as any;
    bh.read(tok("app-agent"));
    bh.send(tok("app-agent"), { to: "db-agent", kind: "ACK", subject: "", in_reply_to: r.id, received_hash: r.hash });
    bh.read(tok("db-agent"));
    expect(bh.authority("db-agent", 0b0011).tainted_by).toEqual([]);
  });
});

describe("BLK-008 / BLK-010 / BLK-YK-004 — damage control", () => {
  test("rate: the 6th message in a minute trips the door, sounds the alarm, and it stays closed", () => {
    for (let i = 0; i < 5; i++) expect(bh.send(tok("db-agent"), finding("app-agent", { subject: `s${i}` })).ok).toBe(true);
    expect(bh.send(tok("db-agent"), finding("app-agent", { subject: "s5" }))).toMatchObject({ ok: false, rule: "BLK-YK-004" });
    expect(alarms.map((a) => a.rule)).toContain("BLK-010");
    clock += 60 * 60_000; // an hour later the rate is fine, but the door is still shut
    expect(bh.send(tok("db-agent"), finding("app-agent", { subject: "later" }))).toMatchObject({ ok: false, rule: "BLK-008" });
    raiseOpenEpoch(join(dir, "doors.json"), "db-to-app"); // a person re-opens it (BLK-012)
    expect(bh.send(tok("db-agent"), finding("app-agent", { subject: "after opening" })).ok).toBe(true);
  });
  test("depth: a reply chain deeper than the door allows trips it", () => {
    fresh([
      { id: "app-to-ops", from: "app", to: "ops", kinds: ["FINDING", "REQUEST"], max_depth: 1 },
      { id: "ops-to-app", from: "ops", to: "app", kinds: ["FINDING", "REQUEST"], max_depth: 1 },
    ]);
    const m0 = bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "fix", body: {} }) as any;
    const m1 = bh.send(tok("ops-agent"), { to: "app-agent", kind: "REQUEST", subject: "fix", body: {}, in_reply_to: m0.id }) as any;
    expect(m1.ok).toBe(true);
    expect(bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "fix", body: {}, in_reply_to: m1.id })).toMatchObject({ ok: false, rule: "BLK-YK-004" });
  });
  test("ping-pong: two agents trading fixes on one subject trip the door", () => {
    fresh([
      { id: "app-to-ops", from: "app", to: "ops", kinds: ["REQUEST"], pingpong_max: 3, max_depth: 99 },
      { id: "ops-to-app", from: "ops", to: "app", kinds: ["REQUEST"], pingpong_max: 3, max_depth: 99 },
    ]);
    const r1 = bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "fix the fix", body: {} });
    const r2 = bh.send(tok("ops-agent"), { to: "app-agent", kind: "REQUEST", subject: "fix the fix", body: {} });
    const r3 = bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "fix the fix", body: {} });
    expect([r1.ok, r2.ok, r3.ok]).toEqual([true, true, true]);
    expect(bh.send(tok("ops-agent"), { to: "app-agent", kind: "REQUEST", subject: "fix the fix", body: {} })).toMatchObject({ ok: false, rule: "BLK-YK-004" });
    // a different subject between the same pair is not the same loop
    expect(bh.send(tok("app-agent"), { to: "ops-agent", kind: "REQUEST", subject: "other", body: {} }).ok).toBe(true);
  });
  test("closing a compartment shuts every door in and out of it until a person opens it", () => {
    bh.closeCompartment("app", "founder", "app agent misbehaving");
    expect(bh.send(tok("db-agent"), finding("app-agent"))).toMatchObject({ ok: false, rule: "BLK-008" });
    expect(bh.send(tok("app-agent"), { to: "ops-agent", kind: "FINDING", subject: "x", body: {} })).toMatchObject({ ok: false, rule: "BLK-008" });
    raiseOpenEpoch(join(dir, "doors.json"), "app");
    expect(bh.send(tok("db-agent"), finding("app-agent")).ok).toBe(true);
  });
});

describe("BLK-007 — the general alarm", () => {
  test("is never refused, even with every compartment closed, and is written", () => {
    for (const c of ["db", "app", "ops"]) bh.closeCompartment(c, "founder", "all shut");
    bh.alarm("db-agent", "disk at 98% on the root volume");
    expect(alarms.map((a) => a.text)).toContain("disk at 98% on the root volume");
    expect(readFileSync(join(dir, "alarms.jsonl"), "utf-8")).toContain("98%");
    expect(readFileSync(join(dir, "bell-book.jsonl"), "utf-8")).toContain('"event":"alarm"');
  });
  test("carries no request to any agent: no queue grows", () => {
    bh.alarm("db-agent", "help");
    expect(bh.status().queued).toBe(0);
  });
});

describe("state survives a restart of the bulkhead", () => {
  test("queue, taints, closed doors and the bell book carry over", () => {
    bh.send(tok("db-agent"), finding("app-agent"));
    bh.closeCompartment("ops", "founder", "test");
    const again = new Bulkhead({ dir, identity: fakeIdentity, now: () => clock });
    expect((again.read(tok("app-agent")) as any[]).length).toBe(1);
    expect(again.authority("app-agent", 0b1111).mask).toBe(0b0011);
    expect(again.status().closed_compartments).toHaveProperty("ops");
    expect(verifyBellBook(join(dir, "bell-book.jsonl")).holds).toBe(true);
  });
});

describe("BLK-T1.9 — the process on a unix socket", () => {
  test("send and read across the socket", async () => {
    const server = serve(bh);
    await new Promise((r) => setTimeout(r, 50));
    try {
      const s = await call(dir, { op: "send", token: tok("db-agent"), message: finding("app-agent") });
      expect(s.ok).toBe(true);
      const got = await call(dir, { op: "read", token: tok("app-agent") });
      expect(got[0].untrusted).toBe(true);
      const a = await call(dir, { op: "authority", agent_id: "app-agent", own_mask: 0b1111 });
      expect(a.mask).toBe(0b0011);
    } finally {
      server.close();
    }
  });
});

// Issuing real tokens and swarms must land under the scratch HOME, never the live ~/.aegis: in a full-suite
// run another file may have loaded aegis under the real HOME first (it did, 21 Oct 2026). Skip there.
const { getDbPath, getAegisDir } = await import("../src/core/config");
const identityUnsafe = (!getDbPath().startsWith(scratchHome) || !getAegisDir().startsWith(scratchHome)) && !process.env.CI;
if (identityUnsafe) console.warn(`[bulkhead] identity test SKIPPED: aegis resolves to ${getAegisDir()}, not the scratch HOME; run this file on its own`);

describe("INF-BLK-002 — the default identity: aegis delegation token + swarm", () => {
  (identityUnsafe ? test.skip : test)("a real SDT in a swarm is proven; the same agent outside a swarm, or a forged token, is not", async () => {
    const { issueSdt } = await import("../src/auth/sdt");
    const { createSwarm, enrollAgent } = await import("../src/sandbox/swarm");
    const { sdtIdentity } = await import("../src/bulkhead/identity");
    const id = await sdtIdentity();

    const coord = issueSdt({ agent_id: "coord-1", agent_class: "orchestrator", spawner_id: "human:test", requested_mask: 0b1111, task_scope: [] });
    const worker = issueSdt({ agent_id: "db-real", agent_class: "worker", spawner_id: "coord-1", parent_token_id: coord.token.token_id, requested_mask: 0b0011, task_scope: [] });
    expect(id.resolve(worker.token)).toHaveProperty("error"); // in no swarm yet

    const { swarm } = createSwarm("coord-1", 0b0111, 0b1111);
    enrollAgent(swarm.swarm_id, "db-real", 0b0011);
    expect(id.resolve(worker.token)).toMatchObject({ agent_id: "db-real", mask: 0b0011, compartment: swarm.swarm_id, ceiling: 0b0111 });

    const forged = structuredClone(worker.token);
    forged.delegation.delegated_mask = 0b1111;
    expect(id.resolve(forged)).toHaveProperty("error");
  });
});
