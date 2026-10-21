// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead Phase 4 — second opinion (BLK-T4.1..T4.4), every rule both ways.
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md (BLK-017..019, BLK-YK-006, INF-BLK-006)
//
// Runs under a throwaway HOME and AEGIS_DIR set before any aegis module loads, put back in afterAll.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-p4-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { loadDoors } = await import("../src/bulkhead/doors");
const { handle } = await import("../src/bulkhead/server");
const { PERM_STANDARD } = await import("../src/kavach/perm-mask");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

// A performance agent proposes "cylinder 3 is running hot" from noon reports; checkers answer from their own data.
const AGENTS: Record<string, string> = {
  "perf-agent": "perf", "engine-agent": "engine", "engine2-agent": "engine", "fuel-agent": "fuel",
};
const identity = {
  resolve(t: any) {
    const c = t && AGENTS[t.proof];
    return c ? { agent_id: t.proof, mask: PERM_STANDARD, compartment: c, ceiling: PERM_STANDARD } : { error: "unknown" };
  },
  compartmentOf: (id: string) => (AGENTS[id] ? { compartment: AGENTS[id], ceiling: PERM_STANDARD } : null),
};
const tok = (a: string) => ({ proof: a });
const DATA_PATHS = { perf: ["noon-reports"], engine: ["ams-sensors", "noon-reports"], fuel: ["bunker-delivery-notes"] };
const DOORS = [
  { id: "perf-to-engine", from: "perf", to: "engine", kinds: ["REQUEST", "FINDING"] },
  { id: "engine-checks-perf", from: "engine", to: "perf", kinds: ["FINDING", "ACK"], check: true },
  { id: "perf-to-fuel", from: "perf", to: "fuel", kinds: ["REQUEST"] },
  { id: "fuel-checks-perf", from: "fuel", to: "perf", kinds: ["FINDING"], check: true, fields: ["verdict", "note"] },
];

function setup(doors: object[] = DOORS) {
  const dir = mkdtempSync(join(scratchHome, "bh-"));
  writeFileSync(join(dir, "doors.json"), JSON.stringify({ data_paths: DATA_PATHS, doors }));
  return { dir, bh: new Bulkhead({ dir, identity }) };
}
// The proposal goes to each checker; returns the ids each checker answers.
function propose(bh: InstanceType<typeof Bulkhead>) {
  const req = { kind: "REQUEST", subject: "cyl 3 hot", body: { claim: "exh temp high" }, evidence_path: "noon-reports" };
  const toEngine = bh.send(tok("perf-agent"), { ...req, to: "engine-agent" }) as any;
  const toEngine2 = bh.send(tok("perf-agent"), { ...req, to: "engine2-agent" }) as any;
  const toFuel = bh.send(tok("perf-agent"), { ...req, to: "fuel-agent" }) as any;
  expect([toEngine.ok, toEngine2.ok, toFuel.ok]).toEqual([true, true, true]);
  return { engine: toEngine.id, engine2: toEngine2.id, fuel: toFuel.id };
}
const reply = (id: string, verdict: string, path?: string) =>
  ({ to: "perf-agent", kind: "FINDING", subject: "cyl 3 hot", in_reply_to: id, body: { verdict }, ...(path ? { evidence_path: path } : {}) });

describe("BLK-018 — a message names only a data path its compartment declares", () => {
  test("a declared path passes; an undeclared one is refused", () => {
    const { bh } = setup();
    expect(bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "s", evidence_path: "noon-reports" }).ok).toBe(true);
    expect(bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "s", evidence_path: "ams-sensors" })).toMatchObject({ ok: false, rule: "BLK-018" });
  });
  test("no data_paths in the doors file: any named path is refused, an unnamed one passes", () => {
    const dir = mkdtempSync(join(scratchHome, "bh-"));
    writeFileSync(join(dir, "doors.json"), JSON.stringify({ doors: DOORS }));
    const bh = new Bulkhead({ dir, identity });
    expect(bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "s", evidence_path: "noon-reports" })).toMatchObject({ ok: false, rule: "BLK-018" });
    expect(bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "s" }).ok).toBe(true);
  });
});

describe("BLK-017 — on a check door the reply is an independent verdict", () => {
  test("a confirmation from a path the proposal did not name passes", () => {
    const { bh } = setup();
    const ids = propose(bh);
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "ams-sensors")).ok).toBe(true);
  });
  test("a confirmation from the proposer's own path is refused: that is no check", () => {
    const { bh } = setup();
    const ids = propose(bh);
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "noon-reports"))).toMatchObject({ ok: false, rule: "BLK-017", reason: expect.stringContaining("no independent check") });
  });
  test("no verdict, an unknown verdict, or a confirmation with no path: refused", () => {
    const { bh } = setup();
    const ids = propose(bh);
    expect(bh.send(tok("engine-agent"), { ...reply(ids.engine, "confirms", "ams-sensors"), body: {} })).toMatchObject({ rule: "BLK-017" });
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "agrees", "ams-sensors"))).toMatchObject({ rule: "BLK-017" });
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "confirms"))).toMatchObject({ rule: "BLK-017" });
  });
  test("cannot_check needs no path", () => {
    const { bh } = setup();
    const ids = propose(bh);
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "cannot_check")).ok).toBe(true);
  });
  test("a reply that answers nothing, or answers a message sent to someone else: refused", () => {
    const { bh } = setup();
    const ids = propose(bh);
    const { in_reply_to, ...noParent } = reply(ids.engine, "confirms", "ams-sensors");
    expect(bh.send(tok("engine-agent"), noParent)).toMatchObject({ ok: false, rule: "BLK-017" });
    expect(bh.send(tok("engine-agent"), reply(ids.fuel, "confirms", "ams-sensors"))).toMatchObject({ ok: false, rule: "BLK-017" });
  });
  test("an ordinary door asks no verdict (Phase 1 unchanged)", () => {
    const { bh } = setup();
    const r = bh.send(tok("perf-agent"), { to: "engine-agent", kind: "FINDING", subject: "fyi", body: { x: 1 } });
    expect(r.ok).toBe(true);
  });
  test("a check door that cannot carry FINDING, or whose fields leave out verdict, is dropped and reported", () => {
    const { dir } = setup([
      { id: "bad1", from: "engine", to: "perf", kinds: ["ACK"], check: true },
      { id: "bad2", from: "fuel", to: "perf", kinds: ["FINDING"], check: true, fields: ["note"] },
    ]);
    const t = loadDoors(join(dir, "doors.json"));
    expect(t.doors).toEqual([]);
    expect(t.errors.join(" ")).toContain("check door carries FINDING");
    expect(t.errors.join(" ")).toContain("must include verdict");
  });
});

describe("BLK-019 / BLK-YK-006 — count distinct paths, not agreeing agents", () => {
  test("two checkers on two other paths: a count of 2", () => {
    const { bh } = setup();
    const ids = propose(bh);
    bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "ams-sensors"));
    bh.send(tok("fuel-agent"), reply(ids.fuel, "confirms", "bunker-delivery-notes"));
    // The same claim went to each checker as its own message; asked from any copy, the count covers all.
    for (const id of [ids.engine, ids.fuel]) {
      expect(bh.evidence(id)).toMatchObject({ copies: 3, count: 2, confirming_paths: ["ams-sensors", "bunker-delivery-notes"], proposer_paths: ["noon-reports"] });
    }
  });
  test("two agents who read the same path are one check", () => {
    const { bh } = setup();
    const ids = propose(bh);
    expect(bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "ams-sensors")).ok).toBe(true);
    expect(bh.send(tok("engine2-agent"), reply(ids.engine2, "confirms", "ams-sensors")).ok).toBe(true);
    const e = bh.evidence(ids.engine) as any;
    expect(e.confirmations.map((c: any) => c.from).sort()).toEqual(["engine-agent", "engine2-agent"]);
    expect(e.count).toBe(1);
  });
  test("a different claim (other body) is not counted with it", () => {
    const { bh } = setup();
    const ids = propose(bh);
    const other = bh.send(tok("perf-agent"), { to: "fuel-agent", kind: "REQUEST", subject: "cyl 3 hot", body: { claim: "something else" }, evidence_path: "noon-reports" }) as any;
    bh.send(tok("fuel-agent"), reply(other.id, "confirms", "bunker-delivery-notes"));
    expect(bh.evidence(ids.engine)).toMatchObject({ copies: 3, count: 0 });
  });
  test("a contradiction is listed beside the count, never netted against it", () => {
    const { bh } = setup();
    const req = bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "cyl 3 hot", evidence_path: "noon-reports" }) as any;
    bh.send(tok("engine-agent"), reply(req.id, "confirms", "ams-sensors"));
    bh.send(tok("engine-agent"), reply(req.id, "contradicts", "ams-sensors"));
    bh.send(tok("engine-agent"), reply(req.id, "cannot_check"));
    const e = bh.evidence(req.id) as any;
    expect(e.count).toBe(1);
    expect(e.contradictions).toEqual([expect.objectContaining({ from: "engine-agent", path: "ams-sensors" })]);
    expect(e.cannot_check).toHaveLength(1);
  });
  test("a path named anywhere up the chain is not independent (a re-check of a check)", () => {
    const { bh } = setup();
    const req = bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "cyl 3 hot", evidence_path: "noon-reports" }) as any;
    const c1 = bh.send(tok("engine-agent"), reply(req.id, "confirms", "ams-sensors")) as any;
    // perf asks engine again about that confirmation; engine may not confirm it from ams again, nor from noon reports
    const again = bh.send(tok("perf-agent"), { to: "engine-agent", kind: "REQUEST", subject: "cyl 3 hot", in_reply_to: c1.id }) as any;
    expect(again.ok).toBe(true);
    expect(bh.send(tok("engine-agent"), reply(again.id, "confirms", "ams-sensors"))).toMatchObject({ rule: "BLK-017" });
    expect(bh.send(tok("engine-agent"), reply(again.id, "confirms", "noon-reports"))).toMatchObject({ rule: "BLK-017" });
  });
  test("evidence on an unknown message is an error, and the socket answers it", () => {
    const { bh } = setup();
    expect(bh.evidence("nope")).toHaveProperty("error");
    const ids = propose(bh);
    bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "ams-sensors"));
    expect(handle(bh, { op: "evidence", message_id: ids.engine })).toMatchObject({ count: 1 });
  });
  test("the bell book records the path and the verdict of each reply", () => {
    const { dir, bh } = setup();
    const ids = propose(bh);
    bh.send(tok("engine-agent"), reply(ids.engine, "confirms", "ams-sensors"));
    const rows = require("fs").readFileSync(join(dir, "bell-book.jsonl"), "utf-8").trim().split("\n").map((l: string) => JSON.parse(l));
    expect(rows.at(-1)).toMatchObject({ event: "sent", evidence_path: "ams-sensors", verdict: "confirms", door: "engine-checks-perf" });
  });
});
