// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// ACC event flow fields (GTP-024, governed-turn-protocol spec §19): five optional fields on every event,
// added to the acc_events table without changing anything that was there. Uses only a temporary file.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { SqliteEventWriter } from "../src/acc/bus";
import { openSqlite } from "../src/core/sqlite";
import type { AccReceipt } from "../src/acc/types";

const dir = mkdtempSync(join(tmpdir(), "acc-flow-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const ev = (n: number, extra: Partial<AccReceipt> = {}): AccReceipt => ({
  receipt_id: `r${n}`, primitive: "aegis", event_type: "gate.decided",
  emitted_at: new Date(Date.UTC(2026, 9, 15, 0, 0, n)).toISOString(), ...extra,
});

describe("ACC flow fields", () => {
  test("events carry the five fields and read back by flow, in order", () => {
    const w = new SqliteEventWriter({ path: join(dir, "a.db") });
    w.write(ev(2, { flow_id: "cc:S", turn_id: "tool:T2", parent_turn_id: "agent:A", mandate_id: "mdr_1", session_ref: "ase:x" }));
    w.write(ev(1, { flow_id: "cc:S", turn_id: "tool:T1", parent_turn_id: "prompt:P" }));
    w.write(ev(3, { flow_id: "cc:OTHER", turn_id: "tool:T3" }));
    const flow = w.queryByFlow("cc:S");
    expect(flow.map((e) => e.turn_id)).toEqual(["tool:T1", "tool:T2"]);
    expect(flow[1]).toMatchObject({ parent_turn_id: "agent:A", mandate_id: "mdr_1", session_ref: "ase:x" });
    expect(w.queryNewer(0).find((e) => e.receipt_id === "r2")?.flow_id).toBe("cc:S");
    w.close();
  });

  test("an event without flow fields stays valid", () => {
    const w = new SqliteEventWriter({ path: join(dir, "b.db") });
    w.write(ev(1, { agent_id: "a1", verdict: "PASS" }));
    const [e] = w.queryByAgent("a1");
    expect(e).toMatchObject({ receipt_id: "r1", verdict: "PASS" });
    expect(e.flow_id).toBeUndefined();
    expect(e.turn_id).toBeUndefined();
    w.close();
  });

  test("a table created before the flow fields gains them; old rows still read", () => {
    const path = join(dir, "old.db");
    const old = openSqlite(path);
    old.exec(`CREATE TABLE acc_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, receipt_id TEXT NOT NULL, primitive TEXT NOT NULL,
      event_type TEXT NOT NULL, emitted_at TEXT NOT NULL, agent_id TEXT, verdict TEXT, rules_fired TEXT,
      summary TEXT, payload TEXT, ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`);
    old.run("INSERT INTO acc_events (receipt_id, primitive, event_type, emitted_at, rules_fired) VALUES (?,?,?,?,?)",
      "old1", "chitta-detect", "scan.evaluated", "2026-05-17T12:00:00.000Z", JSON.stringify(["CG-006"]));
    old.close();

    const w = new SqliteEventWriter({ path });
    const before = w.queryByPrimitive("chitta-detect");
    expect(before).toHaveLength(1);
    expect(before[0]).toMatchObject({ receipt_id: "old1", rules_fired: ["CG-006"] });
    expect(before[0].flow_id).toBeUndefined();
    w.write(ev(1, { flow_id: "cc:S", turn_id: "tool:T1" }));
    expect(w.queryByFlow("cc:S").map((e) => e.receipt_id)).toEqual(["r1"]);
    expect(w.totalCount()).toBe(2);
    w.close();
  });
});
