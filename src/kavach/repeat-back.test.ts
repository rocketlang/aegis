// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:RPB-001..006 — each rule is driven both ways here: the act it records and the act it refuses.

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  type Act, type Evidence, RecordBroken, classify, readRecord, recordDecision, recordRequest,
  repeatBackPhrase, report, verdictOf,
} from "./repeat-back";

const ACT: Act = { repo: "rocketlang/aegis", package: "@rocketlang/aegis", version: "2.30.0", commit: "a".repeat(40) };
const ev = (verdict: Evidence["verdict"], at = "2026-10-30T10:00:00.000Z"): Evidence => ({
  verdict, read_at: at,
  checks: verdict === "none" ? [] : [{ name: "test", status: verdict === "pending" ? "in_progress" : "completed", conclusion: verdict === "green" ? "success" : verdict === "red" ? "failure" : null }],
});
const T0 = new Date("2026-10-30T10:00:00Z");
const T1 = new Date("2026-10-30T10:20:00Z");

let dir: string; let path: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "rpb-")); path = join(dir, "repeat-back.jsonl"); });
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("verdictOf (RPB-003)", () => {
  it("no checks is none, never green", () => expect(verdictOf([])).toBe("none"));
  it("any failure is red, even beside a pending one", () => {
    expect(verdictOf([{ name: "a", status: "completed", conclusion: "failure" }, { name: "b", status: "queued", conclusion: null }])).toBe("red");
  });
  it("anything unfinished is pending", () => expect(verdictOf([{ name: "a", status: "in_progress", conclusion: null }])).toBe("pending"));
  it("all completed and passing is green", () => {
    expect(verdictOf([{ name: "a", status: "completed", conclusion: "success" }, { name: "b", status: "completed", conclusion: "skipped" }])).toBe("green");
  });
});

describe("request (RPB-001)", () => {
  it("records the exact act and the evidence; asking twice is one request", () => {
    const a = recordRequest(ACT, ev("green"), T0, path);
    const b = recordRequest(ACT, ev("green"), T0, path);
    expect(a.id).toBe(b.id);
    expect(readRecord(path)).toHaveLength(1);
  });
  it("a changed act is a new request", () => {
    const a = recordRequest(ACT, ev("green"), T0, path);
    const b = recordRequest({ ...ACT, commit: "b".repeat(40) }, ev("green"), T0, path);
    expect(a.id).not.toBe(b.id);
  });
  it("refuses a short commit", () => {
    expect(() => recordRequest({ ...ACT, commit: "abc1234" }, ev("green"), T0, path)).toThrow(/full 40/);
  });
});

describe("decision (RPB-002, RPB-004)", () => {
  it("records nothing unless the act is typed back exactly", () => {
    const q = recordRequest(ACT, ev("green"), T0, path);
    expect(() => recordDecision(q.id, "approve", "yes", ev("green"), { by: "capt", now: T1, path })).toThrow(/not repeated back/);
    expect(() => recordDecision(q.id, "approve", "@rocketlang/aegis@2.30.0 bbbbbbb", ev("green"), { by: "capt", now: T1, path })).toThrow(/not repeated back/);
    expect(readRecord(path)).toHaveLength(1);
  });
  it("records a yes on the exact words", () => {
    const q = recordRequest(ACT, ev("green"), T0, path);
    expect(repeatBackPhrase(q)).toBe("@rocketlang/aegis@2.30.0 aaaaaaa");
    const d = recordDecision(q.id, "approve", "@rocketlang/aegis@2.30.0 aaaaaaa", ev("green"), { by: "capt", now: T1, path });
    expect(d.decision).toBe("approve");
  });
  it("records a no like a yes, and a no needs a reason", () => {
    const q = recordRequest(ACT, ev("green"), T0, path);
    expect(() => recordDecision(q.id, "deny", repeatBackPhrase(q), ev("green"), { by: "capt", now: T1, path })).toThrow(/reason/);
    const d = recordDecision(q.id, "deny", repeatBackPhrase(q), ev("green"), { by: "capt", reason: "changelog wrong", now: T1, path });
    expect(d.reason).toBe("changelog wrong");
  });
  it("decides a request once", () => {
    const q = recordRequest(ACT, ev("green"), T0, path);
    recordDecision(q.id, "approve", repeatBackPhrase(q), ev("green"), { by: "capt", now: T1, path });
    expect(() => recordDecision(q.id, "deny", repeatBackPhrase(q), ev("green"), { by: "capt", reason: "x", now: T1, path })).toThrow(/already decided/);
  });
});

describe("chain (RPB-005)", () => {
  it("refuses a record whose row was altered", () => {
    const q = recordRequest(ACT, ev("green"), T0, path);
    recordDecision(q.id, "approve", repeatBackPhrase(q), ev("red"), { by: "capt", now: T1, path });
    writeFileSync(path, readFileSync(path, "utf8").replace('"verdict":"red"', '"verdict":"green"'));
    expect(() => readRecord(path)).toThrow(RecordBroken);
  });
  it("refuses a record with a row taken out", () => {
    recordRequest(ACT, ev("green"), T0, path);
    recordRequest({ ...ACT, version: "2.30.1" }, ev("green"), T0, path);
    recordRequest({ ...ACT, version: "2.30.2" }, ev("green"), T0, path);
    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    writeFileSync(path, [lines[0], lines[2]].join("\n") + "\n");
    expect(() => readRecord(path)).toThrow(/chain broken/);
  });
});

describe("report (RPB-006)", () => {
  it("classes each decision against the verdict at the moment of decision, not at asking", () => {
    const q1 = recordRequest(ACT, ev("green"), T0, path);
    const q2 = recordRequest({ ...ACT, version: "2.30.1" }, ev("green"), T0, path);
    const q3 = recordRequest({ ...ACT, version: "2.30.2" }, ev("red"), T0, path);
    const q4 = recordRequest({ ...ACT, version: "2.30.3" }, ev("pending"), T0, path);
    recordRequest({ ...ACT, version: "2.30.4" }, ev("green"), T0, path); // left open
    const d1 = recordDecision(q1.id, "approve", repeatBackPhrase(q1), ev("green"), { by: "capt", now: T1, path });
    const d2 = recordDecision(q2.id, "approve", repeatBackPhrase(q2), ev("red"), { by: "capt", now: T1, path }); // went red since asking
    const d3 = recordDecision(q3.id, "deny", repeatBackPhrase(q3), ev("red"), { by: "capt", reason: "tests", now: T1, path });
    const d4 = recordDecision(q4.id, "deny", repeatBackPhrase(q4), ev("green"), { by: "capt", reason: "wrong notes", now: T1, path });
    expect([d1, d2, d3, d4].map(classify)).toEqual(["confirmed", "overrode", "agreed", "changed"]);
    const r = report(readRecord(path));
    expect(r).toMatchObject({ requests: 5, decided: 4, open: 1, counts: { confirmed: 1, overrode: 1, changed: 1, agreed: 1 }, wait_minutes_median: 20 });
    expect(r.overrides.map((o) => o.act)).toEqual(["@rocketlang/aegis@2.30.1 aaaaaaa"]);
  });
  it("a yes with no CI at all is an override", () => {
    const q = recordRequest(ACT, ev("none"), T0, path);
    expect(classify(recordDecision(q.id, "approve", repeatBackPhrase(q), ev("none"), { by: "capt", now: T1, path }))).toBe("overrode");
  });
});
