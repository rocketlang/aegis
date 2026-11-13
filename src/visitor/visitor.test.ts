// SPDX-License-Identifier: AGPL-3.0-only
// Visitor scope (design §7 of proposals/aegis-aface-pilot--brainstorm--formal--2026-11-13.md; rulings B1-B4).
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { openSqlite, type SqlDb } from "../core/sqlite.js";
import { decideVisit, ensureVisitorTables, recordGrant, setQuarantine, visitorTokenFor, policyFor } from "./visitor";

let dir: string, db: SqlDb;
const P = "mari8x-legal";
const ask = (principal: string, capability = "MARI_CHAT", cost = 1, now = new Date("2026-11-13T10:00:00Z"), overrides?: unknown) =>
  decideVisit(db, P, { product: P, principal, capability, cost }, overrides, now);

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "visitor-")); db = openSqlite(join(dir, "t.db")); ensureVisitorTables(db); });
afterEach(() => { db.close?.(); rmSync(dir, { recursive: true, force: true }); });

describe("tokens (B2)", () => {
  const tokens = { "mari8x-legal": "a".repeat(32), complymitra: "b".repeat(32), weak: "short" };
  it("names the product whose token it is", () => {
    expect(visitorTokenFor(`Bearer ${"a".repeat(32)}`, tokens)).toBe("mari8x-legal");
    expect(visitorTokenFor(`Bearer ${"b".repeat(32)}`, tokens)).toBe("complymitra");
  });
  it("refuses a wrong, short, missing or non-bearer token", () => {
    expect(visitorTokenFor(`Bearer ${"c".repeat(32)}`, tokens)).toBeNull();
    expect(visitorTokenFor("Bearer short", tokens)).toBeNull();
    expect(visitorTokenFor(undefined, tokens)).toBeNull();
    expect(visitorTokenFor("a".repeat(32), tokens)).toBeNull();
    expect(visitorTokenFor(`Bearer ${"a".repeat(32)}`, undefined)).toBeNull();
  });
  it("a token for one product cannot ask for another", () => {
    expect(() => decideVisit(db, "complymitra", { product: P, principal: "user:u1", capability: "MARI_CHAT" }, undefined)).toThrow();
  });
});

describe("decisions", () => {
  it("a new signed-in user gets the product's default scope and budget", () => {
    const d = ask("user:u1");
    expect(d.decision).toBe("ALLOW");
    expect(d.daily_turns).toBe(policyFor(P, undefined)!.daily_turns);
    expect(d.turns_today).toBe(1);
  });
  it("out of scope is refused", () => {
    expect(ask("user:u1", "DELETE_EVERYTHING").decision).toBe("REFUSE");
    expect(ask("user:u1", "DELETE_EVERYTHING").rule).toBe("visitor:out-of-scope");
  });
  it("the daily budget holds, and resets the next day (B3: cost counts)", () => {
    const o = { [P]: { daily_turns: 3 } };
    expect(ask("user:u2", "MARI_CHAT", 2, undefined, o).decision).toBe("ALLOW");
    expect(ask("user:u2", "MARI_CHAT", 2, undefined, o).rule).toBe("visitor:budget"); // 2 + 2 > 3, not charged
    expect(ask("user:u2", "MARI_CHAT", 1, undefined, o).decision).toBe("ALLOW");      // 3 of 3
    expect(ask("user:u2", "MARI_CHAT", 1, undefined, o).decision).toBe("REFUSE");
    expect(ask("user:u2", "MARI_CHAT", 1, new Date("2026-11-14T00:05:00Z"), o).decision).toBe("ALLOW");
  });
  it("an agent cannot name its own grant", () => {
    const d = ask("grant:g1");
    expect(d.decision).toBe("REFUSE");
    expect(d.rule).toBe("visitor:no-grant");
  });
  it("a recorded grant only narrows scope and budget, and expires", () => {
    const row = recordGrant(db, { product: P, principal: "grant:g2", scope: ["MARI_CHAT", "ROOT_SHELL"], daily_turns: 999, granted_by: "person@example.invalid", expires_at: "2026-11-13T12:00:00.000Z" }, undefined);
    expect(JSON.parse(row.scope)).toEqual(["MARI_CHAT"]);
    expect(row.daily_turns).toBe(policyFor(P, undefined)!.daily_turns);
    expect(ask("grant:g2").decision).toBe("ALLOW");
    expect(ask("grant:g2", "MARI_OFFICE").rule).toBe("visitor:out-of-scope");
    expect(ask("grant:g2", "MARI_CHAT", 1, new Date("2026-11-13T12:00:01Z")).rule).toBe("visitor:expired");
  });
  it("a grant needs the person who gave it", () => {
    expect(() => recordGrant(db, { product: P, principal: "grant:g3", scope: ["MARI_CHAT"], granted_by: " " }, undefined)).toThrow();
  });
  it("quarantine refuses until released; both need a reason and a person", () => {
    ask("user:u3");
    expect(() => setQuarantine(db, P, "user:u3", true, "", "founder")).toThrow();
    expect(setQuarantine(db, P, "user:u3", true, "scraping", "founder")).toBe(true);
    expect(ask("user:u3").rule).toBe("visitor:quarantined");
    expect(setQuarantine(db, P, "user:u3", false, "cleared", "founder")).toBe(true);
    expect(ask("user:u3").decision).toBe("ALLOW");
  });
  it("an unknown product is refused, and bad input is rejected before any decision", () => {
    expect(decideVisit(db, "nopolicy", { product: "nopolicy", principal: "user:u1", capability: "X" }, undefined).rule).toBe("visitor:no-policy");
    expect(() => ask("anon:someone")).toThrow();
    expect(() => ask("user:u1", "lowercase")).toThrow();
    expect(() => ask("user:u1", "MARI_CHAT", 0)).toThrow();
  });
  it("every decision is logged, refusals included", () => {
    ask("user:u4"); ask("user:u4", "NOPE"); ask("grant:none");
    const n = db.prepare<{ n: number }>(`SELECT COUNT(*) AS n FROM visitor_decisions`).get()!.n;
    expect(Number(n)).toBe(3);
  });
});
