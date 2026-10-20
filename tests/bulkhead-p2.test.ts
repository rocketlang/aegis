// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// aegis Bulkhead Phase 2 — joined to the live gates (BLK-T2.1, T2.3, T2.4, T2.5), every rule both ways.
// Logics: /root/proposals/aegis-bulkhead--logics--formal--2026-10-21.md (BLK-012, BLK-013)
//
// Runs under a throwaway HOME and AEGIS_DIR set before any aegis module loads (the shield's own-files
// rule and the hook's refusal ledger both follow them), put back in afterAll.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const scratchHome = mkdtempSync(join(tmpdir(), "aegis-bulkhead-p2-"));
const HOME_BEFORE = process.env.HOME;
const AEGIS_DIR_BEFORE = process.env.AEGIS_DIR;
process.env.HOME = scratchHome;
process.env.AEGIS_DIR = join(scratchHome, ".aegis");
mkdirSync(process.env.AEGIS_DIR, { recursive: true });

const { Bulkhead } = await import("../src/bulkhead/bulkhead");
const { raiseOpenEpoch } = await import("../src/bulkhead/doors");
const { handle } = await import("../src/bulkhead/server");
const { bulkheadVerdict } = await import("../src/bulkhead/gate");
const { PERM, PERM_STANDARD } = await import("../src/kavach/perm-mask");
const { loadShieldRules, bashFileVerdict, detectPersistenceWrite } = await import("../src/shield/injection-detector");
const { getAegisDir } = await import("../src/core/config");

afterAll(() => {
  process.env.HOME = HOME_BEFORE;
  if (AEGIS_DIR_BEFORE === undefined) delete process.env.AEGIS_DIR; else process.env.AEGIS_DIR = AEGIS_DIR_BEFORE;
  rmSync(scratchHome, { recursive: true, force: true });
});

const AGENTS: Record<string, { mask: number; compartment: string }> = {
  "db-agent": { mask: PERM.READ | PERM.DB_READ, compartment: "db" },
  "app-agent": { mask: PERM_STANDARD, compartment: "app" },
};
const CEIL: Record<string, number> = { db: PERM.READ | PERM.DB_READ, app: PERM_STANDARD };
const identity = {
  resolve(t: any) {
    const a = t && AGENTS[t.proof];
    return a ? { agent_id: t.proof, mask: a.mask, compartment: a.compartment, ceiling: CEIL[a.compartment] } : { error: "unknown" };
  },
  compartmentOf: (id: string) => (AGENTS[id] ? { compartment: AGENTS[id].compartment, ceiling: CEIL[AGENTS[id].compartment] } : null),
};
const tok = (a: string) => ({ proof: a });
const finding = { to: "app-agent", kind: "FINDING", subject: "slow query", body: { metric: "p99" } };

function fresh() {
  const dir = mkdtempSync(join(scratchHome, "bh-"));
  writeFileSync(join(dir, "doors.json"), JSON.stringify({ doors: [{ id: "db-to-app", from: "db", to: "app", kinds: ["FINDING"], rate_per_min: 1 }] }));
  return { dir, bh: new Bulkhead({ dir, identity }) };
}

describe("BLK-012 — closing is anyone's; opening is a person raising an open epoch", () => {
  test("a tripped door stays shut until its epoch is raised; then it opens", () => {
    const { dir, bh } = fresh();
    expect(bh.send(tok("db-agent"), finding).ok).toBe(true);
    expect(bh.send(tok("db-agent"), { ...finding, subject: "2" }).ok).toBe(false); // trips (rate 1)
    expect(bh.send(tok("db-agent"), { ...finding, subject: "3" })).toMatchObject({ ok: false, rule: "BLK-008" });
    raiseOpenEpoch(join(dir, "doors.json"), "db-to-app");
    expect(bh.status().closed_doors).not.toHaveProperty("db-to-app");
  });
  test("an epoch already raised before the closure does not open it", () => {
    const { dir, bh } = fresh();
    raiseOpenEpoch(join(dir, "doors.json"), "app");
    bh.closeCompartment("app", "db-agent", "agent shuts a neighbour it distrusts"); // anyone may close
    expect(bh.send(tok("db-agent"), finding)).toMatchObject({ ok: false, rule: "BLK-008" });
    raiseOpenEpoch(join(dir, "doors.json"), "app");
    expect(bh.send(tok("db-agent"), finding).ok).toBe(true);
  });
  test("the socket has no open: only close, and the request is answered as unknown", () => {
    const { bh } = fresh();
    bh.closeCompartment("app", "x", "y");
    expect(handle(bh, { op: "open", door: "db-to-app" })).toHaveProperty("error");
    expect(handle(bh, { op: "open-compartment", compartment: "app" })).toHaveProperty("error");
    expect(bh.status().closed_compartments).toHaveProperty("app");
  });
  test("raising an epoch keeps the doors, and turns an array file into the object form", () => {
    const { dir } = fresh();
    writeFileSync(join(dir, "doors.json"), JSON.stringify([{ id: "d", from: "a", to: "b", kinds: ["FINDING"] }]));
    expect(raiseOpenEpoch(join(dir, "doors.json"), "d")).toBe(1);
    expect(raiseOpenEpoch(join(dir, "doors.json"), "d")).toBe(2);
    const raw = JSON.parse(require("fs").readFileSync(join(dir, "doors.json"), "utf-8"));
    expect(raw.doors[0].id).toBe("d");
    expect(raw.open_epochs.d).toBe(2);
  });
});

describe("BLK-013 — the gate's verdict (pure)", () => {
  const state = (dir: string, taints: unknown) => writeFileSync(join(dir, "state.json"), JSON.stringify({ taints }));
  const now = Date.parse("2026-10-21T12:00:00Z");
  test("no bulkhead state: allowed, untainted, nothing read", () => {
    const dir = mkdtempSync(join(scratchHome, "g-"));
    expect(bulkheadVerdict(dir, "a", () => { throw new Error("must not be called"); }, PERM.WRITE, now)).toEqual({ allowed: true, tainted: false });
  });
  test("tainted by a read-only peer: Read passes, Write and Bash are refused", () => {
    const dir = mkdtempSync(join(scratchHome, "g-"));
    state(dir, [{ agent_id: "a", message_id: "m1", cap: PERM.READ | PERM.DB_READ, expires_at: now + 60_000 }]);
    expect(bulkheadVerdict(dir, "a", PERM_STANDARD, PERM.READ, now)).toMatchObject({ allowed: true, tainted: true });
    expect(bulkheadVerdict(dir, "a", PERM_STANDARD, PERM.WRITE, now)).toMatchObject({ allowed: false });
    expect(bulkheadVerdict(dir, "a", PERM_STANDARD, PERM.EXEC_BASH, now)).toMatchObject({ allowed: false });
  });
  test("another agent's taint, or an expired one, changes nothing", () => {
    const dir = mkdtempSync(join(scratchHome, "g-"));
    state(dir, [{ agent_id: "b", message_id: "m1", cap: 0, expires_at: now + 60_000 }, { agent_id: "a", message_id: "m0", cap: 0, expires_at: now - 1 }]);
    expect(bulkheadVerdict(dir, "a", PERM_STANDARD, PERM.WRITE, now)).toEqual({ allowed: true, tainted: false });
  });
  test("a state that exists but cannot be read refuses", () => {
    const dir = mkdtempSync(join(scratchHome, "g-"));
    writeFileSync(join(dir, "state.json"), "{not json");
    expect(bulkheadVerdict(dir, "a", PERM_STANDARD, PERM.READ, now)).toMatchObject({ allowed: false });
  });
});

describe("BLK-013 — the live hook (check-destructive) end to end", () => {
  const runHook = (env: Record<string, string>, input: unknown) => {
    const p = Bun.spawnSync(["bun", "src/cli/index.ts", "check-destructive"], {
      cwd: join(import.meta.dir, ".."),
      stdin: Buffer.from(JSON.stringify(input)),
      env: { ...process.env, HOME: scratchHome, AEGIS_DIR: join(scratchHome, ".aegis"), ...env },
    });
    return { code: p.exitCode, err: p.stderr.toString() };
  };
  const edit = { tool_name: "Edit", agent_id: "hook-agent", session_id: "s-hook", tool_input: { file_path: join(scratchHome, "x.ts"), old_string: "a", new_string: "b" } };

  test("tainted by a read-only peer: the Edit is refused with exit 2 and Rule: BLK-013", () => {
    const dir = mkdtempSync(join(scratchHome, "hook-"));
    writeFileSync(join(dir, "state.json"), JSON.stringify({ taints: [{ agent_id: "hook-agent", message_id: "m1", cap: PERM.READ, expires_at: Date.now() + 600_000 }] }));
    const r = runHook({ AEGIS_BULKHEAD_DIR: dir }, edit);
    expect(r.code).toBe(2);
    expect(r.err).toContain("Rule: BLK-013");
  });
  test("control: the same Edit with no taint passes", () => {
    const dir = mkdtempSync(join(scratchHome, "hook-"));
    writeFileSync(join(dir, "state.json"), JSON.stringify({ taints: [] }));
    expect(runHook({ AEGIS_BULKHEAD_DIR: dir }, edit).code).toBe(0);
  });
  test("control: no bulkhead folder at all passes, as before Phase 2", () => {
    expect(runHook({ AEGIS_BULKHEAD_DIR: join(scratchHome, "no-such-dir") }, edit).code).toBe(0);
  });
});

describe("BLK-T2.3 / BLK-012 — the shield", () => {
  const rules = loadShieldRules();
  const ctx = { cwd: join(scratchHome, "project"), home: scratchHome };
  const bh = join(getAegisDir(), "bulkhead"); // the dir aegis loaded with, as the shield sees it
  test("the doors file, bell book and state are the shield's own files (KAV-096): Write/Edit refused", () => {
    for (const f of ["doors.json", "bell-book.jsonl", "state.json"]) {
      expect(detectPersistenceWrite(join(bh, f), rules, ctx)).toMatchObject({ verdict: "QUARANTINE", rule_id: "KAV-096" });
    }
  });
  test("a shell write to the doors file is refused (KAV-096)", () => {
    expect(bashFileVerdict(`echo '{}' > ${bh}/doors.json`, rules, ctx).verdict).toBe("QUARANTINE");
  });
  test("opening as a tool call is refused (BLK-012), by either name", () => {
    expect(bashFileVerdict("aegis bulkhead open db-to-app", rules, ctx)).toMatchObject({ verdict: "QUARANTINE", rule_id: "BLK-012" });
    expect(bashFileVerdict("bun src/bulkhead/cli.ts open app", rules, ctx)).toMatchObject({ verdict: "QUARANTINE", rule_id: "BLK-012" });
    expect(bashFileVerdict("bun /root/aegis/src/cli/index.ts bulkhead open app", rules, ctx)).toMatchObject({ rule_id: "BLK-012" });
  });
  test("closing, status, verify and showing the words are not refused", () => {
    for (const c of ["aegis bulkhead close app 'loop'", "aegis bulkhead status", "aegis bulkhead verify", "echo aegis bulkhead open x", "grep 'bulkhead open' notes.md"]) {
      expect(bashFileVerdict(c, rules, ctx).rule_id).not.toBe("BLK-012");
    }
  });
});

describe("BLK-T2.5 — 'aegis bulkhead' in the dispatcher", () => {
  test("aegis bulkhead verify runs and reports an empty book as holding", () => {
    const dir = mkdtempSync(join(scratchHome, "cli-"));
    const p = Bun.spawnSync(["bun", "src/cli/index.ts", "bulkhead", "verify"], {
      cwd: join(import.meta.dir, ".."),
      env: { ...process.env, HOME: scratchHome, AEGIS_DIR: join(scratchHome, ".aegis"), AEGIS_BULKHEAD_DIR: dir },
    });
    expect(p.exitCode).toBe(0);
    expect(JSON.parse(p.stdout.toString())).toMatchObject({ holds: true, rows: 0 });
  });
});
