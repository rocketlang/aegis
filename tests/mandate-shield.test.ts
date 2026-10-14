// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// P3 in the live hook: the real check-shield, run as a subprocess under a throwaway HOME, in enforce
// and in monitor mode. GTP-017 (no mandate), GTP-022 (revoked), and founder ruling 2a (monitor records,
// enforce refuses). Nothing here touches the real aegis directory.

import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, appendFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";

const root = mkdtempSync(join(tmpdir(), "aegis-mandate-shield-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function box(mode: "enforce" | "monitor", withApprover = true): { home: string; env: Record<string, string> } {
  const home = mkdtempSync(join(root, `${mode}-`));
  mkdirSync(join(home, ".aegis"), { recursive: true });
  writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode }, kavach: { enabled: true } }));
  const approvers = join(home, "approvers.json");
  writeFileSync(approvers, JSON.stringify(withApprover ? { owners: { telegram: ["555000111"] } } : { owners: {} }));
  return { home, env: { ...process.env as Record<string, string>, HOME: home, AEGIS_DIR: join(home, ".aegis"), AOS_APPROVERS_FILE: approvers, KAVACHOS_MUDRIKA_SECRET: "t", AEGIS_FLOW_EVENTS: "on" } };
}

function call(env: Record<string, string>, session: string, tool = "Read"): { code: number; err: string } {
  const input = JSON.stringify({ hook_event_name: "PreToolUse", session_id: session, prompt_id: "p", tool_use_id: `t${Math.random().toString(36).slice(2, 8)}`, tool_name: tool, tool_input: { file_path: "/tmp/harmless.txt" }, cwd: "/tmp" });
  const r = spawnSync("bun", ["run", join(import.meta.dir, "..", "src/cli/index.ts"), "check-shield"], { input, env, encoding: "utf8", timeout: 30000 });
  return { code: r.status ?? -1, err: r.stderr ?? "" };
}

const sessionPointer = (home: string, s: string) => readFileSync(join(home, ".aegis", "mandates", `session-${s}`), "utf8").trim();

describe("mandate in the shield", () => {
  test("enforce: the first call issues a mandate and is allowed", () => {
    const { home, env } = box("enforce");
    expect(call(env, "S1").code).toBe(0);
    expect(sessionPointer(home, "S1")).toMatch(/^mdr_/);
  });

  test("enforce: after a person revokes it, the next call is refused GTP-022, and it is not reissued", () => {
    const { home, env } = box("enforce");
    expect(call(env, "S2").code).toBe(0);
    const id = sessionPointer(home, "S2");
    appendFileSync(join(home, ".aegis", "mandates", "revoked.jsonl"), JSON.stringify({ mudrika_id: id, revoked_at: new Date().toISOString(), by: "test" }) + "\n");
    const r = call(env, "S2");
    expect(r.code).toBe(2);
    expect(r.err).toContain("GTP-022");
    expect(sessionPointer(home, "S2")).toBe(id);
  });

  test("enforce: no approver means no mandate, refused GTP-017", () => {
    const { env } = box("enforce", false);
    const r = call(env, "S3");
    expect(r.code).toBe(2);
    expect(r.err).toContain("GTP-017");
  });

  test("monitor: a revoked mandate is recorded, not refused", () => {
    const { home, env } = box("monitor");
    expect(call(env, "S4").code).toBe(0);
    const id = sessionPointer(home, "S4");
    appendFileSync(join(home, ".aegis", "mandates", "revoked.jsonl"), JSON.stringify({ mudrika_id: id, revoked_at: new Date().toISOString(), by: "test" }) + "\n");
    expect(call(env, "S4").code).toBe(0);
    const { Database } = require("bun:sqlite");
    const db = new Database(join(home, ".aegis", "flow-events.db"), { readonly: true });
    const last = db.query("SELECT mandate_id, payload FROM acc_events ORDER BY id DESC LIMIT 1").get() as { mandate_id: string; payload: string };
    db.close();
    expect(last.mandate_id).toBe(id);
    expect(JSON.parse(last.payload).mandate).toBe("revoked");
  });
});
