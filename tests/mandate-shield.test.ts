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

// "enforce" = the box enforces and has opted in to mandate refusals; "enforce-no-optin" = the box enforces
// but never set kavach.mandate (every box upgraded from 2.20.x).
function box(mode: "enforce" | "enforce-no-optin" | "monitor", withApprover = true): { home: string; env: Record<string, string> } {
  const home = mkdtempSync(join(root, `${mode}-`));
  mkdirSync(join(home, ".aegis"), { recursive: true });
  const kavach = mode === "enforce" ? { enabled: true, mandate: "enforce" } : { enabled: true };
  writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode: mode === "monitor" ? "monitor" : "enforce" }, kavach }));
  const approvers = join(home, "approvers.json");
  writeFileSync(approvers, JSON.stringify(withApprover ? { owners: { telegram: ["555000111"] } } : { owners: {} }));
  const env: Record<string, string> = { ...process.env as Record<string, string>, HOME: home, AEGIS_DIR: join(home, ".aegis"), AOS_APPROVERS_FILE: approvers, KAVACHOS_MUDRIKA_SECRET: "t", AEGIS_FLOW_EVENTS: "on" };
  // Run from inside a governed session, the parent's AEGIS_FLOW would name a mandate this throwaway
  // home does not hold (GTP-021) and every call would be refused; its env file is not ours to write.
  delete env.AEGIS_FLOW;
  delete env.CLAUDE_ENV_FILE;
  return { home, env };
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

  // Founder ruling 2026-10-23: an expired mandate is renewed at the next call inside the same session.
  test("enforce: a mandate that expired mid-session is renewed at the next call, and the call is allowed", () => {
    const { home, env } = box("enforce");
    const issue = `const M = await import(${JSON.stringify(join(import.meta.dir, "..", "src/kavach/mandate.ts"))});
      const m = M.issueMandate("S7", { trustMask: 1, scopeKey: "aegis", principal: "owner:telegram:555000111", now: new Date(Date.now() - 25 * 3600 * 1000) });
      console.log(m.mudrika_id, M.mandateForCall("S7").status);`;
    const r0 = spawnSync("bun", ["-e", issue], { env, encoding: "utf8", timeout: 30000 });
    const [old, status] = r0.stdout.trim().split(" ");
    expect(status).toBe("expired");
    expect(call(env, "S7").code).toBe(0);
    const now = sessionPointer(home, "S7");
    expect(now).toMatch(/^mdr_/);
    expect(now).not.toBe(old);
    expect(call(env, "S7").code).toBe(0);
    expect(sessionPointer(home, "S7")).toBe(now);
  });

  test("enforce: no approver means no mandate, refused GTP-017", () => {
    const { env } = box("enforce", false);
    const r = call(env, "S3");
    expect(r.code).toBe(2);
    expect(r.err).toContain("GTP-017");
  });

  test("enforce without the opt-in (an upgraded box): no approver is allowed, not refused", () => {
    const { env } = box("enforce-no-optin", false);
    expect(call(env, "S5").code).toBe(0);
  });

  test("enforce without the opt-in: a revoked mandate is recorded, not refused", () => {
    const { home, env } = box("enforce-no-optin");
    expect(call(env, "S6").code).toBe(0);
    const id = sessionPointer(home, "S6");
    appendFileSync(join(home, ".aegis", "mandates", "revoked.jsonl"), JSON.stringify({ mudrika_id: id, revoked_at: new Date().toISOString(), by: "test" }) + "\n");
    expect(call(env, "S6").code).toBe(0);
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
