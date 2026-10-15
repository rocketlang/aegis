// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
//
// Gap 2 of the flow guardrails: carriage into subprocesses (GTP-020/021/022, INF-GTP-008).
// A child agent started from the parent session's shell carries AEGIS_FLOW='<parent session>:<mandate id>'.
// Its mandate must be narrowed from the parent's, fall when the parent's is revoked, and a child naming a
// parent that does not exist must not become a root. Throwaway HOME; the real hooks run as subprocesses.

import { afterAll, describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { spawnSync } from "child_process";

const root = mkdtempSync(join(tmpdir(), "aegis-flow-carriage-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));
const cli = join(import.meta.dir, "..", "src/cli/index.ts");

function box(mode: "enforce" | "monitor") {
  const home = mkdtempSync(join(root, `${mode}-`));
  mkdirSync(join(home, ".aegis"), { recursive: true });
  writeFileSync(join(home, ".aegis", "config.json"), JSON.stringify({ enforcement: { mode }, kavach: mode === "enforce" ? { enabled: true, mandate: "enforce" } : { enabled: true } }));
  const approvers = join(home, "approvers.json");
  writeFileSync(approvers, JSON.stringify({ owners: { telegram: ["555000111"] } }));
  const env: Record<string, string> = { ...(process.env as Record<string, string>), HOME: home, AEGIS_DIR: join(home, ".aegis"), AOS_APPROVERS_FILE: approvers, KAVACHOS_MUDRIKA_SECRET: "t", AEGIS_URL: "http://127.0.0.1:9" };
  delete env.AEGIS_FLOW;
  delete env.CLAUDE_ENV_FILE;
  return { home, env };
}
const hook = (env: Record<string, string>, cmd: string, input: unknown) =>
  spawnSync("bun", ["run", cli, cmd], { input: JSON.stringify(input), env, encoding: "utf8", timeout: 30000 });
const toolCall = (env: Record<string, string>, session: string) =>
  hook(env, "check-shield", { hook_event_name: "PreToolUse", session_id: session, prompt_id: "p", tool_use_id: `t${Math.random().toString(36).slice(2, 7)}`, tool_name: "Read", tool_input: { file_path: "/tmp/harmless.txt" }, cwd: "/tmp" });
const mandateOf = (home: string, session: string) => {
  const id = readFileSync(join(home, ".aegis", "mandates", `session-${session}`), "utf8").trim();
  return JSON.parse(readFileSync(join(home, ".aegis", "mandates", `${id}.json`), "utf8")) as Record<string, any>;
};
const revoke = (home: string, id: string) =>
  appendFileSync(join(home, ".aegis", "mandates", "revoked.jsonl"), JSON.stringify({ mudrika_id: id, revoked_at: new Date().toISOString(), by: "test" }) + "\n");

describe("carriage into a subprocess (AEGIS_FLOW)", () => {
  test("flow-start hands the flow to later shell commands through CLAUDE_ENV_FILE", () => {
    const { home, env } = box("monitor");
    const envFile = join(home, "session-env.sh");
    writeFileSync(envFile, "export OTHER_HOOK=1\n");
    const r = hook({ ...env, CLAUDE_ENV_FILE: envFile }, "flow-start", { hook_event_name: "SessionStart", session_id: "P1", cwd: "/tmp", source: "startup" });
    expect(r.status).toBe(0);
    const m = mandateOf(home, "P1");
    const text = readFileSync(envFile, "utf8");
    expect(text).toContain("export OTHER_HOOK=1"); // appended, never overwritten
    expect(text).toContain(`export AEGIS_FLOW='P1:${m.mudrika_id}'`);
  });

  test("a child's mandate is narrowed from its parent's and names it", () => {
    const { home, env } = box("monitor");
    hook(env, "flow-start", { session_id: "P2", cwd: "/tmp" });
    const parent = mandateOf(home, "P2");
    toolCall({ ...env, AEGIS_FLOW: `P2:${parent.mudrika_id}` }, "C2");
    const child = mandateOf(home, "C2");
    expect(child.parent_mandate_id).toBe(parent.mudrika_id);
    expect(child.principal_id).toBe(parent.principal_id);
    expect((child.trust_mask & ~parent.trust_mask) >>> 0).toBe(0);
  });

  test("enforce: revoking the parent's mandate refuses the child's next call (GTP-022, the tree falls)", () => {
    const { home, env } = box("enforce");
    hook(env, "flow-start", { session_id: "P3", cwd: "/tmp" });
    const parent = mandateOf(home, "P3");
    const childEnv = { ...env, AEGIS_FLOW: `P3:${parent.mudrika_id}` };
    expect(toolCall(childEnv, "C3").status).toBe(0);
    revoke(home, parent.mudrika_id);
    const r = toolCall(childEnv, "C3");
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("GTP-022");
  });

  test("enforce: a child naming a parent that does not exist is not made a root; refused (GTP-021)", () => {
    const { home, env } = box("enforce");
    const r = toolCall({ ...env, AEGIS_FLOW: "GHOST:mdr_nope_000000000000" }, "C4");
    expect(r.status).toBe(2);
    let issued = true;
    try { mandateOf(home, "C4"); } catch { issued = false; }
    expect(issued).toBe(false);
  });

  test("AEGIS_FLOW naming the session itself is ignored (the parent's own shell is not its child)", () => {
    const { home, env } = box("monitor");
    hook(env, "flow-start", { session_id: "P5", cwd: "/tmp" });
    const m = mandateOf(home, "P5");
    expect(toolCall({ ...env, AEGIS_FLOW: `P5:${m.mudrika_id}` }, "P5").status).toBe(0);
    expect(mandateOf(home, "P5").mudrika_id).toBe(m.mudrika_id);
    expect(mandateOf(home, "P5").parent_mandate_id).toBeUndefined();
  });
});
